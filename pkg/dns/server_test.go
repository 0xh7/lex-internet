package dns

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestUDPResponseWriterSetsTCBitOnTruncation(t *testing.T) {
	serverConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(server): %v", err)
	}
	defer serverConn.Close()

	clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP(client): %v", err)
	}
	defer clientConn.Close()

	msg := NewResponse(NewQuery(7, "example.com", TypeTXT, ClassIN), RCodeNoError, []ResourceRecord{{
		Name:     "example.com",
		Type:     TypeTXT,
		Class:    ClassIN,
		TTL:      60,
		RDLength: 600,
		RData:    bytes.Repeat([]byte("a"), 600),
	}})

	raw, err := msg.Marshal()
	if err != nil {
		t.Fatalf("Marshal(): %v", err)
	}
	if len(raw) <= 512 {
		t.Fatalf("test message too small: %d bytes", len(raw))
	}

	writer := &udpResponseWriter{
		conn: serverConn,
		addr: clientConn.LocalAddr().(*net.UDPAddr),
	}
	if err := writer.WriteMsg(msg); err != nil {
		t.Fatalf("WriteMsg(): %v", err)
	}

	buf := make([]byte, 1024)
	if err := clientConn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("SetReadDeadline(): %v", err)
	}
	n, _, err := clientConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("ReadFromUDP(): %v", err)
	}
	if n != 512 {
		t.Fatalf("udp reply length = %d, want 512", n)
	}
	if !FlagsTC(binary.BigEndian.Uint16(buf[2:4])) {
		t.Fatal("truncated udp reply missing TC bit")
	}
}
