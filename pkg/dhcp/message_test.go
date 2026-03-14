package dhcp

import (
	"net"
	"testing"
)

func TestMarshalIgnoresNonIPv4HeaderAddresses(t *testing.T) {
	m := &Message{
		Op:     OpReply,
		HType:  1,
		HLen:   6,
		CIAddr: net.ParseIP("2001:db8::1"),
		YIAddr: net.ParseIP("2001:db8::2"),
		SIAddr: net.IPv4(192, 0, 2, 1),
		GIAddr: net.ParseIP("2001:db8::3"),
	}

	raw := m.Marshal()

	if got := net.IP(raw[12:16]).String(); got != "0.0.0.0" {
		t.Fatalf("CIAddr bytes = %q, want 0.0.0.0", got)
	}
	if got := net.IP(raw[16:20]).String(); got != "0.0.0.0" {
		t.Fatalf("YIAddr bytes = %q, want 0.0.0.0", got)
	}
	if got := net.IP(raw[20:24]).String(); got != "192.0.2.1" {
		t.Fatalf("SIAddr bytes = %q, want 192.0.2.1", got)
	}
	if got := net.IP(raw[24:28]).String(); got != "0.0.0.0" {
		t.Fatalf("GIAddr bytes = %q, want 0.0.0.0", got)
	}
}
