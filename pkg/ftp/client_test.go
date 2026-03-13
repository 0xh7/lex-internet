package ftp

import (
	"bufio"
	"fmt"
	"net"
	"runtime"
	"testing"
	"time"
)

func TestEnterPassiveUsesControlConnectionHost(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("loopback data-channel test is covered on Linux CI")
	}

	dataLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen(data): %v", err)
	}
	defer dataLn.Close()

	accepted := make(chan struct{}, 1)
	go func() {
		conn, err := dataLn.Accept()
		if err == nil {
			accepted <- struct{}{}
			_ = conn.Close()
		}
	}()

	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	go func() {
		reader := bufio.NewReader(serverConn)
		line, err := reader.ReadString('\n')
		if err == nil && line == "PASV\r\n" {
			port := dataLn.Addr().(*net.TCPAddr).Port
			_, _ = fmt.Fprintf(serverConn, "227 Entering Passive Mode (10,0,0,1,%d,%d)\r\n", port/256, port%256)
		}
	}()

	client := &Client{
		conn:   clientConn,
		reader: bufio.NewReader(clientConn),
		writer: bufio.NewWriter(clientConn),
		host:   "127.0.0.1",
	}

	dataConn, err := client.enterPassive()
	if err != nil {
		t.Fatalf("enterPassive(): %v", err)
	}
	_ = dataConn.Close()

	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for passive data connection")
	}
}
