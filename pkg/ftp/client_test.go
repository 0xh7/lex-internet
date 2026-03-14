package ftp

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"runtime"
	"strings"
	"testing"
	"time"
)

type ftpStringer string

func (s ftpStringer) String() string { return string(s) }

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

func TestEnterPassiveRejectsOutOfRangeValues(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	go func() {
		reader := bufio.NewReader(serverConn)
		line, err := reader.ReadString('\n')
		if err == nil && line == "PASV\r\n" {
			_, _ = fmt.Fprintf(serverConn, "227 Entering Passive Mode (10,0,0,1,300,1)\r\n")
		}
	}()

	client := &Client{
		conn:   clientConn,
		reader: bufio.NewReader(clientConn),
		writer: bufio.NewWriter(clientConn),
		host:   "127.0.0.1",
	}

	if _, err := client.enterPassive(); err == nil {
		t.Fatal("enterPassive() error = nil, want PASV range error")
	}
}

func TestCommandRejectsCRLFInjection(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	client := &Client{
		conn:   clientConn,
		reader: bufio.NewReader(clientConn),
		writer: bufio.NewWriter(clientConn),
		host:   "127.0.0.1",
	}

	_, _, err := client.command("USER %s", "attacker\r\nQUIT")
	if !errors.Is(err, errFTPCommandInjection) {
		t.Fatalf("command() error = %v, want %v", err, errFTPCommandInjection)
	}

	_ = serverConn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 64)
	n, readErr := serverConn.Read(buf)
	if n > 0 || readErr == nil {
		t.Fatalf("server observed injected command bytes: %q", strings.TrimSpace(string(buf[:n])))
	}
}

func TestCommandRejectsCRLFInjectionFromStringer(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	client := &Client{
		conn:   clientConn,
		reader: bufio.NewReader(clientConn),
		writer: bufio.NewWriter(clientConn),
		host:   "127.0.0.1",
	}

	_, _, err := client.command("USER %v", ftpStringer("attacker\r\nQUIT"))
	if !errors.Is(err, errFTPCommandInjection) {
		t.Fatalf("command() error = %v, want %v", err, errFTPCommandInjection)
	}
}
