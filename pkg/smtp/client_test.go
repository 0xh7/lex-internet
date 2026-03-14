package smtp

import (
	"bufio"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

var errSMTPWriteFailed = errors.New("smtp: write failed")

type smtpFailingConn struct{}

func (smtpFailingConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (smtpFailingConn) Write([]byte) (int, error)        { return 0, errSMTPWriteFailed }
func (smtpFailingConn) Close() error                     { return nil }
func (smtpFailingConn) LocalAddr() net.Addr              { return &net.TCPAddr{} }
func (smtpFailingConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (smtpFailingConn) SetDeadline(time.Time) error      { return nil }
func (smtpFailingConn) SetReadDeadline(time.Time) error  { return nil }
func (smtpFailingConn) SetWriteDeadline(time.Time) error { return nil }

func TestCommandPropagatesWriteErrors(t *testing.T) {
	conn := smtpFailingConn{}
	c := &Client{
		conn:       conn,
		reader:     bufio.NewReader(conn),
		writer:     bufio.NewWriterSize(conn, 1),
		extensions: make(map[string]string),
	}

	_, _, err := c.command("NOOP")
	if err == nil {
		t.Fatal("command() error = nil, want write error")
	}
	if !errors.Is(err, errSMTPWriteFailed) {
		t.Fatalf("command() error = %v, want wrapped %v", err, errSMTPWriteFailed)
	}
	if !strings.Contains(err.Error(), "smtp: write") {
		t.Fatalf("command() error = %q, want smtp write context", err.Error())
	}
}

func TestCommandRejectsCRLFInjection(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	c := &Client{
		conn:       clientConn,
		reader:     bufio.NewReader(clientConn),
		writer:     bufio.NewWriter(clientConn),
		extensions: make(map[string]string),
	}

	_, _, err := c.command("MAIL FROM:<%s>", "a@b>\r\nRCPT TO:<evil@x>")
	if !errors.Is(err, errSMTPCommandInjection) {
		t.Fatalf("command() error = %v, want %v", err, errSMTPCommandInjection)
	}

	_ = serverConn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 64)
	n, readErr := serverConn.Read(buf)
	if n > 0 || readErr == nil {
		t.Fatalf("server observed injected command bytes: %q", strings.TrimSpace(string(buf[:n])))
	}
}
