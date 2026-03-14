package smtp

import (
	"bufio"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestReadLineLimitedConsumesOverlongLine(t *testing.T) {
	long := strings.Repeat("a", maxCommandLineLen+16)
	reader := bufio.NewReader(strings.NewReader(long + "\r\nNEXT\r\n"))

	if _, err := readLineLimited(reader, maxCommandLineLen); !errors.Is(err, errLineTooLong) {
		t.Fatalf("readLineLimited() error = %v, want %v", err, errLineTooLong)
	}

	line, err := readLineLimited(reader, maxCommandLineLen)
	if err != nil {
		t.Fatalf("readLineLimited(next): %v", err)
	}
	if line != "NEXT" {
		t.Fatalf("next line = %q, want %q", line, "NEXT")
	}
}

func TestDiscardDataStopsAtDotAndKeepsSessionSynced(t *testing.T) {
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	sess := &session{
		conn:   serverConn,
		reader: bufio.NewReader(serverConn),
	}

	done := make(chan struct{})
	go func() {
		sess.discardData()
		close(done)
	}()

	dataWriteErr := make(chan error, 1)
	go func() {
		_, err := clientConn.Write([]byte("line1\r\nline2\r\n.\r\n"))
		dataWriteErr <- err
	}()

	select {
	case err := <-dataWriteErr:
		if err != nil {
			t.Fatalf("write DATA payload: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("writing DATA payload blocked")
	}

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("discardData did not finish")
	}

	cmdWriteErr := make(chan error, 1)
	go func() {
		_, err := clientConn.Write([]byte("NOOP\r\n"))
		cmdWriteErr <- err
	}()

	line, err := readLineLimited(sess.reader, maxCommandLineLen)
	if err != nil {
		t.Fatalf("read command after discardData: %v", err)
	}
	if line != "NOOP" {
		t.Fatalf("line after DATA terminator = %q, want %q", line, "NOOP")
	}

	select {
	case err := <-cmdWriteErr:
		if err != nil {
			t.Fatalf("write command payload: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("writing command payload blocked")
	}
}
