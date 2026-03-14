package smtp

import (
	"bufio"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

type noopDeadlineConn struct{ net.Conn }

func (noopDeadlineConn) SetReadDeadline(time.Time) error { return nil }

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
	sess := &session{
		conn:   noopDeadlineConn{},
		reader: bufio.NewReader(strings.NewReader("line1\r\nline2\r\n.\r\nNOOP\r\n")),
	}

	sess.discardData()

	line, err := readLineLimited(sess.reader, maxCommandLineLen)
	if err != nil {
		t.Fatalf("read command after discardData: %v", err)
	}
	if line != "NOOP" {
		t.Fatalf("line after DATA terminator = %q, want %q", line, "NOOP")
	}
}
