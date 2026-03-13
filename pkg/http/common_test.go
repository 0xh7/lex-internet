package http

import (
	"bufio"
	"strings"
	"testing"
)

func TestParseResponseConsumesChunkedTrailers(t *testing.T) {
	raw := strings.Join([]string{
		"HTTP/1.1 200 OK",
		"Transfer-Encoding: chunked",
		"",
		"5",
		"hello",
		"0",
		"X-Trace: one",
		"",
		"HTTP/1.1 204 No Content",
		"Content-Length: 0",
		"",
		"",
	}, "\r\n")

	reader := bufio.NewReader(strings.NewReader(raw))

	first, err := ParseResponse(reader)
	if err != nil {
		t.Fatalf("ParseResponse(first): %v", err)
	}
	if got := string(first.Body); got != "hello" {
		t.Fatalf("first body = %q, want %q", got, "hello")
	}

	second, err := ParseResponse(reader)
	if err != nil {
		t.Fatalf("ParseResponse(second): %v", err)
	}
	if second.StatusCode != 204 {
		t.Fatalf("second status = %d, want 204", second.StatusCode)
	}
}

func TestCanonicalHeaderKeyUsesStandardForm(t *testing.T) {
	if got := canonicalHeaderKey("www-authenticate"); got != "Www-Authenticate" {
		t.Fatalf("canonicalHeaderKey = %q, want %q", got, "Www-Authenticate")
	}
	if got := canonicalHeaderKey("content-md5"); got != "Content-Md5" {
		t.Fatalf("canonicalHeaderKey = %q, want %q", got, "Content-Md5")
	}
}
