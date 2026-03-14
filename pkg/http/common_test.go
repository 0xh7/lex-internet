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

func TestParseResponseReadsCloseDelimitedBody(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader(
		"HTTP/1.1 200 OK\r\n\r\nhello-close-delimited",
	))

	resp, err := ParseResponse(reader)
	if err != nil {
		t.Fatalf("ParseResponse(): %v", err)
	}
	if got := string(resp.Body); got != "hello-close-delimited" {
		t.Fatalf("body = %q, want %q", got, "hello-close-delimited")
	}
}

func TestParseRequestWithoutBodyLengthKeepsNextRequest(t *testing.T) {
	raw := strings.Join([]string{
		"GET /one HTTP/1.1",
		"Host: example.com",
		"",
		"GET /two HTTP/1.1",
		"Host: example.com",
		"",
		"",
	}, "\r\n")

	reader := bufio.NewReader(strings.NewReader(raw))

	first, err := ParseRequest(reader)
	if err != nil {
		t.Fatalf("ParseRequest(first): %v", err)
	}
	if first.Path != "/one" {
		t.Fatalf("first path = %q, want %q", first.Path, "/one")
	}
	if len(first.Body) != 0 {
		t.Fatalf("first body len = %d, want 0", len(first.Body))
	}

	second, err := ParseRequest(reader)
	if err != nil {
		t.Fatalf("ParseRequest(second): %v", err)
	}
	if second.Path != "/two" {
		t.Fatalf("second path = %q, want %q", second.Path, "/two")
	}
}

func TestParseResponseRejectsConflictingContentLengthHeaders(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader(strings.Join([]string{
		"HTTP/1.1 200 OK",
		"Content-Length: 5",
		"Content-Length: 7",
		"",
		"payload",
	}, "\r\n")))

	if _, err := ParseResponse(reader); err == nil {
		t.Fatal("ParseResponse() error = nil, want conflicting Content-Length error")
	}
}
