package http

import (
	"bufio"
	"net"
	"strings"
	"testing"
)

func TestShouldReuseConnectionRequiresDelimitedBody(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader(""))

	if shouldReuseConnection(&Response{StatusCode: 200, Headers: map[string][]string{}}, reader) {
		t.Fatal("expected undelimited 200 response to close the connection")
	}

	if !shouldReuseConnection(&Response{
		StatusCode: 200,
		Headers:    map[string][]string{"Content-Length": {"5"}},
	}, reader) {
		t.Fatal("expected Content-Length response to be reusable")
	}

	if !shouldReuseConnection(&Response{
		StatusCode: 204,
		Headers:    map[string][]string{},
	}, reader) {
		t.Fatal("expected 204 response to be reusable")
	}
}

func TestGetConnReturnsPooledReader(t *testing.T) {
	c := NewClient()
	serverConn, clientConn := net.Pipe()
	defer serverConn.Close()
	defer clientConn.Close()

	reader := bufio.NewReaderSize(serverConn, 4096)
	c.putConn("example.com:80", serverConn, reader)

	gotConn, gotReader, err := c.getConn("example.com:80")
	if err != nil {
		t.Fatalf("getConn(): %v", err)
	}
	if gotConn != serverConn {
		t.Fatal("getConn() did not return the pooled connection")
	}
	if gotReader != reader {
		t.Fatal("getConn() did not return the pooled reader")
	}
}

func TestParseResponseDelimitedBodyIsReusable(t *testing.T) {
	reader := bufio.NewReader(strings.NewReader(
		"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nhello",
	))

	resp, err := ParseResponse(reader)
	if err != nil {
		t.Fatalf("ParseResponse(): %v", err)
	}
	if string(resp.Body) != "hello" {
		t.Fatalf("body = %q, want %q", string(resp.Body), "hello")
	}
	if !shouldReuseConnection(resp, reader) {
		t.Fatal("expected parsed delimited response to be reusable")
	}
}

func TestShouldReuseConnectionHonorsAnyCloseToken(t *testing.T) {
	resp := &Response{
		StatusCode: 200,
		Headers: map[string][]string{
			"Content-Length": {"5"},
			"Connection":     {"keep-alive", "close"},
		},
	}
	if shouldReuseConnection(resp, bufio.NewReader(strings.NewReader(""))) {
		t.Fatal("expected response with any close token to be non-reusable")
	}
}
