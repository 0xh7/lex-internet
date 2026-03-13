package http

import (
	"bufio"
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
