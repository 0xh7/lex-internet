package proxy

import (
	"net/http"
	"testing"
)

func TestRemoveHopByHopHandlesMultipleConnectionHeaders(t *testing.T) {
	h := http.Header{}
	h.Add("Connection", "Keep-Alive")
	h.Add("Connection", "X-Extra")
	h.Add("Keep-Alive", "timeout=5")
	h.Add("X-Extra", "1")
	h.Add("Transfer-Encoding", "chunked")
	h.Add("X-Trace", "ok")

	removeHopByHop(h)

	if got := h.Get("Keep-Alive"); got != "" {
		t.Fatalf("Keep-Alive header still present: %q", got)
	}
	if got := h.Get("X-Extra"); got != "" {
		t.Fatalf("X-Extra header still present: %q", got)
	}
	if got := h.Get("Transfer-Encoding"); got != "" {
		t.Fatalf("Transfer-Encoding header still present: %q", got)
	}
	if got := h.Get("X-Trace"); got != "ok" {
		t.Fatalf("X-Trace = %q, want %q", got, "ok")
	}
}
