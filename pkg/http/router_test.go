package http

import "testing"

func TestRouterRestoresParamsAfterBacktracking(t *testing.T) {
	router := NewRouter()
	handler := func(req *Request, w *ResponseWriter) {}

	router.Add("GET", "/a/:id/*", handler)
	router.Add("GET", "/a/:id/x/:id/z", handler)

	route, params := router.Match("GET", "/a/first/x/second/q")
	if route == nil {
		t.Fatal("expected route match")
	}
	if route.Pattern != "/a/:id/*" {
		t.Fatalf("matched pattern = %q, want %q", route.Pattern, "/a/:id/*")
	}
	if got := params["id"]; got != "first" {
		t.Fatalf("id param = %q, want %q", got, "first")
	}
	if got := params["*"]; got != "x/second/q" {
		t.Fatalf("wildcard param = %q, want %q", got, "x/second/q")
	}
}
