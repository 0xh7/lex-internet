package ftp

import (
	"path/filepath"
	"testing"
)

func TestResolvePathKeepsAbsolutePathsInsideRoot(t *testing.T) {
	root := t.TempDir()
	sess := &session{
		server: &Server{rootDir: root},
		cwd:    "/",
	}

	actual, virtual, err := sess.resolvePath("/etc/passwd")
	if err != nil {
		t.Fatalf("resolvePath(): %v", err)
	}
	wantActual := filepath.Join(root, "etc", "passwd")
	if actual != wantActual {
		t.Fatalf("actual path = %q, want %q", actual, wantActual)
	}
	if virtual != "/etc/passwd" {
		t.Fatalf("virtual path = %q, want %q", virtual, "/etc/passwd")
	}
}

func TestResolvePathUsesSessionCWD(t *testing.T) {
	root := t.TempDir()
	sess := &session{
		server: &Server{rootDir: root},
		cwd:    "/pub",
	}

	actual, virtual, err := sess.resolvePath("etc/passwd")
	if err != nil {
		t.Fatalf("resolvePath(): %v", err)
	}
	wantActual := filepath.Join(root, "pub", "etc", "passwd")
	if actual != wantActual {
		t.Fatalf("actual path = %q, want %q", actual, wantActual)
	}
	if virtual != "/pub/etc/passwd" {
		t.Fatalf("virtual path = %q, want %q", virtual, "/pub/etc/passwd")
	}
}
