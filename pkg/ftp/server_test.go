package ftp

import "testing"

func TestResolvePathKeepsAbsolutePathsInsideRoot(t *testing.T) {
	sess := &session{
		server: &Server{rootDir: "/var/ftp"},
		cwd:    "/",
	}

	actual, virtual, err := sess.resolvePath("/etc/passwd")
	if err != nil {
		t.Fatalf("resolvePath(): %v", err)
	}
	if actual != "/var/ftp/etc/passwd" {
		t.Fatalf("actual path = %q, want %q", actual, "/var/ftp/etc/passwd")
	}
	if virtual != "/etc/passwd" {
		t.Fatalf("virtual path = %q, want %q", virtual, "/etc/passwd")
	}
}

func TestResolvePathAllowsRootFilesystemWhenConfigured(t *testing.T) {
	sess := &session{
		server: &Server{rootDir: "/"},
		cwd:    "/",
	}

	actual, virtual, err := sess.resolvePath("etc/passwd")
	if err != nil {
		t.Fatalf("resolvePath(): %v", err)
	}
	if actual != "/etc/passwd" {
		t.Fatalf("actual path = %q, want %q", actual, "/etc/passwd")
	}
	if virtual != "/etc/passwd" {
		t.Fatalf("virtual path = %q, want %q", virtual, "/etc/passwd")
	}
}
