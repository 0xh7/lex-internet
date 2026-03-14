package http

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestResolvePathWithinRootRejectsTraversal(t *testing.T) {
	root := t.TempDir()

	_, err := resolvePathWithinRoot(root, "../secret.txt")
	if !errors.Is(err, errPathTraversal) {
		t.Fatalf("resolvePathWithinRoot traversal error = %v, want %v", err, errPathTraversal)
	}
}

func TestResolvePathWithinRootRejectsAbsoluteOutsideRoot(t *testing.T) {
	root := t.TempDir()
	outside := filepath.Join(filepath.Dir(root), "outside.txt")

	_, err := resolvePathWithinRoot(root, outside)
	if !errors.Is(err, errPathTraversal) {
		t.Fatalf("resolvePathWithinRoot absolute outside error = %v, want %v", err, errPathTraversal)
	}
}

func TestResolvePathWithinRootAllowsPathInsideRoot(t *testing.T) {
	root := t.TempDir()
	got, err := resolvePathWithinRoot(root, filepath.Join("assets", "index.html"))
	if err != nil {
		t.Fatalf("resolvePathWithinRoot inside root: %v", err)
	}

	want := filepath.Join(root, "assets", "index.html")
	if got != want {
		t.Fatalf("resolved path = %q, want %q", got, want)
	}
}

func TestResolvePathWithinRootRejectsSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics/permissions vary on Windows runners; covered on Linux CI")
	}

	root := t.TempDir()
	outsideDir := t.TempDir()
	outsideFile := filepath.Join(outsideDir, "secret.txt")
	if err := os.WriteFile(outsideFile, []byte("secret"), 0o644); err != nil {
		t.Fatalf("write outside file: %v", err)
	}

	link := filepath.Join(root, "escape.txt")
	if err := os.Symlink(outsideFile, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	_, err := resolvePathWithinRoot(root, "escape.txt")
	if !errors.Is(err, errPathTraversal) {
		t.Fatalf("resolvePathWithinRoot symlink escape error = %v, want %v", err, errPathTraversal)
	}
}
