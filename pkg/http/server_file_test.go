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
	rootNorm := root
	if r, err := filepath.EvalSymlinks(root); err == nil {
		rootNorm = r
	}
	if !pathWithinRoot(rootNorm, got) {
		t.Fatalf("resolved path %q escaped root %q", got, rootNorm)
	}
	if base := filepath.Base(got); base != "index.html" {
		t.Fatalf("resolved file name = %q, want %q", base, "index.html")
	}
	if dirBase := filepath.Base(filepath.Dir(got)); dirBase != "assets" {
		t.Fatalf("resolved parent dir = %q, want %q", dirBase, "assets")
	}
}

func TestResolvePathWithinRootAllowsPathInsideSymlinkedRoot(t *testing.T) {
	realRoot := t.TempDir()
	linkParent := t.TempDir()
	linkRoot := filepath.Join(linkParent, "root-link")

	if err := os.Symlink(realRoot, linkRoot); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	got, err := resolvePathWithinRoot(linkRoot, filepath.Join("assets", "index.html"))
	if err != nil {
		t.Fatalf("resolvePathWithinRoot symlinked root: %v", err)
	}

	realRootNorm := realRoot
	if r, err := filepath.EvalSymlinks(realRoot); err == nil {
		realRootNorm = r
	}
	if !pathWithinRoot(realRootNorm, got) {
		t.Fatalf("resolved path %q escaped real root %q", got, realRootNorm)
	}
	if base := filepath.Base(got); base != "index.html" {
		t.Fatalf("resolved file name = %q, want %q", base, "index.html")
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
