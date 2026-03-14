package ftp

import (
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestResolvePathKeepsAbsolutePathsInsideRoot(t *testing.T) {
	root := t.TempDir()
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
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
	if r, err := filepath.EvalSymlinks(root); err == nil {
		root = r
	}
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

func TestSetAuthDisablesAnonymousByDefault(t *testing.T) {
	s := NewServer("127.0.0.1:0", t.TempDir())
	if !s.anonymous {
		t.Fatal("expected anonymous login to be enabled by default")
	}

	s.SetAuth("user", "pass")
	if s.anonymous {
		t.Fatal("expected SetAuth to disable anonymous login")
	}
}

type ftpTestConn struct {
	local net.Addr
}

func (c ftpTestConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c ftpTestConn) Write([]byte) (int, error)        { return 0, io.EOF }
func (c ftpTestConn) Close() error                     { return nil }
func (c ftpTestConn) LocalAddr() net.Addr              { return c.local }
func (c ftpTestConn) RemoteAddr() net.Addr             { return &net.TCPAddr{} }
func (c ftpTestConn) SetDeadline(time.Time) error      { return nil }
func (c ftpTestConn) SetReadDeadline(time.Time) error  { return nil }
func (c ftpTestConn) SetWriteDeadline(time.Time) error { return nil }

func TestPassiveIPFallsBackWhenLocalAddrIsIPv6(t *testing.T) {
	sess := &session{
		conn: ftpTestConn{
			local: &net.TCPAddr{IP: net.ParseIP("2001:db8::1"), Port: 21},
		},
	}

	ip := sess.passiveIP()
	if ip == nil || ip.To4() == nil {
		t.Fatalf("passiveIP() = %v, want non-nil IPv4", ip)
	}
}

func TestResolvePathRejectsSymlinkParentEscapeForCreate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink semantics/permissions vary on Windows runners")
	}

	root := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(root, "link")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink not available: %v", err)
	}

	sess := &session{
		server: &Server{rootDir: root},
		cwd:    "/",
	}

	if _, _, err := sess.resolvePath("/link/new-file.txt"); err == nil {
		t.Fatal("resolvePath() error = nil, want symlink escape error")
	}
}
