package ftp

import (
	"bufio"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	maxUploadSize     = 512 * 1024 * 1024
	maxCommandLineLen = 4096
)

var errUploadTooLarge = errors.New("ftp: upload exceeds maximum size")
var errCommandTooLong = errors.New("ftp: command too long")

type limitedWriter struct {
	w         io.Writer
	remaining int64
}

func (lw *limitedWriter) Write(p []byte) (int, error) {
	if lw.remaining <= 0 {
		return 0, errUploadTooLarge
	}
	if int64(len(p)) > lw.remaining {
		n, err := lw.w.Write(p[:lw.remaining])
		lw.remaining -= int64(n)
		if err != nil {
			return n, err
		}
		return n, errUploadTooLarge
	}
	n, err := lw.w.Write(p)
	lw.remaining -= int64(n)
	return n, err
}

type Server struct {
	addr      string
	rootDir   string
	username  string
	password  string
	anonymous bool

	mu       sync.RWMutex
	listener net.Listener
}

type session struct {
	server        *Server
	conn          net.Conn
	reader        *bufio.Reader
	writer        *bufio.Writer
	user          string
	authenticated bool
	cwd           string
	transferType  string
	passiveLn     net.Listener
	activeAddr    *net.TCPAddr
}

func NewServer(addr, rootDir string) *Server {
	return &Server{
		addr:      addr,
		rootDir:   rootDir,
		anonymous: true,
	}
}

func (s *Server) SetAuth(user, pass string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.username = user
	s.password = pass
	if user != "" {
		s.anonymous = false
	}
}

func (s *Server) AllowAnonymous(v bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.anonymous = v
}

func (s *Server) ListenAndServe() error {
	root, err := filepath.Abs(s.rootDir)
	if err != nil {
		return err
	}
	s.rootDir = root

	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return err
	}

	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()

	for {
		conn, err := ln.Accept()
		if err != nil {
			s.mu.RLock()
			closed := s.listener == nil
			s.mu.RUnlock()
			if closed {
				return nil
			}
			continue
		}

		go s.handleConn(conn)
	}
}

func (s *Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return nil
	}
	err := s.listener.Close()
	s.listener = nil
	return err
}

func (s *Server) authSnapshot() (username, password string, anonymous bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.username, s.password, s.anonymous
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	sess := &session{
		server:       s,
		conn:         conn,
		reader:       bufio.NewReader(conn),
		writer:       bufio.NewWriter(conn),
		cwd:          "/",
		transferType: "I",
	}
	defer sess.closeDataListener()

	sess.reply(220, "FTP server ready")

	for {
		conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		line, err := readLineLimited(sess.reader, maxCommandLineLen)
		if err != nil {
			if errors.Is(err, errCommandTooLong) {
				sess.reply(500, "command too long")
			}
			return
		}
		if line == "" {
			sess.reply(500, "empty command")
			continue
		}

		cmd, arg := splitCommand(line)
		if !sess.handleCommand(strings.ToUpper(cmd), arg) {
			return
		}
	}
}

func (sess *session) handleCommand(cmd, arg string) bool {
	switch cmd {
	case "USER":
		sess.handleUSER(arg)
	case "PASS":
		sess.handlePASS(arg)
	case "SYST":
		sess.reply(215, "UNIX Type: L8")
	case "FEAT":
		sess.replyLines(211, []string{"Extensions supported:", " PASV", " PORT", " SIZE", " UTF8"})
	case "NOOP":
		sess.reply(200, "OK")
	case "QUIT":
		sess.reply(221, "Goodbye")
		return false
	case "PWD":
		if !sess.requireAuth() {
			return true
		}
		sess.reply(257, "\"%s\"", sess.cwd)
	case "CWD":
		if !sess.requireAuth() {
			return true
		}
		sess.handleCWD(arg)
	case "CDUP":
		if !sess.requireAuth() {
			return true
		}
		sess.handleCWD("..")
	case "TYPE":
		if !sess.requireAuth() {
			return true
		}
		sess.handleTYPE(arg)
	case "PASV":
		if !sess.requireAuth() {
			return true
		}
		sess.handlePASV()
	case "PORT":
		if !sess.requireAuth() {
			return true
		}
		sess.handlePORT(arg)
	case "LIST":
		if !sess.requireAuth() {
			return true
		}
		sess.handleLIST(arg)
	case "RETR":
		if !sess.requireAuth() {
			return true
		}
		sess.handleRETR(arg)
	case "STOR":
		if !sess.requireAuth() {
			return true
		}
		sess.handleSTOR(arg)
	case "DELE":
		if !sess.requireAuth() {
			return true
		}
		sess.handleDELE(arg)
	case "MKD":
		if !sess.requireAuth() {
			return true
		}
		sess.handleMKD(arg)
	case "RMD":
		if !sess.requireAuth() {
			return true
		}
		sess.handleRMD(arg)
	case "SIZE":
		if !sess.requireAuth() {
			return true
		}
		sess.handleSIZE(arg)
	default:
		sess.reply(502, "Command not implemented")
	}

	return true
}

func (sess *session) handleUSER(arg string) {
	arg = strings.TrimSpace(arg)
	if arg == "" {
		sess.reply(501, "Username required")
		return
	}

	sess.user = arg
	sess.authenticated = false

	username, _, anonymous := sess.server.authSnapshot()
	if anonymous && strings.EqualFold(arg, "anonymous") {
		sess.reply(331, "Anonymous login ok, send any password")
		return
	}

	if username == "" {
		sess.authenticated = true
		sess.reply(230, "Login successful")
		return
	}

	sess.reply(331, "User name okay, need password")
}

func (sess *session) handlePASS(arg string) {
	username, password, anonymous := sess.server.authSnapshot()
	switch {
	case sess.user == "":
		sess.reply(503, "Login with USER first")
	case anonymous && strings.EqualFold(sess.user, "anonymous"):
		sess.authenticated = true
		sess.reply(230, "Anonymous login successful")
	case username == "":
		sess.authenticated = true
		sess.reply(230, "Login successful")
	case secureEqualString(sess.user, username) && secureEqualString(arg, password):
		sess.authenticated = true
		sess.reply(230, "Login successful")
	default:
		sess.reply(530, "Authentication failed")
	}
}

func (sess *session) handleCWD(arg string) {
	target, virtual, err := sess.resolvePath(arg)
	if err != nil {
		sess.reply(550, "Invalid path")
		return
	}

	info, err := os.Stat(target)
	if err != nil || !info.IsDir() {
		sess.reply(550, "Directory not available")
		return
	}

	sess.cwd = virtual
	sess.reply(250, "Directory changed")
}

func (sess *session) handleTYPE(arg string) {
	arg = strings.ToUpper(strings.TrimSpace(arg))
	if arg != "A" && arg != "I" {
		sess.reply(504, "Unsupported TYPE")
		return
	}
	sess.transferType = arg
	sess.reply(200, "TYPE set to %s", arg)
}

func (sess *session) handlePASV() {
	sess.closeDataListener()

	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		sess.reply(425, "Can't open passive listener")
		return
	}
	sess.passiveLn = ln
	sess.activeAddr = nil

	addr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		sess.closeDataListener()
		sess.reply(425, "Passive mode unavailable")
		return
	}
	ip := sess.passiveIP()
	port := addr.Port
	octets := strings.Split(ip.String(), ".")
	if len(octets) != 4 {
		sess.closeDataListener()
		sess.reply(425, "Passive mode unavailable")
		return
	}

	sess.reply(227, "Entering Passive Mode (%s,%s,%s,%s,%d,%d)",
		octets[0], octets[1], octets[2], octets[3], port/256, port%256)
}

func (sess *session) handlePORT(arg string) {
	parts := strings.Split(strings.TrimSpace(arg), ",")
	if len(parts) != 6 {
		sess.reply(501, "Invalid PORT command")
		return
	}

	var nums [6]int
	for i, part := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil || n < 0 || n > 255 {
			sess.reply(501, "Invalid PORT command")
			return
		}
		nums[i] = n
	}

	requestedIP := net.IPv4(byte(nums[0]), byte(nums[1]), byte(nums[2]), byte(nums[3]))
	port := nums[4]*256 + nums[5]
	remoteAddr, ok := sess.conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		sess.reply(425, "Client address unavailable")
		return
	}
	clientIP := remoteAddr.IP
	if !requestedIP.Equal(clientIP) {
		sess.reply(504, "PORT to foreign address denied")
		return
	}
	if port < 1024 {
		sess.reply(504, "PORT to privileged port denied")
		return
	}

	sess.closeDataListener()
	sess.activeAddr = &net.TCPAddr{
		IP:   requestedIP,
		Port: port,
	}
	sess.reply(200, "PORT command successful")
}

func (sess *session) handleLIST(arg string) {
	target, _, err := sess.resolvePath(arg)
	if err != nil {
		sess.reply(550, "Invalid path")
		return
	}

	info, err := os.Stat(target)
	if err != nil {
		sess.reply(550, "Path not available")
		return
	}

	sess.reply(150, "Opening data connection for directory list")
	dataConn, err := sess.openDataConn()
	if err != nil {
		sess.reply(425, "Can't open data connection")
		return
	}
	defer dataConn.Close()

	var entries []os.DirEntry
	if info.IsDir() {
		entries, err = os.ReadDir(target)
		if err != nil {
			sess.reply(550, "Failed to list directory")
			return
		}
	} else {
		parent := filepath.Dir(target)
		name := filepath.Base(target)
		all, err := os.ReadDir(parent)
		if err != nil {
			sess.reply(550, "Failed to list directory")
			return
		}
		for _, entry := range all {
			if entry.Name() == name {
				entries = []os.DirEntry{entry}
				break
			}
		}
	}

	var builder strings.Builder
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}
		mode := "-rw-r--r--"
		if info.IsDir() {
			mode = "drwxr-xr-x"
		}
		fmt.Fprintf(
			&builder,
			"%s 1 ftp ftp %12d %s %s\r\n",
			mode,
			info.Size(),
			info.ModTime().Format("Jan _2 15:04"),
			entry.Name(),
		)
	}

	if _, err := io.WriteString(dataConn, builder.String()); err != nil {
		sess.reply(426, "Data transfer aborted")
		return
	}

	sess.reply(226, "Transfer complete")
}

func (sess *session) handleRETR(arg string) {
	target, _, err := sess.resolvePath(arg)
	if err != nil {
		sess.reply(550, "Invalid path")
		return
	}

	file, err := os.Open(target)
	if err != nil {
		sess.reply(550, "File unavailable")
		return
	}
	defer file.Close()

	sess.reply(150, "Opening data connection for file transfer")
	dataConn, err := sess.openDataConn()
	if err != nil {
		sess.reply(425, "Can't open data connection")
		return
	}
	defer dataConn.Close()

	if _, err := io.Copy(dataConn, file); err != nil {
		sess.reply(426, "Data transfer aborted")
		return
	}

	sess.reply(226, "Transfer complete")
}

func (sess *session) handleSTOR(arg string) {
	target, _, err := sess.resolvePath(arg)
	if err != nil {
		sess.reply(550, "Invalid path")
		return
	}

	if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
		sess.reply(550, "Cannot create parent directory")
		return
	}

	file, err := os.Create(target)
	if err != nil {
		sess.reply(550, "Cannot create file")
		return
	}
	cleanup := true
	defer func() {
		_ = file.Close()
		if cleanup {
			_ = os.Remove(target)
		}
	}()

	sess.reply(150, "Opening data connection for upload")
	dataConn, err := sess.openDataConn()
	if err != nil {
		sess.reply(425, "Can't open data connection")
		return
	}
	defer dataConn.Close()

	w := &limitedWriter{w: file, remaining: maxUploadSize}
	_, err = io.Copy(w, dataConn)
	if errors.Is(err, errUploadTooLarge) {
		sess.reply(552, "Upload exceeds maximum size")
		return
	}
	if err != nil {
		sess.reply(426, "Data transfer aborted")
		return
	}

	cleanup = false
	sess.reply(226, "Transfer complete")
}

func (sess *session) handleDELE(arg string) {
	target, _, err := sess.resolvePath(arg)
	if err != nil {
		sess.reply(550, "Invalid path")
		return
	}
	if err := os.Remove(target); err != nil {
		sess.reply(550, "Delete failed")
		return
	}
	sess.reply(250, "File deleted")
}

func (sess *session) handleMKD(arg string) {
	target, virtual, err := sess.resolvePath(arg)
	if err != nil {
		sess.reply(550, "Invalid path")
		return
	}
	if err := os.Mkdir(target, 0755); err != nil {
		sess.reply(550, "Create directory failed")
		return
	}
	sess.reply(257, "\"%s\" created", virtual)
}

func (sess *session) handleRMD(arg string) {
	target, _, err := sess.resolvePath(arg)
	if err != nil {
		sess.reply(550, "Invalid path")
		return
	}
	if err := os.Remove(target); err != nil {
		sess.reply(550, "Remove directory failed")
		return
	}
	sess.reply(250, "Directory removed")
}

func (sess *session) handleSIZE(arg string) {
	target, _, err := sess.resolvePath(arg)
	if err != nil {
		sess.reply(550, "Invalid path")
		return
	}
	info, err := os.Stat(target)
	if err != nil || info.IsDir() {
		sess.reply(550, "File unavailable")
		return
	}
	sess.reply(213, "%d", info.Size())
}

func (sess *session) requireAuth() bool {
	if sess.authenticated {
		return true
	}
	sess.reply(530, "Please login with USER and PASS")
	return false
}

func (sess *session) openDataConn() (net.Conn, error) {
	switch {
	case sess.passiveLn != nil:
		if tcpLn, ok := sess.passiveLn.(*net.TCPListener); ok {
			tcpLn.SetDeadline(time.Now().Add(30 * time.Second))
		}
		conn, err := sess.passiveLn.Accept()
		sess.closeDataListener()
		if err != nil {
			return nil, err
		}
		clientAddr, ok1 := sess.conn.RemoteAddr().(*net.TCPAddr)
		dataAddr, ok2 := conn.RemoteAddr().(*net.TCPAddr)
		if ok1 && ok2 && !dataAddr.IP.Equal(clientAddr.IP) {
			conn.Close()
			return nil, errors.New("ftp: PASV connection from foreign IP rejected")
		}
		_ = conn.SetDeadline(time.Time{})
		return conn, nil
	case sess.activeAddr != nil:
		addr := sess.activeAddr
		sess.activeAddr = nil
		conn, err := net.DialTimeout("tcp", addr.String(), 10*time.Second)
		if err == nil {
			_ = conn.SetDeadline(time.Time{})
		}
		return conn, err
	default:
		return nil, errors.New("ftp: no data connection configured")
	}
}

func (sess *session) closeDataListener() {
	if sess.passiveLn != nil {
		sess.passiveLn.Close()
		sess.passiveLn = nil
	}
}

func (sess *session) passiveIP() net.IP {
	if addr, ok := sess.conn.LocalAddr().(*net.TCPAddr); ok && addr.IP != nil && !addr.IP.IsUnspecified() {
		if ip := addr.IP.To4(); ip != nil {
			return ip
		}
	}

	ifaces, err := net.InterfaceAddrs()
	if err == nil {
		for _, addr := range ifaces {
			ipNet, ok := addr.(*net.IPNet)
			if !ok || ipNet.IP == nil || ipNet.IP.IsLoopback() {
				continue
			}
			if ip := ipNet.IP.To4(); ip != nil {
				return ip
			}
		}
	}

	return net.IPv4(127, 0, 0, 1)
}

func (sess *session) resolvePath(raw string) (string, string, error) {
	virtual := sess.cwd
	raw = strings.TrimSpace(raw)
	if raw != "" {
		if strings.HasPrefix(raw, "/") {
			virtual = path.Clean(raw)
		} else {
			virtual = path.Clean(path.Join(sess.cwd, raw))
		}
	}
	if !strings.HasPrefix(virtual, "/") {
		virtual = "/" + virtual
	}

	root := filepath.Clean(sess.server.rootDir)
	relative := strings.TrimPrefix(virtual, "/")
	actual := filepath.Clean(filepath.Join(root, filepath.FromSlash(relative)))
	rel, err := filepath.Rel(root, actual)
	if err != nil {
		return "", "", fmt.Errorf("ftp: resolve path: %w", err)
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", "", errors.New("ftp: path escapes root")
	}
	resolved, err := resolvePathInsideRoot(root, actual)
	if err != nil {
		return "", "", err
	}
	actual = resolved

	return actual, virtual, nil
}

func resolvePathInsideRoot(root, actual string) (string, error) {
	rootReal := root
	if rr, err := filepath.EvalSymlinks(root); err == nil {
		rootReal = rr
	}

	existing := actual
	for {
		if _, err := os.Lstat(existing); err == nil {
			break
		}
		parent := filepath.Dir(existing)
		if parent == existing {
			break
		}
		existing = parent
	}

	resolved := actual
	if _, err := os.Lstat(existing); err == nil {
		suffix, err := filepath.Rel(existing, actual)
		if err != nil {
			return "", fmt.Errorf("ftp: resolve path: %w", err)
		}
		existingReal, err := filepath.EvalSymlinks(existing)
		if err != nil {
			return "", fmt.Errorf("ftp: resolve path: %w", err)
		}
		resolved = filepath.Clean(filepath.Join(existingReal, suffix))
	}

	relReal, err := filepath.Rel(rootReal, resolved)
	if err != nil {
		return "", fmt.Errorf("ftp: resolve path: %w", err)
	}
	if relReal == ".." || strings.HasPrefix(relReal, ".."+string(filepath.Separator)) {
		return "", errors.New("ftp: path escapes root via symlink")
	}
	return resolved, nil
}

func (sess *session) reply(code int, format string, args ...interface{}) {
	if _, err := fmt.Fprintf(sess.writer, "%d %s\r\n", code, fmt.Sprintf(format, args...)); err != nil {
		_ = sess.conn.Close()
		return
	}
	if err := sess.writer.Flush(); err != nil {
		_ = sess.conn.Close()
		return
	}
}

func (sess *session) replyLines(code int, lines []string) {
	if len(lines) == 0 {
		sess.reply(code, "")
		return
	}
	if _, err := fmt.Fprintf(sess.writer, "%d-%s\r\n", code, lines[0]); err != nil {
		_ = sess.conn.Close()
		return
	}
	for _, line := range lines[1:] {
		if _, err := fmt.Fprintf(sess.writer, "%s\r\n", line); err != nil {
			_ = sess.conn.Close()
			return
		}
	}
	if _, err := fmt.Fprintf(sess.writer, "%d End\r\n", code); err != nil {
		_ = sess.conn.Close()
		return
	}
	if err := sess.writer.Flush(); err != nil {
		_ = sess.conn.Close()
		return
	}
}

func splitCommand(line string) (string, string) {
	parts := strings.SplitN(line, " ", 2)
	if len(parts) == 1 {
		return parts[0], ""
	}
	return parts[0], strings.TrimSpace(parts[1])
}

func readLineLimited(reader *bufio.Reader, max int) (string, error) {
	var line []byte
	for {
		chunk, isPrefix, err := reader.ReadLine()
		if err != nil {
			return "", err
		}
		line = append(line, chunk...)
		if len(line) > max {
			return "", errCommandTooLong
		}
		if !isPrefix {
			return string(line), nil
		}
	}
}

func secureEqualString(got, want string) bool {
	return subtle.ConstantTimeCompare([]byte(got), []byte(want)) == 1
}
