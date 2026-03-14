package http

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"mime"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type HandlerFunc func(req *Request, w *ResponseWriter)

type Server struct {
	Addr         string
	router       *Router
	middleware   []MiddlewareFunc
	readTimeout  time.Duration
	writeTimeout time.Duration
	listener     net.Listener
	mu           sync.Mutex
	shutdown     chan struct{}
	shutdownOnce sync.Once
	wg           sync.WaitGroup
}

type ResponseWriter struct {
	conn        net.Conn
	headers     map[string][]string
	statusCode  int
	wroteHeader bool
	keepAlive   bool
	writeErr    error
}

var errPathTraversal = errors.New("http: path escapes configured root")

func NewServer(addr string) *Server {
	return &Server{
		Addr:         addr,
		router:       NewRouter(),
		readTimeout:  30 * time.Second,
		writeTimeout: 30 * time.Second,
		shutdown:     make(chan struct{}),
	}
}

func (s *Server) SetReadTimeout(d time.Duration)  { s.readTimeout = d }
func (s *Server) SetWriteTimeout(d time.Duration) { s.writeTimeout = d }

func (s *Server) Handle(method, pattern string, handler HandlerFunc) {
	s.router.Add(method, pattern, handler)
}

func (s *Server) GET(pattern string, handler HandlerFunc)    { s.Handle("GET", pattern, handler) }
func (s *Server) POST(pattern string, handler HandlerFunc)   { s.Handle("POST", pattern, handler) }
func (s *Server) PUT(pattern string, handler HandlerFunc)    { s.Handle("PUT", pattern, handler) }
func (s *Server) DELETE(pattern string, handler HandlerFunc) { s.Handle("DELETE", pattern, handler) }

func (s *Server) Use(mw MiddlewareFunc) {
	s.middleware = append(s.middleware, mw)
}

func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return fmt.Errorf("http: listen %s: %w", s.Addr, err)
	}

	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()

	log.Printf("http: listening on %s", s.Addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.shutdown:
				return nil
			default:
				log.Printf("http: accept: %v", err)
				continue
			}
		}

		s.wg.Add(1)
		go s.handleConnection(conn)
	}
}

func (s *Server) Shutdown() error {
	s.shutdownOnce.Do(func() {
		close(s.shutdown)

		s.mu.Lock()
		ln := s.listener
		s.listener = nil
		s.mu.Unlock()

		if ln != nil {
			_ = ln.Close()
		}
	})

	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		return fmt.Errorf("http: shutdown timed out")
	}
	return nil
}

func (s *Server) handleConnection(conn net.Conn) {
	defer s.wg.Done()
	defer conn.Close()

	reader := bufio.NewReaderSize(conn, 4096)

	for {
		select {
		case <-s.shutdown:
			return
		default:
		}

		conn.SetReadDeadline(time.Now().Add(s.readTimeout))

		req, err := ParseRequest(reader)
		if err != nil {
			if err != io.EOF && !isTimeout(err) {
				writeError(conn, 400, "Bad Request")
			}
			return
		}

		req.RemoteAddr = conn.RemoteAddr().String()

		w := &ResponseWriter{
			conn:    conn,
			headers: make(map[string][]string),
		}

		connection := strings.ToLower(req.Header("Connection"))
		if req.Version == "HTTP/1.1" && connection != "close" {
			w.keepAlive = true
		} else if connection == "keep-alive" {
			w.keepAlive = true
		}

		route, params := s.router.Match(req.Method, req.Path)
		if route == nil {
			allowed := s.router.AllowedMethods(req.Path)
			if len(allowed) > 0 {
				w.SetHeader("Allow", strings.Join(allowed, ", "))
				conn.SetWriteDeadline(time.Now().Add(s.writeTimeout))
				w.Text(405, "Method Not Allowed")
			} else {
				conn.SetWriteDeadline(time.Now().Add(s.writeTimeout))
				w.Text(404, "Not Found")
			}
		} else {
			req.params = params
			handler := route.Handler
			for i := len(s.middleware) - 1; i >= 0; i-- {
				handler = s.middleware[i](handler)
			}
			conn.SetWriteDeadline(time.Now().Add(s.writeTimeout))
			handler(req, w)
		}

		if !w.wroteHeader {
			w.SetHeader("Content-Length", "0")
			w.WriteHeader(200)
		}

		if !w.keepAlive {
			return
		}
	}
}

func (w *ResponseWriter) WriteHeader(code int) {
	if w.wroteHeader {
		return
	}
	w.wroteHeader = true
	w.statusCode = code

	if statusAllowsBody(code) {
		if _, ok := w.headers["Content-Length"]; !ok {
			w.keepAlive = false
			if _, ok := w.headers["Connection"]; !ok {
				w.headers["Connection"] = []string{"close"}
			}
		}
	}

	text := StatusText(code)

	var buf strings.Builder
	fmt.Fprintf(&buf, "HTTP/1.1 %d %s\r\n", code, text)

	if _, ok := w.headers["Date"]; !ok {
		fmt.Fprintf(&buf, "Date: %s\r\n", time.Now().UTC().Format(time.RFC1123))
	}
	if w.keepAlive {
		if _, ok := w.headers["Connection"]; !ok {
			buf.WriteString("Connection: keep-alive\r\n")
		}
	}

	for key, vals := range w.headers {
		for _, v := range vals {
			fmt.Fprintf(&buf, "%s: %s\r\n", key, v)
		}
	}
	buf.WriteString("\r\n")

	w.writeErr = writeFull(w.conn, []byte(buf.String()))
	if w.writeErr != nil {
		w.keepAlive = false
	}
}

func (w *ResponseWriter) Write(data []byte) (int, error) {
	if !w.wroteHeader {
		if _, ok := w.headers["Content-Type"]; !ok {
			w.SetHeader("Content-Type", "text/plain; charset=utf-8")
		}
		w.WriteHeader(200)
	}
	if w.writeErr != nil {
		return 0, w.writeErr
	}
	if err := writeFull(w.conn, data); err != nil {
		w.writeErr = err
		w.keepAlive = false
		return 0, err
	}
	return len(data), nil
}

func (w *ResponseWriter) SetHeader(key, value string) {
	canonical := canonicalHeaderKey(key)
	w.headers[canonical] = []string{value}
}

func (w *ResponseWriter) AddHeader(key, value string) {
	canonical := canonicalHeaderKey(key)
	w.headers[canonical] = append(w.headers[canonical], value)
}

func (w *ResponseWriter) JSON(code int, v interface{}) {
	data, err := json.Marshal(v)
	if err != nil {
		w.Text(500, "Internal Server Error")
		return
	}
	w.SetHeader("Content-Type", "application/json; charset=utf-8")
	w.SetHeader("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(code)
	if w.writeErr == nil {
		w.writeErr = writeFull(w.conn, data)
	}
}

func (w *ResponseWriter) Text(code int, text string) {
	data := []byte(text)
	w.SetHeader("Content-Type", "text/plain; charset=utf-8")
	w.SetHeader("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(code)
	if w.writeErr == nil {
		w.writeErr = writeFull(w.conn, data)
	}
}

func (w *ResponseWriter) HTML(code int, html string) {
	data := []byte(html)
	w.SetHeader("Content-Type", "text/html; charset=utf-8")
	w.SetHeader("Content-Length", strconv.Itoa(len(data)))
	w.WriteHeader(code)
	if w.writeErr == nil {
		w.writeErr = writeFull(w.conn, data)
	}
}

func (w *ResponseWriter) File(path string) error {
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}
	return w.FileFromRoot(cwd, path)
}

func (w *ResponseWriter) FileFromRoot(rootDir, path string) error {
	cleaned, err := resolvePathWithinRoot(rootDir, path)
	if err != nil {
		if errors.Is(err, errPathTraversal) {
			w.Text(403, "Forbidden")
			return nil
		}
		return err
	}

	info, err := os.Stat(cleaned)
	if err != nil {
		if os.IsNotExist(err) {
			w.Text(404, "Not Found")
			return nil
		}
		return err
	}
	if info.IsDir() {
		indexPath := filepath.Join(cleaned, "index.html")
		indexPath, err = resolvePathWithinRoot(rootDir, indexPath)
		if err != nil {
			if errors.Is(err, errPathTraversal) {
				w.Text(403, "Forbidden")
				return nil
			}
			return err
		}
		if indexInfo, err := os.Stat(indexPath); err == nil {
			cleaned = indexPath
			info = indexInfo
		} else {
			w.Text(403, "Forbidden")
			return nil
		}
	}

	f, err := os.Open(cleaned)
	if err != nil {
		return err
	}
	defer f.Close()

	ct := detectContentType(cleaned)
	w.SetHeader("Content-Type", ct)
	w.SetHeader("Content-Length", strconv.FormatInt(info.Size(), 10))
	w.SetHeader("Last-Modified", info.ModTime().UTC().Format(time.RFC1123))
	w.WriteHeader(200)

	if _, err := io.Copy(w, f); err != nil {
		return fmt.Errorf("http: sending file: %w", err)
	}
	return nil
}

func resolvePathWithinRoot(rootDir, path string) (string, error) {
	if rootDir == "" {
		rootDir = "."
	}
	rootAbs, err := filepath.Abs(rootDir)
	if err != nil {
		return "", err
	}
	rootReal := rootAbs
	if resolvedRoot, err := filepath.EvalSymlinks(rootAbs); err == nil {
		rootReal = resolvedRoot
	}

	candidate := filepath.Clean(path)
	if !filepath.IsAbs(candidate) {
		candidate = filepath.Join(rootAbs, candidate)
	}
	candidateAbs, err := filepath.Abs(candidate)
	if err != nil {
		return "", err
	}
	if !pathWithinRoot(rootAbs, candidateAbs) {
		return "", errPathTraversal
	}

	resolvedCandidate := candidateAbs
	if resolved, err := filepath.EvalSymlinks(candidateAbs); err == nil {
		resolvedCandidate = resolved
	} else if errors.Is(err, os.ErrNotExist) {
		parent := filepath.Dir(candidateAbs)
		if resolvedParent, perr := filepath.EvalSymlinks(parent); perr == nil {
			resolvedCandidate = filepath.Join(resolvedParent, filepath.Base(candidateAbs))
		} else if relToRoot, rerr := filepath.Rel(rootAbs, candidateAbs); rerr == nil {
			// Keep non-existent descendants anchored to the canonical root path.
			// This avoids false traversal failures when rootAbs and rootReal use
			// different path spellings (for example 8.3 vs long paths on Windows).
			resolvedCandidate = filepath.Join(rootReal, relToRoot)
		}
	}
	if !pathWithinRoot(rootReal, resolvedCandidate) {
		return "", errPathTraversal
	}

	return resolvedCandidate, nil
}

func pathWithinRoot(rootAbs, candidateAbs string) bool {
	rel, err := filepath.Rel(rootAbs, candidateAbs)
	if err != nil {
		return false
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return false
	}
	return true
}

func writeError(conn net.Conn, code int, msg string) {
	body := []byte(msg)
	if _, err := fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\n", code, StatusText(code)); err != nil {
		return
	}
	if _, err := fmt.Fprintf(conn, "Content-Type: text/plain\r\n"); err != nil {
		return
	}
	if _, err := fmt.Fprintf(conn, "Content-Length: %d\r\n", len(body)); err != nil {
		return
	}
	if _, err := fmt.Fprintf(conn, "Connection: close\r\n"); err != nil {
		return
	}
	if _, err := fmt.Fprintf(conn, "\r\n"); err != nil {
		return
	}
	_ = writeFull(conn, body)
}

func statusAllowsBody(code int) bool {
	return code >= 200 && code != 204 && code != 304
}

func writeFull(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := conn.Write(data)
		if err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}

func detectContentType(path string) string {
	ext := filepath.Ext(path)
	ct := mime.TypeByExtension(ext)
	if ct != "" {
		return ct
	}

	switch ext {
	case ".html", ".htm":
		return "text/html; charset=utf-8"
	case ".css":
		return "text/css; charset=utf-8"
	case ".js":
		return "application/javascript"
	case ".json":
		return "application/json"
	case ".png":
		return "image/png"
	case ".jpg", ".jpeg":
		return "image/jpeg"
	case ".gif":
		return "image/gif"
	case ".svg":
		return "image/svg+xml"
	case ".ico":
		return "image/x-icon"
	case ".txt":
		return "text/plain; charset=utf-8"
	case ".xml":
		return "application/xml"
	case ".pdf":
		return "application/pdf"
	case ".wasm":
		return "application/wasm"
	}
	return "application/octet-stream"
}

func isTimeout(err error) bool {
	if ne, ok := err.(net.Error); ok {
		return ne.Timeout()
	}
	return false
}
