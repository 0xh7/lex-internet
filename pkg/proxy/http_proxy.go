package proxy

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

var hopByHop = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
	"Proxy-Connection":    true,
	"Te":                  true,
	"Trailer":             true,
	"Transfer-Encoding":   true,
	"Upgrade":             true,
}

type HTTPProxy struct {
	Addr           string
	DialTimeout    time.Duration
	RequestTimeout time.Duration

	listener net.Listener
	logger   *log.Logger
	mu       sync.Mutex
	active   int64
}

func NewHTTPProxy(addr string) *HTTPProxy {
	return &HTTPProxy{
		Addr:           addr,
		DialTimeout:    10 * time.Second,
		RequestTimeout: 60 * time.Second,
		logger:         log.Default(),
	}
}

func (p *HTTPProxy) ListenAndServe() error {
	ln, err := net.Listen("tcp", p.Addr)
	if err != nil {
		return err
	}
	p.mu.Lock()
	p.listener = ln
	p.mu.Unlock()
	p.logger.Printf("http proxy listening on %s", p.Addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			p.mu.Lock()
			closed := p.listener == nil
			p.mu.Unlock()
			if closed {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return err
		}
		p.mu.Lock()
		p.active++
		p.mu.Unlock()
		go p.handle(conn)
	}
}

func (p *HTTPProxy) Close() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.listener != nil {
		err := p.listener.Close()
		p.listener = nil
		return err
	}
	return nil
}

func (p *HTTPProxy) ActiveConnections() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.active
}

func (p *HTTPProxy) handle(conn net.Conn) {
	defer func() {
		conn.Close()
		p.mu.Lock()
		p.active--
		p.mu.Unlock()
	}()

	conn.SetDeadline(time.Now().Add(p.RequestTimeout))
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		p.logger.Printf("[%s] bad request: %v", conn.RemoteAddr(), err)
		return
	}

	start := time.Now()

	if req.Method == http.MethodConnect {
		p.handleConnect(conn, req)
	} else {
		p.handleHTTP(conn, req)
	}

	p.logger.Printf("%s %s %s %s %v",
		conn.RemoteAddr(), req.Method, req.URL, req.Proto, time.Since(start).Round(time.Millisecond))
}

func (p *HTTPProxy) handleConnect(client net.Conn, req *http.Request) {
	target, err := dialAllowedTCP(req.Host, "", p.DialTimeout)
	if errors.Is(err, errTargetBlocked) {
		http.Error(newResponseWriter(client), "forbidden", http.StatusForbidden)
		return
	}
	if err != nil {
		resp := &http.Response{
			StatusCode: http.StatusBadGateway,
			Proto:      "HTTP/1.1",
			ProtoMajor: 1,
			ProtoMinor: 1,
		}
		resp.Write(client)
		return
	}
	defer target.Close()

	if _, err := fmt.Fprintf(client, "HTTP/1.1 200 Connection Established\r\n\r\n"); err != nil {
		return
	}

	var wg sync.WaitGroup
	wg.Add(2)
	relay := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	}

	go relay(target, client)
	go relay(client, target)
	wg.Wait()
}

func (p *HTTPProxy) handleHTTP(client net.Conn, req *http.Request) {
	if !req.URL.IsAbs() {
		http.Error(
			newResponseWriter(client),
			"absolute URI required for proxy requests",
			http.StatusBadRequest,
		)
		return
	}

	removeHopByHop(req.Header)
	req.Header.Add("Via", fmt.Sprintf("1.1 %s", p.Addr))

	defaultPort := "80"
	if req.URL.Scheme == "https" {
		defaultPort = "443"
	}

	upstream, err := dialAllowedTCP(req.URL.Host, defaultPort, p.DialTimeout)
	if errors.Is(err, errTargetBlocked) {
		http.Error(newResponseWriter(client), "forbidden", http.StatusForbidden)
		return
	}
	if err != nil {
		http.Error(
			newResponseWriter(client),
			"gateway error",
			http.StatusBadGateway,
		)
		return
	}
	defer upstream.Close()

	upstream.SetDeadline(time.Now().Add(p.RequestTimeout))

	req.RequestURI = req.URL.RequestURI()
	if err := req.Write(upstream); err != nil {
		http.Error(
			newResponseWriter(client),
			"gateway error",
			http.StatusBadGateway,
		)
		return
	}

	resp, err := http.ReadResponse(bufio.NewReader(upstream), req)
	if err != nil {
		http.Error(
			newResponseWriter(client),
			"bad gateway response",
			http.StatusBadGateway,
		)
		return
	}
	defer resp.Body.Close()

	removeHopByHop(resp.Header)
	if err := resp.Write(client); err != nil {
		return
	}
}

func removeHopByHop(h http.Header) {
	// Process Connection header value: any header listed in Connection
	// is also hop-by-hop and must be removed (RFC 7230 Section 6.1).
	if conn := h.Get("Connection"); conn != "" {
		for _, name := range strings.Split(conn, ",") {
			name = strings.TrimSpace(name)
			if name != "" {
				h.Del(name)
			}
		}
	}
	for k := range h {
		if hopByHop[http.CanonicalHeaderKey(k)] {
			h.Del(k)
		}
	}
}

type responseWriter struct {
	conn        net.Conn
	header      http.Header
	wroteHeader bool
	statusCode  int
	writeErr    error
}

func newResponseWriter(conn net.Conn) *responseWriter {
	return &responseWriter{conn: conn, header: make(http.Header)}
}

func (rw *responseWriter) Header() http.Header { return rw.header }

func (rw *responseWriter) WriteHeader(code int) {
	if rw.wroteHeader {
		return
	}
	rw.wroteHeader = true
	rw.statusCode = code
	if _, err := fmt.Fprintf(rw.conn, "HTTP/1.1 %d %s\r\n", code, http.StatusText(code)); err != nil {
		rw.writeErr = err
		return
	}
	if err := rw.header.Write(rw.conn); err != nil {
		rw.writeErr = err
		return
	}
	if _, err := fmt.Fprintf(rw.conn, "\r\n"); err != nil {
		rw.writeErr = err
	}
}

func (rw *responseWriter) Write(b []byte) (int, error) {
	if !rw.wroteHeader {
		rw.WriteHeader(http.StatusOK)
	}
	if rw.writeErr != nil {
		return 0, rw.writeErr
	}
	if err := writeFull(rw.conn, b); err != nil {
		rw.writeErr = err
		return 0, err
	}
	return len(b), nil
}

func writeFull(conn net.Conn, b []byte) error {
	for len(b) > 0 {
		n, err := conn.Write(b)
		if err != nil {
			return err
		}
		b = b[n:]
	}
	return nil
}
