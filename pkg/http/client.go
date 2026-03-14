package http

import (
	"bufio"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultClientTimeout  = 30 * time.Second
	defaultIdleTimeout    = 90 * time.Second
	defaultMaxRedirects   = 10
	maxConnectionsPerHost = 4
)

type Client struct {
	Timeout         time.Duration
	FollowRedirects bool
	MaxRedirects    int
	pool            connPool
}

type connPool struct {
	mu          sync.Mutex
	idle        map[string][]poolConn
	idleTimeout time.Duration
}

type poolConn struct {
	conn    net.Conn
	reader  *bufio.Reader
	created time.Time
}

func NewClient() *Client {
	return &Client{
		Timeout:         defaultClientTimeout,
		FollowRedirects: true,
		MaxRedirects:    defaultMaxRedirects,
		pool: connPool{
			idle:        make(map[string][]poolConn),
			idleTimeout: defaultIdleTimeout,
		},
	}
}

func (c *Client) Do(req *Request) (*Response, error) {
	return c.doFollow(req, 0)
}

func (c *Client) doFollow(req *Request, redirects int) (*Response, error) {
	host := req.Host
	if !strings.Contains(host, ":") {
		host = host + ":80"
	}

	conn, reader, err := c.getConn(host)
	if err != nil {
		return nil, fmt.Errorf("http: connect %s: %w", host, err)
	}

	if req.Header("Host") == "" {
		req.SetHeader("Host", req.Host)
	}
	if req.Header("User-Agent") == "" {
		req.SetHeader("User-Agent", "lex-internet/1.0")
	}
	if req.Header("Accept") == "" {
		req.SetHeader("Accept", "*/*")
	}
	if req.Header("Connection") == "" {
		req.SetHeader("Connection", "keep-alive")
	}

	conn.SetDeadline(time.Now().Add(c.Timeout))

	if err := writeConnFull(conn, req.Marshal()); err != nil {
		conn.Close()
		return nil, fmt.Errorf("http: write request: %w", err)
	}

	resp, err := ParseResponse(reader)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("http: read response: %w", err)
	}

	if shouldReuseConnection(resp, reader) {
		c.putConn(host, conn, reader)
	} else {
		conn.Close()
	}

	if c.FollowRedirects && resp.IsRedirect() && redirects < c.MaxRedirects {
		location := resp.Header("Location")
		if location == "" {
			return resp, nil
		}

		nextReq, err := buildRedirect(req, location)
		if err != nil {
			return resp, nil
		}
		return c.doFollow(nextReq, redirects+1)
	}

	return resp, nil
}

func (c *Client) Get(url string) (*Response, error) {
	req, err := NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

func (c *Client) Post(url string, contentType string, body []byte) (*Response, error) {
	req, err := NewRequest("POST", url, body)
	if err != nil {
		return nil, err
	}
	req.SetHeader("Content-Type", contentType)
	req.SetHeader("Content-Length", strconv.Itoa(len(body)))
	return c.Do(req)
}

func (c *Client) Put(url string, body []byte) (*Response, error) {
	req, err := NewRequest("PUT", url, body)
	if err != nil {
		return nil, err
	}
	if len(body) > 0 {
		req.SetHeader("Content-Type", "application/octet-stream")
	}
	return c.Do(req)
}

func (c *Client) Delete(url string) (*Response, error) {
	req, err := NewRequest("DELETE", url, nil)
	if err != nil {
		return nil, err
	}
	return c.Do(req)
}

func (c *Client) getConn(host string) (net.Conn, *bufio.Reader, error) {
	c.pool.mu.Lock()
	conns := c.pool.idle[host]
	now := time.Now()

	for len(conns) > 0 {
		pc := conns[len(conns)-1]
		conns = conns[:len(conns)-1]

		if now.Sub(pc.created) < c.pool.idleTimeout {
			c.pool.idle[host] = conns
			c.pool.mu.Unlock()
			if pc.reader == nil {
				pc.reader = bufio.NewReaderSize(pc.conn, 4096)
			}
			return pc.conn, pc.reader, nil
		}
		pc.conn.Close()
	}

	delete(c.pool.idle, host)
	c.pool.mu.Unlock()

	conn, err := net.DialTimeout("tcp", host, c.Timeout)
	if err != nil {
		return nil, nil, err
	}
	return conn, bufio.NewReaderSize(conn, 4096), nil
}

func (c *Client) putConn(host string, conn net.Conn, reader *bufio.Reader) {
	c.pool.mu.Lock()
	defer c.pool.mu.Unlock()

	conns := c.pool.idle[host]
	if len(conns) >= maxConnectionsPerHost {
		conn.Close()
		return
	}
	c.pool.idle[host] = append(conns, poolConn{
		conn:    conn,
		reader:  reader,
		created: time.Now(),
	})
}

func (c *Client) CloseIdleConnections() {
	c.pool.mu.Lock()
	defer c.pool.mu.Unlock()

	for host, conns := range c.pool.idle {
		for _, pc := range conns {
			pc.conn.Close()
		}
		delete(c.pool.idle, host)
	}
}

func buildRedirect(orig *Request, location string) (*Request, error) {
	if strings.HasPrefix(location, "/") {
		req, err := NewRequest("GET", "http://"+orig.Host+location, nil)
		if err != nil {
			return nil, err
		}
		for k, vals := range orig.Headers {
			lower := strings.ToLower(k)
			if lower == "content-type" || lower == "content-length" ||
				lower == "authorization" || lower == "cookie" {
				continue
			}
			req.Headers[k] = vals
		}
		return req, nil
	}

	req, err := NewRequest("GET", location, nil)
	if err != nil {
		return nil, err
	}
	return req, nil
}

func shouldReuseConnection(resp *Response, reader *bufio.Reader) bool {
	if reader.Buffered() != 0 {
		return false
	}
	if strings.EqualFold(resp.Header("Connection"), "close") {
		return false
	}
	if hasBodylessStatus(resp.StatusCode) {
		return true
	}
	if resp.Header("Content-Length") != "" {
		return true
	}
	return strings.Contains(strings.ToLower(resp.Header("Transfer-Encoding")), "chunked")
}

func hasBodylessStatus(code int) bool {
	return (code >= 100 && code < 200) || code == 204 || code == 304
}

func writeConnFull(conn net.Conn, data []byte) error {
	for len(data) > 0 {
		n, err := conn.Write(data)
		if err != nil {
			return err
		}
		data = data[n:]
	}
	return nil
}
