package http

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

type Request struct {
	Method      string
	Path        string
	Version     string
	Headers     map[string][]string
	Body        []byte
	Host        string
	RemoteAddr  string
	QueryParams map[string][]string
	params      map[string]string
}

func ParseRequest(reader *bufio.Reader) (*Request, error) {
	line, err := readLine(reader)
	if err != nil {
		return nil, fmt.Errorf("http: reading request line: %w", err)
	}

	parts := strings.SplitN(line, " ", 3)
	if len(parts) != 3 {
		return nil, errors.New("http: malformed request line")
	}

	req := &Request{
		Method:      parts[0],
		Version:     parts[2],
		Headers:     make(map[string][]string),
		QueryParams: make(map[string][]string),
	}

	rawPath := parts[1]
	if idx := strings.IndexByte(rawPath, '?'); idx != -1 {
		req.Path = rawPath[:idx]
		parseQueryString(rawPath[idx+1:], req.QueryParams)
	} else {
		req.Path = rawPath
	}

	if err := parseHeaders(reader, req.Headers); err != nil {
		return nil, err
	}

	if host := req.Header("Host"); host != "" {
		req.Host = host
	}

	body, err := readBody(reader, req.Headers, false)
	if err != nil {
		return nil, err
	}
	req.Body = body

	return req, nil
}

func NewRequest(method, rawurl string, body []byte) (*Request, error) {
	if method == "" {
		return nil, errors.New("http: empty method")
	}

	host, path, query, err := parseURL(rawurl)
	if err != nil {
		return nil, err
	}

	req := &Request{
		Method:      method,
		Path:        path,
		Version:     "HTTP/1.1",
		Headers:     make(map[string][]string),
		Body:        body,
		Host:        host,
		QueryParams: make(map[string][]string),
	}

	if query != "" {
		parseQueryString(query, req.QueryParams)
	}

	req.SetHeader("Host", host)
	if len(body) > 0 {
		req.SetHeader("Content-Length", strconv.Itoa(len(body)))
	}

	return req, nil
}

func (r *Request) Marshal() []byte {
	var buf bytes.Buffer

	path := r.Path
	if len(r.QueryParams) > 0 {
		path += "?" + encodeQueryString(r.QueryParams)
	}

	fmt.Fprintf(&buf, "%s %s %s\r\n", r.Method, path, r.Version)

	for key, vals := range r.Headers {
		for _, v := range vals {
			fmt.Fprintf(&buf, "%s: %s\r\n", sanitizeHeaderValue(key), sanitizeHeaderValue(v))
		}
	}
	buf.WriteString("\r\n")

	if len(r.Body) > 0 {
		buf.Write(r.Body)
	}

	return buf.Bytes()
}

func (r *Request) Header(key string) string {
	canonical := canonicalHeaderKey(key)
	if vals, ok := r.Headers[canonical]; ok && len(vals) > 0 {
		return vals[0]
	}
	return ""
}

func (r *Request) SetHeader(key, value string) {
	canonical := canonicalHeaderKey(key)
	r.Headers[canonical] = []string{value}
}

func (r *Request) ContentLength() int {
	cl := r.Header("Content-Length")
	if cl == "" {
		return 0
	}
	n, err := strconv.Atoi(cl)
	if err != nil {
		return 0
	}
	return n
}

func (r *Request) Param(name string) string {
	if r.params == nil {
		return ""
	}
	return r.params[name]
}

func (r *Request) Query(name string) string {
	if vals, ok := r.QueryParams[name]; ok && len(vals) > 0 {
		return vals[0]
	}
	return ""
}

func parseURL(rawurl string) (host, path, query string, err error) {
	u := rawurl

	if strings.HasPrefix(u, "http://") {
		u = u[7:]
	} else if strings.HasPrefix(u, "https://") {
		u = u[8:]
	}

	slashIdx := strings.IndexByte(u, '/')
	if slashIdx == -1 {
		host = u
		path = "/"
	} else {
		host = u[:slashIdx]
		path = u[slashIdx:]
	}

	if qIdx := strings.IndexByte(path, '?'); qIdx != -1 {
		query = path[qIdx+1:]
		path = path[:qIdx]
	}

	if host == "" {
		err = errors.New("http: empty host in URL")
	}

	return
}

func parseQueryString(raw string, out map[string][]string) {
	for _, pair := range strings.Split(raw, "&") {
		if pair == "" {
			continue
		}
		k, v, _ := strings.Cut(pair, "=")
		k = queryUnescape(k)
		v = queryUnescape(v)
		out[k] = append(out[k], v)
	}
}

func encodeQueryString(params map[string][]string) string {
	var parts []string
	for k, vals := range params {
		for _, v := range vals {
			parts = append(parts, queryEscape(k)+"="+queryEscape(v))
		}
	}
	return strings.Join(parts, "&")
}

func queryEscape(s string) string {
	var buf strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isUnreserved(c) {
			buf.WriteByte(c)
		} else if c == ' ' {
			buf.WriteByte('+')
		} else {
			fmt.Fprintf(&buf, "%%%02X", c)
		}
	}
	return buf.String()
}

func queryUnescape(s string) string {
	var buf strings.Builder
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '+':
			buf.WriteByte(' ')
		case s[i] == '%' && i+2 < len(s):
			hi := unhex(s[i+1])
			lo := unhex(s[i+2])
			if hi >= 0 && lo >= 0 {
				buf.WriteByte(byte(hi<<4 | lo))
				i += 2
			} else {
				buf.WriteByte('%')
			}
		default:
			buf.WriteByte(s[i])
		}
	}
	return buf.String()
}

func isUnreserved(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
		(c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.' || c == '~'
}

func unhex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}
