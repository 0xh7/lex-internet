package http

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var statusText = map[int]string{
	100: "Continue",
	101: "Switching Protocols",
	200: "OK",
	201: "Created",
	204: "No Content",
	301: "Moved Permanently",
	302: "Found",
	303: "See Other",
	304: "Not Modified",
	307: "Temporary Redirect",
	308: "Permanent Redirect",
	400: "Bad Request",
	401: "Unauthorized",
	403: "Forbidden",
	404: "Not Found",
	405: "Method Not Allowed",
	408: "Request Timeout",
	409: "Conflict",
	411: "Length Required",
	413: "Payload Too Large",
	414: "URI Too Long",
	415: "Unsupported Media Type",
	429: "Too Many Requests",
	500: "Internal Server Error",
	501: "Not Implemented",
	502: "Bad Gateway",
	503: "Service Unavailable",
	504: "Gateway Timeout",
}

func StatusText(code int) string {
	if text, ok := statusText[code]; ok {
		return text
	}
	return "Unknown"
}

type Response struct {
	Version    string
	StatusCode int
	StatusText string
	Headers    map[string][]string
	Body       []byte
}

func ParseResponse(reader *bufio.Reader) (*Response, error) {
	line, err := readLine(reader)
	if err != nil {
		return nil, fmt.Errorf("http: reading status line: %w", err)
	}

	parts := strings.SplitN(line, " ", 3)
	if len(parts) < 2 {
		return nil, errors.New("http: malformed status line")
	}

	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return nil, fmt.Errorf("http: invalid status code: %w", err)
	}

	resp := &Response{
		Version:    parts[0],
		StatusCode: code,
		Headers:    make(map[string][]string),
	}

	if len(parts) == 3 {
		resp.StatusText = parts[2]
	} else {
		resp.StatusText = StatusText(code)
	}

	if err := parseHeaders(reader, resp.Headers); err != nil {
		return nil, err
	}

	if hasBodylessStatus(resp.StatusCode) {
		return resp, nil
	}

	body, err := readBody(reader, resp.Headers, true)
	if err != nil {
		return nil, err
	}
	resp.Body = body

	return resp, nil
}

func NewResponse(statusCode int, body []byte) *Response {
	resp := &Response{
		Version:    "HTTP/1.1",
		StatusCode: statusCode,
		StatusText: StatusText(statusCode),
		Headers:    make(map[string][]string),
		Body:       body,
	}
	if len(body) > 0 {
		resp.SetHeader("Content-Length", strconv.Itoa(len(body)))
		resp.SetHeader("Content-Type", "application/octet-stream")
	}
	return resp
}

func (r *Response) Marshal() []byte {
	var buf bytes.Buffer

	fmt.Fprintf(&buf, "%s %d %s\r\n", r.Version, r.StatusCode, r.StatusText)

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

func (r *Response) Header(key string) string {
	canonical := canonicalHeaderKey(key)
	if vals, ok := r.Headers[canonical]; ok && len(vals) > 0 {
		return vals[0]
	}
	return ""
}

func (r *Response) SetHeader(key, value string) {
	canonical := canonicalHeaderKey(key)
	r.Headers[canonical] = []string{value}
}

func (r *Response) IsRedirect() bool {
	switch r.StatusCode {
	case 301, 302, 303, 307, 308:
		return true
	}
	return false
}
