package http

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/textproto"
	"strconv"
	"strings"
)

const (
	maxLineLength  = 8192
	maxHeaderCount = 128
	maxBodySize    = 64 * 1024 * 1024
)

func readLine(reader *bufio.Reader) (string, error) {
	var line []byte
	for {
		chunk, isPrefix, err := reader.ReadLine()
		if err != nil {
			return "", err
		}
		line = append(line, chunk...)
		if len(line) > maxLineLength {
			return "", errors.New("http: line too long")
		}
		if !isPrefix {
			break
		}
	}
	return string(line), nil
}

func parseHeaders(reader *bufio.Reader, headers map[string][]string) error {
	count := 0
	for {
		line, err := readLine(reader)
		if err != nil {
			return fmt.Errorf("http: reading header: %w", err)
		}
		if line == "" {
			break
		}

		count++
		if count > maxHeaderCount {
			return errors.New("http: too many headers")
		}

		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			return fmt.Errorf("http: malformed header line: %q", line)
		}

		key := canonicalHeaderKey(strings.TrimSpace(line[:colon]))
		value := strings.TrimSpace(line[colon+1:])
		headers[key] = append(headers[key], value)
	}
	return nil
}

func readBody(reader *bufio.Reader, headers map[string][]string, readUntilEOF bool) ([]byte, error) {
	if headerHasToken(headers, "Transfer-Encoding", "chunked") {
		return readChunked(reader)
	}

	clVals := headerValues(headers, "Content-Length")
	cl := ""
	if len(clVals) > 0 {
		cl = strings.TrimSpace(clVals[0])
		for i := 1; i < len(clVals); i++ {
			if strings.TrimSpace(clVals[i]) != cl {
				return nil, errors.New("http: conflicting Content-Length headers")
			}
		}
	}
	if cl == "" {
		if !readUntilEOF {
			return nil, nil
		}

		body, err := io.ReadAll(io.LimitReader(reader, maxBodySize+1))
		if err != nil {
			return nil, fmt.Errorf("http: reading body: %w", err)
		}
		if len(body) == 0 {
			return nil, nil
		}
		if len(body) > maxBodySize {
			return nil, errors.New("http: body exceeds maximum")
		}
		return body, nil
	}

	length, err := strconv.Atoi(cl)
	if err != nil {
		return nil, fmt.Errorf("http: bad Content-Length: %w", err)
	}
	if length == 0 {
		return nil, nil
	}
	if length < 0 {
		return nil, errors.New("http: negative Content-Length")
	}
	if length > maxBodySize {
		return nil, errors.New("http: Content-Length exceeds maximum")
	}

	body := make([]byte, length)
	_, err = io.ReadFull(reader, body)
	if err != nil {
		return nil, fmt.Errorf("http: reading body: %w", err)
	}
	return body, nil
}

const maxChunkedBody = 64 * 1024 * 1024

func readChunked(reader *bufio.Reader) ([]byte, error) {
	var buf bytes.Buffer
	for {
		line, err := readLine(reader)
		if err != nil {
			return nil, fmt.Errorf("http: reading chunk size: %w", err)
		}

		line = strings.TrimSpace(line)
		if semi := strings.IndexByte(line, ';'); semi >= 0 {
			line = line[:semi]
		}

		size, err := strconv.ParseInt(line, 16, 64)
		if err != nil {
			return nil, fmt.Errorf("http: invalid chunk size %q: %w", line, err)
		}

		if size == 0 {
			trailers := make(map[string][]string)
			if err := parseHeaders(reader, trailers); err != nil {
				return nil, fmt.Errorf("http: reading chunk trailers: %w", err)
			}
			break
		}

		if size < 0 || size > maxChunkedBody {
			return nil, errors.New("http: chunk size exceeds maximum")
		}
		if int64(buf.Len())+size > maxChunkedBody {
			return nil, errors.New("http: chunked body exceeds maximum size")
		}

		chunk := make([]byte, size)
		if _, err := io.ReadFull(reader, chunk); err != nil {
			return nil, fmt.Errorf("http: reading chunk data: %w", err)
		}
		buf.Write(chunk)

		if _, err := readLine(reader); err != nil {
			return nil, fmt.Errorf("http: reading chunk trailer: %w", err)
		}
	}
	return buf.Bytes(), nil
}

func canonicalHeaderKey(s string) string {
	return textproto.CanonicalMIMEHeaderKey(s)
}

func headerGet(headers map[string][]string, key string) string {
	canonical := canonicalHeaderKey(key)
	if vals, ok := headers[canonical]; ok && len(vals) > 0 {
		return vals[0]
	}
	return ""
}

func headerValues(headers map[string][]string, key string) []string {
	canonical := canonicalHeaderKey(key)
	return headers[canonical]
}

func headerHasToken(headers map[string][]string, key, token string) bool {
	token = strings.ToLower(strings.TrimSpace(token))
	for _, value := range headerValues(headers, key) {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

func sanitizeHeaderValue(v string) string {
	return strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' {
			return -1
		}
		return r
	}, v)
}
