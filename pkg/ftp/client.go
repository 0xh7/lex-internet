package ftp

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	conn   net.Conn
	reader *bufio.Reader
	writer *bufio.Writer
	host   string
}

var errFTPCommandInjection = errors.New("ftp: command argument contains CR or LF")

func Dial(addr string) (*Client, error) {
	conn, err := net.DialTimeout("tcp", addr, 10*time.Second)
	if err != nil {
		return nil, err
	}

	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}

	c := &Client{
		conn:   conn,
		reader: bufio.NewReader(conn),
		writer: bufio.NewWriter(conn),
		host:   host,
	}

	code, _, err := c.readResponse()
	if err != nil {
		conn.Close()
		return nil, err
	}
	if code != 220 {
		conn.Close()
		return nil, fmt.Errorf("ftp: unexpected greeting %d", code)
	}

	return c, nil
}

func (c *Client) Login(user, pass string) error {
	code, _, err := c.command("USER %s", user)
	if err != nil {
		return err
	}
	if code == 230 {
		return nil
	}
	if code != 331 {
		return fmt.Errorf("ftp: USER failed with %d", code)
	}

	code, _, err = c.command("PASS %s", pass)
	if err != nil {
		return err
	}
	if code != 230 {
		return fmt.Errorf("ftp: PASS failed with %d", code)
	}

	return nil
}

func (c *Client) List(path string) ([]string, error) {
	dataConn, err := c.enterPassive()
	if err != nil {
		return nil, err
	}
	defer dataConn.Close()

	cmd := "LIST"
	if strings.TrimSpace(path) != "" {
		cmd += " " + path
	}

	code, _, err := c.command("%s", cmd)
	if err != nil {
		return nil, err
	}
	if code != 125 && code != 150 {
		return nil, fmt.Errorf("ftp: LIST failed with %d", code)
	}

	const maxListSize = 16 * 1024 * 1024
	data, err := io.ReadAll(io.LimitReader(dataConn, maxListSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxListSize {
		return nil, errors.New("ftp: LIST response too large")
	}

	code, _, err = c.readResponse()
	if err != nil {
		return nil, err
	}
	if code != 226 && code != 250 {
		return nil, fmt.Errorf("ftp: LIST completion failed with %d", code)
	}

	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	out := make([]string, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line != "" {
			out = append(out, line)
		}
	}
	return out, nil
}

func (c *Client) Get(remote string) ([]byte, error) {
	dataConn, err := c.enterPassive()
	if err != nil {
		return nil, err
	}
	defer dataConn.Close()

	code, _, err := c.command("RETR %s", remote)
	if err != nil {
		return nil, err
	}
	if code != 125 && code != 150 {
		return nil, fmt.Errorf("ftp: RETR failed with %d", code)
	}

	const maxFileSize = 512 * 1024 * 1024
	data, err := io.ReadAll(io.LimitReader(dataConn, maxFileSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxFileSize {
		return nil, errors.New("ftp: RETR response too large")
	}

	code, _, err = c.readResponse()
	if err != nil {
		return nil, err
	}
	if code != 226 {
		return nil, fmt.Errorf("ftp: RETR completion failed with %d", code)
	}

	return data, nil
}

func (c *Client) Put(remote string, data []byte) error {
	dataConn, err := c.enterPassive()
	if err != nil {
		return err
	}

	code, _, err := c.command("STOR %s", remote)
	if err != nil {
		_ = dataConn.Close()
		return err
	}
	if code != 125 && code != 150 {
		_ = dataConn.Close()
		return fmt.Errorf("ftp: STOR failed with %d", code)
	}

	if _, err := io.Copy(dataConn, bytes.NewReader(data)); err != nil {
		_ = dataConn.Close()
		return fmt.Errorf("ftp: STOR data transfer: %w", err)
	}

	if err := dataConn.Close(); err != nil {
		return fmt.Errorf("ftp: STOR close data connection: %w", err)
	}

	code, _, err = c.readResponse()
	if err != nil {
		return err
	}
	if code != 226 {
		return fmt.Errorf("ftp: STOR completion failed with %d", code)
	}

	return nil
}

func (c *Client) Mkdir(path string) error {
	code, _, err := c.command("MKD %s", path)
	if err != nil {
		return err
	}
	if code != 257 {
		return fmt.Errorf("ftp: MKD failed with %d", code)
	}
	return nil
}

func (c *Client) Delete(path string) error {
	code, _, err := c.command("DELE %s", path)
	if err != nil {
		return err
	}
	if code != 250 {
		return fmt.Errorf("ftp: DELE failed with %d", code)
	}
	return nil
}

func (c *Client) Cd(path string) error {
	code, _, err := c.command("CWD %s", path)
	if err != nil {
		return err
	}
	if code != 250 {
		return fmt.Errorf("ftp: CWD failed with %d", code)
	}
	return nil
}

func (c *Client) Pwd() (string, error) {
	code, msg, err := c.command("PWD")
	if err != nil {
		return "", err
	}
	if code != 257 {
		return "", fmt.Errorf("ftp: PWD failed with %d", code)
	}

	start := strings.IndexByte(msg, '"')
	end := strings.LastIndexByte(msg, '"')
	if start >= 0 && end > start {
		return msg[start+1 : end], nil
	}
	return strings.TrimSpace(msg), nil
}

func (c *Client) Quit() error {
	code, _, err := c.command("QUIT")
	if err != nil {
		c.conn.Close()
		return err
	}
	c.conn.Close()
	if code != 221 {
		return fmt.Errorf("ftp: QUIT failed with %d", code)
	}
	return nil
}

func (c *Client) enterPassive() (net.Conn, error) {
	code, msg, err := c.command("PASV")
	if err != nil {
		return nil, err
	}
	if code != 227 {
		return nil, fmt.Errorf("ftp: PASV failed with %d", code)
	}

	start := strings.IndexByte(msg, '(')
	end := strings.IndexByte(msg, ')')
	if start < 0 || end <= start {
		return nil, fmt.Errorf("ftp: malformed PASV response %q", msg)
	}

	parts := strings.Split(msg[start+1:end], ",")
	if len(parts) != 6 {
		return nil, fmt.Errorf("ftp: malformed PASV address %q", msg)
	}

	values := make([]int, 0, 6)
	for _, part := range parts {
		n, err := strconv.Atoi(strings.TrimSpace(part))
		if err != nil {
			return nil, fmt.Errorf("ftp: malformed PASV address %q: %w", msg, err)
		}
		if n < 0 || n > 255 {
			return nil, fmt.Errorf("ftp: PASV value out of range: %d", n)
		}
		values = append(values, n)
	}

	port := values[4]*256 + values[5]
	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("ftp: PASV port out of range: %d", port)
	}

	return net.DialTimeout("tcp", net.JoinHostPort(c.host, strconv.Itoa(port)), 10*time.Second)
}

func (c *Client) command(format string, args ...interface{}) (int, string, error) {
	for _, arg := range args {
		if s, ok := arg.(string); ok && strings.ContainsAny(s, "\r\n") {
			return 0, "", errFTPCommandInjection
		}
	}

	if _, err := fmt.Fprintf(c.writer, format+"\r\n", args...); err != nil {
		return 0, "", err
	}
	if err := c.writer.Flush(); err != nil {
		return 0, "", err
	}
	return c.readResponse()
}

func (c *Client) readResponse() (int, string, error) {
	line, err := c.reader.ReadString('\n')
	if err != nil {
		return 0, "", err
	}
	line = strings.TrimRight(line, "\r\n")
	if len(line) < 3 {
		return 0, "", fmt.Errorf("ftp: malformed response %q", line)
	}

	code, err := strconv.Atoi(line[:3])
	if err != nil {
		return 0, "", err
	}

	if len(line) > 3 && line[3] == '-' {
		const maxMultiLines = 1024
		var lines []string
		lines = append(lines, line[4:])
		for {
			if len(lines) > maxMultiLines {
				return 0, "", fmt.Errorf("ftp: multi-line response exceeds %d lines", maxMultiLines)
			}
			next, err := c.reader.ReadString('\n')
			if err != nil {
				return 0, "", err
			}
			next = strings.TrimRight(next, "\r\n")
			if strings.HasPrefix(next, line[:3]+" ") {
				lines = append(lines, next[4:])
				return code, strings.Join(lines, "\n"), nil
			}
			lines = append(lines, next)
		}
	}

	if len(line) > 4 {
		return code, line[4:], nil
	}
	return code, "", nil
}
