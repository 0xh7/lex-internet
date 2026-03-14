package smtp

import (
	"bufio"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

type Client struct {
	conn       net.Conn
	reader     *bufio.Reader
	writer     *bufio.Writer
	serverName string
	extensions map[string]string
}

var errSMTPCommandInjection = errors.New("smtp: command argument contains CR or LF")

func Dial(addr string) (*Client, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("smtp: dial: %w", err)
	}

	c := &Client{
		conn:       conn,
		reader:     bufio.NewReader(conn),
		writer:     bufio.NewWriter(conn),
		extensions: make(map[string]string),
	}

	code, _, err := c.readResponse()
	if err != nil {
		conn.Close()
		return nil, err
	}
	if code != 220 {
		conn.Close()
		return nil, fmt.Errorf("smtp: unexpected greeting: %d", code)
	}

	return c, nil
}

func (c *Client) Hello(name string) error {
	code, msg, err := c.command("EHLO %s", name)
	if err != nil {
		return err
	}
	if code == 250 {
		c.parseExtensions(msg)
		return nil
	}

	code, _, err = c.command("HELO %s", name)
	if err != nil {
		return err
	}
	if code != 250 {
		return fmt.Errorf("smtp: HELO rejected: %d", code)
	}
	return nil
}

func (c *Client) Mail(from string) error {
	code, _, err := c.command("MAIL FROM:<%s>", from)
	if err != nil {
		return err
	}
	if code != 250 {
		return fmt.Errorf("smtp: MAIL FROM rejected: %d", code)
	}
	return nil
}

func (c *Client) Rcpt(to string) error {
	code, _, err := c.command("RCPT TO:<%s>", to)
	if err != nil {
		return err
	}
	if code != 250 {
		return fmt.Errorf("smtp: RCPT TO rejected: %d", code)
	}
	return nil
}

func (c *Client) Data(msg []byte) error {
	code, _, err := c.command("DATA")
	if err != nil {
		return err
	}
	if code != 354 {
		return fmt.Errorf("smtp: DATA rejected: %d", code)
	}

	lines := strings.Split(string(msg), "\n")
	for _, line := range lines {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, ".") {
			line = "." + line
		}
		if _, err := fmt.Fprintf(c.writer, "%s\r\n", line); err != nil {
			return fmt.Errorf("smtp: write data: %w", err)
		}
	}
	if _, err := fmt.Fprintf(c.writer, ".\r\n"); err != nil {
		return fmt.Errorf("smtp: write terminator: %w", err)
	}
	if err := c.writer.Flush(); err != nil {
		return fmt.Errorf("smtp: flush data: %w", err)
	}

	code, _, err = c.readResponse()
	if err != nil {
		return err
	}
	if code != 250 {
		return fmt.Errorf("smtp: message not accepted: %d", code)
	}
	return nil
}

func (c *Client) Quit() error {
	_, _, err := c.command("QUIT")
	c.conn.Close()
	return err
}

func (c *Client) SendMail(from string, to []string, msg []byte) error {
	if err := c.Hello("localhost"); err != nil {
		return err
	}
	if err := c.Mail(from); err != nil {
		return err
	}
	for _, rcpt := range to {
		if err := c.Rcpt(rcpt); err != nil {
			return err
		}
	}
	if err := c.Data(msg); err != nil {
		return err
	}
	return c.Quit()
}

func (c *Client) command(format string, args ...interface{}) (int, string, error) {
	cmd := fmt.Sprintf(format, args...)
	if strings.ContainsAny(cmd, "\r\n") {
		return 0, "", errSMTPCommandInjection
	}
	if _, err := fmt.Fprintf(c.writer, "%s\r\n", cmd); err != nil {
		return 0, "", fmt.Errorf("smtp: write: %w", err)
	}
	if err := c.writer.Flush(); err != nil {
		return 0, "", fmt.Errorf("smtp: flush: %w", err)
	}
	return c.readResponse()
}

func (c *Client) readResponse() (int, string, error) {
	var lines []string
	for {
		line, err := c.reader.ReadString('\n')
		if err != nil {
			return 0, "", fmt.Errorf("smtp: read: %w", err)
		}
		line = strings.TrimRight(line, "\r\n")
		if len(line) < 3 {
			return 0, "", fmt.Errorf("smtp: short response line")
		}

		code, err := strconv.Atoi(line[:3])
		if err != nil {
			return 0, "", fmt.Errorf("smtp: invalid response code: %q", line[:3])
		}

		msg := ""
		if len(line) > 4 {
			msg = line[4:]
		}
		lines = append(lines, msg)

		if len(line) == 3 || line[3] == ' ' {
			return code, strings.Join(lines, "\n"), nil
		}
	}
}

func (c *Client) parseExtensions(msg string) {
	for _, line := range strings.Split(msg, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		key := line
		val := ""
		if i := strings.IndexByte(line, ' '); i >= 0 {
			key = line[:i]
			val = line[i+1:]
		}
		c.extensions[strings.ToUpper(key)] = val
	}
}
