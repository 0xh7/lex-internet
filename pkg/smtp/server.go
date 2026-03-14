package smtp

import (
	"bufio"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

const (
	stateConnected = iota
	stateGreeted
	stateMailFrom
	stateRcptTo
	stateData
)

const (
	defaultMaxSize     = 10 * 1024 * 1024
	defaultReadTimeout = 5 * time.Minute
	maxCommandLineLen  = 4096
	maxDataLineLen     = 64 * 1024
)

var errLineTooLong = errors.New("smtp: line too long")

type MessageHandler interface {
	HandleMessage(from string, to []string, data []byte) error
}

type Server struct {
	addr    string
	domain  string
	maxSize int
	handler MessageHandler

	mu       sync.Mutex
	listener net.Listener
	wg       sync.WaitGroup
}

type session struct {
	conn   net.Conn
	reader *bufio.Reader
	writer *bufio.Writer
	server *Server
	state  int
	from   string
	to     []string
	ehlo   string
	quit   bool
}

func NewServer(addr, domain string, handler MessageHandler) *Server {
	return &Server{
		addr:    addr,
		domain:  domain,
		maxSize: defaultMaxSize,
		handler: handler,
	}
}

func (s *Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("smtp: listen: %w", err)
	}

	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()

	log.Printf("smtp: listening on %s (domain %s)", s.addr, s.domain)

	for {
		conn, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.listener == nil
			s.mu.Unlock()
			if closed {
				return nil
			}
			log.Printf("smtp: accept error: %v", err)
			continue
		}
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			s.handleConn(c)
		}(conn)
	}
}

func (s *Server) Close() error {
	s.mu.Lock()
	if s.listener != nil {
		err := s.listener.Close()
		s.listener = nil
		s.mu.Unlock()
		s.wg.Wait()
		return err
	}
	s.mu.Unlock()
	return nil
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	sess := &session{
		conn:   conn,
		reader: bufio.NewReader(conn),
		writer: bufio.NewWriter(conn),
		server: s,
		state:  stateConnected,
	}

	sess.reply(220, "%s ESMTP ready", s.domain)

	for !sess.quit {
		conn.SetReadDeadline(time.Now().Add(defaultReadTimeout))
		line, err := readLineLimited(sess.reader, maxCommandLineLen)
		if err != nil {
			if errors.Is(err, errLineTooLong) {
				sess.reply(500, "line too long")
			}
			return
		}
		sess.handleCommand(line)
	}
}

func (sess *session) handleCommand(line string) {
	if len(line) == 0 {
		sess.reply(500, "unrecognized command")
		return
	}

	verb := line
	arg := ""
	if i := strings.IndexByte(line, ' '); i >= 0 {
		verb = line[:i]
		arg = line[i+1:]
	}
	verb = strings.ToUpper(verb)

	switch verb {
	case "HELO":
		sess.cmdHelo(arg, false)
	case "EHLO":
		sess.cmdHelo(arg, true)
	case "MAIL":
		sess.cmdMail(arg)
	case "RCPT":
		sess.cmdRcpt(arg)
	case "DATA":
		sess.cmdData()
	case "QUIT":
		sess.cmdQuit()
	case "RSET":
		sess.cmdRset()
	case "NOOP":
		sess.reply(250, "OK")
	case "VRFY":
		sess.reply(252, "cannot VRFY user, but will accept message")
	default:
		sess.reply(500, "unrecognized command")
	}
}

func (sess *session) cmdHelo(arg string, extended bool) {
	if arg == "" {
		sess.reply(501, "hostname required")
		return
	}

	sess.ehlo = arg
	sess.state = stateGreeted
	sess.resetEnvelope()

	if extended {
		sess.replyMulti(250, []string{
			sess.server.domain + " greets " + arg,
			fmt.Sprintf("SIZE %d", sess.server.maxSize),
			"PIPELINING",
			"8BITMIME",
		})
	} else {
		sess.reply(250, "%s greets %s", sess.server.domain, arg)
	}
}

func (sess *session) cmdMail(arg string) {
	if sess.state < stateGreeted {
		sess.reply(503, "send HELO/EHLO first")
		return
	}
	if sess.state >= stateMailFrom {
		sess.reply(503, "sender already specified")
		return
	}

	upper := strings.ToUpper(arg)
	if !strings.HasPrefix(upper, "FROM:") {
		sess.reply(501, "syntax: MAIL FROM:<address>")
		return
	}
	addr := extractAddress(arg[5:])
	if addr == "" {
		sess.reply(501, "syntax: MAIL FROM:<address>")
		return
	}

	if addr == nullSender {
		sess.from = ""
	} else {
		sess.from = addr
	}
	sess.state = stateMailFrom
	sess.reply(250, "OK")
}

const maxRecipients = 100

func (sess *session) cmdRcpt(arg string) {
	if sess.state < stateMailFrom {
		sess.reply(503, "send MAIL FROM first")
		return
	}

	upper := strings.ToUpper(arg)
	if !strings.HasPrefix(upper, "TO:") {
		sess.reply(501, "syntax: RCPT TO:<address>")
		return
	}
	addr := extractAddress(arg[3:])
	if addr == "" {
		sess.reply(501, "syntax: RCPT TO:<address>")
		return
	}

	if len(sess.to) >= maxRecipients {
		sess.reply(452, "too many recipients")
		return
	}

	sess.to = append(sess.to, addr)
	sess.state = stateRcptTo
	sess.reply(250, "OK")
}

func (sess *session) cmdData() {
	if sess.state < stateRcptTo || len(sess.to) == 0 {
		sess.reply(503, "send RCPT TO first")
		return
	}

	sess.reply(354, "start mail input; end with <CRLF>.<CRLF>")

	var data []byte
	for {
		sess.conn.SetReadDeadline(time.Now().Add(defaultReadTimeout))
		line, err := readLineLimited(sess.reader, maxDataLineLen)
		if err != nil {
			if errors.Is(err, errLineTooLong) {
				sess.reply(552, "line too long")
				sess.discardData()
				sess.resetEnvelope()
			}
			return
		}
		if line == "." {
			break
		}
		if strings.HasPrefix(line, "..") {
			line = line[1:]
		}
		wireLine := line + "\r\n"
		remaining := sess.server.maxSize - len(data)
		if remaining < 0 || len(wireLine) > remaining {
			sess.reply(552, "message exceeds maximum size")
			sess.discardData()
			sess.resetEnvelope()
			return
		}
		data = append(data, wireLine...)
	}

	if sess.server.handler != nil {
		if err := sess.server.handler.HandleMessage(sess.from, sess.to, data); err != nil {
			log.Printf("smtp: handler error: %v", err)
			sess.reply(451, "processing error")
			sess.resetEnvelope()
			return
		}
	}

	sess.reply(250, "OK")
	sess.resetEnvelope()
}

func (sess *session) cmdQuit() {
	sess.reply(221, "%s closing connection", sess.server.domain)
	sess.quit = true
}

func (sess *session) cmdRset() {
	sess.resetEnvelope()
	sess.reply(250, "OK")
}

func (sess *session) discardData() {
	for {
		sess.conn.SetReadDeadline(time.Now().Add(defaultReadTimeout))
		line, err := readLineLimited(sess.reader, maxDataLineLen)
		if err != nil {
			if errors.Is(err, errLineTooLong) {
				continue
			}
			return
		}
		if line == "." {
			return
		}
	}
}

func (sess *session) resetEnvelope() {
	sess.from = ""
	sess.to = nil
	if sess.state > stateGreeted {
		sess.state = stateGreeted
	}
}

func (sess *session) reply(code int, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if _, err := fmt.Fprintf(sess.writer, "%d %s\r\n", code, msg); err != nil {
		sess.quit = true
		return
	}
	if err := sess.writer.Flush(); err != nil {
		sess.quit = true
	}
}

func (sess *session) replyMulti(code int, lines []string) {
	for i, line := range lines {
		sep := "-"
		if i == len(lines)-1 {
			sep = " "
		}
		if _, err := fmt.Fprintf(sess.writer, "%d%s%s\r\n", code, sep, line); err != nil {
			sess.quit = true
			return
		}
	}
	if err := sess.writer.Flush(); err != nil {
		sess.quit = true
	}
}

const nullSender = "<>"

func extractAddress(s string) string {
	s = strings.TrimSpace(s)
	if s == "<>" {
		return nullSender
	}
	if strings.HasPrefix(s, "<") {
		end := strings.IndexByte(s, '>')
		if end < 0 {
			return ""
		}
		return s[1:end]
	}
	// Bare address without angle brackets - strip any trailing SMTP parameters.
	if sp := strings.IndexByte(s, ' '); sp >= 0 {
		s = s[:sp]
	}
	if strings.Contains(s, "@") {
		return s
	}
	return ""
}

func readLineLimited(reader *bufio.Reader, max int) (string, error) {
	var line []byte
	tooLong := false
	for {
		chunk, isPrefix, err := reader.ReadLine()
		if err != nil {
			return "", err
		}
		if !tooLong {
			if len(line)+len(chunk) > max {
				tooLong = true
			} else {
				line = append(line, chunk...)
			}
		}
		if !isPrefix {
			if tooLong {
				return "", errLineTooLong
			}
			return string(line), nil
		}
	}
}
