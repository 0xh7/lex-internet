package proxy

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"sync"
	"time"
)

const (
	socks5Version = 0x05

	authNone         = 0x00
	authUserPass     = 0x02
	authNoAcceptable = 0xff

	cmdConnect = 0x01
	cmdBind    = 0x02

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSuccess          = 0x00
	repGeneralFailure   = 0x01
	repNotAllowed       = 0x02
	repNetUnreachable   = 0x03
	repHostUnreachable  = 0x04
	repConnRefused      = 0x05
	repTTLExpired       = 0x06
	repCmdNotSupported  = 0x07
	repAddrNotSupported = 0x08
)

type SOCKS5Server struct {
	Addr        string
	DialTimeout time.Duration

	listener net.Listener
	logger   *log.Logger
	mu       sync.RWMutex
	username string
	password string
	authReq  bool
}

func NewSOCKS5(addr string) *SOCKS5Server {
	return &SOCKS5Server{
		Addr:        addr,
		DialTimeout: 10 * time.Second,
		logger:      log.Default(),
	}
}

func (s *SOCKS5Server) SetAuth(username, password string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.username = username
	s.password = password
	s.authReq = username != "" || password != ""
}

func (s *SOCKS5Server) ListenAndServe() error {
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.listener = ln
	s.mu.Unlock()
	s.logger.Printf("socks5 listening on %s", s.Addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			s.mu.RLock()
			closed := s.listener == nil
			s.mu.RUnlock()
			if closed {
				return nil
			}
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			return err
		}
		go s.handle(conn)
	}
}

func (s *SOCKS5Server) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener != nil {
		err := s.listener.Close()
		s.listener = nil
		return err
	}
	return nil
}

func (s *SOCKS5Server) handle(conn net.Conn) {
	defer conn.Close()

	if err := s.negotiate(conn); err != nil {
		s.logger.Printf("[%s] negotiation failed: %v", conn.RemoteAddr(), err)
		return
	}

	if err := s.processRequest(conn); err != nil {
		s.logger.Printf("[%s] request failed: %v", conn.RemoteAddr(), err)
	}
}

func (s *SOCKS5Server) negotiate(conn net.Conn) error {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return err
	}
	if hdr[0] != socks5Version {
		return errors.New("socks5: unsupported version")
	}

	nMethods := int(hdr[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	s.mu.RLock()
	needAuth := s.authReq
	s.mu.RUnlock()

	if needAuth {
		if !containsByte(methods, authUserPass) {
			if err := writeAll(conn, []byte{socks5Version, authNoAcceptable}); err != nil {
				return err
			}
			return errors.New("socks5: client does not support username/password auth")
		}
		if err := writeAll(conn, []byte{socks5Version, authUserPass}); err != nil {
			return err
		}
		return s.authenticateUserPass(conn)
	}

	if !containsByte(methods, authNone) {
		if err := writeAll(conn, []byte{socks5Version, authNoAcceptable}); err != nil {
			return err
		}
		return errors.New("socks5: no acceptable auth method")
	}
	if err := writeAll(conn, []byte{socks5Version, authNone}); err != nil {
		return err
	}
	return nil
}

func (s *SOCKS5Server) authenticateUserPass(conn net.Conn) error {
	hdr := make([]byte, 2)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return err
	}
	if hdr[0] != 0x01 {
		return errors.New("socks5: invalid auth subnegotiation version")
	}

	uLen := int(hdr[1])
	user := make([]byte, uLen)
	if _, err := io.ReadFull(conn, user); err != nil {
		return err
	}

	pLenBuf := make([]byte, 1)
	if _, err := io.ReadFull(conn, pLenBuf); err != nil {
		return err
	}

	pass := make([]byte, int(pLenBuf[0]))
	if _, err := io.ReadFull(conn, pass); err != nil {
		return err
	}

	s.mu.RLock()
	expectedUser := []byte(s.username)
	expectedPass := []byte(s.password)
	s.mu.RUnlock()

	ok := subtle.ConstantTimeCompare(user, expectedUser) == 1 &&
		subtle.ConstantTimeCompare(pass, expectedPass) == 1

	if !ok {
		if err := writeAll(conn, []byte{0x01, 0x01}); err != nil {
			return err
		}
		return errors.New("socks5: authentication failed")
	}
	if err := writeAll(conn, []byte{0x01, 0x00}); err != nil {
		return err
	}
	return nil
}

func (s *SOCKS5Server) processRequest(conn net.Conn) error {
	hdr := make([]byte, 4)
	if _, err := io.ReadFull(conn, hdr); err != nil {
		return err
	}
	if hdr[0] != socks5Version {
		return errors.New("socks5: invalid version in request")
	}

	cmd := hdr[1]
	atyp := hdr[3]

	addr, err := readAddr(conn, atyp)
	if err != nil {
		_ = s.sendReply(conn, repAddrNotSupported, nil)
		return err
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return err
	}
	port := binary.BigEndian.Uint16(portBuf)
	target := net.JoinHostPort(addr, fmt.Sprintf("%d", port))

	switch cmd {
	case cmdConnect:
		return s.handleConnect(conn, target)
	case cmdBind:
		return s.handleBind(conn, target)
	default:
		_ = s.sendReply(conn, repCmdNotSupported, nil)
		return fmt.Errorf("socks5: unsupported command 0x%02x", cmd)
	}
}

func (s *SOCKS5Server) handleConnect(conn net.Conn, target string) error {
	remote, err := dialAllowedTCP(target, "", s.DialTimeout)
	if err != nil {
		rep := repGeneralFailure
		if errors.Is(err, errTargetBlocked) {
			rep = repNotAllowed
		}
		if ne, ok := err.(*net.OpError); ok {
			if ne.Timeout() {
				rep = repTTLExpired
			} else {
				rep = repHostUnreachable
			}
		}
		_ = s.sendReply(conn, byte(rep), nil)
		return err
	}
	defer remote.Close()

	bndAddr, ok := remote.LocalAddr().(*net.TCPAddr)
	if !ok {
		_ = s.sendReply(conn, repGeneralFailure, nil)
		return errors.New("socks5: unexpected address type from dial")
	}
	if err := s.sendReply(conn, repSuccess, bndAddr); err != nil {
		return err
	}

	s.logger.Printf("[%s] CONNECT %s", conn.RemoteAddr(), target)

	var wg sync.WaitGroup
	wg.Add(2)
	pipe := func(dst, src net.Conn) {
		defer wg.Done()
		io.Copy(dst, src)
		if cw, ok := dst.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
	}
	go pipe(remote, conn)
	go pipe(conn, remote)
	wg.Wait()
	return nil
}

func (s *SOCKS5Server) handleBind(conn net.Conn, target string) error {
	_, port, allowedIPs, err := resolveAllowedTarget(target, "")
	if err != nil {
		rep := repGeneralFailure
		if errors.Is(err, errTargetBlocked) {
			rep = repNotAllowed
		}
		_ = s.sendReply(conn, byte(rep), nil)
		return err
	}

	expectedPort, err := strconv.Atoi(port)
	if err != nil {
		_ = s.sendReply(conn, repAddrNotSupported, nil)
		return fmt.Errorf("socks5: invalid port %q", port)
	}

	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		_ = s.sendReply(conn, repGeneralFailure, nil)
		return err
	}
	defer ln.Close()

	bndAddr, ok := ln.Addr().(*net.TCPAddr)
	if !ok {
		_ = s.sendReply(conn, repGeneralFailure, nil)
		return errors.New("socks5: unexpected listener address type")
	}
	if err := s.sendReply(conn, repSuccess, bndAddr); err != nil {
		return err
	}

	if tcpLn, ok := ln.(*net.TCPListener); ok {
		tcpLn.SetDeadline(time.Now().Add(60 * time.Second))
	}

	for {
		incoming, err := ln.Accept()
		if err != nil {
			_ = s.sendReply(conn, repGeneralFailure, nil)
			return err
		}

		inAddr, ok := incoming.RemoteAddr().(*net.TCPAddr)
		if !ok {
			incoming.Close()
			continue
		}
		if !matchesResolvedIP(inAddr.IP, allowedIPs) || (expectedPort != 0 && inAddr.Port != expectedPort) {
			incoming.Close()
			continue
		}

		defer incoming.Close()
		if err := s.sendReply(conn, repSuccess, inAddr); err != nil {
			return err
		}

		var wg sync.WaitGroup
		wg.Add(2)
		pipe := func(dst, src net.Conn) {
			defer wg.Done()
			io.Copy(dst, src)
		}
		go pipe(incoming, conn)
		go pipe(conn, incoming)
		wg.Wait()
		return nil
	}
}

func (s *SOCKS5Server) sendReply(conn net.Conn, rep byte, addr *net.TCPAddr) error {
	buf := []byte{socks5Version, rep, 0x00}

	if addr == nil {
		buf = append(buf, atypIPv4, 0, 0, 0, 0, 0, 0)
		return writeAll(conn, buf)
	}

	ip4 := addr.IP.To4()
	if ip4 != nil {
		buf = append(buf, atypIPv4)
		buf = append(buf, ip4...)
	} else {
		buf = append(buf, atypIPv6)
		buf = append(buf, addr.IP.To16()...)
	}
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, uint16(addr.Port))
	buf = append(buf, port...)
	return writeAll(conn, buf)
}

func readAddr(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case atypIPv4:
		buf := make([]byte, 4)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	case atypIPv6:
		buf := make([]byte, 16)
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	case atypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			return "", err
		}
		domain := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(r, domain); err != nil {
			return "", err
		}
		return string(domain), nil
	default:
		return "", fmt.Errorf("socks5: unsupported address type 0x%02x", atyp)
	}
}

func containsByte(s []byte, b byte) bool {
	for _, v := range s {
		if v == b {
			return true
		}
	}
	return false
}

func writeAll(w io.Writer, buf []byte) error {
	for len(buf) > 0 {
		n, err := w.Write(buf)
		if err != nil {
			return err
		}
		buf = buf[n:]
	}
	return nil
}
