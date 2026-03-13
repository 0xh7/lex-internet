package dns

import (
	"encoding/binary"
	"log"
	"net"
	"sync"
	"time"
)

const tcpIOTimeout = 30 * time.Second

type Handler interface {
	ServeDNS(w ResponseWriter, r *Message)
}

type HandlerFunc func(w ResponseWriter, r *Message)

func (f HandlerFunc) ServeDNS(w ResponseWriter, r *Message) { f(w, r) }

type ResponseWriter interface {
	WriteMsg(msg *Message) error
	RemoteAddr() net.Addr
}

type Server struct {
	Addr    string
	Handler Handler

	udpConn   *net.UDPConn
	tcpLn     net.Listener
	mu        sync.Mutex
	shutdown  chan struct{}
	closeOnce sync.Once
	wg        sync.WaitGroup
}

func NewServer(addr string, handler Handler) *Server {
	return &Server{
		Addr:     addr,
		Handler:  handler,
		shutdown: make(chan struct{}),
	}
}

func (s *Server) ListenAndServe() error {
	addr, err := net.ResolveUDPAddr("udp", s.Addr)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.udpConn = conn
	s.mu.Unlock()
	s.wg.Add(1)
	go s.serveUDP(conn)
	return nil
}

func (s *Server) serveUDP(conn *net.UDPConn) {
	defer s.wg.Done()
	buf := make([]byte, 4096)

	for {
		select {
		case <-s.shutdown:
			return
		default:
		}

		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-s.shutdown:
				return
			default:
				log.Printf("dns: udp read: %v", err)
				continue
			}
		}

		raw := make([]byte, n)
		copy(raw, buf[:n])

		s.wg.Add(1)
		go func(data []byte, addr *net.UDPAddr) {
			defer s.wg.Done()
			s.handleUDP(conn, data, addr)
		}(raw, raddr)
	}
}

func (s *Server) handleUDP(conn *net.UDPConn, raw []byte, addr *net.UDPAddr) {
	msg, err := ParseMessage(raw)
	if err != nil {
		log.Printf("dns: parse from %s: %v", addr, err)
		return
	}

	w := &udpResponseWriter{
		conn: conn,
		addr: addr,
	}
	s.Handler.ServeDNS(w, msg)
}

type udpResponseWriter struct {
	conn *net.UDPConn
	addr *net.UDPAddr
}

func (w *udpResponseWriter) WriteMsg(msg *Message) error {
	raw, err := msg.Marshal()
	if err != nil {
		return err
	}
	if len(raw) > 512 {
		msg.Header.Flags |= flagTC
		raw, _ = msg.Marshal()
		binary.BigEndian.PutUint16(raw[2:4], msg.Header.Flags)
		// Zero out answer/authority/additional counts for truncated response
		binary.BigEndian.PutUint16(raw[6:8], 0)
		binary.BigEndian.PutUint16(raw[8:10], 0)
		binary.BigEndian.PutUint16(raw[10:12], 0)
		// Keep only the header + question section (first 12 bytes + question)
		if len(raw) > 512 {
			raw = raw[:512]
		}
	}
	_, err = w.conn.WriteToUDP(raw, w.addr)
	return err
}

func (w *udpResponseWriter) RemoteAddr() net.Addr { return w.addr }

func (s *Server) ListenAndServeTCP() error {
	ln, err := net.Listen("tcp", s.Addr)
	if err != nil {
		return err
	}
	s.mu.Lock()
	s.tcpLn = ln
	s.mu.Unlock()
	s.wg.Add(1)
	go s.serveTCP(ln)
	return nil
}

func (s *Server) serveTCP(ln net.Listener) {
	defer s.wg.Done()

	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.shutdown:
				return
			default:
				log.Printf("dns: tcp accept: %v", err)
				continue
			}
		}
		s.wg.Add(1)
		go func(c net.Conn) {
			defer s.wg.Done()
			defer c.Close()
			s.handleTCP(c)
		}(conn)
	}
}

func (s *Server) handleTCP(conn net.Conn) {
	lenBuf := make([]byte, 2)
	for {
		if err := conn.SetReadDeadline(time.Now().Add(tcpIOTimeout)); err != nil {
			return
		}
		if _, err := readFull(conn, lenBuf); err != nil {
			return
		}
		msgLen := binary.BigEndian.Uint16(lenBuf)
		raw := make([]byte, msgLen)
		if err := conn.SetReadDeadline(time.Now().Add(tcpIOTimeout)); err != nil {
			return
		}
		if _, err := readFull(conn, raw); err != nil {
			return
		}

		msg, err := ParseMessage(raw)
		if err != nil {
			log.Printf("dns: tcp parse from %s: %v", conn.RemoteAddr(), err)
			return
		}

		w := &tcpResponseWriter{conn: conn}
		s.Handler.ServeDNS(w, msg)
	}
}

type tcpResponseWriter struct {
	conn net.Conn
}

func (w *tcpResponseWriter) WriteMsg(msg *Message) error {
	raw, err := msg.Marshal()
	if err != nil {
		return err
	}
	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(raw)))
	if err := w.conn.SetWriteDeadline(time.Now().Add(tcpIOTimeout)); err != nil {
		return err
	}
	_, err = w.conn.Write(append(length, raw...))
	return err
}

func (w *tcpResponseWriter) RemoteAddr() net.Addr { return w.conn.RemoteAddr() }

func (s *Server) Shutdown() error {
	s.closeOnce.Do(func() {
		close(s.shutdown)
		s.mu.Lock()
		if s.udpConn != nil {
			_ = s.udpConn.Close()
			s.udpConn = nil
		}
		if s.tcpLn != nil {
			_ = s.tcpLn.Close()
			s.tcpLn = nil
		}
		s.mu.Unlock()
	})
	s.wg.Wait()
	return nil
}
