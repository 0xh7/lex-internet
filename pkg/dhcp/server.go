package dhcp

import (
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"time"
)

type Pool struct {
	Start     net.IP
	End       net.IP
	Subnet    net.IPMask
	Gateway   net.IP
	DNS       net.IP
	LeaseTime time.Duration
}

type Lease struct {
	IP       net.IP
	MAC      net.HardwareAddr
	Expiry   time.Time
	Hostname string
}

type Server struct {
	listenAddr string
	pool       Pool
	mu         sync.Mutex
	leases     map[string]*Lease
	allocated  map[string]bool
}

func NewServer(listenAddr string, pool Pool) *Server {
	return &Server{
		listenAddr: listenAddr,
		pool:       pool,
		leases:     make(map[string]*Lease),
		allocated:  make(map[string]bool),
	}
}

func (s *Server) ListenAndServe() error {
	addr, err := net.ResolveUDPAddr("udp4", s.listenAddr)
	if err != nil {
		return fmt.Errorf("dhcp: resolve address: %w", err)
	}

	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		return fmt.Errorf("dhcp: listen: %w", err)
	}
	defer conn.Close()

	log.Printf("dhcp: listening on %s", s.listenAddr)

	buf := make([]byte, 1500)
	for {
		n, raddr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("dhcp: read error: %v", err)
			continue
		}

		msg, err := ParseMessage(buf[:n])
		if err != nil {
			log.Printf("dhcp: parse error from %s: %v", raddr, err)
			continue
		}

		if msg.Op != OpRequest {
			continue
		}

		reply := s.handleMessage(msg)
		if reply == nil {
			continue
		}

		raw := reply.Marshal()

		dst := &net.UDPAddr{IP: net.IPv4(255, 255, 255, 255), Port: 68}
		if msg.GIAddr != nil && !msg.GIAddr.Equal(net.IPv4zero) {
			dst = &net.UDPAddr{IP: msg.GIAddr, Port: 67}
		}

		if _, err := conn.WriteToUDP(raw, dst); err != nil {
			log.Printf("dhcp: write error to %s: %v", dst, err)
		}
	}
}

func (s *Server) handleMessage(req *Message) *Message {
	switch req.MessageType() {
	case MsgDiscover:
		return s.handleDiscover(req)
	case MsgRequest:
		return s.handleRequest(req)
	case MsgRelease:
		s.handleRelease(req)
		return nil
	case MsgDecline:
		s.handleDecline(req)
		return nil
	default:
		return nil
	}
}

func (s *Server) handleDiscover(req *Message) *Message {
	mac := net.HardwareAddr(req.CHAddr[:req.HLen])
	log.Printf("dhcp: DISCOVER from %s", mac)

	s.mu.Lock()
	defer s.mu.Unlock()

	s.expireLeases()

	ip := s.allocateIP(mac)
	if ip == nil {
		log.Printf("dhcp: pool exhausted, cannot offer to %s", mac)
		return nil
	}

	reply := s.buildReply(req, MsgOffer, ip)
	log.Printf("dhcp: OFFER %s to %s", ip, mac)
	return reply
}

func (s *Server) handleRequest(req *Message) *Message {
	mac := net.HardwareAddr(req.CHAddr[:req.HLen])
	log.Printf("dhcp: REQUEST from %s", mac)

	s.mu.Lock()
	defer s.mu.Unlock()

	s.expireLeases()

	var requestedIP net.IP
	if opt := req.GetOption(OptRequestedIP); opt != nil && len(opt.Data) == 4 {
		requestedIP = net.IP(opt.Data)
	} else if !req.CIAddr.Equal(net.IPv4zero) {
		requestedIP = req.CIAddr
	}

	if requestedIP == nil {
		log.Printf("dhcp: REQUEST from %s without requested IP", mac)
		return s.buildReply(req, MsgNak, net.IPv4zero)
	}

	if !s.inRange(requestedIP) {
		log.Printf("dhcp: REQUEST from %s for out-of-range IP %s", mac, requestedIP)
		return s.buildReply(req, MsgNak, net.IPv4zero)
	}

	macStr := mac.String()
	ipStr := requestedIP.String()

	if owner, ok := s.leases[macStr]; ok && owner.IP.Equal(requestedIP) {
		owner.Expiry = time.Now().Add(s.pool.LeaseTime)
		log.Printf("dhcp: ACK (renew) %s to %s", requestedIP, mac)
		return s.buildReply(req, MsgAck, requestedIP)
	}

	if s.allocated[ipStr] {
		existing := s.findLeaseByIP(requestedIP)
		if existing != nil && existing.MAC.String() != macStr {
			log.Printf("dhcp: NAK %s already allocated", requestedIP)
			return s.buildReply(req, MsgNak, net.IPv4zero)
		}
	}

	lease := &Lease{
		IP:     requestedIP,
		MAC:    mac,
		Expiry: time.Now().Add(s.pool.LeaseTime),
	}
	if old, ok := s.leases[macStr]; ok {
		delete(s.allocated, old.IP.String())
	}
	s.leases[macStr] = lease
	s.allocated[ipStr] = true

	log.Printf("dhcp: ACK %s to %s", requestedIP, mac)
	return s.buildReply(req, MsgAck, requestedIP)
}

func (s *Server) handleRelease(req *Message) {
	mac := net.HardwareAddr(req.CHAddr[:req.HLen])
	macStr := mac.String()

	s.mu.Lock()
	defer s.mu.Unlock()

	if lease, ok := s.leases[macStr]; ok {
		log.Printf("dhcp: RELEASE %s from %s", lease.IP, mac)
		delete(s.allocated, lease.IP.String())
		delete(s.leases, macStr)
	}
}

func (s *Server) handleDecline(req *Message) {
	mac := net.HardwareAddr(req.CHAddr[:req.HLen])
	log.Printf("dhcp: DECLINE from %s", mac)

	s.mu.Lock()
	defer s.mu.Unlock()

	macStr := mac.String()
	if lease, ok := s.leases[macStr]; ok {
		delete(s.allocated, lease.IP.String())
		delete(s.leases, macStr)
	}
}

func (s *Server) buildReply(req *Message, msgType uint8, yiaddr net.IP) *Message {
	gateway4 := s.pool.Gateway.To4()
	dns4 := s.pool.DNS.To4()
	subnet := []byte(s.pool.Subnet)

	reply := &Message{
		Op:    OpReply,
		HType: req.HType,
		HLen:  req.HLen,
		Hops:  0,
		XID:   req.XID,
		Secs:  0,
		Flags: req.Flags,
	}

	reply.CIAddr = net.IPv4zero
	reply.YIAddr = yiaddr
	reply.SIAddr = gateway4
	reply.GIAddr = req.GIAddr
	reply.CHAddr = req.CHAddr

	reply.SetOption(OptMessageType, []byte{msgType})
	if gateway4 != nil {
		reply.SetOption(OptServerID, gateway4)
	}

	if msgType == MsgOffer || msgType == MsgAck {
		if len(subnet) == 4 {
			reply.SetOption(OptSubnetMask, subnet)
		}
		if gateway4 != nil {
			reply.SetOption(OptRouter, gateway4)
		}
		if dns4 != nil {
			reply.SetOption(OptDNS, dns4)
		}

		leaseSeconds := uint32(s.pool.LeaseTime.Seconds())
		ltBuf := make([]byte, 4)
		binary.BigEndian.PutUint32(ltBuf, leaseSeconds)
		reply.SetOption(OptLeaseTime, ltBuf)
	}

	return reply
}

func (s *Server) allocateIP(mac net.HardwareAddr) net.IP {
	macStr := mac.String()

	if lease, ok := s.leases[macStr]; ok {
		lease.Expiry = time.Now().Add(s.pool.LeaseTime)
		return lease.IP
	}

	start := s.pool.Start.To4()
	end := s.pool.End.To4()
	if start == nil || end == nil {
		return nil
	}

	startN := binary.BigEndian.Uint32(start)
	endN := binary.BigEndian.Uint32(end)
	if startN > endN {
		return nil
	}

	for n := startN; ; n++ {
		candidate := make(net.IP, 4)
		binary.BigEndian.PutUint32(candidate, n)
		if !s.allocated[candidate.String()] {
			lease := &Lease{
				IP:     candidate,
				MAC:    mac,
				Expiry: time.Now().Add(s.pool.LeaseTime),
			}
			s.leases[macStr] = lease
			s.allocated[candidate.String()] = true
			return lease.IP
		}
		if n == endN || n == 0xFFFFFFFF {
			break
		}
	}

	return nil
}

func (s *Server) expireLeases() {
	now := time.Now()
	for macStr, lease := range s.leases {
		if now.After(lease.Expiry) {
			log.Printf("dhcp: lease expired for %s (%s)", lease.IP, lease.MAC)
			delete(s.allocated, lease.IP.String())
			delete(s.leases, macStr)
		}
	}
}

func (s *Server) findLeaseByIP(ip net.IP) *Lease {
	for _, lease := range s.leases {
		if lease.IP.Equal(ip) {
			return lease
		}
	}
	return nil
}

func (s *Server) inRange(ip net.IP) bool {
	ip4 := ip.To4()
	start := s.pool.Start.To4()
	end := s.pool.End.To4()
	if ip4 == nil || start == nil || end == nil {
		return false
	}
	a := binary.BigEndian.Uint32(ip4)
	lo := binary.BigEndian.Uint32(start)
	hi := binary.BigEndian.Uint32(end)
	return a >= lo && a <= hi
}

func (s *Server) Leases() []Lease {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Lease, 0, len(s.leases))
	for _, l := range s.leases {
		out = append(out, *l)
	}
	return out
}
