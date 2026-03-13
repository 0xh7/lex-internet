package routing

import (
	"errors"
	"net"
	"sync"
)

type iface struct {
	ip   net.IP
	mask net.IPMask
}

type Router struct {
	table      *Table
	mu         sync.RWMutex
	interfaces map[string]iface
}

func NewRouter() *Router {
	return &Router{
		table:      NewTable(),
		interfaces: make(map[string]iface),
	}
}

func (r *Router) Table() *Table {
	return r.table
}

func (r *Router) AddInterface(name string, ip net.IP, mask net.IPMask) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.interfaces[name] = iface{ip: ip.To4(), mask: mask}

	netIP := ip.Mask(mask)
	netmask := net.IP(mask)
	return r.table.Add(Route{
		Destination: netIP,
		Netmask:     netmask,
		Interface:   name,
		Metric:      0,
	})
}

func (r *Router) Route(packet []byte) (string, net.IP, error) {
	if len(packet) < 20 {
		return "", nil, errors.New("router: packet too short for IPv4")
	}

	version := packet[0] >> 4
	if version != 4 {
		return "", nil, errors.New("router: not an IPv4 packet")
	}

	dstIP := net.IP(make([]byte, 4))
	copy(dstIP, packet[16:20])

	route, err := r.table.Lookup(dstIP)
	if err != nil {
		return "", nil, err
	}

	nextHop := dstIP
	if route.Gateway != nil && !route.Gateway.Equal(net.IPv4zero) {
		nextHop = route.Gateway
	}

	r.mu.RLock()
	_, ok := r.interfaces[route.Interface]
	r.mu.RUnlock()
	if !ok {
		return "", nil, errors.New("router: interface not found: " + route.Interface)
	}

	return route.Interface, nextHop, nil
}
