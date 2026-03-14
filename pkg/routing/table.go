package routing

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
)

type Route struct {
	Destination net.IP
	Gateway     net.IP
	Netmask     net.IP
	Interface   string
	Metric      int
}

type Table struct {
	mu     sync.RWMutex
	routes []Route
}

func NewTable() *Table {
	return &Table{}
}

func (t *Table) Add(route Route) error {
	if route.Destination == nil {
		return errors.New("routing: destination required")
	}
	if route.Netmask == nil {
		return errors.New("routing: netmask required")
	}

	route.Destination = route.Destination.To4()
	route.Netmask = route.Netmask.To4()
	if route.Gateway != nil {
		route.Gateway = route.Gateway.To4()
	}

	if route.Destination == nil || route.Netmask == nil {
		return errors.New("routing: IPv4 only")
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	for _, r := range t.routes {
		if r.Destination.Equal(route.Destination) && r.Netmask.Equal(route.Netmask) {
			return errors.New("routing: route already exists")
		}
	}

	t.routes = append(t.routes, route)
	return nil
}

func (t *Table) Remove(destination net.IP) error {
	destination = destination.To4()
	if destination == nil {
		return errors.New("routing: IPv4 only")
	}

	t.mu.Lock()
	defer t.mu.Unlock()

	for i, r := range t.routes {
		if r.Destination.Equal(destination) {
			t.routes = append(t.routes[:i], t.routes[i+1:]...)
			return nil
		}
	}
	return errors.New("routing: route not found")
}

func (t *Table) Lookup(dst net.IP) (*Route, error) {
	dst = dst.To4()
	if dst == nil {
		return nil, errors.New("routing: IPv4 only")
	}

	t.mu.RLock()
	defer t.mu.RUnlock()

	var best *Route
	bestLen := -1

	dstVal := binary.BigEndian.Uint32(dst)

	for i := range t.routes {
		r := &t.routes[i]
		mask := binary.BigEndian.Uint32(r.Netmask.To4())
		dest := binary.BigEndian.Uint32(r.Destination.To4())

		if dstVal&mask == dest&mask {
			prefixLen := prefixLength(mask)
			if prefixLen > bestLen || (prefixLen == bestLen && best != nil && r.Metric < best.Metric) {
				best = r
				bestLen = prefixLen
			}
		}
	}

	if best == nil {
		return nil, errors.New("routing: no route to host")
	}

	result := *best
	result.Destination = cloneIP(best.Destination)
	result.Gateway = cloneIP(best.Gateway)
	result.Netmask = cloneIP(best.Netmask)
	return &result, nil
}

func (t *Table) Print() {
	t.mu.RLock()
	defer t.mu.RUnlock()

	fmt.Printf("%-18s %-18s %-18s %-12s %s\n",
		"Destination", "Gateway", "Netmask", "Interface", "Metric")
	fmt.Println(strings.Repeat("-", 78))

	for _, r := range t.routes {
		gw := "*"
		if r.Gateway != nil {
			gw = r.Gateway.String()
		}
		fmt.Printf("%-18s %-18s %-18s %-12s %d\n",
			r.Destination, gw, r.Netmask, r.Interface, r.Metric)
	}
}

func cloneIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	dup := make(net.IP, len(ip))
	copy(dup, ip)
	return dup
}

func prefixLength(mask uint32) int {
	n := 0
	for mask != 0 {
		n++
		mask <<= 1
	}
	return n
}
