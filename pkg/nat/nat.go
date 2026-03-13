package nat

import (
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

const (
	defaultTCPTimeout = 30 * time.Minute
	defaultUDPTimeout = 5 * time.Minute
)

type NATTable struct {
	externalIP    net.IP
	externalReady bool
	portRange     [2]uint16

	mu       sync.RWMutex
	mappings map[string]*Mapping
	reverse  map[string]*Mapping
	nextPort uint16
}

type Mapping struct {
	InternalIP   net.IP
	InternalPort uint16
	ExternalIP   net.IP
	ExternalPort uint16
	Protocol     uint8
	Expiry       time.Time
}

func NewNATTable(externalIP net.IP, portRange [2]uint16) *NATTable {
	if portRange[0] == 0 || portRange[1] == 0 || portRange[0] > portRange[1] {
		portRange = [2]uint16{40000, 60000}
	}
	ext4 := externalIP.To4()
	ready := ext4 != nil && !ext4.IsUnspecified()

	return &NATTable{
		externalIP:    cloneIP(ext4),
		externalReady: ready,
		portRange:     portRange,
		mappings:      make(map[string]*Mapping),
		reverse:       make(map[string]*Mapping),
		nextPort:      portRange[0],
	}
}

func (t *NATTable) Translate(srcIP net.IP, srcPort uint16, proto uint8) (net.IP, uint16) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if !t.externalReady {
		return nil, 0
	}

	now := time.Now()
	key := tupleKey(srcIP, srcPort, proto)
	if mapping, ok := t.mappings[key]; ok && mapping.Expiry.After(now) {
		mapping.Expiry = now.Add(protocolTimeout(proto))
		return cloneIP(mapping.ExternalIP), mapping.ExternalPort
	}

	port, ok := t.allocatePort(proto)
	if !ok {
		return nil, 0
	}

	mapping := &Mapping{
		InternalIP:   cloneIP(srcIP),
		InternalPort: srcPort,
		ExternalIP:   cloneIP(t.externalIP),
		ExternalPort: port,
		Protocol:     proto,
		Expiry:       now.Add(protocolTimeout(proto)),
	}

	t.mappings[key] = mapping
	t.reverse[reverseKey(port, proto)] = mapping
	return cloneIP(mapping.ExternalIP), mapping.ExternalPort
}

func (t *NATTable) ReverseTranslate(dstPort uint16, proto uint8) (net.IP, uint16, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()

	mapping, ok := t.reverse[reverseKey(dstPort, proto)]
	if !ok {
		return nil, 0, false
	}
	if time.Now().After(mapping.Expiry) {
		t.deleteMapping(mapping)
		return nil, 0, false
	}

	mapping.Expiry = time.Now().Add(protocolTimeout(proto))
	return cloneIP(mapping.InternalIP), mapping.InternalPort, true
}

func (t *NATTable) Cleanup() {
	t.mu.Lock()
	defer t.mu.Unlock()

	now := time.Now()
	for _, mapping := range t.reverse {
		if now.After(mapping.Expiry) {
			t.deleteMapping(mapping)
		}
	}
}

func (t *NATTable) Snapshot() []Mapping {
	t.mu.RLock()
	defer t.mu.RUnlock()

	out := make([]Mapping, 0, len(t.reverse))
	for _, mapping := range t.reverse {
		out = append(out, Mapping{
			InternalIP:   cloneIP(mapping.InternalIP),
			InternalPort: mapping.InternalPort,
			ExternalIP:   cloneIP(mapping.ExternalIP),
			ExternalPort: mapping.ExternalPort,
			Protocol:     mapping.Protocol,
			Expiry:       mapping.Expiry,
		})
	}

	sort.Slice(out, func(i, j int) bool {
		if out[i].Protocol == out[j].Protocol {
			return out[i].ExternalPort < out[j].ExternalPort
		}
		return out[i].Protocol < out[j].Protocol
	})

	return out
}

func (t *NATTable) allocatePort(proto uint8) (uint16, bool) {
	total := int(t.portRange[1]-t.portRange[0]) + 1
	now := time.Now()

	for i := 0; i < total; i++ {
		port := t.nextPort
		t.nextPort++
		if t.nextPort > t.portRange[1] {
			t.nextPort = t.portRange[0]
		}

		key := reverseKey(port, proto)
		mapping, exists := t.reverse[key]
		if !exists {
			return port, true
		}
		if now.After(mapping.Expiry) {
			t.deleteMapping(mapping)
			return port, true
		}
	}

	return 0, false
}

func (t *NATTable) deleteMapping(mapping *Mapping) {
	delete(t.mappings, tupleKey(mapping.InternalIP, mapping.InternalPort, mapping.Protocol))
	delete(t.reverse, reverseKey(mapping.ExternalPort, mapping.Protocol))
}

func protocolTimeout(proto uint8) time.Duration {
	switch proto {
	case 17:
		return defaultUDPTimeout
	default:
		return defaultTCPTimeout
	}
}

func tupleKey(ip net.IP, port uint16, proto uint8) string {
	return fmt.Sprintf("%s:%d/%d", ip.String(), port, proto)
}

func reverseKey(port uint16, proto uint8) string {
	return fmt.Sprintf("%d/%d", port, proto)
}

func cloneIP(ip net.IP) net.IP {
	if ip == nil {
		return nil
	}
	out := make(net.IP, len(ip))
	copy(out, ip)
	return out
}
