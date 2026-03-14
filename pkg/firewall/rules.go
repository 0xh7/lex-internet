package firewall

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
)

type Action uint8

const (
	Allow Action = iota
	Deny
	Drop
)

type Direction uint8

const (
	Inbound Direction = iota
	Outbound
	Both
)

type PortRange struct {
	Low  uint16
	High uint16
}

func (pr PortRange) Contains(port uint16) bool {
	return port >= pr.Low && port <= pr.High
}

type Rule struct {
	Action    Action
	Protocol  string
	SrcIP     *net.IPNet
	DstIP     *net.IPNet
	SrcPort   PortRange
	DstPort   PortRange
	Direction Direction
}

func (r *Rule) Matches(pkt PacketInfo) bool {
	if r.Direction != Both {
		if r.Direction == Inbound && pkt.Direction != Inbound {
			return false
		}
		if r.Direction == Outbound && pkt.Direction != Outbound {
			return false
		}
	}

	if r.Protocol != "" && r.Protocol != "*" {
		if !strings.EqualFold(r.Protocol, pkt.Protocol) {
			return false
		}
	}

	if r.SrcIP != nil && !r.SrcIP.Contains(pkt.SrcIP) {
		return false
	}
	if r.DstIP != nil && !r.DstIP.Contains(pkt.DstIP) {
		return false
	}

	if r.SrcPort.High > 0 && !r.SrcPort.Contains(pkt.SrcPort) {
		return false
	}
	if r.DstPort.High > 0 && !r.DstPort.Contains(pkt.DstPort) {
		return false
	}

	return true
}

type RuleSet struct {
	mu    sync.RWMutex
	rules []Rule
}

func NewRuleSet() *RuleSet {
	return &RuleSet{}
}

func (rs *RuleSet) AddRule(rule Rule) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	rs.rules = append(rs.rules, rule)
}

func (rs *RuleSet) InsertRule(index int, rule Rule) {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if index < 0 {
		index = 0
	}
	if index >= len(rs.rules) {
		rs.rules = append(rs.rules, rule)
		return
	}
	rs.rules = append(rs.rules, Rule{})
	copy(rs.rules[index+1:], rs.rules[index:])
	rs.rules[index] = rule
}

func (rs *RuleSet) RemoveRule(index int) bool {
	rs.mu.Lock()
	defer rs.mu.Unlock()
	if index < 0 || index >= len(rs.rules) {
		return false
	}
	rs.rules = append(rs.rules[:index], rs.rules[index+1:]...)
	return true
}

func (rs *RuleSet) Match(pkt PacketInfo) Action {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	for _, r := range rs.rules {
		if r.Matches(pkt) {
			return r.Action
		}
	}
	return Deny
}

func (rs *RuleSet) Len() int {
	rs.mu.RLock()
	defer rs.mu.RUnlock()
	return len(rs.rules)
}

func LoadRules(path string) (*RuleSet, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	rs := NewRuleSet()
	scanner := bufio.NewScanner(f)
	lineNo := 0

	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		rule, err := parseRule(line)
		if err != nil {
			return nil, fmt.Errorf("line %d: %w", lineNo, err)
		}
		rs.AddRule(rule)
	}
	return rs, scanner.Err()
}

func parseRule(line string) (Rule, error) {
	fields := strings.Fields(line)
	if len(fields) < 6 {
		return Rule{}, fmt.Errorf("expected at least 6 fields, got %d", len(fields))
	}

	var r Rule

	switch strings.ToLower(fields[0]) {
	case "allow":
		r.Action = Allow
	case "deny":
		r.Action = Deny
	case "drop":
		r.Action = Drop
	default:
		return Rule{}, fmt.Errorf("unknown action: %s", fields[0])
	}

	switch strings.ToLower(fields[1]) {
	case "in":
		r.Direction = Inbound
	case "out":
		r.Direction = Outbound
	case "both", "*":
		r.Direction = Both
	default:
		return Rule{}, fmt.Errorf("unknown direction: %s", fields[1])
	}

	r.Protocol = strings.ToLower(fields[2])

	var err error
	r.SrcIP, err = parseCIDR(fields[3])
	if err != nil {
		return Rule{}, fmt.Errorf("src ip: %w", err)
	}

	r.DstIP, err = parseCIDR(fields[4])
	if err != nil {
		return Rule{}, fmt.Errorf("dst ip: %w", err)
	}

	if len(fields) >= 7 {
		r.SrcPort, err = parsePortRange(fields[5])
		if err != nil {
			return Rule{}, fmt.Errorf("src port: %w", err)
		}
		r.DstPort, err = parsePortRange(fields[6])
		if err != nil {
			return Rule{}, fmt.Errorf("dst port: %w", err)
		}
	}

	return r, nil
}

func parseCIDR(s string) (*net.IPNet, error) {
	if s == "*" || s == "any" {
		return nil, nil
	}
	if !strings.Contains(s, "/") {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil, fmt.Errorf("invalid IP: %s", s)
		}
		if ip.To4() != nil {
			s += "/32"
		} else {
			s += "/128"
		}
	}
	_, cidr, err := net.ParseCIDR(s)
	return cidr, err
}

func parsePortRange(s string) (PortRange, error) {
	if s == "*" || s == "any" {
		return PortRange{}, nil
	}

	if idx := strings.Index(s, "-"); idx >= 0 {
		lo, err := strconv.ParseUint(s[:idx], 10, 16)
		if err != nil {
			return PortRange{}, err
		}
		hi, err := strconv.ParseUint(s[idx+1:], 10, 16)
		if err != nil {
			return PortRange{}, err
		}
		if lo > hi {
			return PortRange{}, fmt.Errorf("invalid port range: %d > %d", lo, hi)
		}
		return PortRange{Low: uint16(lo), High: uint16(hi)}, nil
	}

	p, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return PortRange{}, err
	}
	return PortRange{Low: uint16(p), High: uint16(p)}, nil
}
