package dns

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
)

type Zone struct {
	Origin  string
	records map[string][]ResourceRecord
	mu      sync.RWMutex
}

func NewZone(origin string) *Zone {
	return &Zone{
		Origin:  strings.TrimSuffix(origin, "."),
		records: make(map[string][]ResourceRecord),
	}
}

func (z *Zone) AddRecord(name string, rr ResourceRecord) {
	z.mu.Lock()
	defer z.mu.Unlock()
	key := z.normalize(name)
	rr.Name = key
	z.records[key] = append(z.records[key], rr)
}

func (z *Zone) RemoveRecord(name string, rrType uint16) {
	z.mu.Lock()
	defer z.mu.Unlock()
	key := z.normalize(name)
	rrs := z.records[key]
	var filtered []ResourceRecord
	for _, rr := range rrs {
		if rr.Type != rrType {
			filtered = append(filtered, rr)
		}
	}
	if len(filtered) == 0 {
		delete(z.records, key)
	} else {
		z.records[key] = filtered
	}
}

func (z *Zone) Lookup(name string, rrType uint16) []ResourceRecord {
	z.mu.RLock()
	defer z.mu.RUnlock()
	key := z.normalize(name)
	var result []ResourceRecord
	for _, rr := range z.records[key] {
		if rrType == TypeANY || rr.Type == rrType {
			result = append(result, rr)
		}
	}
	return result
}

func (z *Zone) normalize(name string) string {
	name = strings.TrimSuffix(name, ".")
	name = strings.ToLower(name)
	if name == "@" || name == "" {
		return strings.ToLower(z.Origin)
	}
	if !strings.Contains(name, ".") && z.Origin != "" {
		return name + "." + strings.ToLower(z.Origin)
	}
	return name
}

func (z *Zone) ServeDNS(w ResponseWriter, r *Message) {
	if len(r.Questions) == 0 {
		resp := NewResponse(r, RCodeFormErr, nil)
		w.WriteMsg(resp)
		return
	}

	q := r.Questions[0]
	records := z.Lookup(q.Name, q.Type)

	if len(records) == 0 && q.Type != TypeCNAME {
		cnames := z.Lookup(q.Name, TypeCNAME)
		if len(cnames) > 0 {
			target := rdataToName(cnames[0].RData)
			targetRRs := z.Lookup(target, q.Type)
			records = append(cnames, targetRRs...)
		}
	}

	if len(records) == 0 {
		all := z.Lookup(q.Name, TypeANY)
		if len(all) == 0 {
			resp := NewResponse(r, RCodeNXDomain, nil)
			w.WriteMsg(resp)
			return
		}
		resp := NewResponse(r, RCodeNoError, nil)
		w.WriteMsg(resp)
		return
	}

	resp := NewResponse(r, RCodeNoError, records)
	resp.Header.Flags |= flagAA
	w.WriteMsg(resp)
}

func LoadZoneFile(path string) (*Zone, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var zone *Zone
	var origin string
	defaultTTL := uint32(3600)
	lastName := ""

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := stripComment(scanner.Text())
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "$ORIGIN") {
			origin = strings.TrimSpace(strings.TrimPrefix(line, "$ORIGIN"))
			origin = strings.TrimSuffix(origin, ".")
			if zone == nil {
				zone = NewZone(origin)
			} else {
				zone.Origin = origin
			}
			continue
		}

		if strings.HasPrefix(line, "$TTL") {
			ttlStr := strings.TrimSpace(strings.TrimPrefix(line, "$TTL"))
			if v, err := parseTTL(ttlStr); err == nil {
				defaultTTL = v
			}
			continue
		}

		if zone == nil {
			zone = NewZone(origin)
		}

		rr, name, err := parseZoneLine(line, lastName, origin, defaultTTL)
		if err != nil {
			continue
		}
		lastName = name
		zone.AddRecord(name, rr)
	}

	if zone == nil {
		return nil, fmt.Errorf("dns: empty zone file: %s", path)
	}
	return zone, scanner.Err()
}

func parseZoneLine(line, lastName, origin string, defaultTTL uint32) (ResourceRecord, string, error) {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return ResourceRecord{}, "", fmt.Errorf("too few fields")
	}

	idx := 0
	name := fields[idx]
	if name == "@" {
		name = origin
	} else if isRRType(name) || isClass(name) || isTTL(name) {
		name = lastName
		idx--
	}
	idx++

	ttl := defaultTTL
	class := ClassIN

	if idx < len(fields) && isTTL(fields[idx]) {
		if v, err := parseTTL(fields[idx]); err == nil {
			ttl = v
		}
		idx++
	}

	if idx < len(fields) && isClass(fields[idx]) {
		class = parseClass(fields[idx])
		idx++
	}

	if idx >= len(fields) {
		return ResourceRecord{}, "", fmt.Errorf("missing type")
	}

	rrType := StringToType(strings.ToUpper(fields[idx]))
	if rrType == 0 {
		return ResourceRecord{}, "", fmt.Errorf("unknown type: %s", fields[idx])
	}
	idx++

	if idx >= len(fields) {
		return ResourceRecord{}, "", fmt.Errorf("missing rdata")
	}

	rdata, err := buildRData(rrType, fields[idx:], origin)
	if err != nil {
		return ResourceRecord{}, "", err
	}

	rr := ResourceRecord{
		Name:     name,
		Type:     rrType,
		Class:    uint16(class),
		TTL:      ttl,
		RDLength: uint16(len(rdata)),
		RData:    rdata,
	}
	return rr, name, nil
}

func buildRData(rrType uint16, fields []string, origin string) ([]byte, error) {
	switch rrType {
	case TypeA:
		parsed := net.ParseIP(fields[0])
		if parsed == nil {
			return nil, fmt.Errorf("invalid A record: %s", fields[0])
		}
		ip := parsed.To4()
		if ip == nil {
			return nil, fmt.Errorf("invalid A record (not IPv4): %s", fields[0])
		}
		return ip, nil

	case TypeAAAA:
		parsed := net.ParseIP(fields[0])
		if parsed == nil {
			return nil, fmt.Errorf("invalid AAAA record: %s", fields[0])
		}
		ip := parsed.To16()
		if ip == nil {
			return nil, fmt.Errorf("invalid AAAA record (not IPv6): %s", fields[0])
		}
		return ip, nil

	case TypeNS, TypeCNAME, TypePTR:
		target := qualify(fields[0], origin)
		return encodeName(target), nil

	case TypeMX:
		if len(fields) < 2 {
			return nil, fmt.Errorf("MX requires preference and exchange")
		}
		pref, err := strconv.ParseUint(fields[0], 10, 16)
		if err != nil {
			return nil, err
		}
		exchange := qualify(fields[1], origin)
		buf := make([]byte, 2)
		binary.BigEndian.PutUint16(buf, uint16(pref))
		return append(buf, encodeName(exchange)...), nil

	case TypeTXT:
		text := strings.Join(fields, " ")
		text = strings.Trim(text, "\"")
		var rdata []byte
		raw := []byte(text)
		for len(raw) > 0 {
			chunk := raw
			if len(chunk) > 255 {
				chunk = raw[:255]
			}
			rdata = append(rdata, byte(len(chunk)))
			rdata = append(rdata, chunk...)
			raw = raw[len(chunk):]
		}
		return rdata, nil

	case TypeSOA:
		if len(fields) < 7 {
			return nil, fmt.Errorf("SOA requires 7 fields")
		}
		mname := qualify(fields[0], origin)
		rname := qualify(fields[1], origin)
		var buf []byte
		buf = append(buf, encodeName(mname)...)
		buf = append(buf, encodeName(rname)...)
		for _, f := range fields[2:7] {
			f = strings.Trim(f, "()")
			v, err := strconv.ParseUint(f, 10, 32)
			if err != nil {
				return nil, err
			}
			b := make([]byte, 4)
			binary.BigEndian.PutUint32(b, uint32(v))
			buf = append(buf, b...)
		}
		return buf, nil

	case TypeSRV:
		if len(fields) < 4 {
			return nil, fmt.Errorf("SRV requires priority, weight, port, target")
		}
		var buf []byte
		for _, f := range fields[:3] {
			v, err := strconv.ParseUint(f, 10, 16)
			if err != nil {
				return nil, err
			}
			b := make([]byte, 2)
			binary.BigEndian.PutUint16(b, uint16(v))
			buf = append(buf, b...)
		}
		target := qualify(fields[3], origin)
		return append(buf, encodeName(target)...), nil
	}

	return nil, fmt.Errorf("unsupported record type for zone file: %s", TypeToString(rrType))
}

func qualify(name, origin string) string {
	name = strings.TrimSuffix(name, ".")
	if name == "@" {
		return origin
	}
	return name
}

func stripComment(line string) string {
	inQuote := false
	for i, ch := range line {
		if ch == '"' {
			inQuote = !inQuote
		}
		if ch == ';' && !inQuote {
			return line[:i]
		}
	}
	return line
}

func isRRType(s string) bool {
	return StringToType(strings.ToUpper(s)) != 0
}

func isClass(s string) bool {
	s = strings.ToUpper(s)
	return s == "IN" || s == "CH" || s == "HS" || s == "ANY"
}

func parseClass(s string) uint16 {
	switch strings.ToUpper(s) {
	case "IN":
		return ClassIN
	case "CH":
		return ClassCH
	case "HS":
		return ClassHS
	case "ANY":
		return ClassANY
	}
	return ClassIN
}

func isTTL(s string) bool {
	_, err := parseTTL(s)
	return err == nil
}

func parseTTL(s string) (uint32, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty ttl")
	}

	var total uint32
	var current uint32
	for _, ch := range s {
		switch {
		case ch >= '0' && ch <= '9':
			current = current*10 + uint32(ch-'0')
		case ch == 's' || ch == 'S':
			total += current
			current = 0
		case ch == 'm' || ch == 'M':
			total += current * 60
			current = 0
		case ch == 'h' || ch == 'H':
			total += current * 3600
			current = 0
		case ch == 'd' || ch == 'D':
			total += current * 86400
			current = 0
		case ch == 'w' || ch == 'W':
			total += current * 604800
			current = 0
		default:
			return 0, fmt.Errorf("invalid ttl: %s", s)
		}
	}
	total += current
	return total, nil
}
