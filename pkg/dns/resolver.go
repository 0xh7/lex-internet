package dns

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

type MXRecord struct {
	Preference uint16
	Exchange   string
}

type SRVRecord struct {
	Priority uint16
	Weight   uint16
	Port     uint16
	Target   string
}

type Resolver struct {
	nameservers []string
	timeout     time.Duration
	retries     int
}

func NewResolver(nameservers ...string) *Resolver {
	if len(nameservers) == 0 {
		nameservers = []string{"8.8.8.8:53", "8.8.4.4:53"}
	}
	for i, ns := range nameservers {
		if _, _, err := net.SplitHostPort(ns); err != nil {
			nameservers[i] = net.JoinHostPort(ns, "53")
		}
	}
	return &Resolver{
		nameservers: nameservers,
		timeout:     5 * time.Second,
		retries:     3,
	}
}

func (r *Resolver) SetTimeout(d time.Duration) { r.timeout = d }
func (r *Resolver) SetRetries(n int)           { r.retries = n }

func (r *Resolver) Resolve(name string, qtype uint16) (*Message, error) {
	id, err := randomID()
	if err != nil {
		return nil, err
	}

	query := NewQuery(id, name, qtype, ClassIN)
	raw, err := query.Marshal()
	if err != nil {
		return nil, fmt.Errorf("dns: marshal query: %w", err)
	}

	var lastErr error
	for _, ns := range r.nameservers {
		for attempt := 0; attempt < r.retries; attempt++ {
			resp, err := r.exchangeUDP(ns, raw)
			if err != nil {
				lastErr = err
				continue
			}
			msg, err := ParseMessage(resp)
			if err != nil {
				lastErr = err
				continue
			}
			if FlagsTC(msg.Header.Flags) {
				resp, err = r.exchangeTCP(ns, raw)
				if err != nil {
					lastErr = err
					continue
				}
				msg, err = ParseMessage(resp)
				if err != nil {
					lastErr = err
					continue
				}
			}
			if msg.Header.ID != id {
				lastErr = errors.New("dns: response ID mismatch")
				continue
			}
			return msg, nil
		}
	}
	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errors.New("dns: no nameservers available")
}

func (r *Resolver) exchangeUDP(server string, query []byte) ([]byte, error) {
	conn, err := net.DialTimeout("udp", server, r.timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(r.timeout))
	if _, err := conn.Write(query); err != nil {
		return nil, err
	}

	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func (r *Resolver) exchangeTCP(server string, query []byte) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", server, r.timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(r.timeout))

	length := make([]byte, 2)
	binary.BigEndian.PutUint16(length, uint16(len(query)))
	if _, err := conn.Write(append(length, query...)); err != nil {
		return nil, err
	}

	if _, err := readFull(conn, length); err != nil {
		return nil, err
	}
	respLen := binary.BigEndian.Uint16(length)
	resp := make([]byte, respLen)
	if _, err := readFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func (r *Resolver) LookupA(name string) ([]net.IP, error) {
	msg, err := r.Resolve(name, TypeA)
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	for _, rr := range msg.Answers {
		if rr.Type == TypeA && len(rr.RData) == 4 {
			ips = append(ips, net.IP(rr.RData))
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("dns: no A records for %s", name)
	}
	return ips, nil
}

func (r *Resolver) LookupAAAA(name string) ([]net.IP, error) {
	msg, err := r.Resolve(name, TypeAAAA)
	if err != nil {
		return nil, err
	}
	var ips []net.IP
	for _, rr := range msg.Answers {
		if rr.Type == TypeAAAA && len(rr.RData) == 16 {
			ips = append(ips, net.IP(rr.RData))
		}
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("dns: no AAAA records for %s", name)
	}
	return ips, nil
}

func (r *Resolver) LookupMX(name string) ([]MXRecord, error) {
	msg, err := r.Resolve(name, TypeMX)
	if err != nil {
		return nil, err
	}
	var records []MXRecord
	for _, rr := range msg.Answers {
		if rr.Type == TypeMX && len(rr.RData) >= 3 {
			pref := binary.BigEndian.Uint16(rr.RData[:2])
			exchange := rdataToName(rr.RData[2:])
			records = append(records, MXRecord{Preference: pref, Exchange: exchange})
		}
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("dns: no MX records for %s", name)
	}
	return records, nil
}

func (r *Resolver) LookupNS(name string) ([]string, error) {
	msg, err := r.Resolve(name, TypeNS)
	if err != nil {
		return nil, err
	}
	var servers []string
	for _, rr := range msg.Answers {
		if rr.Type == TypeNS {
			servers = append(servers, rdataToName(rr.RData))
		}
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("dns: no NS records for %s", name)
	}
	return servers, nil
}

func (r *Resolver) LookupTXT(name string) ([]string, error) {
	msg, err := r.Resolve(name, TypeTXT)
	if err != nil {
		return nil, err
	}
	var texts []string
	for _, rr := range msg.Answers {
		if rr.Type == TypeTXT {
			txt, err := decodeTXT(rr.RData)
			if err != nil {
				continue
			}
			texts = append(texts, txt)
		}
	}
	if len(texts) == 0 {
		return nil, fmt.Errorf("dns: no TXT records for %s", name)
	}
	return texts, nil
}

func (r *Resolver) LookupCNAME(name string) (string, error) {
	msg, err := r.Resolve(name, TypeCNAME)
	if err != nil {
		return "", err
	}
	for _, rr := range msg.Answers {
		if rr.Type == TypeCNAME {
			return rdataToName(rr.RData), nil
		}
	}
	return "", fmt.Errorf("dns: no CNAME record for %s", name)
}

func decodeTXT(rdata []byte) (string, error) {
	var result []byte
	off := 0
	for off < len(rdata) {
		length := int(rdata[off])
		off++
		if off+length > len(rdata) {
			return "", errors.New("dns: TXT string extends beyond rdata")
		}
		result = append(result, rdata[off:off+length]...)
		off += length
	}
	return string(result), nil
}

func randomID() (uint16, error) {
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(b[:]), nil
}
