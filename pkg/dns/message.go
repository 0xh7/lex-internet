package dns

import (
	"encoding/binary"
	"errors"
	"strings"
)

const headerLen = 12

type Header struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
}

type Question struct {
	Name  string
	Type  uint16
	Class uint16
}

type ResourceRecord struct {
	Name     string
	Type     uint16
	Class    uint16
	TTL      uint32
	RDLength uint16
	RData    []byte
}

type Message struct {
	Header     Header
	Questions  []Question
	Answers    []ResourceRecord
	Authority  []ResourceRecord
	Additional []ResourceRecord
}

func ParseMessage(raw []byte) (*Message, error) {
	if len(raw) < headerLen {
		return nil, errors.New("dns: message too short")
	}

	m := &Message{}
	m.Header.ID = binary.BigEndian.Uint16(raw[0:2])
	m.Header.Flags = binary.BigEndian.Uint16(raw[2:4])
	m.Header.QDCount = binary.BigEndian.Uint16(raw[4:6])
	m.Header.ANCount = binary.BigEndian.Uint16(raw[6:8])
	m.Header.NSCount = binary.BigEndian.Uint16(raw[8:10])
	m.Header.ARCount = binary.BigEndian.Uint16(raw[10:12])

	offset := headerLen
	var err error

	m.Questions = make([]Question, m.Header.QDCount)
	for i := 0; i < int(m.Header.QDCount); i++ {
		m.Questions[i], offset, err = parseQuestion(raw, offset)
		if err != nil {
			return nil, err
		}
	}

	m.Answers, offset, err = parseRRs(raw, offset, int(m.Header.ANCount))
	if err != nil {
		return nil, err
	}
	m.Authority, offset, err = parseRRs(raw, offset, int(m.Header.NSCount))
	if err != nil {
		return nil, err
	}
	m.Additional, _, err = parseRRs(raw, offset, int(m.Header.ARCount))
	if err != nil {
		return nil, err
	}

	return m, nil
}

func parseQuestion(raw []byte, offset int) (Question, int, error) {
	name, off, err := decodeName(raw, offset)
	if err != nil {
		return Question{}, 0, err
	}
	if off+4 > len(raw) {
		return Question{}, 0, errors.New("dns: question section truncated")
	}
	q := Question{
		Name:  name,
		Type:  binary.BigEndian.Uint16(raw[off : off+2]),
		Class: binary.BigEndian.Uint16(raw[off+2 : off+4]),
	}
	return q, off + 4, nil
}

func parseRRs(raw []byte, offset, count int) ([]ResourceRecord, int, error) {
	rrs := make([]ResourceRecord, count)
	var err error
	for i := 0; i < count; i++ {
		rrs[i], offset, err = parseRR(raw, offset)
		if err != nil {
			return nil, 0, err
		}
	}
	return rrs, offset, nil
}

func parseRR(raw []byte, offset int) (ResourceRecord, int, error) {
	name, off, err := decodeName(raw, offset)
	if err != nil {
		return ResourceRecord{}, 0, err
	}
	if off+10 > len(raw) {
		return ResourceRecord{}, 0, errors.New("dns: resource record truncated")
	}

	rr := ResourceRecord{
		Name:     name,
		Type:     binary.BigEndian.Uint16(raw[off : off+2]),
		Class:    binary.BigEndian.Uint16(raw[off+2 : off+4]),
		TTL:      binary.BigEndian.Uint32(raw[off+4 : off+8]),
		RDLength: binary.BigEndian.Uint16(raw[off+8 : off+10]),
	}
	off += 10

	if off+int(rr.RDLength) > len(raw) {
		return ResourceRecord{}, 0, errors.New("dns: rdata extends beyond message")
	}

	switch rr.Type {
	case TypeCNAME, TypeNS, TypePTR:
		decoded, _, err := decodeName(raw, off)
		if err != nil {
			return ResourceRecord{}, 0, err
		}
		rr.RData = encodeName(decoded)
	case TypeMX:
		if int(rr.RDLength) < 3 {
			return ResourceRecord{}, 0, errors.New("dns: MX rdata too short")
		}
		pref := raw[off : off+2]
		mx, _, err := decodeName(raw, off+2)
		if err != nil {
			return ResourceRecord{}, 0, err
		}
		rr.RData = append([]byte{pref[0], pref[1]}, encodeName(mx)...)
	default:
		rr.RData = make([]byte, rr.RDLength)
		copy(rr.RData, raw[off:off+int(rr.RDLength)])
	}

	return rr, off + int(rr.RDLength), nil
}

func decodeName(raw []byte, offset int) (string, int, error) {
	var parts []string
	visited := make(map[int]bool)
	cur := offset
	finalOffset := -1
	totalLen := 0

	for {
		if cur >= len(raw) {
			return "", 0, errors.New("dns: name offset out of bounds")
		}

		length := int(raw[cur])

		if length == 0 {
			cur++
			break
		}

		if length&0xc0 == 0xc0 {
			if cur+1 >= len(raw) {
				return "", 0, errors.New("dns: pointer truncated")
			}
			ptr := int(binary.BigEndian.Uint16(raw[cur:cur+2])) & 0x3fff
			if visited[ptr] {
				return "", 0, errors.New("dns: pointer loop detected")
			}
			visited[ptr] = true
			if finalOffset == -1 {
				finalOffset = cur + 2
			}
			cur = ptr
			continue
		}
		if length > 63 {
			return "", 0, errors.New("dns: label exceeds 63 bytes")
		}

		cur++
		if cur+length > len(raw) {
			return "", 0, errors.New("dns: label extends beyond message")
		}
		totalLen += 1 + length // length byte + label data
		if totalLen > 254 {    // 255 including final zero byte
			return "", 0, errors.New("dns: name exceeds 255 bytes")
		}
		parts = append(parts, string(raw[cur:cur+length]))
		cur += length
	}

	if finalOffset == -1 {
		finalOffset = cur
	}

	return strings.Join(parts, "."), finalOffset, nil
}

func encodeName(name string) []byte {
	encoded, err := encodeNameChecked(name)
	if err != nil {
		return []byte{0}
	}
	return encoded
}

func encodeNameChecked(name string) ([]byte, error) {
	if name == "" || name == "." {
		return []byte{0}, nil
	}
	name = strings.TrimSuffix(name, ".")
	var buf []byte
	for _, label := range strings.Split(name, ".") {
		if len(label) > 63 {
			return nil, errors.New("dns: label exceeds 63 bytes")
		}
		buf = append(buf, byte(len(label)))
		buf = append(buf, []byte(label)...)
	}
	buf = append(buf, 0)
	if len(buf) > 255 {
		return nil, errors.New("dns: encoded name exceeds 255 bytes")
	}
	return buf, nil
}

func (m *Message) Marshal() ([]byte, error) {
	ct := newCompressionTable()
	buf := make([]byte, headerLen)

	binary.BigEndian.PutUint16(buf[0:2], m.Header.ID)
	binary.BigEndian.PutUint16(buf[2:4], m.Header.Flags)
	binary.BigEndian.PutUint16(buf[4:6], uint16(len(m.Questions)))
	binary.BigEndian.PutUint16(buf[6:8], uint16(len(m.Answers)))
	binary.BigEndian.PutUint16(buf[8:10], uint16(len(m.Authority)))
	binary.BigEndian.PutUint16(buf[10:12], uint16(len(m.Additional)))

	var err error
	for _, q := range m.Questions {
		buf, err = marshalQuestion(buf, q, ct)
		if err != nil {
			return nil, err
		}
	}
	for _, rr := range m.Answers {
		buf, err = marshalRR(buf, rr, ct)
		if err != nil {
			return nil, err
		}
	}
	for _, rr := range m.Authority {
		buf, err = marshalRR(buf, rr, ct)
		if err != nil {
			return nil, err
		}
	}
	for _, rr := range m.Additional {
		buf, err = marshalRR(buf, rr, ct)
		if err != nil {
			return nil, err
		}
	}

	return buf, nil
}

type compressionTable struct {
	offsets map[string]int
}

func newCompressionTable() *compressionTable {
	return &compressionTable{offsets: make(map[string]int)}
}

func (ct *compressionTable) compressName(name string, buf []byte) ([]byte, error) {
	if name == "" || name == "." {
		return append(buf, 0), nil
	}
	name = strings.TrimSuffix(name, ".")
	labels := strings.Split(name, ".")

	for i := range labels {
		if len(labels[i]) > 63 {
			return nil, errors.New("dns: label exceeds 63 bytes")
		}
		suffix := strings.Join(labels[i:], ".")
		if ptr, ok := ct.offsets[suffix]; ok && ptr <= 0x3fff {
			p := uint16(0xc000) | uint16(ptr)
			buf = append(buf, byte(p>>8), byte(p))
			return buf, nil
		}
		pos := len(buf)
		if pos <= 0x3fff {
			ct.offsets[suffix] = pos
		}
		buf = append(buf, byte(len(labels[i])))
		buf = append(buf, []byte(labels[i])...)
	}
	buf = append(buf, 0)
	return buf, nil
}

func marshalQuestion(buf []byte, q Question, ct *compressionTable) ([]byte, error) {
	var err error
	buf, err = ct.compressName(q.Name, buf)
	if err != nil {
		return nil, err
	}
	tail := [4]byte{}
	binary.BigEndian.PutUint16(tail[0:2], q.Type)
	binary.BigEndian.PutUint16(tail[2:4], q.Class)
	return append(buf, tail[:]...), nil
}

func marshalRR(buf []byte, rr ResourceRecord, ct *compressionTable) ([]byte, error) {
	var err error
	buf, err = ct.compressName(rr.Name, buf)
	if err != nil {
		return nil, err
	}

	fixed := [10]byte{}
	binary.BigEndian.PutUint16(fixed[0:2], rr.Type)
	binary.BigEndian.PutUint16(fixed[2:4], rr.Class)
	binary.BigEndian.PutUint32(fixed[4:8], rr.TTL)

	var rdata []byte
	switch rr.Type {
	case TypeCNAME, TypeNS, TypePTR:
		rdata, err = ct.compressName(rdataToName(rr.RData), nil)
		if err != nil {
			return nil, err
		}
	case TypeMX:
		if len(rr.RData) < 3 {
			return nil, errors.New("dns: invalid MX rdata")
		}
		exchange, err := ct.compressName(rdataToName(rr.RData[2:]), nil)
		if err != nil {
			return nil, err
		}
		rdata = append([]byte{rr.RData[0], rr.RData[1]}, exchange...)
	default:
		rdata = rr.RData
	}

	binary.BigEndian.PutUint16(fixed[8:10], uint16(len(rdata)))
	buf = append(buf, fixed[:]...)
	buf = append(buf, rdata...)
	return buf, nil
}

func rdataToName(rdata []byte) string {
	var parts []string
	off := 0
	for off < len(rdata) {
		length := int(rdata[off])
		if length == 0 {
			break
		}
		off++
		if off+length > len(rdata) {
			break
		}
		parts = append(parts, string(rdata[off:off+length]))
		off += length
	}
	return strings.Join(parts, ".")
}

func NewQuery(id uint16, name string, qtype, qclass uint16) *Message {
	return &Message{
		Header: Header{
			ID:      id,
			Flags:   BuildFlags(false, OpcodeQuery, RCodeNoError, false, false, true, false),
			QDCount: 1,
		},
		Questions: []Question{{Name: name, Type: qtype, Class: qclass}},
	}
}

func NewResponse(query *Message, rcode uint16, answers []ResourceRecord) *Message {
	return &Message{
		Header: Header{
			ID:      query.Header.ID,
			Flags:   BuildFlags(true, OpcodeQuery, rcode, false, false, FlagsRD(query.Header.Flags), true),
			QDCount: query.Header.QDCount,
			ANCount: uint16(len(answers)),
		},
		Questions: query.Questions,
		Answers:   answers,
	}
}
