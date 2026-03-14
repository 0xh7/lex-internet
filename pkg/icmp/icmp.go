package icmp

import (
	"encoding/binary"
	"errors"

	"github.com/0xh7/lex-internet/pkg/ip"
)

const (
	TypeEchoReply       uint8 = 0
	TypeDestUnreachable uint8 = 3
	TypeEchoRequest     uint8 = 8
	TypeTimeExceeded    uint8 = 11

	headerLen = 8
)

type Message struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	ID       uint16
	Seq      uint16
	Data     []byte
}

// ParsePacket parses ICMP data from either a raw ICMP message or an IPv4
// packet carrying ICMP payload.
func ParsePacket(raw []byte) (*Message, error) {
	payload := raw
	if len(raw) >= 20 && raw[0]>>4 == 4 && (raw[0]&0x0f) >= 5 {
		ihl := int(raw[0]&0x0f) * 4
		if ihl > len(raw) {
			return nil, errors.New("icmp: IPv4 header exceeds packet size")
		}
		if raw[9] != ip.ProtocolICMP {
			return nil, errors.New("icmp: IPv4 payload is not ICMP")
		}
		totalLen := int(binary.BigEndian.Uint16(raw[2:4]))
		if totalLen == 0 {
			totalLen = len(raw)
		}
		if totalLen < ihl {
			return nil, errors.New("icmp: invalid IPv4 total length")
		}
		if totalLen > len(raw) {
			return nil, errors.New("icmp: IPv4 total length exceeds packet size")
		}
		payload = raw[ihl:totalLen]
	}
	return Parse(payload)
}

func Parse(raw []byte) (*Message, error) {
	if len(raw) < headerLen {
		return nil, errors.New("icmp: message too short")
	}

	m := &Message{
		Type:     raw[0],
		Code:     raw[1],
		Checksum: binary.BigEndian.Uint16(raw[2:4]),
		ID:       binary.BigEndian.Uint16(raw[4:6]),
		Seq:      binary.BigEndian.Uint16(raw[6:8]),
	}

	if len(raw) > headerLen {
		m.Data = make([]byte, len(raw)-headerLen)
		copy(m.Data, raw[headerLen:])
	}

	return m, nil
}

func (m *Message) Marshal() []byte {
	buf := make([]byte, headerLen+len(m.Data))
	buf[0] = m.Type
	buf[1] = m.Code
	binary.BigEndian.PutUint16(buf[4:6], m.ID)
	binary.BigEndian.PutUint16(buf[6:8], m.Seq)
	copy(buf[headerLen:], m.Data)

	binary.BigEndian.PutUint16(buf[2:4], ip.Checksum(buf))

	return buf
}

func NewEchoRequest(id, seq uint16, data []byte) *Message {
	return &Message{
		Type: TypeEchoRequest,
		Code: 0,
		ID:   id,
		Seq:  seq,
		Data: data,
	}
}
