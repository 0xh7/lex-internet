package tcp

import (
	"encoding/binary"
	"errors"
)

const (
	FIN uint8 = 0x01
	SYN uint8 = 0x02
	RST uint8 = 0x04
	PSH uint8 = 0x08
	ACK uint8 = 0x10
	URG uint8 = 0x20

	minHeaderLen = 20
)

type Segment struct {
	SrcPort    uint16
	DstPort    uint16
	Seq        uint32
	Ack        uint32
	DataOffset uint8
	Flags      uint8
	Window     uint16
	Checksum   uint16
	Urgent     uint16
	Options    []byte
	Payload    []byte
}

func Parse(raw []byte) (*Segment, error) {
	if len(raw) < minHeaderLen {
		return nil, errors.New("tcp: segment too short")
	}

	s := &Segment{
		SrcPort: binary.BigEndian.Uint16(raw[0:2]),
		DstPort: binary.BigEndian.Uint16(raw[2:4]),
		Seq:     binary.BigEndian.Uint32(raw[4:8]),
		Ack:     binary.BigEndian.Uint32(raw[8:12]),
	}

	s.DataOffset = raw[12] >> 4
	s.Flags = raw[13] & 0x3f
	s.Window = binary.BigEndian.Uint16(raw[14:16])
	s.Checksum = binary.BigEndian.Uint16(raw[16:18])
	s.Urgent = binary.BigEndian.Uint16(raw[18:20])

	headerLen := int(s.DataOffset) * 4
	if headerLen < minHeaderLen {
		return nil, errors.New("tcp: invalid data offset")
	}
	if headerLen > len(raw) {
		return nil, errors.New("tcp: segment shorter than data offset indicates")
	}

	if headerLen > minHeaderLen {
		s.Options = make([]byte, headerLen-minHeaderLen)
		copy(s.Options, raw[minHeaderLen:headerLen])
	}

	if len(raw) > headerLen {
		s.Payload = make([]byte, len(raw)-headerLen)
		copy(s.Payload, raw[headerLen:])
	}

	return s, nil
}

func (s *Segment) Marshal() []byte {
	optLen := len(s.Options)
	padding := (4 - optLen%4) % 4
	headerLen := minHeaderLen + optLen + padding
	dataOffset := uint8(headerLen / 4)

	buf := make([]byte, headerLen+len(s.Payload))

	binary.BigEndian.PutUint16(buf[0:2], s.SrcPort)
	binary.BigEndian.PutUint16(buf[2:4], s.DstPort)
	binary.BigEndian.PutUint32(buf[4:8], s.Seq)
	binary.BigEndian.PutUint32(buf[8:12], s.Ack)
	buf[12] = dataOffset << 4
	buf[13] = s.Flags & 0x3f
	binary.BigEndian.PutUint16(buf[14:16], s.Window)
	binary.BigEndian.PutUint16(buf[16:18], s.Checksum)
	binary.BigEndian.PutUint16(buf[18:20], s.Urgent)

	if optLen > 0 {
		copy(buf[minHeaderLen:], s.Options)
	}
	copy(buf[headerLen:], s.Payload)

	return buf
}

func (s *Segment) HasFlag(flag uint8) bool {
	return s.Flags&flag != 0
}

func (s *Segment) SetFlag(flag uint8) {
	s.Flags |= flag
}
