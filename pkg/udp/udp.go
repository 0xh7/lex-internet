package udp

import (
	"encoding/binary"
	"errors"
)

const headerLen = 8

type Datagram struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
	Payload  []byte
}

func Parse(raw []byte) (*Datagram, error) {
	if len(raw) < headerLen {
		return nil, errors.New("udp: datagram too short")
	}

	d := &Datagram{
		SrcPort:  binary.BigEndian.Uint16(raw[0:2]),
		DstPort:  binary.BigEndian.Uint16(raw[2:4]),
		Length:   binary.BigEndian.Uint16(raw[4:6]),
		Checksum: binary.BigEndian.Uint16(raw[6:8]),
	}

	if int(d.Length) < headerLen {
		return nil, errors.New("udp: invalid length field")
	}

	payloadLen := int(d.Length) - headerLen
	if len(raw)-headerLen < payloadLen {
		return nil, errors.New("udp: payload shorter than length field indicates")
	}

	if payloadLen > 0 {
		d.Payload = make([]byte, payloadLen)
		copy(d.Payload, raw[headerLen:headerLen+payloadLen])
	}

	return d, nil
}

func (d *Datagram) Marshal() ([]byte, error) {
	totalLen := headerLen + len(d.Payload)
	if totalLen > 0xFFFF {
		return nil, errors.New("udp: datagram exceeds maximum size (65535 bytes)")
	}
	buf := make([]byte, totalLen)

	binary.BigEndian.PutUint16(buf[0:2], d.SrcPort)
	binary.BigEndian.PutUint16(buf[2:4], d.DstPort)
	binary.BigEndian.PutUint16(buf[4:6], uint16(totalLen))
	binary.BigEndian.PutUint16(buf[6:8], d.Checksum)
	copy(buf[headerLen:], d.Payload)

	return buf, nil
}

func New(srcPort, dstPort uint16, payload []byte) (*Datagram, error) {
	totalLen := headerLen + len(payload)
	if totalLen > 0xFFFF {
		return nil, errors.New("udp: payload too large for UDP datagram")
	}
	return &Datagram{
		SrcPort: srcPort,
		DstPort: dstPort,
		Length:  uint16(totalLen),
		Payload: payload,
	}, nil
}
