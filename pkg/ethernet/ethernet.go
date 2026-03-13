package ethernet

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

const (
	EtherTypeIPv4 uint16 = 0x0800
	EtherTypeARP  uint16 = 0x0806
	EtherTypeVLAN uint16 = 0x8100
	EtherTypeIPv6 uint16 = 0x86DD

	headerLen = 14
	minFrame  = 14
)

type Frame struct {
	Dst       [6]byte
	Src       [6]byte
	EtherType uint16
	Payload   []byte
}

func Parse(raw []byte) (*Frame, error) {
	if len(raw) < minFrame {
		return nil, errors.New("ethernet: frame too short")
	}

	f := &Frame{
		EtherType: binary.BigEndian.Uint16(raw[12:14]),
	}
	copy(f.Dst[:], raw[0:6])
	copy(f.Src[:], raw[6:12])

	if len(raw) > headerLen {
		f.Payload = make([]byte, len(raw)-headerLen)
		copy(f.Payload, raw[headerLen:])
	}

	return f, nil
}

func (f *Frame) Marshal() []byte {
	buf := make([]byte, headerLen+len(f.Payload))
	copy(buf[0:6], f.Dst[:])
	copy(buf[6:12], f.Src[:])
	binary.BigEndian.PutUint16(buf[12:14], f.EtherType)
	copy(buf[headerLen:], f.Payload)
	return buf
}

func FormatMAC(mac [6]byte) string {
	return fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5])
}

func ParseMAC(s string) ([6]byte, error) {
	hw, err := net.ParseMAC(s)
	if err != nil {
		return [6]byte{}, fmt.Errorf("ethernet: %w", err)
	}
	if len(hw) != 6 {
		return [6]byte{}, errors.New("ethernet: not a 48-bit MAC address")
	}
	var mac [6]byte
	copy(mac[:], hw)
	return mac, nil
}
