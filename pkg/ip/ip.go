package ip

import (
	"encoding/binary"
	"errors"
	"net"
)

const (
	ProtocolICMP uint8 = 1
	ProtocolTCP  uint8 = 6
	ProtocolUDP  uint8 = 17

	minHeaderLen = 20
)

type Packet struct {
	Version    uint8
	IHL        uint8
	TOS        uint8
	TotalLen   uint16
	ID         uint16
	Flags      uint8
	FragOffset uint16
	TTL        uint8
	Protocol   uint8
	Checksum   uint16
	SrcIP      net.IP
	DstIP      net.IP
	Options    []byte
	Payload    []byte
}

func Parse(raw []byte) (*Packet, error) {
	if len(raw) < minHeaderLen {
		return nil, errors.New("ip: packet too short")
	}

	p := &Packet{
		Version: raw[0] >> 4,
		IHL:     raw[0] & 0x0f,
	}

	if p.Version != 4 {
		return nil, errors.New("ip: not an IPv4 packet")
	}

	headerLen := int(p.IHL) * 4
	if headerLen < minHeaderLen {
		return nil, errors.New("ip: invalid header length")
	}
	if len(raw) < headerLen {
		return nil, errors.New("ip: packet shorter than header length")
	}

	p.TOS = raw[1]
	p.TotalLen = binary.BigEndian.Uint16(raw[2:4])
	p.ID = binary.BigEndian.Uint16(raw[4:6])

	flagsFrag := binary.BigEndian.Uint16(raw[6:8])
	p.Flags = uint8(flagsFrag >> 13)
	p.FragOffset = flagsFrag & 0x1fff

	p.TTL = raw[8]
	p.Protocol = raw[9]
	p.Checksum = binary.BigEndian.Uint16(raw[10:12])

	p.SrcIP = make(net.IP, 4)
	copy(p.SrcIP, raw[12:16])
	p.DstIP = make(net.IP, 4)
	copy(p.DstIP, raw[16:20])

	if headerLen > minHeaderLen {
		p.Options = make([]byte, headerLen-minHeaderLen)
		copy(p.Options, raw[minHeaderLen:headerLen])
	}

	if int(p.TotalLen) > headerLen && int(p.TotalLen) <= len(raw) {
		p.Payload = make([]byte, int(p.TotalLen)-headerLen)
		copy(p.Payload, raw[headerLen:p.TotalLen])
	} else if len(raw) > headerLen {
		p.Payload = make([]byte, len(raw)-headerLen)
		copy(p.Payload, raw[headerLen:])
	}

	return p, nil
}

func (p *Packet) Marshal() ([]byte, error) {
	ihl := uint8(minHeaderLen+len(p.Options)) / 4
	if len(p.Options)%4 != 0 {
		return nil, errors.New("ip: options length must be a multiple of 4")
	}

	headerLen := int(ihl) * 4
	totalLen := headerLen + len(p.Payload)
	buf := make([]byte, totalLen)

	buf[0] = (4 << 4) | ihl
	buf[1] = p.TOS
	binary.BigEndian.PutUint16(buf[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(buf[4:6], p.ID)

	flagsFrag := (uint16(p.Flags) << 13) | (p.FragOffset & 0x1fff)
	binary.BigEndian.PutUint16(buf[6:8], flagsFrag)

	buf[8] = p.TTL
	buf[9] = p.Protocol
	copy(buf[12:16], p.SrcIP.To4())
	copy(buf[16:20], p.DstIP.To4())

	if len(p.Options) > 0 {
		copy(buf[minHeaderLen:], p.Options)
	}
	copy(buf[headerLen:], p.Payload)

	binary.BigEndian.PutUint16(buf[10:12], Checksum(buf[:headerLen]))

	return buf, nil
}

func Checksum(data []byte) uint16 {
	var sum uint32
	n := len(data)

	for i := 0; i+1 < n; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if n%2 != 0 {
		sum += uint32(data[n-1]) << 8
	}

	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}

	return ^uint16(sum)
}

func PseudoHeaderChecksum(src, dst net.IP, proto uint8, length uint16) uint16 {
	pseudo := make([]byte, 12)
	copy(pseudo[0:4], src.To4())
	copy(pseudo[4:8], dst.To4())
	pseudo[8] = 0
	pseudo[9] = proto
	binary.BigEndian.PutUint16(pseudo[10:12], length)
	return Checksum(pseudo)
}
