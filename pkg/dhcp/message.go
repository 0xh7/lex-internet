package dhcp

import (
	"encoding/binary"
	"errors"
	"net"
)

const (
	minMsgLen   = 240
	headerLen   = 236
	magicCookie = 0x63825363
)

const (
	OpRequest uint8 = 1
	OpReply   uint8 = 2
)

const (
	MsgDiscover uint8 = 1
	MsgOffer    uint8 = 2
	MsgRequest  uint8 = 3
	MsgDecline  uint8 = 4
	MsgAck      uint8 = 5
	MsgNak      uint8 = 6
	MsgRelease  uint8 = 7
)

const (
	OptSubnetMask  uint8 = 1
	OptRouter      uint8 = 3
	OptDNS         uint8 = 6
	OptRequestedIP uint8 = 50
	OptLeaseTime   uint8 = 51
	OptMessageType uint8 = 53
	OptServerID    uint8 = 54
	OptEnd         uint8 = 255
	OptPad         uint8 = 0
)

type Option struct {
	Code   uint8
	Length uint8
	Data   []byte
}

type Message struct {
	Op      uint8
	HType   uint8
	HLen    uint8
	Hops    uint8
	XID     uint32
	Secs    uint16
	Flags   uint16
	CIAddr  net.IP
	YIAddr  net.IP
	SIAddr  net.IP
	GIAddr  net.IP
	CHAddr  [16]byte
	SName   [64]byte
	File    [128]byte
	Options []Option
}

func ParseMessage(raw []byte) (*Message, error) {
	if len(raw) < minMsgLen {
		return nil, errors.New("dhcp: message too short")
	}

	cookie := binary.BigEndian.Uint32(raw[headerLen : headerLen+4])
	if cookie != magicCookie {
		return nil, errors.New("dhcp: invalid magic cookie")
	}

	if raw[2] == 0 || raw[2] > 16 {
		return nil, errors.New("dhcp: HLen is invalid (must be 1-16)")
	}

	m := &Message{
		Op:    raw[0],
		HType: raw[1],
		HLen:  raw[2],
		Hops:  raw[3],
		XID:   binary.BigEndian.Uint32(raw[4:8]),
		Secs:  binary.BigEndian.Uint16(raw[8:10]),
		Flags: binary.BigEndian.Uint16(raw[10:12]),
	}

	m.CIAddr = make(net.IP, 4)
	copy(m.CIAddr, raw[12:16])
	m.YIAddr = make(net.IP, 4)
	copy(m.YIAddr, raw[16:20])
	m.SIAddr = make(net.IP, 4)
	copy(m.SIAddr, raw[20:24])
	m.GIAddr = make(net.IP, 4)
	copy(m.GIAddr, raw[24:28])

	copy(m.CHAddr[:], raw[28:44])
	copy(m.SName[:], raw[44:108])
	copy(m.File[:], raw[108:236])

	opts := raw[minMsgLen:]
	for len(opts) > 0 {
		code := opts[0]
		if code == OptEnd {
			break
		}
		if code == OptPad {
			opts = opts[1:]
			continue
		}
		if len(opts) < 2 {
			return nil, errors.New("dhcp: truncated option")
		}
		length := opts[1]
		if len(opts) < int(2+length) {
			return nil, errors.New("dhcp: option data truncated")
		}
		data := make([]byte, length)
		copy(data, opts[2:2+length])
		m.Options = append(m.Options, Option{
			Code:   code,
			Length: length,
			Data:   data,
		})
		opts = opts[2+length:]
	}

	return m, nil
}

func (m *Message) Marshal() []byte {
	optLen := 0
	for _, o := range m.Options {
		optLen += 2 + len(o.Data)
	}
	optLen++

	buf := make([]byte, minMsgLen+optLen)

	buf[0] = m.Op
	buf[1] = m.HType
	buf[2] = m.HLen
	buf[3] = m.Hops
	binary.BigEndian.PutUint32(buf[4:8], m.XID)
	binary.BigEndian.PutUint16(buf[8:10], m.Secs)
	binary.BigEndian.PutUint16(buf[10:12], m.Flags)

	copyIPv4(buf[12:16], m.CIAddr)
	copyIPv4(buf[16:20], m.YIAddr)
	copyIPv4(buf[20:24], m.SIAddr)
	copyIPv4(buf[24:28], m.GIAddr)

	copy(buf[28:44], m.CHAddr[:])
	copy(buf[44:108], m.SName[:])
	copy(buf[108:236], m.File[:])

	binary.BigEndian.PutUint32(buf[headerLen:headerLen+4], magicCookie)

	offset := minMsgLen
	for _, o := range m.Options {
		buf[offset] = o.Code
		buf[offset+1] = uint8(len(o.Data))
		copy(buf[offset+2:], o.Data)
		offset += 2 + len(o.Data)
	}
	buf[offset] = OptEnd

	return buf
}

func copyIPv4(dst []byte, ip net.IP) {
	if ip4 := ip.To4(); ip4 != nil {
		copy(dst, ip4)
	}
}

func (m *Message) GetOption(code uint8) *Option {
	for i := range m.Options {
		if m.Options[i].Code == code {
			return &m.Options[i]
		}
	}
	return nil
}

func (m *Message) SetOption(code uint8, data []byte) {
	if len(data) > 255 {
		return
	}
	for i := range m.Options {
		if m.Options[i].Code == code {
			m.Options[i].Length = uint8(len(data))
			m.Options[i].Data = data
			return
		}
	}
	m.Options = append(m.Options, Option{
		Code:   code,
		Length: uint8(len(data)),
		Data:   data,
	})
}

func (m *Message) MessageType() uint8 {
	opt := m.GetOption(OptMessageType)
	if opt == nil || len(opt.Data) < 1 {
		return 0
	}
	return opt.Data[0]
}
