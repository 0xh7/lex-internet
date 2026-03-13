package arp

import (
	"encoding/binary"
	"errors"
	"net"
)

const (
	OperationRequest uint16 = 1
	OperationReply   uint16 = 2

	HardwareTypeEthernet uint16 = 1

	packetLen = 28
)

type Packet struct {
	HardwareType uint16
	ProtocolType uint16
	HardwareLen  uint8
	ProtocolLen  uint8
	Operation    uint16
	SenderMAC    [6]byte
	SenderIP     net.IP
	TargetMAC    [6]byte
	TargetIP     net.IP
}

func Parse(raw []byte) (*Packet, error) {
	if len(raw) < packetLen {
		return nil, errors.New("arp: packet too short")
	}

	p := &Packet{
		HardwareType: binary.BigEndian.Uint16(raw[0:2]),
		ProtocolType: binary.BigEndian.Uint16(raw[2:4]),
		HardwareLen:  raw[4],
		ProtocolLen:  raw[5],
		Operation:    binary.BigEndian.Uint16(raw[6:8]),
	}

	if p.HardwareLen != 6 || p.ProtocolLen != 4 {
		return nil, errors.New("arp: unsupported address lengths")
	}

	copy(p.SenderMAC[:], raw[8:14])
	p.SenderIP = make(net.IP, 4)
	copy(p.SenderIP, raw[14:18])
	copy(p.TargetMAC[:], raw[18:24])
	p.TargetIP = make(net.IP, 4)
	copy(p.TargetIP, raw[24:28])

	return p, nil
}

func (p *Packet) Marshal() ([]byte, error) {
	senderIP := p.SenderIP.To4()
	if senderIP == nil {
		return nil, errors.New("arp: SenderIP is not a valid IPv4 address")
	}
	targetIP := p.TargetIP.To4()
	if targetIP == nil {
		return nil, errors.New("arp: TargetIP is not a valid IPv4 address")
	}

	buf := make([]byte, packetLen)

	binary.BigEndian.PutUint16(buf[0:2], p.HardwareType)
	binary.BigEndian.PutUint16(buf[2:4], p.ProtocolType)
	buf[4] = p.HardwareLen
	buf[5] = p.ProtocolLen
	binary.BigEndian.PutUint16(buf[6:8], p.Operation)

	copy(buf[8:14], p.SenderMAC[:])
	copy(buf[14:18], senderIP)
	copy(buf[18:24], p.TargetMAC[:])
	copy(buf[24:28], targetIP)

	return buf, nil
}

func NewRequest(senderMAC [6]byte, senderIP, targetIP net.IP) (*Packet, error) {
	sip := senderIP.To4()
	if sip == nil {
		return nil, errors.New("arp: senderIP is not a valid IPv4 address")
	}
	tip := targetIP.To4()
	if tip == nil {
		return nil, errors.New("arp: targetIP is not a valid IPv4 address")
	}
	return &Packet{
		HardwareType: HardwareTypeEthernet,
		ProtocolType: 0x0800,
		HardwareLen:  6,
		ProtocolLen:  4,
		Operation:    OperationRequest,
		SenderMAC:    senderMAC,
		SenderIP:     sip,
		TargetMAC:    [6]byte{},
		TargetIP:     tip,
	}, nil
}

func NewReply(senderMAC, targetMAC [6]byte, senderIP, targetIP net.IP) (*Packet, error) {
	sip := senderIP.To4()
	if sip == nil {
		return nil, errors.New("arp: senderIP is not a valid IPv4 address")
	}
	tip := targetIP.To4()
	if tip == nil {
		return nil, errors.New("arp: targetIP is not a valid IPv4 address")
	}
	return &Packet{
		HardwareType: HardwareTypeEthernet,
		ProtocolType: 0x0800,
		HardwareLen:  6,
		ProtocolLen:  4,
		Operation:    OperationReply,
		SenderMAC:    senderMAC,
		SenderIP:     sip,
		TargetMAC:    targetMAC,
		TargetIP:     tip,
	}, nil
}
