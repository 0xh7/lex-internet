package tls

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
)

const (
	ContentChangeCipherSpec uint8 = 20
	ContentAlert            uint8 = 21
	ContentHandshake        uint8 = 22
	ContentApplicationData  uint8 = 23
)

const (
	HandshakeClientHello       uint8 = 1
	HandshakeServerHello       uint8 = 2
	HandshakeCertificate       uint8 = 11
	HandshakeServerHelloDone   uint8 = 14
	HandshakeClientKeyExchange uint8 = 16
	HandshakeFinished          uint8 = 20
)

const (
	VersionTLS10 uint16 = 0x0301
	VersionTLS11 uint16 = 0x0302
	VersionTLS12 uint16 = 0x0303
)

const (
	TLS_RSA_WITH_AES_128_CBC_SHA          uint16 = 0x002f
	TLS_RSA_WITH_AES_256_CBC_SHA          uint16 = 0x0035
	TLS_RSA_WITH_AES_128_CBC_SHA256       uint16 = 0x003c
	TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 uint16 = 0xc02f
	TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 uint16 = 0xc030
)

const maxRecordLen = 1 << 14

type Record struct {
	ContentType uint8
	Version     uint16
	Length      uint16
	Fragment    []byte
}

type ClientHello struct {
	Version            uint16
	Random             [32]byte
	SessionID          []byte
	CipherSuites       []uint16
	CompressionMethods []uint8
}

type ServerHello struct {
	Version           uint16
	Random            [32]byte
	SessionID         []byte
	CipherSuite       uint16
	CompressionMethod uint8
}

func ParseRecord(reader io.Reader) (*Record, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(reader, hdr); err != nil {
		return nil, err
	}

	r := &Record{
		ContentType: hdr[0],
		Version:     binary.BigEndian.Uint16(hdr[1:3]),
		Length:      binary.BigEndian.Uint16(hdr[3:5]),
	}

	if r.ContentType < ContentChangeCipherSpec || r.ContentType > ContentApplicationData {
		return nil, errors.New("tls: unknown content type")
	}
	if r.Length > maxRecordLen {
		return nil, errors.New("tls: record too large")
	}

	r.Fragment = make([]byte, r.Length)
	if _, err := io.ReadFull(reader, r.Fragment); err != nil {
		return nil, err
	}

	return r, nil
}

func (r *Record) Marshal() []byte {
	buf := make([]byte, 5+len(r.Fragment))
	buf[0] = r.ContentType
	binary.BigEndian.PutUint16(buf[1:3], r.Version)
	binary.BigEndian.PutUint16(buf[3:5], uint16(len(r.Fragment)))
	copy(buf[5:], r.Fragment)
	return buf
}

func ParseClientHello(data []byte) (*ClientHello, error) {
	if len(data) < 4 {
		return nil, errors.New("tls: handshake message too short")
	}
	if data[0] != HandshakeClientHello {
		return nil, errors.New("tls: not a ClientHello")
	}

	msgLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	body := data[4:]
	if len(body) < msgLen {
		return nil, errors.New("tls: ClientHello body truncated")
	}
	body = body[:msgLen]

	if len(body) < 34 {
		return nil, errors.New("tls: ClientHello too short for version+random")
	}

	ch := &ClientHello{
		Version: binary.BigEndian.Uint16(body[0:2]),
	}
	copy(ch.Random[:], body[2:34])
	off := 34

	if off >= len(body) {
		return nil, errors.New("tls: ClientHello missing session ID length")
	}
	sidLen := int(body[off])
	off++
	if off+sidLen > len(body) {
		return nil, errors.New("tls: ClientHello session ID truncated")
	}
	ch.SessionID = make([]byte, sidLen)
	copy(ch.SessionID, body[off:off+sidLen])
	off += sidLen

	if off+2 > len(body) {
		return nil, errors.New("tls: ClientHello missing cipher suites length")
	}
	csLen := int(binary.BigEndian.Uint16(body[off : off+2]))
	off += 2
	if csLen%2 != 0 || off+csLen > len(body) {
		return nil, errors.New("tls: ClientHello cipher suites malformed")
	}
	ch.CipherSuites = make([]uint16, csLen/2)
	for i := range ch.CipherSuites {
		ch.CipherSuites[i] = binary.BigEndian.Uint16(body[off : off+2])
		off += 2
	}

	if off >= len(body) {
		return nil, errors.New("tls: ClientHello missing compression methods")
	}
	cmLen := int(body[off])
	off++
	if off+cmLen > len(body) {
		return nil, errors.New("tls: ClientHello compression methods truncated")
	}
	ch.CompressionMethods = make([]uint8, cmLen)
	copy(ch.CompressionMethods, body[off:off+cmLen])

	return ch, nil
}

func (ch *ClientHello) Marshal() []byte {
	sidLen := len(ch.SessionID)
	csLen := len(ch.CipherSuites) * 2
	cmLen := len(ch.CompressionMethods)
	bodyLen := 2 + 32 + 1 + sidLen + 2 + csLen + 1 + cmLen

	buf := make([]byte, 4+bodyLen)
	buf[0] = HandshakeClientHello
	buf[1] = byte(bodyLen >> 16)
	buf[2] = byte(bodyLen >> 8)
	buf[3] = byte(bodyLen)

	binary.BigEndian.PutUint16(buf[4:6], ch.Version)
	copy(buf[6:38], ch.Random[:])
	off := 38

	buf[off] = byte(sidLen)
	off++
	copy(buf[off:], ch.SessionID)
	off += sidLen

	binary.BigEndian.PutUint16(buf[off:off+2], uint16(csLen))
	off += 2
	for _, cs := range ch.CipherSuites {
		binary.BigEndian.PutUint16(buf[off:off+2], cs)
		off += 2
	}

	buf[off] = byte(cmLen)
	off++
	copy(buf[off:], ch.CompressionMethods)

	return buf
}

func BuildServerHello(sessionID []byte, cipherSuite uint16) *ServerHello {
	sh := &ServerHello{
		Version:           VersionTLS12,
		CipherSuite:       cipherSuite,
		CompressionMethod: 0,
	}
	rand.Read(sh.Random[:])
	if sessionID != nil {
		sh.SessionID = make([]byte, len(sessionID))
		copy(sh.SessionID, sessionID)
	} else {
		sh.SessionID = make([]byte, 32)
		rand.Read(sh.SessionID)
	}
	return sh
}

func (sh *ServerHello) Marshal() []byte {
	sidLen := len(sh.SessionID)
	bodyLen := 2 + 32 + 1 + sidLen + 2 + 1

	buf := make([]byte, 4+bodyLen)
	buf[0] = HandshakeServerHello
	buf[1] = byte(bodyLen >> 16)
	buf[2] = byte(bodyLen >> 8)
	buf[3] = byte(bodyLen)

	binary.BigEndian.PutUint16(buf[4:6], sh.Version)
	copy(buf[6:38], sh.Random[:])
	off := 38

	buf[off] = byte(sidLen)
	off++
	copy(buf[off:], sh.SessionID)
	off += sidLen

	binary.BigEndian.PutUint16(buf[off:off+2], sh.CipherSuite)
	off += 2
	buf[off] = sh.CompressionMethod

	return buf
}

func ParseServerHello(data []byte) (*ServerHello, error) {
	if len(data) < 4 {
		return nil, errors.New("tls: handshake message too short")
	}
	if data[0] != HandshakeServerHello {
		return nil, errors.New("tls: not a ServerHello")
	}

	msgLen := int(data[1])<<16 | int(data[2])<<8 | int(data[3])
	body := data[4:]
	if len(body) < msgLen {
		return nil, errors.New("tls: ServerHello body truncated")
	}
	body = body[:msgLen]

	if len(body) < 35 {
		return nil, errors.New("tls: ServerHello too short")
	}

	sh := &ServerHello{
		Version: binary.BigEndian.Uint16(body[0:2]),
	}
	copy(sh.Random[:], body[2:34])

	sidLen := int(body[34])
	off := 35
	if off+sidLen+3 > len(body) {
		return nil, errors.New("tls: ServerHello truncated")
	}
	sh.SessionID = make([]byte, sidLen)
	copy(sh.SessionID, body[off:off+sidLen])
	off += sidLen

	sh.CipherSuite = binary.BigEndian.Uint16(body[off : off+2])
	off += 2
	sh.CompressionMethod = body[off]

	return sh, nil
}
