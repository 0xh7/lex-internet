package tls

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"sync"
	"time"
)

type Conn struct {
	raw       net.Conn
	tlsConn   *tls.Conn
	mu        sync.Mutex
	handshook bool
	isClient  bool
}

func NewServerConn(raw net.Conn, cert tls.Certificate) (*Conn, error) {
	cfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}

	tlsConn := tls.Server(raw, cfg)
	if err := tlsConn.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}

	return &Conn{
		raw:       raw,
		tlsConn:   tlsConn,
		handshook: true,
		isClient:  false,
	}, nil
}

func NewClientConn(raw net.Conn, serverName string) (*Conn, error) {
	if serverName == "" {
		raw.Close()
		return nil, fmt.Errorf("tls: serverName is required for client connections")
	}

	cfg := &tls.Config{
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
	}

	tlsConn := tls.Client(raw, cfg)
	if err := tlsConn.Handshake(); err != nil {
		raw.Close()
		return nil, err
	}

	return &Conn{
		raw:       raw,
		tlsConn:   tlsConn,
		handshook: true,
		isClient:  true,
	}, nil
}

func (c *Conn) Read(b []byte) (int, error) {
	return c.tlsConn.Read(b)
}

func (c *Conn) Write(b []byte) (int, error) {
	return c.tlsConn.Write(b)
}

func (c *Conn) Close() error {
	return c.tlsConn.Close()
}

func (c *Conn) LocalAddr() net.Addr {
	return c.tlsConn.LocalAddr()
}

func (c *Conn) RemoteAddr() net.Addr {
	return c.tlsConn.RemoteAddr()
}

func (c *Conn) SetDeadline(t time.Time) error {
	return c.tlsConn.SetDeadline(t)
}

func (c *Conn) SetReadDeadline(t time.Time) error {
	return c.tlsConn.SetReadDeadline(t)
}

func (c *Conn) SetWriteDeadline(t time.Time) error {
	return c.tlsConn.SetWriteDeadline(t)
}

func (c *Conn) ConnectionState() tls.ConnectionState {
	return c.tlsConn.ConnectionState()
}

func (c *Conn) Handshook() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.handshook
}

func GenerateSelfSigned(hosts []string) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, err
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{Organization: []string{"Internet Stack"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}

	certDER, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return tls.X509KeyPair(certPEM, keyPEM)
}
