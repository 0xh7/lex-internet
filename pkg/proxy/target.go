package proxy

import (
	"errors"
	"net"
	"time"
)

var (
	errTargetBlocked  = errors.New("proxy: target blocked")
	errNoResolvedAddr = errors.New("proxy: no usable address")
)

func isBlockedIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		if ip4.Equal(net.IPv4bcast) || ip4[0] >= 240 {
			return true
		}
	}
	return false
}

func splitTarget(target, defaultPort string) (string, string, error) {
	host, port, err := net.SplitHostPort(target)
	if err == nil {
		return host, port, nil
	}
	if defaultPort == "" {
		return "", "", err
	}
	return target, defaultPort, nil
}

func resolveAllowedIPs(host string) ([]net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		if isBlockedIP(ip) {
			return nil, errTargetBlocked
		}
		return []net.IP{ip}, nil
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, errNoResolvedAddr
	}
	for _, ip := range ips {
		if isBlockedIP(ip) {
			return nil, errTargetBlocked
		}
	}
	return ips, nil
}

func resolveAllowedTarget(target, defaultPort string) (string, string, []net.IP, error) {
	host, port, err := splitTarget(target, defaultPort)
	if err != nil {
		return "", "", nil, err
	}
	ips, err := resolveAllowedIPs(host)
	if err != nil {
		return "", "", nil, err
	}
	return host, port, ips, nil
}

func dialAllowedTCP(target, defaultPort string, timeout time.Duration) (net.Conn, error) {
	_, port, ips, err := resolveAllowedTarget(target, defaultPort)
	if err != nil {
		return nil, err
	}

	var lastErr error
	for _, ip := range ips {
		conn, err := net.DialTimeout("tcp", net.JoinHostPort(ip.String(), port), timeout)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, errNoResolvedAddr
}

func matchesResolvedIP(remote net.IP, allowed []net.IP) bool {
	for _, ip := range allowed {
		if ip.Equal(remote) {
			return true
		}
	}
	return false
}
