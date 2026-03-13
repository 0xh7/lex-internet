//go:build windows

package main

import "syscall"

func setTTL(fd uintptr, ttl int) {
	syscall.SetsockoptInt(syscall.Handle(fd), syscall.IPPROTO_IP, syscall.IP_TTL, ttl)
}
