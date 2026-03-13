package firewall

import (
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"
)

type PacketInfo struct {
	SrcIP     net.IP
	DstIP     net.IP
	SrcPort   uint16
	DstPort   uint16
	Protocol  string
	Direction Direction
}

type connKey struct {
	srcIP   [16]byte
	dstIP   [16]byte
	srcPort uint16
	dstPort uint16
	proto   string
}

type connEntry struct {
	state    connState
	lastSeen time.Time
}

type connState uint8

const (
	stateNew connState = iota
	stateEstablished
	stateClosing
)

const (
	connTimeout     = 5 * time.Minute
	cleanupInterval = 30 * time.Second
)

type FirewallStats struct {
	Allowed     uint64
	Denied      uint64
	Dropped     uint64
	ActiveConns int
}

type Engine struct {
	rules  *RuleSet
	logger *log.Logger

	allowed atomic.Uint64
	denied  atomic.Uint64
	dropped atomic.Uint64

	connMu    sync.RWMutex
	connTable map[connKey]*connEntry
	stateful  atomic.Bool

	done      chan struct{}
	closeOnce sync.Once
}

func NewEngine(rules *RuleSet) *Engine {
	e := &Engine{
		rules:     rules,
		logger:    log.Default(),
		connTable: make(map[connKey]*connEntry),

		done: make(chan struct{}),
	}
	e.stateful.Store(true)
	go e.cleanupLoop()
	return e
}

func (e *Engine) SetStateful(enabled bool) {
	e.stateful.Store(enabled)
}

func (e *Engine) SetLogger(l *log.Logger) {
	e.logger = l
}

func (e *Engine) Process(info PacketInfo) bool {
	if e.stateful.Load() {
		if e.checkConnTrack(info) {
			e.allowed.Add(1)
			return true
		}
	}

	action := e.rules.Match(info)

	switch action {
	case Allow:
		e.allowed.Add(1)
		if e.stateful.Load() {
			e.trackConn(info)
		}
		return true
	case Deny:
		e.denied.Add(1)
		return false
	case Drop:
		e.dropped.Add(1)
		return false
	default:
		e.denied.Add(1)
		return false
	}
}

func (e *Engine) Stats() FirewallStats {
	e.connMu.RLock()
	active := len(e.connTable)
	e.connMu.RUnlock()

	return FirewallStats{
		Allowed:     e.allowed.Load(),
		Denied:      e.denied.Load(),
		Dropped:     e.dropped.Load(),
		ActiveConns: active,
	}
}

func (e *Engine) Close() {
	e.closeOnce.Do(func() {
		close(e.done)
	})
}

func (e *Engine) makeKey(info PacketInfo) connKey {
	var k connKey
	copy(k.srcIP[:], info.SrcIP.To16())
	copy(k.dstIP[:], info.DstIP.To16())
	k.srcPort = info.SrcPort
	k.dstPort = info.DstPort
	k.proto = info.Protocol
	return k
}

func (e *Engine) reverseKey(info PacketInfo) connKey {
	var k connKey
	copy(k.srcIP[:], info.DstIP.To16())
	copy(k.dstIP[:], info.SrcIP.To16())
	k.srcPort = info.DstPort
	k.dstPort = info.SrcPort
	k.proto = info.Protocol
	return k
}

func (e *Engine) checkConnTrack(info PacketInfo) bool {
	fwd := e.makeKey(info)
	rev := e.reverseKey(info)

	e.connMu.Lock()
	defer e.connMu.Unlock()

	entry, ok := e.connTable[fwd]
	if !ok {
		entry, ok = e.connTable[rev]
	}
	if !ok {
		return false
	}
	now := time.Now()
	entry.lastSeen = now
	if entry.state == stateNew {
		entry.state = stateEstablished
	}
	return true
}

func (e *Engine) trackConn(info PacketInfo) {
	e.connMu.Lock()
	defer e.connMu.Unlock()

	k := e.makeKey(info)
	e.connTable[k] = &connEntry{
		state:    stateNew,
		lastSeen: time.Now(),
	}
}

func (e *Engine) cleanupLoop() {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-e.done:
			return
		case <-ticker.C:
			e.purgeExpired()
		}
	}
}

func (e *Engine) purgeExpired() {
	e.connMu.Lock()
	defer e.connMu.Unlock()

	now := time.Now()
	for k, entry := range e.connTable {
		if now.Sub(entry.lastSeen) > connTimeout {
			delete(e.connTable, k)
		}
	}
}
