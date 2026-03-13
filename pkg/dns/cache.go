package dns

import (
	"strings"
	"sync"
	"time"
)

const cacheCleanInterval = 30 * time.Second

type cacheEntry struct {
	records []ResourceRecord
	expires time.Time
}

type Cache struct {
	entries   map[string]cacheEntry
	mu        sync.RWMutex
	maxSize   int
	stop      chan struct{}
	closeOnce sync.Once
}

func NewCache(maxSize int) *Cache {
	c := &Cache{
		entries: make(map[string]cacheEntry),
		maxSize: maxSize,
		stop:    make(chan struct{}),
	}
	go c.cleaner()
	return c
}

func (c *Cache) Get(name string, qtype uint16) ([]ResourceRecord, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	key := cacheKey(name, qtype)
	entry, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	if time.Now().After(entry.expires) {
		return nil, false
	}

	return cloneRecords(entry.records), true
}

func (c *Cache) Set(name string, qtype uint16, records []ResourceRecord, ttl uint32) {
	if ttl == 0 || len(records) == 0 {
		return
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.entries) >= c.maxSize {
		c.evictLocked()
	}

	key := cacheKey(name, qtype)
	c.entries[key] = cacheEntry{
		records: cloneRecords(records),
		expires: time.Now().Add(time.Duration(ttl) * time.Second),
	}
}

func (c *Cache) Evict() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.evictLocked()
}

func (c *Cache) evictLocked() {
	now := time.Now()
	for k, v := range c.entries {
		if now.After(v.expires) {
			delete(c.entries, k)
		}
	}
	if len(c.entries) >= c.maxSize {
		var oldestKey string
		var oldestTime time.Time
		first := true
		for k, v := range c.entries {
			if first || v.expires.Before(oldestTime) {
				oldestKey = k
				oldestTime = v.expires
				first = false
			}
		}
		if !first {
			delete(c.entries, oldestKey)
		}
	}
}

func (c *Cache) Len() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

func (c *Cache) Flush() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]cacheEntry)
}

func (c *Cache) Close() {
	c.closeOnce.Do(func() {
		close(c.stop)
	})
}

func (c *Cache) cleaner() {
	ticker := time.NewTicker(cacheCleanInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.Evict()
		case <-c.stop:
			return
		}
	}
}

func cacheKey(name string, qtype uint16) string {
	return strings.ToLower(name) + "/" + uitoa(qtype)
}

type CachingHandler struct {
	cache *Cache
	next  Handler
}

func NewCachingHandler(cache *Cache, next Handler) *CachingHandler {
	return &CachingHandler{cache: cache, next: next}
}

func (h *CachingHandler) ServeDNS(w ResponseWriter, r *Message) {
	if len(r.Questions) > 0 {
		q := r.Questions[0]
		if records, ok := h.cache.Get(q.Name, q.Type); ok {
			resp := NewResponse(r, RCodeNoError, records)
			w.WriteMsg(resp)
			return
		}
	}

	cw := &cachingWriter{
		ResponseWriter: w,
		cache:          h.cache,
		query:          r,
	}
	h.next.ServeDNS(cw, r)
}

type cachingWriter struct {
	ResponseWriter
	cache *Cache
	query *Message
}

func (w *cachingWriter) WriteMsg(msg *Message) error {
	if len(msg.Answers) > 0 && len(w.query.Questions) > 0 {
		q := w.query.Questions[0]
		var minTTL uint32
		for i, rr := range msg.Answers {
			if i == 0 || rr.TTL < minTTL {
				minTTL = rr.TTL
			}
		}
		w.cache.Set(q.Name, q.Type, msg.Answers, minTTL)
	}
	return w.ResponseWriter.WriteMsg(msg)
}

func cloneRecords(records []ResourceRecord) []ResourceRecord {
	cloned := make([]ResourceRecord, len(records))
	for i := range records {
		cloned[i] = records[i]
		if records[i].RData != nil {
			cloned[i].RData = append([]byte(nil), records[i].RData...)
		}
	}
	return cloned
}
