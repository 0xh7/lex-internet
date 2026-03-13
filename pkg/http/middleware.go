package http

import (
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"runtime/debug"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type MiddlewareFunc func(HandlerFunc) HandlerFunc

func Logger() MiddlewareFunc {
	return func(next HandlerFunc) HandlerFunc {
		return func(req *Request, w *ResponseWriter) {
			start := time.Now()
			next(req, w)
			elapsed := time.Since(start)
			log.Printf("%s %s %d %s %s",
				req.Method, req.Path, w.statusCode, elapsed.Round(time.Microsecond), req.RemoteAddr)
		}
	}
}

func Recovery() MiddlewareFunc {
	return func(next HandlerFunc) HandlerFunc {
		return func(req *Request, w *ResponseWriter) {
			defer func() {
				if r := recover(); r != nil {
					log.Printf("panic: %v\n%s", r, debug.Stack())
					if !w.wroteHeader {
						w.WriteHeader(500)
						w.Write([]byte("Internal Server Error"))
					}
				}
			}()
			next(req, w)
		}
	}
}

func CORS(origins ...string) MiddlewareFunc {
	allowed := "*"
	if len(origins) > 0 {
		allowed = strings.Join(origins, ", ")
	}

	return func(next HandlerFunc) HandlerFunc {
		return func(req *Request, w *ResponseWriter) {
			w.SetHeader("Access-Control-Allow-Origin", allowed)
			w.SetHeader("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS, PATCH")
			w.SetHeader("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Requested-With")
			w.SetHeader("Access-Control-Max-Age", "86400")

			if req.Method == "OPTIONS" {
				w.WriteHeader(204)
				return
			}
			next(req, w)
		}
	}
}

type tokenBucket struct {
	mu       sync.Mutex
	tokens   float64
	max      float64
	rate     float64
	lastFill time.Time
}

func (b *tokenBucket) take() bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := time.Now()
	elapsed := now.Sub(b.lastFill).Seconds()
	b.tokens += elapsed * b.rate
	if b.tokens > b.max {
		b.tokens = b.max
	}
	b.lastFill = now

	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func cleanupBuckets(buckets *sync.Map) {
	cutoff := time.Now().Add(-5 * time.Minute)
	buckets.Range(func(key, val any) bool {
		b := val.(*tokenBucket)
		b.mu.Lock()
		stale := b.lastFill.Before(cutoff)
		b.mu.Unlock()
		if stale {
			buckets.Delete(key)
		}
		return true
	})
}

func RateLimit(rps int) MiddlewareFunc {
	return RateLimitWithStop(rps, nil)
}

func RateLimitWithStop(rps int, stop <-chan struct{}) MiddlewareFunc {
	buckets := &sync.Map{}
	var lastCleanup atomic.Int64

	if stop != nil {
		go func() {
			ticker := time.NewTicker(5 * time.Minute)
			defer ticker.Stop()

			for {
				select {
				case <-ticker.C:
					cleanupBuckets(buckets)
				case <-stop:
					return
				}
			}
		}()
	} else {
		lastCleanup.Store(time.Now().UnixNano())
	}

	return func(next HandlerFunc) HandlerFunc {
		return func(req *Request, w *ResponseWriter) {
			if stop == nil {
				now := time.Now()
				last := lastCleanup.Load()
				if now.UnixNano()-last >= int64(5*time.Minute) && lastCleanup.CompareAndSwap(last, now.UnixNano()) {
					cleanupBuckets(buckets)
				}
			}

			addr := req.RemoteAddr
			if host, _, err := net.SplitHostPort(addr); err == nil {
				addr = host
			}

			val, _ := buckets.LoadOrStore(addr, &tokenBucket{
				tokens:   float64(rps),
				max:      float64(rps),
				rate:     float64(rps),
				lastFill: time.Now(),
			})
			bucket := val.(*tokenBucket)

			if !bucket.take() {
				w.SetHeader("Retry-After", "1")
				w.Text(429, "Too Many Requests")
				return
			}
			next(req, w)
		}
	}
}

func BasicAuth(realm string, credentials map[string]string) MiddlewareFunc {
	return func(next HandlerFunc) HandlerFunc {
		return func(req *Request, w *ResponseWriter) {
			auth := req.Header("Authorization")
			if auth == "" || !strings.HasPrefix(auth, "Basic ") {
				w.SetHeader("Www-Authenticate", fmt.Sprintf(`Basic realm="%s"`, realm))
				w.Text(401, "Unauthorized")
				return
			}

			decoded, err := base64.StdEncoding.DecodeString(auth[6:])
			if err != nil {
				w.Text(401, "Unauthorized")
				return
			}

			user, pass, ok := strings.Cut(string(decoded), ":")
			if !ok {
				w.Text(401, "Unauthorized")
				return
			}

			expected, exists := credentials[user]
			if !exists || subtle.ConstantTimeCompare([]byte(expected), []byte(pass)) != 1 {
				w.SetHeader("Www-Authenticate", fmt.Sprintf(`Basic realm="%s"`, realm))
				w.Text(401, "Unauthorized")
				return
			}

			next(req, w)
		}
	}
}

func MaxBody(size int64) MiddlewareFunc {
	return func(next HandlerFunc) HandlerFunc {
		return func(req *Request, w *ResponseWriter) {
			if int64(len(req.Body)) > size {
				w.Text(413, "Payload Too Large")
				return
			}
			next(req, w)
		}
	}
}
