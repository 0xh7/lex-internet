package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"

	"github.com/0xh7/lex-internet/pkg/http"
)

type Item struct {
	ID   int    `json:"id"`
	Name string `json:"name"`
	Done bool   `json:"done"`
}

type store struct {
	mu    sync.RWMutex
	items map[int]*Item
	seq   int
}

func newStore() *store {
	return &store{items: make(map[int]*Item)}
}

func (s *store) create(name string) *Item {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	item := &Item{ID: s.seq, Name: name}
	s.items[item.ID] = item
	return item
}

func (s *store) get(id int) (Item, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	item, ok := s.items[id]
	if !ok {
		return Item{}, false
	}
	return *item, true
}

func (s *store) list() []Item {
	s.mu.RLock()
	defer s.mu.RUnlock()
	result := make([]Item, 0, len(s.items))
	for _, item := range s.items {
		result = append(result, *item)
	}
	return result
}

func (s *store) update(id int, name string, done bool) (Item, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	item, ok := s.items[id]
	if !ok {
		return Item{}, false
	}
	item.Name = name
	item.Done = done
	return *item, true
}

func (s *store) delete(id int) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.items[id]; !ok {
		return false
	}
	delete(s.items, id)
	return true
}

func main() {
	port := flag.Int("port", 8080, "listen port")
	dir := flag.String("dir", ".", "static file directory")
	flag.Parse()

	addr := fmt.Sprintf(":%d", *port)
	srv := http.NewServer(addr)

	srv.Use(http.Recovery())
	srv.Use(http.Logger())
	srv.Use(http.CORS())

	staticDir, err := filepath.Abs(*dir)
	if err != nil {
		log.Fatalf("invalid directory: %v", err)
	}

	db := newStore()

	srv.GET("/", func(req *http.Request, w *http.ResponseWriter) {
		w.HTML(200, `<!DOCTYPE html>
<html>
<head><title>lex-internet HTTP server</title></head>
<body>
<h1>lex-internet HTTP/1.1 Server</h1>
<p>API endpoints:</p>
<ul>
<li>GET /api/items</li>
<li>POST /api/items</li>
<li>GET /api/items/:id</li>
<li>PUT /api/items/:id</li>
<li>DELETE /api/items/:id</li>
</ul>
<p>Static files available at /static/</p>
</body>
</html>`)
	})

	srv.GET("/api/items", func(req *http.Request, w *http.ResponseWriter) {
		w.JSON(200, db.list())
	})

	srv.POST("/api/items", func(req *http.Request, w *http.ResponseWriter) {
		var body struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(req.Body, &body); err != nil || body.Name == "" {
			w.JSON(400, map[string]string{"error": "name is required"})
			return
		}
		item := db.create(body.Name)
		w.JSON(201, item)
	})

	srv.GET("/api/items/:id", func(req *http.Request, w *http.ResponseWriter) {
		id, err := strconv.Atoi(req.Param("id"))
		if err != nil {
			w.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		item, ok := db.get(id)
		if !ok {
			w.JSON(404, map[string]string{"error": "not found"})
			return
		}
		w.JSON(200, item)
	})

	srv.PUT("/api/items/:id", func(req *http.Request, w *http.ResponseWriter) {
		id, err := strconv.Atoi(req.Param("id"))
		if err != nil {
			w.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		var body struct {
			Name string `json:"name"`
			Done bool   `json:"done"`
		}
		if err := json.Unmarshal(req.Body, &body); err != nil {
			w.JSON(400, map[string]string{"error": "invalid body"})
			return
		}
		item, ok := db.update(id, body.Name, body.Done)
		if !ok {
			w.JSON(404, map[string]string{"error": "not found"})
			return
		}
		w.JSON(200, item)
	})

	srv.DELETE("/api/items/:id", func(req *http.Request, w *http.ResponseWriter) {
		id, err := strconv.Atoi(req.Param("id"))
		if err != nil {
			w.JSON(400, map[string]string{"error": "invalid id"})
			return
		}
		if !db.delete(id) {
			w.JSON(404, map[string]string{"error": "not found"})
			return
		}
		w.JSON(200, map[string]string{"status": "deleted"})
	})

	srv.GET("/static/*", func(req *http.Request, w *http.ResponseWriter) {
		rel := req.Param("*")
		path := filepath.Join(staticDir, filepath.FromSlash(rel))
		path = filepath.Clean(path)
		if !strings.HasPrefix(path, staticDir+string(filepath.Separator)) && path != staticDir {
			w.Text(403, "Forbidden")
			return
		}
		if err := w.File(path); err != nil {
			log.Printf("static file error: %v", err)
			w.Text(500, "Internal Server Error")
		}
	})

	srv.GET("/health", func(req *http.Request, w *http.ResponseWriter) {
		w.JSON(200, map[string]string{"status": "ok"})
	})

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-sigCh
		log.Println("shutting down...")
		srv.Shutdown()
	}()

	log.Printf("serving static files from %s", staticDir)
	if err := srv.ListenAndServe(); err != nil {
		log.Fatal(err)
	}
}
