// Command preview serves the frontend with a mock backend, to work on the UI in
// any browser without Windows. mock.js lives here, outside frontend/, so it can
// never be embedded in the app: a diagnostic tool must not be able to show fake
// results.
//
//	go run ./dev/preview              then open the URL it prints
//
// Scenarios: healthy, proxy, proxywin, proxyauth, proxydown, pacbroken, rogue, loop,
// down, basic, nopeers, hidden. Add &autorun to run both checks straight away, and
// &hostile to put markup in a peer name and the rogue server's domain, which must
// show as plain text.
package main

import (
	_ "embed"
	"flag"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
)

//go:embed mock.js
var mockJS []byte

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "listen address (default: any free port)")
	flag.Parse()

	http.HandleFunc("/mock.js", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/javascript")
		w.Write(mockJS)
	})
	files := http.FileServer(http.Dir("frontend"))
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			files.ServeHTTP(w, r)
			return
		}
		page, err := os.ReadFile("frontend/index.html")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(strings.Replace(string(page), `<script src="app.js"`, `<script src="mock.js"></script><script src="app.js"`, 1)))
	})
	l, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("preview on http://%s/?scenario=healthy", l.Addr())
	log.Fatal(http.Serve(l, nil))
}
