package main

import (
	"flag"
	"log"
	"net/http"
	"time"

	"windetect/internal/api"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:8765", "HTTP listen address")
	flag.Parse()

	srv := api.New()
	handler := srv.Routes()

	httpServer := &http.Server{
		Addr:         *addr,
		Handler:      handler,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second, // scans can take a while
		IdleTimeout:  60 * time.Second,
	}

	log.Printf("WinDiag Pro backend listening on http://%s", *addr)
	log.Printf("API base: http://%s/api", *addr)
	if err := httpServer.ListenAndServe(); err != nil {
		log.Fatalf("server error: %v", err)
	}
}
