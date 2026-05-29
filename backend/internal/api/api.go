package api

import (
	"encoding/json"
	"log"
	"net/http"
	"sync"
	"time"

	"windetect/internal/collector"
	"windetect/internal/models"
	"windetect/internal/report"
)

// Server holds cached scan results so multiple views share one scan.
type Server struct {
	mu      sync.RWMutex
	lastSec *models.SecurityResult
	lastDiag *models.DiagResult
}

// New creates a Server.
func New() *Server { return &Server{} }

// Routes registers all HTTP handlers and returns the mux.
func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/api/health", s.handleHealth)
	mux.HandleFunc("/api/quick", s.handleQuick)
	mux.HandleFunc("/api/security/scan", s.handleSecurityScan)
	mux.HandleFunc("/api/security/last", s.handleSecurityLast)
	mux.HandleFunc("/api/diag/scan", s.handleDiagScan)
	mux.HandleFunc("/api/diag/last", s.handleDiagLast)
	mux.HandleFunc("/api/checklist", s.handleChecklist)
	mux.HandleFunc("/api/report/html", s.handleReportHTML)
	mux.HandleFunc("/api/report/csv", s.handleReportCSV)
	mux.HandleFunc("/api/report/json", s.handleReportJSON)
	return withCORS(mux)
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"ok": true, "time": time.Now().Format(time.RFC3339)})
}

// handleQuick returns a fast live snapshot for the header/dashboard gauges.
func (s *Server) handleQuick(w http.ResponseWriter, r *http.Request) {
	data := collector.QuickData()
	writeJSON(w, data)
}

func (s *Server) handleSecurityScan(w http.ResponseWriter, r *http.Request) {
	res := collector.Security()
	s.mu.Lock()
	s.lastSec = &res
	s.mu.Unlock()
	writeJSON(w, res)
}

func (s *Server) handleSecurityLast(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.lastSec == nil {
		writeJSON(w, nil)
		return
	}
	writeJSON(w, s.lastSec)
}

func (s *Server) handleDiagScan(w http.ResponseWriter, r *http.Request) {
	res := collector.Diagnostics()
	s.mu.Lock()
	s.lastDiag = &res
	s.mu.Unlock()
	writeJSON(w, res)
}

func (s *Server) handleDiagLast(w http.ResponseWriter, r *http.Request) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.lastDiag == nil {
		writeJSON(w, nil)
		return
	}
	writeJSON(w, s.lastDiag)
}

func (s *Server) handleChecklist(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, collector.Checklist())
}

func (s *Server) buildBundle(meta report.Meta) report.Bundle {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return report.Bundle{Meta: meta, Security: s.lastSec, Diag: s.lastDiag}
}

func (s *Server) handleReportHTML(w http.ResponseWriter, r *http.Request) {
	meta := decodeMeta(r)
	out := report.HTML(s.buildBundle(meta))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=windiag-report.html")
	_, _ = w.Write([]byte(out))
}

func (s *Server) handleReportCSV(w http.ResponseWriter, r *http.Request) {
	meta := decodeMeta(r)
	out, err := report.CSV(s.buildBundle(meta))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	w.Header().Set("Content-Disposition", "attachment; filename=windiag-report.csv")
	_, _ = w.Write([]byte(out))
}

func (s *Server) handleReportJSON(w http.ResponseWriter, r *http.Request) {
	meta := decodeMeta(r)
	w.Header().Set("Content-Disposition", "attachment; filename=windiag-report.json")
	writeJSON(w, s.buildBundle(meta))
}

func decodeMeta(r *http.Request) report.Meta {
	var meta report.Meta
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&meta)
	}
	return meta
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	if err := enc.Encode(v); err != nil {
		log.Printf("encode error: %v", err)
	}
}

func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}
