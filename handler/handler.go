package handler

import (
	"bytes"
	"net/http"

	"gorm.io/gorm"

	"github.com/kaiizer777/go-auth/config"
	"github.com/kaiizer777/go-auth/errors"
)

// Handler maintains the HTTP router, database connection, and configuration.
type Handler struct {
	mux *http.ServeMux
	db  *gorm.DB
	cfg config.Config
}

// New initializes the handler scaffold, registers routes, and applies CORS middleware.
func New(db *gorm.DB, cfg config.Config) http.Handler {
	h := &Handler{
		mux: http.NewServeMux(),
		db:  db,
		cfg: cfg,
	}
	h.registerRoutes()
	return CORS(cfg)(h)
}

// ServeHTTP handles requests, dispatching to the router and translating 404/405 to standardized JSON responses.
func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	ri := &responseInterceptor{ResponseWriter: w}
	h.mux.ServeHTTP(ri, r)

	if !ri.headerWritten {
		if ri.statusCode == http.StatusNotFound {
			h.NotFound(w, r)
			return
		}
		if ri.statusCode == http.StatusMethodNotAllowed {
			h.MethodNotAllowed(w, r)
			return
		}
		if ri.statusCode != 0 {
			w.WriteHeader(ri.statusCode)
		}
		if ri.body.Len() > 0 {
			_, _ = w.Write(ri.body.Bytes())
		}
	}
}

// NotFound writes a standardized 404 NOT_FOUND JSON error response.
func (h *Handler) NotFound(w http.ResponseWriter, r *http.Request) {
	errors.WriteJSON(w, errors.New(errors.CodeNotFound, "not found", nil))
}

// MethodNotAllowed writes a standardized 405 METHOD_NOT_ALLOWED JSON error response.
func (h *Handler) MethodNotAllowed(w http.ResponseWriter, r *http.Request) {
	errors.WriteJSON(w, errors.New(errors.CodeMethodNotAllowed, "method not allowed", nil))
}

// NotFoundHandler returns an http.Handler that writes a 404 NOT_FOUND JSON response.
func NotFoundHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		errors.WriteJSON(w, errors.New(errors.CodeNotFound, "not found", nil))
	})
}

// MethodNotAllowedHandler returns an http.Handler that writes a 405 METHOD_NOT_ALLOWED JSON response.
func MethodNotAllowedHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		errors.WriteJSON(w, errors.New(errors.CodeMethodNotAllowed, "method not allowed", nil))
	})
}

// registerRoutes configures default and endpoint routes on the internal multiplexer.
func (h *Handler) registerRoutes() {
	// Base routes mounted in Phase 1; additional auth routes mount in subsequent phases.
	h.mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		if h.db == nil {
			errors.WriteJSON(w, errors.New(errors.CodeDatabaseUnavailable, "database unavailable", nil))
			return
		}
		sqlDB, err := h.db.DB()
		if err != nil || sqlDB.Ping() != nil {
			errors.WriteJSON(w, errors.New(errors.CodeDatabaseUnavailable, "database unavailable", nil))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
}

type responseInterceptor struct {
	http.ResponseWriter
	statusCode    int
	headerWritten bool
	body          bytes.Buffer
}

func (rw *responseInterceptor) WriteHeader(code int) {
	if rw.headerWritten {
		return
	}
	rw.statusCode = code
	if code != http.StatusNotFound && code != http.StatusMethodNotAllowed {
		rw.headerWritten = true
		rw.ResponseWriter.WriteHeader(code)
	}
}

func (rw *responseInterceptor) Write(b []byte) (int, error) {
	if !rw.headerWritten {
		if rw.statusCode == 0 {
			rw.statusCode = http.StatusOK
		}
		if rw.Header().Get("Content-Type") == "application/json" {
			rw.headerWritten = true
			rw.ResponseWriter.WriteHeader(rw.statusCode)
			return rw.ResponseWriter.Write(b)
		}
		if rw.statusCode != http.StatusNotFound && rw.statusCode != http.StatusMethodNotAllowed {
			rw.headerWritten = true
			rw.ResponseWriter.WriteHeader(rw.statusCode)
			return rw.ResponseWriter.Write(b)
		}
	}
	if (rw.statusCode == http.StatusNotFound || rw.statusCode == http.StatusMethodNotAllowed) && rw.Header().Get("Content-Type") != "application/json" {
		return rw.body.Write(b)
	}
	return rw.ResponseWriter.Write(b)
}
