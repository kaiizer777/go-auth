package handler

import (
	"net/http"

	"gorm.io/gorm"

	"github.com/kaiizer777/go-auth/config"
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
	return CORS(cfg)(h.mux)
}

// registerRoutes configures default and endpoint routes on the internal multiplexer.
func (h *Handler) registerRoutes() {
	// Base routes mounted in Phase 1; additional auth routes mount in subsequent phases.
	h.mux.HandleFunc("GET /health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if h.db == nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"unavailable"}`))
			return
		}
		sqlDB, err := h.db.DB()
		if err != nil || sqlDB.Ping() != nil {
			w.WriteHeader(http.StatusServiceUnavailable)
			_, _ = w.Write([]byte(`{"status":"unavailable"}`))
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})
}
