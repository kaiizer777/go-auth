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

func (h *Handler) registerRoutes() {
	// Base routes mounted in Phase 1; additional auth routes mount in subsequent phases.
	h.mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
}
