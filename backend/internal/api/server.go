package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"opensiem/management/internal/auth"
	"opensiem/management/internal/config"
	"opensiem/management/internal/notify"
	"opensiem/management/internal/store"
)

type Server struct {
	cfg    *config.Config
	db     *store.DB
	hub    *Hub
	jwt    *auth.JWTService
	mailer *notify.Mailer
	logger *slog.Logger
	http   *http.Server
}

func New(cfg *config.Config, db *store.DB, logger *slog.Logger) *Server {
	jwt := auth.NewJWTService(cfg.Auth.JWTSecret, cfg.Auth.TokenDuration)
	hub := NewHub(db, logger)
	mailer := notify.NewMailer(cfg.SMTP)
	s := &Server{cfg: cfg, db: db, hub: hub, jwt: jwt, mailer: mailer, logger: logger}

	mux := http.NewServeMux()

	// Public
	mux.HandleFunc("GET /health", handleHealth(db))
	mux.HandleFunc("POST /auth/login", handleLogin(db, jwt, logger))

	// Protected
	protected := http.NewServeMux()
	protected.HandleFunc("GET /auth/me",            handleMe)
	protected.HandleFunc("PATCH /auth/password",    handleChangePassword(db))

	// Events
	protected.HandleFunc("GET /api/v1/events",              handleListEvents(db))
	protected.HandleFunc("GET /api/v1/events/export",       handleExportEvents(db))
	protected.HandleFunc("GET /api/v1/events/{id}",         handleGetEvent(db))

	// Agents
	protected.HandleFunc("GET /api/v1/agents",              handleListAgents(db))
	protected.HandleFunc("GET /api/v1/agents/{id}",         handleGetAgent(db))

	// Alerts
	protected.HandleFunc("GET /api/v1/alerts",                        handleListAlerts(db))
	protected.HandleFunc("POST /api/v1/alerts",                       handleCreateAlert(db, mailer))
	protected.HandleFunc("GET /api/v1/alerts/{id}",                   handleGetAlert(db))
	protected.HandleFunc("PATCH /api/v1/alerts/{id}/acknowledge",     handleAcknowledgeAlert(db))
	protected.HandleFunc("PATCH /api/v1/alerts/{id}/close",           handleCloseAlert(db))

	// Alert Rules
	protected.HandleFunc("GET /api/v1/alert-rules",         handleListAlertRules(db))
	protected.HandleFunc("POST /api/v1/alert-rules",        handleCreateAlertRule(db))
	protected.HandleFunc("PUT /api/v1/alert-rules/{id}",    handleUpdateAlertRule(db))
	protected.HandleFunc("DELETE /api/v1/alert-rules/{id}", handleDeleteAlertRule(db))

	// Users
	protected.HandleFunc("GET /api/v1/users",               handleListUsers(db))
	protected.HandleFunc("POST /api/v1/users",              handleCreateUser(db))
	protected.HandleFunc("DELETE /api/v1/users/{id}",       handleDeleteUser(db))

	// Audit log
	protected.HandleFunc("GET /api/v1/audit-log",           handleListAuditLog(db))

	// Stats & Threat Intel
	protected.HandleFunc("GET /api/v1/stats",               handleStats(db))
	protected.HandleFunc("GET /api/v1/threat-intel",        handleThreatIntel(db))

	// Settings
	protected.HandleFunc("GET /api/v1/settings/smtp",       handleGetSMTPSettings(cfg))
	protected.HandleFunc("POST /api/v1/settings/smtp/test", handleTestSMTP(mailer))

	// WebSocket
	protected.HandleFunc("GET /ws/events", hub.ServeWS)

	guard := auth.Middleware(jwt)
	mux.Handle("/api/", guard(protected))
	mux.Handle("/auth/me", guard(protected))
	mux.Handle("/auth/password", guard(protected))
	mux.Handle("/ws/", guard(protected))

	handler := corsMiddleware(cfg.Server.CORSOrigins)(loggingMiddleware(logger)(mux))
	s.http = &http.Server{
		Addr:         cfg.Server.ListenAddr,
		Handler:      handler,
		ReadTimeout:  cfg.Server.ReadTimeout,
		WriteTimeout: cfg.Server.WriteTimeout,
	}
	return s
}

func (s *Server) Start(ctx context.Context) error {
	engine := NewAlertEngine(s.db, s.mailer, s.logger)
	go engine.Run(ctx)
	go s.hub.Run(ctx)
	s.logger.Info("management server starting", "addr", s.cfg.Server.ListenAddr)
	return s.http.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.http.Shutdown(ctx)
}

func corsMiddleware(origins []string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			origin := r.Header.Get("Origin")
			allowed := false
			for _, o := range origins {
				if o == "*" || o == origin { allowed = true; break }
			}
			if allowed {
				w.Header().Set("Access-Control-Allow-Origin", origin)
				w.Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Authorization,Content-Type")
			}
			if r.Method == http.MethodOptions {
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func loggingMiddleware(logger *slog.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.Header.Get("Upgrade"), "websocket") {
				next.ServeHTTP(w, r)
				return
			}
			start := time.Now()
			rw := &responseWriter{ResponseWriter: w, code: 200}
			next.ServeHTTP(rw, r)
			logger.Info("http", "method", r.Method, "path", r.URL.Path, "status", rw.code, "ms", time.Since(start).Milliseconds())
		})
	}
}

type responseWriter struct {
	http.ResponseWriter
	code int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.code = code
	rw.ResponseWriter.WriteHeader(code)
}

func writeJSONError(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
