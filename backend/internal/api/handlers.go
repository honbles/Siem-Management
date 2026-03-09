package api

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"obsidianwatch/management/internal/auth"
	"obsidianwatch/management/internal/config"
	"obsidianwatch/management/internal/notify"
	"obsidianwatch/management/internal/store"
)

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func clientIP(r *http.Request) string {
	if ip := r.Header.Get("X-Forwarded-For"); ip != "" {
		return strings.Split(ip, ",")[0]
	}
	return r.RemoteAddr
}

// ── Auth ──────────────────────────────────────────────────────────────────────

func handleLogin(db *store.DB, jwt *auth.JWTService, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"})
			return
		}
		user, hash, err := db.GetUserByUsername(r.Context(), body.Username)
		if err != nil || !store.CheckPassword(hash, body.Password) {
			writeJSON(w, 401, map[string]string{"error": "invalid credentials"})
			return
		}
		token, err := jwt.Sign(user.ID, user.Username, user.Role)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "token generation failed"})
			return
		}
		db.UpdateLastLogin(r.Context(), user.ID)
		db.WriteAudit(r.Context(), user.Username, "login", "", "", clientIP(r))
		logger.Info("auth: login", "user", user.Username)
		writeJSON(w, 200, map[string]interface{}{
			"token":                   token,
			"user":                    user,
			"require_password_change": !user.PasswordChanged,
		})
	}
}

func handleMe(w http.ResponseWriter, r *http.Request) {
	claims := auth.GetClaims(r)
	writeJSON(w, 200, map[string]interface{}{
		"user_id":  claims.UserID,
		"username": claims.Username,
		"role":     claims.Role,
	})
}

func handleChangePassword(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := auth.GetClaims(r)
		var body struct {
			CurrentPassword string `json:"current_password"`
			NewPassword     string `json:"new_password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"})
			return
		}
		if len(body.NewPassword) < 8 {
			writeJSON(w, 400, map[string]string{"error": "new password must be at least 8 characters"})
			return
		}
		_, hash, err := db.GetUserByUsername(r.Context(), claims.Username)
		if err != nil || !store.CheckPassword(hash, body.CurrentPassword) {
			writeJSON(w, 401, map[string]string{"error": "current password is incorrect"})
			return
		}
		if err := db.ChangePassword(r.Context(), claims.UserID, body.NewPassword); err != nil {
			writeJSON(w, 500, map[string]string{"error": "failed to update password"})
			return
		}
		db.WriteAudit(r.Context(), claims.Username, "change_password", "", "", clientIP(r))
		writeJSON(w, 200, map[string]string{"status": "ok"})
	}
}

// ── Events ────────────────────────────────────────────────────────────────────

func handleListEvents(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f := parseEventFilter(r)
		events, total, err := db.QueryEvents(r.Context(), f)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "query failed"})
			return
		}
		writeJSON(w, 200, map[string]interface{}{
			"events": events,
			"total":  total,
			"limit":  f.Limit,
			"offset": f.Offset,
		})
	}
}

func handleGetEvent(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			writeJSON(w, 400, map[string]string{"error": "missing id"})
			return
		}
		event, err := db.GetEventByID(r.Context(), id)
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": "event not found"})
			return
		}
		related, _ := db.RelatedEvents(r.Context(), event.Host, event.Time, id)
		writeJSON(w, 200, map[string]interface{}{
			"event":   event,
			"related": related,
		})
	}
}

func handleExportEvents(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		f := parseEventFilter(r)
		f.Limit = 10000
		format := r.URL.Query().Get("format")
		if format == "" {
			format = "csv"
		}
		events, err := db.ExportEvents(r.Context(), f)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "export failed"})
			return
		}
		if format == "json" {
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="obsidianwatch-events-%s.json"`, time.Now().Format("20060102-150405")))
			json.NewEncoder(w).Encode(events)
			return
		}
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="obsidianwatch-events-%s.csv"`, time.Now().Format("20060102-150405")))
		cw := csv.NewWriter(w)
		cw.Write([]string{"time", "severity", "host", "os", "event_type", "source", "user_name", "process_name", "command_line", "src_ip", "src_port", "dst_ip", "dst_port", "proto"})
		for _, e := range events {
			cw.Write([]string{
				e.Time.Format(time.RFC3339), strconv.Itoa(e.Severity),
				e.Host, e.OS, e.EventType, e.Source,
				strPtr(e.UserName), strPtr(e.ProcessName), strPtr(e.CommandLine),
				strPtr(e.SrcIP), intPtr(e.SrcPort), strPtr(e.DstIP), intPtr(e.DstPort), strPtr(e.Proto),
			})
		}
		cw.Flush()
	}
}

func strPtr(s *string) string {
	if s == nil { return "" }
	return *s
}
func intPtr(i *int) string {
	if i == nil { return "" }
	return strconv.Itoa(*i)
}

func parseEventFilter(r *http.Request) store.EventFilter {
	q := r.URL.Query()
	f := store.EventFilter{
		AgentID:     q.Get("agent_id"),
		Host:        q.Get("host"),
		EventType:   q.Get("event_type"),
		SrcIP:       q.Get("src_ip"),
		DstIP:       q.Get("dst_ip"),
		Proto:       q.Get("proto"),
		UserName:    q.Get("user_name"),
		ProcessName: q.Get("process_name"),
		CommandLine: q.Get("command_line"),
		ImagePath:   q.Get("image_path"),
		FilePath:    q.Get("file_path"),
		RegKey:      q.Get("reg_key"),
		Channel:     q.Get("channel"),
		Search:      q.Get("search"),
	}
	if s := q.Get("severity");  s != "" { f.Severity, _  = strconv.Atoi(s) }
	if s := q.Get("dst_port");  s != "" { f.DstPort, _   = strconv.Atoi(s) }
	if s := q.Get("src_port");  s != "" { f.SrcPort, _   = strconv.Atoi(s) }
	if s := q.Get("event_id");  s != "" { v, _ := strconv.ParseUint(s, 10, 32); f.EventID = uint32(v) }
	if s := q.Get("since");     s != "" { f.Since, _     = time.Parse(time.RFC3339, s) }
	if s := q.Get("until");     s != "" { f.Until, _     = time.Parse(time.RFC3339, s) }
	if s := q.Get("limit");     s != "" { f.Limit, _     = strconv.Atoi(s) }
	if s := q.Get("offset");    s != "" { f.Offset, _    = strconv.Atoi(s) }
	if f.Since.IsZero() && f.Until.IsZero() { f.Since = time.Now().Add(-24 * time.Hour) }
	return f
}

// ── Agents ────────────────────────────────────────────────────────────────────

func handleListAgents(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agents, err := db.ListAgents(r.Context())
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "query failed"})
			return
		}
		writeJSON(w, 200, map[string]interface{}{"agents": agents, "count": len(agents)})
	}
}

func handleGetAgent(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		agents, err := db.ListAgents(r.Context())
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "query failed"})
			return
		}
		for _, a := range agents {
			if a.ID == id {
				f := store.EventFilter{AgentID: id, Since: time.Now().Add(-24 * time.Hour), Limit: 100}
				events, total, _ := db.QueryEvents(r.Context(), f)
				writeJSON(w, 200, map[string]interface{}{"agent": a, "recent_events": events, "event_total": total})
				return
			}
		}
		writeJSON(w, 404, map[string]string{"error": "agent not found"})
	}
}

// ── Alerts ────────────────────────────────────────────────────────────────────

func handleListAlerts(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status := r.URL.Query().Get("status")
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		alerts, err := db.ListAlerts(r.Context(), status, limit)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "query failed"})
			return
		}
		counts, _ := db.CountAlertsByStatus(r.Context())
		writeJSON(w, 200, map[string]interface{}{"alerts": alerts, "counts": counts})
	}
}

func handleCreateAlert(db *store.DB, mailer *notify.Mailer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := auth.GetClaims(r)
		var body struct {
			Title       string `json:"title"`
			Description string `json:"description"`
			Severity    int    `json:"severity"`
			AgentID     string `json:"agent_id"`
			Host        string `json:"host"`
			EventType   string `json:"event_type"`
			EventID     string `json:"event_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"})
			return
		}
		if body.Title == "" {
			writeJSON(w, 400, map[string]string{"error": "title required"})
			return
		}
		if body.Severity < 1 || body.Severity > 5 { body.Severity = 3 }
		id, err := db.CreateAlert(r.Context(), store.Alert{
			Title: body.Title, Description: body.Description, Severity: body.Severity,
			AgentID: body.AgentID, Host: body.Host, EventType: body.EventType, EventID: body.EventID,
		})
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "failed to create alert"})
			return
		}
		db.WriteAudit(r.Context(), claims.Username, "create_alert", fmt.Sprintf("alert:%d", id), body.Title, clientIP(r))
		if mailer.Enabled() {
			go mailer.SendAlert(store.Alert{
				ID: id, Title: body.Title, Description: body.Description,
				Severity: body.Severity, Host: body.Host, EventType: body.EventType,
				Status: "open",
			})
		}
		writeJSON(w, 201, map[string]interface{}{"id": id, "status": "created"})
	}
}

func handleAcknowledgeAlert(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil { writeJSON(w, 400, map[string]string{"error": "invalid id"}); return }
		claims := auth.GetClaims(r)
		if err := db.AcknowledgeAlert(r.Context(), id, claims.Username); err != nil {
			writeJSON(w, 404, map[string]string{"error": err.Error()}); return
		}
		db.WriteAudit(r.Context(), claims.Username, "ack_alert", fmt.Sprintf("alert:%d", id), "", clientIP(r))
		writeJSON(w, 200, map[string]string{"status": "acknowledged"})
	}
}

func handleCloseAlert(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil { writeJSON(w, 400, map[string]string{"error": "invalid id"}); return }
		claims := auth.GetClaims(r)
		if err := db.CloseAlert(r.Context(), id, claims.Username); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()}); return
		}
		db.WriteAudit(r.Context(), claims.Username, "close_alert", fmt.Sprintf("alert:%d", id), "", clientIP(r))
		writeJSON(w, 200, map[string]string{"status": "closed"})
	}
}

// ── Alert Rules ───────────────────────────────────────────────────────────────

func handleListAlertRules(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		rules, err := db.ListAlertRules(r.Context())
		if err != nil { writeJSON(w, 500, map[string]string{"error": "query failed"}); return }
		writeJSON(w, 200, map[string]interface{}{"rules": rules})
	}
}

func handleCreateAlertRule(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := auth.GetClaims(r)
		var rule store.AlertRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"}); return
		}
		if rule.Name == "" { writeJSON(w, 400, map[string]string{"error": "name required"}); return }
		rule.CreatedBy = claims.Username
		id, err := db.CreateAlertRule(r.Context(), rule)
		if err != nil { writeJSON(w, 500, map[string]string{"error": "failed to create rule"}); return }
		db.WriteAudit(r.Context(), claims.Username, "create_alert_rule", fmt.Sprintf("rule:%d", id), rule.Name, clientIP(r))
		writeJSON(w, 201, map[string]interface{}{"id": id})
	}
}

func handleUpdateAlertRule(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := auth.GetClaims(r)
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil { writeJSON(w, 400, map[string]string{"error": "invalid id"}); return }
		var rule store.AlertRule
		if err := json.NewDecoder(r.Body).Decode(&rule); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"}); return
		}
		rule.ID = id
		if err := db.UpdateAlertRule(r.Context(), rule); err != nil {
			writeJSON(w, 500, map[string]string{"error": "failed to update rule"}); return
		}
		db.WriteAudit(r.Context(), claims.Username, "update_alert_rule", fmt.Sprintf("rule:%d", id), rule.Name, clientIP(r))
		writeJSON(w, 200, map[string]string{"status": "updated"})
	}
}

func handleDeleteAlertRule(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := auth.GetClaims(r)
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil { writeJSON(w, 400, map[string]string{"error": "invalid id"}); return }
		if err := db.DeleteAlertRule(r.Context(), id); err != nil {
			writeJSON(w, 500, map[string]string{"error": "failed to delete rule"}); return
		}
		db.WriteAudit(r.Context(), claims.Username, "delete_alert_rule", fmt.Sprintf("rule:%d", id), "", clientIP(r))
		writeJSON(w, 200, map[string]string{"status": "deleted"})
	}
}

// ── Users ─────────────────────────────────────────────────────────────────────

func handleListUsers(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		users, err := db.ListUsers(r.Context())
		if err != nil { writeJSON(w, 500, map[string]string{"error": "query failed"}); return }
		writeJSON(w, 200, map[string]interface{}{"users": users})
	}
}

func handleCreateUser(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := auth.GetClaims(r)
		if claims.Role != "admin" { writeJSON(w, 403, map[string]string{"error": "admin only"}); return }
		var body struct {
			Username string `json:"username"`
			Password string `json:"password"`
			Role     string `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid request"}); return
		}
		if body.Username == "" || body.Password == "" {
			writeJSON(w, 400, map[string]string{"error": "username and password required"}); return
		}
		if body.Role != "admin" && body.Role != "analyst" { body.Role = "analyst" }
		if len(body.Password) < 8 {
			writeJSON(w, 400, map[string]string{"error": "password must be at least 8 characters"}); return
		}
		user, err := db.CreateUser(r.Context(), body.Username, body.Password, body.Role)
		if err != nil { writeJSON(w, 409, map[string]string{"error": "username already exists"}); return }
		db.WriteAudit(r.Context(), claims.Username, "create_user", body.Username, body.Role, clientIP(r))
		writeJSON(w, 201, user)
	}
}

func handleDeleteUser(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := auth.GetClaims(r)
		if claims.Role != "admin" { writeJSON(w, 403, map[string]string{"error": "admin only"}); return }
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil { writeJSON(w, 400, map[string]string{"error": "invalid id"}); return }
		if err := db.DeleteUser(r.Context(), id); err != nil {
			writeJSON(w, 500, map[string]string{"error": "failed to delete user"}); return
		}
		db.WriteAudit(r.Context(), claims.Username, "delete_user", fmt.Sprintf("user:%d", id), "", clientIP(r))
		writeJSON(w, 200, map[string]string{"status": "deleted"})
	}
}

// ── Audit Log ─────────────────────────────────────────────────────────────────

func handleListAuditLog(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		offset, _ := strconv.Atoi(r.URL.Query().Get("offset"))
		entries, total, err := db.ListAuditLog(r.Context(), limit, offset)
		if err != nil { writeJSON(w, 500, map[string]string{"error": "query failed"}); return }
		writeJSON(w, 200, map[string]interface{}{"entries": entries, "total": total})
	}
}

// ── Stats ─────────────────────────────────────────────────────────────────────

func handleStats(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		hours := 24
		if s := r.URL.Query().Get("hours"); s != "" {
			if v, err := strconv.Atoi(s); err == nil { hours = v }
		}
		summary, _ := db.Summary(r.Context())
		timeline, _ := db.EventsOverTime(r.Context(), hours)
		bySeverity, _ := db.EventsBySeverity(r.Context())
		byType, _ := db.EventsByType(r.Context())
		agentStats, _ := db.AgentStats(r.Context())
		dashData, _ := db.DashboardStats(r.Context())
		writeJSON(w, 200, map[string]interface{}{
			"summary": summary, "timeline": timeline,
			"by_severity": bySeverity, "by_type": byType, "agents": agentStats,
			"dashboard": dashData,
		})
	}
}

func handleHealth(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		dbStatus := "ok"
		if err := db.HealthCheck(r.Context()); err != nil { dbStatus = "error: " + err.Error() }
		writeJSON(w, 200, map[string]interface{}{"status": "ok", "database": dbStatus, "time": time.Now().UTC()})
	}
}

func handleThreatIntel(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		data, err := db.ThreatIntel(r.Context())
		if err != nil { writeJSON(w, 500, map[string]string{"error": "query failed"}); return }
		writeJSON(w, 200, data)
	}
}

// ── Alert detail ──────────────────────────────────────────────────────────────

func handleGetAlert(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid id"})
			return
		}
		alert, err := db.GetAlert(r.Context(), id)
		if err != nil {
			writeJSON(w, 404, map[string]string{"error": "alert not found"})
			return
		}
		// Fetch related event if we have an event_id that looks like a real event UUID
		var relatedEvent *store.Event
		if alert.EventID != "" && !strings.HasPrefix(alert.EventID, "rule:") {
			if ev, err := db.GetEventByID(r.Context(), alert.EventID); err == nil {
				relatedEvent = ev
			}
		}
		writeJSON(w, 200, map[string]interface{}{
			"alert":         alert,
			"related_event": relatedEvent,
		})
	}
}

// ── SMTP Settings ─────────────────────────────────────────────────────────────

func handleGetSMTPSettings(cfg *config.Config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Return config without password
		writeJSON(w, 200, map[string]interface{}{
			"enabled":      cfg.SMTP.Enabled,
			"host":         cfg.SMTP.Host,
			"port":         cfg.SMTP.Port,
			"username":     cfg.SMTP.Username,
			"from":         cfg.SMTP.From,
			"to":           cfg.SMTP.To,
			"min_severity": cfg.SMTP.MinSeverity,
			"use_tls":      cfg.SMTP.UseTLS,
		})
	}
}

func handleTestSMTP(mailer *notify.Mailer) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := mailer.TestConnection(); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "test email sent"})
	}
}

// ── Detection Signatures ───────────────────────────────────────────────────────

func handleListDetections() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		type SigInfo struct {
			ID          string `json:"id"`
			Name        string `json:"name"`
			Description string `json:"description"`
			Severity    int    `json:"severity"`
			MITRE       string `json:"mitre"`
			Category    string `json:"category"`
		}
		out := make([]SigInfo, len(threatSignatures))
		for i, s := range threatSignatures {
			out[i] = SigInfo{s.ID, s.Name, s.Description, s.Severity, s.MITRE, s.Category}
		}
		writeJSON(w, 200, map[string]interface{}{"signatures": out, "count": len(out)})
	}
}



// ── Tamper Protection ─────────────────────────────────────────────────────────

func handleSetTamperLock(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agentID := r.PathValue("id")
		var body struct { Locked bool `json:"locked"` }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid body"})
			return
		}
		if err := db.SetTamperLock(r.Context(), agentID, body.Locked); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]bool{"locked": body.Locked})
	}
}

func handleRegenerateKey(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agentID := r.PathValue("id")
		key, err := db.RegenerateInstallKey(r.Context(), agentID)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"install_key": key})
	}
}

// ── Case Management ───────────────────────────────────────────────────────────

func handleAssignAlert(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil { writeJSON(w, 400, map[string]string{"error": "invalid id"}); return }
		var body struct {
			AssignedTo string `json:"assigned_to"`
			Notes      string `json:"notes"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid body"})
			return
		}
		claims := auth.GetClaims(r)
		if err := db.AssignAlert(r.Context(), id, body.AssignedTo, claims.Username, body.Notes); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		db.WriteAudit(r.Context(), claims.Username, "assign_alert", strconv.FormatInt(id, 10), "assigned to "+body.AssignedTo, clientIP(r))
		writeJSON(w, 200, map[string]string{"status": "acknowledged"})
	}
}

func handleUpdateCaseNotes(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil { writeJSON(w, 400, map[string]string{"error": "invalid id"}); return }
		var body struct { Notes string `json:"notes"` }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid body"})
			return
		}
		if err := db.UpdateCaseNotes(r.Context(), id, body.Notes); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "ok"})
	}
}

func handleCloseWithReview(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil { writeJSON(w, 400, map[string]string{"error": "invalid id"}); return }
		var body struct { Comment string `json:"comment"` }
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			writeJSON(w, 400, map[string]string{"error": "invalid body"})
			return
		}
		claims := auth.GetClaims(r)
		if err := db.CloseAlertWithReview(r.Context(), id, claims.Username, body.Comment); err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		db.WriteAudit(r.Context(), claims.Username, "close_alert", strconv.FormatInt(id, 10), body.Comment, clientIP(r))
		writeJSON(w, 200, map[string]string{"status": "closed"})
	}
}


// handleVerifyInstallKey allows agents to verify their install key on service install
func handleVerifyInstallKey(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Query().Get("key")
		if key == "" {
			writeJSON(w, 400, map[string]string{"error": "key required"})
			return
		}
		agent, err := db.GetAgentByInstallKey(r.Context(), key)
		if err != nil || agent == nil {
			writeJSON(w, 403, map[string]string{"error": "invalid key"})
			return
		}
		writeJSON(w, 200, map[string]string{"status": "ok", "hostname": agent.Hostname})
	}
}

// handleThreatIntelHost returns threat intel scoped to a single host
func handleThreatIntelHost(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.PathValue("host")
		hours := 24
		if s := r.URL.Query().Get("hours"); s != "" {
			if v, err := strconv.Atoi(s); err == nil { hours = v }
		}
		data, err := db.ThreatIntelHost(r.Context(), host, hours)
		if err != nil { writeJSON(w, 500, map[string]string{"error": err.Error()}); return }
		writeJSON(w, 200, data)
	}
}

// ── Threat Graph ──────────────────────────────────────────────────────────────

// handleThreatGraphHost returns all process events for a host, grouped by
// application, with parent/child relationships for tree rendering.
func handleThreatGraphHost(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.PathValue("host")
		since := time.Now().Add(-24 * time.Hour)
		if s := r.URL.Query().Get("since_hours"); s != "" {
			if h, err := strconv.Atoi(s); err == nil {
				since = time.Now().Add(-time.Duration(h) * time.Hour)
			}
		}

		// Fetch all process events for this host (ILIKE partial match works for hostname)
		f := store.EventFilter{
			Host:      host,
			EventType: "process",
			Since:     since,
			Limit:     2000,
		}
		events, _, err := db.QueryEvents(r.Context(), f)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "query failed"})
			return
		}

		// Also fetch ALL event types for enrichment (file, network, registry, dns)
		fAll := store.EventFilter{Host: host, Since: since, Limit: 5000}
		allEvents, _, _ := db.QueryEvents(r.Context(), fAll)

		writeJSON(w, 200, map[string]interface{}{
			"host":       host,
			"processes":  events,
			"all_events": allEvents,
			"since":      since,
		})
	}
}

// handleThreatGraphProcess returns full process tree for a specific process name on a host.
func handleThreatGraphProcess(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host        := r.URL.Query().Get("host")
		processName := r.URL.Query().Get("process")
		since       := time.Now().Add(-24 * time.Hour)

		// Get all events related to this process
		f := store.EventFilter{
			Host:        host,
			ProcessName: processName,
			Since:       since,
			Limit:       500,
		}
		events, _, err := db.QueryEvents(r.Context(), f)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "query failed"})
			return
		}

		writeJSON(w, 200, map[string]interface{}{
			"host":    host,
			"process": processName,
			"events":  events,
		})
	}
}
