package api

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"obsidianwatch/management/internal/notify"
	"obsidianwatch/management/internal/store"
)

type AlertEngine struct {
	db     *store.DB
	mailer *notify.Mailer
	logger *slog.Logger
}

func NewAlertEngine(db *store.DB, mailer *notify.Mailer, logger *slog.Logger) *AlertEngine {
	return &AlertEngine{db: db, mailer: mailer, logger: logger}
}

func (e *AlertEngine) Run(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			e.evaluate(ctx)
		}
	}
}

func (e *AlertEngine) evaluate(ctx context.Context) {
	rules, err := e.db.GetEnabledRules(ctx)
	if err != nil {
		e.logger.Warn("alert engine: failed to load rules", "err", err)
		return
	}

	since := time.Now().Add(-1 * time.Minute)
	f := store.EventFilter{Since: since, Limit: 500}
	events, _, err := e.db.QueryEvents(ctx, f)
	if err != nil {
		e.logger.Warn("alert engine: failed to query events", "err", err)
		return
	}

	created := 0
	for _, ev := range events {
		eventIDStr := fmt.Sprintf("%v", ev.EventID)
		for _, rule := range rules {
			if !matchesRule(ev, rule) {
				continue
			}
			dedupKey := fmt.Sprintf("rule:%d:event:%s", rule.ID, ev.ID)
			exists, _ := e.db.AlertExists(ctx, dedupKey)
			if exists {
				continue
			}

			title := fmt.Sprintf("[%s] %s on %s", rule.Name, ev.EventType, ev.Host)
			desc := fmt.Sprintf("Rule '%s' triggered by %s event (severity %d) on host %s at %s",
				rule.Name, ev.EventType, ev.Severity, ev.Host, ev.Time.Format(time.RFC3339))
			if ev.ProcessName != nil && *ev.ProcessName != "" {
				desc += fmt.Sprintf(" | Process: %s", *ev.ProcessName)
			}
			if ev.UserName != nil && *ev.UserName != "" {
				desc += fmt.Sprintf(" | User: %s", *ev.UserName)
			}
			if eventIDStr != "<nil>" && eventIDStr != "0" {
				desc += fmt.Sprintf(" | EventID: %s", eventIDStr)
			}

			alert := store.Alert{
				Title:       title,
				Description: desc,
				Severity:    ev.Severity,
				AgentID:     ev.AgentID,
				Host:        ev.Host,
				EventType:   ev.EventType,
				EventID:     dedupKey,
			}

			id, err := e.db.CreateAlert(ctx, alert)
			if err != nil {
				continue
			}
			alert.CreatedAt = time.Now()
			created++

			// Send email if severity meets threshold
			if e.mailer.Enabled() && ev.Severity >= e.mailer.MinSeverity() {
				go func(a store.Alert, alertID int64) {
					a.ID = alertID
					if err := e.mailer.SendAlert(a); err != nil {
						e.logger.Warn("alert engine: email failed", "alert_id", alertID, "err", err)
					} else {
						e.logger.Info("alert engine: email sent", "alert_id", alertID)
					}
				}(alert, id)
			}
		}
	}
	if created > 0 {
		e.logger.Info("alert engine: created alerts", "count", created)
	}
}

func matchesRule(ev store.Event, rule store.AlertRule) bool {
	if ev.Severity < rule.Severity {
		return false
	}
	if rule.EventType != "" && ev.EventType != rule.EventType {
		return false
	}
	if rule.HostMatch != "" && !strings.Contains(strings.ToLower(ev.Host), strings.ToLower(rule.HostMatch)) {
		return false
	}
	if rule.UserMatch != "" {
		if ev.UserName == nil || !strings.Contains(strings.ToLower(*ev.UserName), strings.ToLower(rule.UserMatch)) {
			return false
		}
	}
	if rule.ProcessMatch != "" {
		if ev.ProcessName == nil || !strings.Contains(strings.ToLower(*ev.ProcessName), strings.ToLower(rule.ProcessMatch)) {
			return false
		}
	}
	return true
}
