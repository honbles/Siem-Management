package api

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"opensiem/management/internal/store"
)

type AlertEngine struct {
	db     *store.DB
	logger *slog.Logger
}

func NewAlertEngine(db *store.DB, logger *slog.Logger) *AlertEngine {
	return &AlertEngine{db: db, logger: logger}
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

		// Check against each rule
		for _, rule := range rules {
			if !matchesRule(ev, rule) {
				continue
			}
			// Use rule+event combo as dedup key
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

			e.db.CreateAlert(ctx, store.Alert{
				Title:       title,
				Description: desc,
				Severity:    ev.Severity,
				AgentID:     ev.AgentID,
				Host:        ev.Host,
				EventType:   ev.EventType,
				EventID:     dedupKey,
			})
			created++
		}
	}
	if created > 0 {
		e.logger.Info("alert engine: created alerts", "count", created)
	}
}

func matchesRule(ev store.Event, rule store.AlertRule) bool {
	// Severity threshold
	if ev.Severity < rule.Severity {
		return false
	}
	// Event type filter
	if rule.EventType != "" && ev.EventType != rule.EventType {
		return false
	}
	// Host match (case-insensitive contains)
	if rule.HostMatch != "" && !strings.Contains(strings.ToLower(ev.Host), strings.ToLower(rule.HostMatch)) {
		return false
	}
	// User match
	if rule.UserMatch != "" {
		if ev.UserName == nil || !strings.Contains(strings.ToLower(*ev.UserName), strings.ToLower(rule.UserMatch)) {
			return false
		}
	}
	// Process match
	if rule.ProcessMatch != "" {
		if ev.ProcessName == nil || !strings.Contains(strings.ToLower(*ev.ProcessName), strings.ToLower(rule.ProcessMatch)) {
			return false
		}
	}
	return true
}
