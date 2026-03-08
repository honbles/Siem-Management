package store

import (
	"context"
	"fmt"
	"time"
)

type Agent struct {
	ID         string    `json:"id"`
	Hostname   string    `json:"hostname"`
	OS         string    `json:"os"`
	Version    string    `json:"version"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
	LastIP     string    `json:"last_ip"`
	EventCount int64     `json:"event_count"`
	// Computed
	Online bool `json:"online"`
}

// ListAgents returns all agents. An agent is online if last_seen < 2 minutes ago.
func (db *DB) ListAgents(ctx context.Context) ([]Agent, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, hostname, os, version, first_seen, last_seen,
		       COALESCE(last_ip, ''), event_count
		FROM agents
		ORDER BY last_seen DESC
	`)
	if err != nil {
		return nil, fmt.Errorf("store: list agents: %w", err)
	}
	defer rows.Close()

	cutoff := time.Now().Add(-2 * time.Minute)
	var agents []Agent
	for rows.Next() {
		var a Agent
		if err := rows.Scan(
			&a.ID, &a.Hostname, &a.OS, &a.Version,
			&a.FirstSeen, &a.LastSeen, &a.LastIP, &a.EventCount,
		); err != nil {
			return nil, err
		}
		a.Online = a.LastSeen.After(cutoff)
		agents = append(agents, a)
	}
	return agents, rows.Err()
}

// AgentStats returns event counts per agent for the last 24 hours.
func (db *DB) AgentStats(ctx context.Context) ([]map[string]interface{}, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT agent_id, host, COUNT(*) as event_count,
		       MAX(severity) as max_severity
		FROM events
		WHERE time > NOW() - INTERVAL '24 hours'
		GROUP BY agent_id, host
		ORDER BY event_count DESC
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var agentID, host string
		var count int64
		var maxSev int
		if err := rows.Scan(&agentID, &host, &count, &maxSev); err != nil {
			return nil, err
		}
		results = append(results, map[string]interface{}{
			"agent_id":    agentID,
			"host":        host,
			"event_count": count,
			"max_severity": maxSev,
		})
	}
	return results, rows.Err()
}
