package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type Event struct {
	ID          string          `json:"id"`
	Time        time.Time       `json:"time"`
	AgentID     string          `json:"agent_id"`
	Host        string          `json:"host"`
	OS          string          `json:"os"`
	EventType   string          `json:"event_type"`
	Severity    int             `json:"severity"`
	Source      string          `json:"source"`
	Raw         json.RawMessage `json:"raw,omitempty"`
	PID         *int            `json:"pid,omitempty"`
	ProcessName *string         `json:"process_name,omitempty"`
	CommandLine *string         `json:"command_line,omitempty"`
	UserName    *string         `json:"user_name,omitempty"`
	Domain      *string         `json:"domain,omitempty"`
	SrcIP       *string         `json:"src_ip,omitempty"`
	SrcPort     *int            `json:"src_port,omitempty"`
	DstIP       *string         `json:"dst_ip,omitempty"`
	DstPort     *int            `json:"dst_port,omitempty"`
	Proto       *string         `json:"proto,omitempty"`
	EventID     *uint32         `json:"event_id,omitempty"`
	Channel     *string         `json:"channel,omitempty"`
}

type EventFilter struct {
	AgentID   string
	Host      string
	EventType string
	Severity  int
	SrcIP     string
	DstIP     string
	UserName  string
	Search    string
	Since     time.Time
	Until     time.Time
	Limit     int
	Offset    int
}

func (db *DB) QueryEvents(ctx context.Context, f EventFilter) ([]Event, int64, error) {
	where, args, n := []string{"1=1"}, []interface{}{}, 1

	add := func(clause string, val interface{}) {
		where = append(where, fmt.Sprintf(clause, n))
		args = append(args, val)
		n++
	}

	if f.AgentID != "" {
		add("agent_id = $%d", f.AgentID)
	}
	if f.Host != "" {
		add("host ILIKE $%d", "%"+f.Host+"%")
	}
	if f.EventType != "" {
		add("event_type = $%d", f.EventType)
	}
	if f.Severity > 0 {
		add("severity >= $%d", f.Severity)
	}
	if f.SrcIP != "" {
		add("src_ip = $%d::inet", f.SrcIP)
	}
	if f.DstIP != "" {
		add("dst_ip = $%d::inet", f.DstIP)
	}
	if f.UserName != "" {
		add("user_name ILIKE $%d", "%"+f.UserName+"%")
	}
	if f.Search != "" {
		add("(host ILIKE $%d OR user_name ILIKE $%d OR process_name ILIKE $%d OR command_line ILIKE $%d)",
			"%"+f.Search+"%")
		// add 3 more args for the same value
		args = append(args, "%"+f.Search+"%", "%"+f.Search+"%", "%"+f.Search+"%")
		n += 3
	}
	if !f.Since.IsZero() {
		add("time >= $%d", f.Since.UTC())
	}
	if !f.Until.IsZero() {
		add("time <= $%d", f.Until.UTC())
	}

	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 100
	}

	whereStr := strings.Join(where, " AND ")

	// Count
	var total int64
	countQ := fmt.Sprintf(`SELECT COUNT(*) FROM events WHERE %s`, whereStr)
	db.QueryRowContext(ctx, countQ, args...).Scan(&total)

	// Fetch
	query := fmt.Sprintf(`
		SELECT id, time, agent_id, host, os, event_type, severity, source,
		       pid, process_name, command_line, user_name, domain,
		       src_ip, src_port, dst_ip, dst_port, proto, event_id, channel
		FROM events WHERE %s
		ORDER BY time DESC
		LIMIT %d OFFSET %d`, whereStr, f.Limit, f.Offset)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("store: query events: %w", err)
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		var e Event
		var srcIP, dstIP *string
		if err := rows.Scan(
			&e.ID, &e.Time, &e.AgentID, &e.Host, &e.OS, &e.EventType, &e.Severity, &e.Source,
			&e.PID, &e.ProcessName, &e.CommandLine, &e.UserName, &e.Domain,
			&srcIP, &e.SrcPort, &dstIP, &e.DstPort, &e.Proto, &e.EventID, &e.Channel,
		); err != nil {
			return nil, 0, err
		}
		e.SrcIP = srcIP
		e.DstIP = dstIP
		events = append(events, e)
	}
	return events, total, rows.Err()
}

// LatestEvents returns the N most recent events — used by the live feed.
func (db *DB) LatestEvents(ctx context.Context, since time.Time, limit int) ([]Event, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, time, agent_id, host, os, event_type, severity, source,
		       pid, process_name, command_line, user_name, domain,
		       src_ip, src_port, dst_ip, dst_port, proto, event_id, channel
		FROM events
		WHERE time > $1
		ORDER BY time DESC
		LIMIT $2
	`, since.UTC(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var events []Event
	for rows.Next() {
		var e Event
		var srcIP, dstIP *string
		if err := rows.Scan(
			&e.ID, &e.Time, &e.AgentID, &e.Host, &e.OS, &e.EventType, &e.Severity, &e.Source,
			&e.PID, &e.ProcessName, &e.CommandLine, &e.UserName, &e.Domain,
			&srcIP, &e.SrcPort, &dstIP, &e.DstPort, &e.Proto, &e.EventID, &e.Channel,
		); err != nil {
			return nil, err
		}
		e.SrcIP = srcIP
		e.DstIP = dstIP
		events = append(events, e)
	}
	return events, rows.Err()
}

// GetEventByID fetches a single event with full raw JSON.
func (db *DB) GetEventByID(ctx context.Context, id string) (*Event, error) {
	var e Event
	var srcIP, dstIP *string
	err := db.QueryRowContext(ctx, `
		SELECT id, time, agent_id, host, os, event_type, severity, source, raw,
		       pid, process_name, command_line, user_name, domain,
		       src_ip, src_port, dst_ip, dst_port, proto, event_id, channel
		FROM events WHERE id = $1
	`, id).Scan(
		&e.ID, &e.Time, &e.AgentID, &e.Host, &e.OS, &e.EventType, &e.Severity, &e.Source, &e.Raw,
		&e.PID, &e.ProcessName, &e.CommandLine, &e.UserName, &e.Domain,
		&srcIP, &e.SrcPort, &dstIP, &e.DstPort, &e.Proto, &e.EventID, &e.Channel,
	)
	if err != nil {
		return nil, err
	}
	e.SrcIP = srcIP
	e.DstIP = dstIP
	return &e, nil
}

// RelatedEvents returns events on the same host within ±5 minutes of a given time, excluding the source event.
func (db *DB) RelatedEvents(ctx context.Context, host string, t time.Time, excludeID string) ([]Event, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, time, agent_id, host, os, event_type, severity, source,
		       pid, process_name, command_line, user_name, domain,
		       src_ip, src_port, dst_ip, dst_port, proto, event_id, channel
		FROM events
		WHERE host = $1
		  AND time BETWEEN $2 AND $3
		  AND id != $4
		ORDER BY time DESC
		LIMIT 50
	`, host, t.Add(-5*time.Minute).UTC(), t.Add(5*time.Minute).UTC(), excludeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var events []Event
	for rows.Next() {
		var e Event
		var srcIP, dstIP *string
		if err := rows.Scan(
			&e.ID, &e.Time, &e.AgentID, &e.Host, &e.OS, &e.EventType, &e.Severity, &e.Source,
			&e.PID, &e.ProcessName, &e.CommandLine, &e.UserName, &e.Domain,
			&srcIP, &e.SrcPort, &dstIP, &e.DstPort, &e.Proto, &e.EventID, &e.Channel,
		); err != nil {
			return nil, err
		}
		e.SrcIP = srcIP
		e.DstIP = dstIP
		events = append(events, e)
	}
	return events, rows.Err()
}

// ExportEvents returns events for CSV/JSON export (no pagination cap).
func (db *DB) ExportEvents(ctx context.Context, f EventFilter) ([]Event, error) {
	if f.Limit <= 0 || f.Limit > 10000 {
		f.Limit = 10000
	}
	events, _, err := db.QueryEvents(ctx, f)
	return events, err
}
