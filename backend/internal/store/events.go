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
	PPID        *int            `json:"ppid,omitempty"`
	ProcessName *string         `json:"process_name,omitempty"`
	CommandLine *string         `json:"command_line,omitempty"`
	ImagePath   *string         `json:"image_path,omitempty"`
	UserName    *string         `json:"user_name,omitempty"`
	Domain      *string         `json:"domain,omitempty"`
	LogonID     *string         `json:"logon_id,omitempty"`
	SrcIP       *string         `json:"src_ip,omitempty"`
	SrcPort     *int            `json:"src_port,omitempty"`
	DstIP       *string         `json:"dst_ip,omitempty"`
	DstPort     *int            `json:"dst_port,omitempty"`
	Proto       *string         `json:"proto,omitempty"`
	RegKey      *string         `json:"reg_key,omitempty"`
	RegValue    *string         `json:"reg_value,omitempty"`
	FilePath    *string         `json:"file_path,omitempty"`
	FileHash    *string         `json:"file_hash,omitempty"`
	EventID     *uint32         `json:"event_id,omitempty"`
	Channel     *string         `json:"channel,omitempty"`
	RecordID    *uint64         `json:"record_id,omitempty"`
}

// EventFilter is the full set of supported search parameters.
type EventFilter struct {
	AgentID     string
	Host        string
	EventType   string
	Severity    int
	SrcIP       string
	DstIP       string
	DstPort     int
	SrcPort     int
	Proto       string
	UserName    string
	ProcessName string
	CommandLine string
	ImagePath   string
	FilePath    string
	RegKey      string
	Channel     string
	EventID     uint32
	Search      string // free-text across key fields
	Since       time.Time
	Until       time.Time
	Limit       int
	Offset      int
}

func (db *DB) QueryEvents(ctx context.Context, f EventFilter) ([]Event, int64, error) {
	where, args, n := []string{"1=1"}, []interface{}{}, 1

	add := func(clause string, vals ...interface{}) {
		// Replace each %d placeholder with n, n+1, ...
		parts := strings.Split(clause, "$?")
		built := ""
		for i, p := range parts {
			built += p
			if i < len(parts)-1 {
				built += fmt.Sprintf("$%d", n)
				n++
			}
		}
		where = append(where, built)
		args = append(args, vals...)
	}

	if f.AgentID != "" {
		where = append(where, fmt.Sprintf("agent_id = $%d", n)); args = append(args, f.AgentID); n++
	}
	if f.Host != "" {
		where = append(where, fmt.Sprintf("host ILIKE $%d", n)); args = append(args, "%"+f.Host+"%"); n++
	}
	if f.EventType != "" {
		where = append(where, fmt.Sprintf("event_type = $%d", n)); args = append(args, f.EventType); n++
	}
	if f.Severity > 0 {
		where = append(where, fmt.Sprintf("severity >= $%d", n)); args = append(args, f.Severity); n++
	}
	if f.SrcIP != "" {
		where = append(where, fmt.Sprintf("src_ip = $%d", n)); args = append(args, f.SrcIP); n++
	}
	if f.DstIP != "" {
		where = append(where, fmt.Sprintf("dst_ip = $%d", n)); args = append(args, f.DstIP); n++
	}
	if f.DstPort > 0 {
		where = append(where, fmt.Sprintf("dst_port = $%d", n)); args = append(args, f.DstPort); n++
	}
	if f.SrcPort > 0 {
		where = append(where, fmt.Sprintf("src_port = $%d", n)); args = append(args, f.SrcPort); n++
	}
	if f.Proto != "" {
		where = append(where, fmt.Sprintf("proto ILIKE $%d", n)); args = append(args, f.Proto); n++
	}
	if f.UserName != "" {
		where = append(where, fmt.Sprintf("user_name ILIKE $%d", n)); args = append(args, "%"+f.UserName+"%"); n++
	}
	if f.ProcessName != "" {
		where = append(where, fmt.Sprintf("process_name ILIKE $%d", n)); args = append(args, "%"+f.ProcessName+"%"); n++
	}
	if f.CommandLine != "" {
		where = append(where, fmt.Sprintf("command_line ILIKE $%d", n)); args = append(args, "%"+f.CommandLine+"%"); n++
	}
	if f.ImagePath != "" {
		where = append(where, fmt.Sprintf("image_path ILIKE $%d", n)); args = append(args, "%"+f.ImagePath+"%"); n++
	}
	if f.FilePath != "" {
		where = append(where, fmt.Sprintf("file_path ILIKE $%d", n)); args = append(args, "%"+f.FilePath+"%"); n++
	}
	if f.RegKey != "" {
		where = append(where, fmt.Sprintf("reg_key ILIKE $%d", n)); args = append(args, "%"+f.RegKey+"%"); n++
	}
	if f.Channel != "" {
		where = append(where, fmt.Sprintf("channel ILIKE $%d", n)); args = append(args, "%"+f.Channel+"%"); n++
	}
	if f.EventID > 0 {
		where = append(where, fmt.Sprintf("event_id = $%d", n)); args = append(args, f.EventID); n++
	}
	if f.Search != "" {
		v := "%" + f.Search + "%"
		clause := fmt.Sprintf(`(
			host ILIKE $%d OR user_name ILIKE $%d OR process_name ILIKE $%d
			OR command_line ILIKE $%d OR src_ip = $%d OR dst_ip = $%d
			OR image_path ILIKE $%d OR file_path ILIKE $%d OR reg_key ILIKE $%d
			OR reg_value ILIKE $%d
		)`, n, n+1, n+2, n+3, n+4, n+5, n+6, n+7, n+8, n+9)
		where = append(where, clause)
		args = append(args, v, v, v, v, f.Search, f.Search, v, v, v, v)
		n += 10
	}
	if !f.Since.IsZero() {
		where = append(where, fmt.Sprintf("time >= $%d", n)); args = append(args, f.Since.UTC()); n++
	}
	if !f.Until.IsZero() {
		where = append(where, fmt.Sprintf("time <= $%d", n)); args = append(args, f.Until.UTC()); n++
	}

	if f.Limit <= 0 || f.Limit > 1000 {
		f.Limit = 100
	}

	whereStr := strings.Join(where, " AND ")

	var total int64
	db.QueryRowContext(ctx, fmt.Sprintf(`SELECT COUNT(*) FROM events WHERE %s`, whereStr), args...).Scan(&total)

	query := fmt.Sprintf(`
		SELECT id, time, agent_id, host, os, event_type, severity, source,
		       pid, ppid, process_name, command_line, image_path, user_name, domain, logon_id,
		       src_ip, src_port, dst_ip, dst_port, proto,
		       reg_key, reg_value, file_path, file_hash,
		       event_id, channel, record_id
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
		if err := rows.Scan(
			&e.ID, &e.Time, &e.AgentID, &e.Host, &e.OS, &e.EventType, &e.Severity, &e.Source,
			&e.PID, &e.PPID, &e.ProcessName, &e.CommandLine, &e.ImagePath, &e.UserName, &e.Domain, &e.LogonID,
			&e.SrcIP, &e.SrcPort, &e.DstIP, &e.DstPort, &e.Proto,
			&e.RegKey, &e.RegValue, &e.FilePath, &e.FileHash,
			&e.EventID, &e.Channel, &e.RecordID,
		); err != nil {
			return nil, 0, err
		}
		events = append(events, e)
	}
	return events, total, rows.Err()
}

func (db *DB) LatestEvents(ctx context.Context, since time.Time, limit int) ([]Event, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, time, agent_id, host, os, event_type, severity, source,
		       pid, ppid, process_name, command_line, image_path, user_name, domain, logon_id,
		       src_ip, src_port, dst_ip, dst_port, proto,
		       reg_key, reg_value, file_path, file_hash,
		       event_id, channel, record_id
		FROM events WHERE time > $1 ORDER BY time DESC LIMIT $2
	`, since.UTC(), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

func (db *DB) GetEventByID(ctx context.Context, id string) (*Event, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, time, agent_id, host, os, event_type, severity, source, raw,
		       pid, ppid, process_name, command_line, image_path, user_name, domain, logon_id,
		       src_ip, src_port, dst_ip, dst_port, proto,
		       reg_key, reg_value, file_path, file_hash,
		       event_id, channel, record_id
		FROM events WHERE id = $1
	`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	if rows.Next() {
		var e Event
		if err := rows.Scan(
			&e.ID, &e.Time, &e.AgentID, &e.Host, &e.OS, &e.EventType, &e.Severity, &e.Source, &e.Raw,
			&e.PID, &e.PPID, &e.ProcessName, &e.CommandLine, &e.ImagePath, &e.UserName, &e.Domain, &e.LogonID,
			&e.SrcIP, &e.SrcPort, &e.DstIP, &e.DstPort, &e.Proto,
			&e.RegKey, &e.RegValue, &e.FilePath, &e.FileHash,
			&e.EventID, &e.Channel, &e.RecordID,
		); err != nil {
			return nil, err
		}
		return &e, nil
	}
	return nil, fmt.Errorf("event not found")
}

func (db *DB) RelatedEvents(ctx context.Context, host string, t time.Time, excludeID string) ([]Event, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, time, agent_id, host, os, event_type, severity, source,
		       pid, ppid, process_name, command_line, image_path, user_name, domain, logon_id,
		       src_ip, src_port, dst_ip, dst_port, proto,
		       reg_key, reg_value, file_path, file_hash,
		       event_id, channel, record_id
		FROM events
		WHERE host = $1 AND time BETWEEN $2 AND $3 AND id != $4
		ORDER BY time DESC LIMIT 50
	`, host, t.Add(-5*time.Minute).UTC(), t.Add(5*time.Minute).UTC(), excludeID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanEvents(rows)
}

func (db *DB) ExportEvents(ctx context.Context, f EventFilter) ([]Event, error) {
	if f.Limit <= 0 || f.Limit > 10000 {
		f.Limit = 10000
	}
	events, _, err := db.QueryEvents(ctx, f)
	return events, err
}

func scanEvents(rows interface {
	Next() bool
	Scan(...interface{}) error
	Err() error
}) ([]Event, error) {
	var events []Event
	for rows.Next() {
		var e Event
		if err := rows.Scan(
			&e.ID, &e.Time, &e.AgentID, &e.Host, &e.OS, &e.EventType, &e.Severity, &e.Source,
			&e.PID, &e.PPID, &e.ProcessName, &e.CommandLine, &e.ImagePath, &e.UserName, &e.Domain, &e.LogonID,
			&e.SrcIP, &e.SrcPort, &e.DstIP, &e.DstPort, &e.Proto,
			&e.RegKey, &e.RegValue, &e.FilePath, &e.FileHash,
			&e.EventID, &e.Channel, &e.RecordID,
		); err != nil {
			return nil, err
		}
		events = append(events, e)
	}
	return events, rows.Err()
}
