package store

import (
	"context"
	"fmt"
	"time"
)

type Alert struct {
	ID             int64      `json:"id"`
	CreatedAt      time.Time  `json:"created_at"`
	Title          string     `json:"title"`
	Description    string     `json:"description"`
	Severity       int        `json:"severity"`
	Status         string     `json:"status"`
	AgentID        string     `json:"agent_id"`
	Host           string     `json:"host"`
	EventType      string     `json:"event_type"`
	EventID        string     `json:"event_id"`
	AcknowledgedBy *string    `json:"acknowledged_by,omitempty"`
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty"`
}

func (db *DB) ListAlerts(ctx context.Context, status string, limit int) ([]Alert, error) {
	if limit <= 0 {
		limit = 100
	}
	query := `
		SELECT id, created_at, title, description, severity, status,
		       COALESCE(agent_id,''), COALESCE(host,''), COALESCE(event_type,''),
		       COALESCE(event_id,''), acknowledged_by, acknowledged_at
		FROM alerts`
	args := []interface{}{}
	if status != "" {
		query += ` WHERE status = $1`
		args = append(args, status)
	}
	query += fmt.Sprintf(` ORDER BY created_at DESC LIMIT %d`, limit)

	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var alerts []Alert
	for rows.Next() {
		var a Alert
		if err := rows.Scan(
			&a.ID, &a.CreatedAt, &a.Title, &a.Description, &a.Severity, &a.Status,
			&a.AgentID, &a.Host, &a.EventType, &a.EventID,
			&a.AcknowledgedBy, &a.AcknowledgedAt,
		); err != nil {
			return nil, err
		}
		alerts = append(alerts, a)
	}
	return alerts, rows.Err()
}

func (db *DB) CreateAlert(ctx context.Context, a Alert) (int64, error) {
	var id int64
	err := db.QueryRowContext(ctx, `
		INSERT INTO alerts (title, description, severity, status, agent_id, host, event_type, event_id)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
		RETURNING id
	`, a.Title, a.Description, a.Severity, "open",
		a.AgentID, a.Host, a.EventType, a.EventID,
	).Scan(&id)
	return id, err
}

func (db *DB) AcknowledgeAlert(ctx context.Context, id int64, username string) error {
	res, err := db.ExecContext(ctx, `
		UPDATE alerts
		SET status = 'acknowledged', acknowledged_by = $1, acknowledged_at = NOW()
		WHERE id = $2 AND status = 'open'
	`, username, id)
	if err != nil {
		return err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return fmt.Errorf("alert not found or already acknowledged")
	}
	return nil
}

func (db *DB) CloseAlert(ctx context.Context, id int64, username string) error {
	_, err := db.ExecContext(ctx, `
		UPDATE alerts SET status = 'closed', acknowledged_by = $1, acknowledged_at = NOW()
		WHERE id = $2
	`, username, id)
	return err
}

// CountAlertsByStatus returns open/acknowledged/closed counts.
func (db *DB) CountAlertsByStatus(ctx context.Context) (map[string]int64, error) {
	rows, err := db.QueryContext(ctx, `SELECT status, COUNT(*) FROM alerts GROUP BY status`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := map[string]int64{"open": 0, "acknowledged": 0, "closed": 0}
	for rows.Next() {
		var status string
		var count int64
		rows.Scan(&status, &count)
		result[status] = count
	}
	return result, nil
}

// AlertExists checks if an alert already exists for a given event to avoid duplicates.
func (db *DB) AlertExists(ctx context.Context, eventID string) (bool, error) {
	var count int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM alerts WHERE event_id = $1`, eventID).Scan(&count)
	return count > 0, err
}

// GetAlert fetches a single alert by ID.
func (db *DB) GetAlert(ctx context.Context, id int64) (*Alert, error) {
	var a Alert
	err := db.QueryRowContext(ctx, `
		SELECT id, created_at, title, description, severity, status,
		       COALESCE(agent_id,''), COALESCE(host,''), COALESCE(event_type,''),
		       COALESCE(event_id,''), acknowledged_by, acknowledged_at
		FROM alerts WHERE id = $1
	`, id).Scan(
		&a.ID, &a.CreatedAt, &a.Title, &a.Description, &a.Severity, &a.Status,
		&a.AgentID, &a.Host, &a.EventType, &a.EventID,
		&a.AcknowledgedBy, &a.AcknowledgedAt,
	)
	if err != nil {
		return nil, err
	}
	return &a, nil
}
