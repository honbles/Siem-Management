package store

import (
	"context"
	"time"
)

type StatPoint struct {
	Time  time.Time `json:"time"`
	Count int64     `json:"count"`
}

// EventsOverTime returns event counts bucketed by hour for the last N hours.
func (db *DB) EventsOverTime(ctx context.Context, hours int) ([]StatPoint, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT time_bucket('1 hour', time) AS bucket, COUNT(*) as count
		FROM events
		WHERE time > NOW() - ($1 || ' hours')::INTERVAL
		GROUP BY bucket
		ORDER BY bucket ASC
	`, hours)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var points []StatPoint
	for rows.Next() {
		var p StatPoint
		if err := rows.Scan(&p.Time, &p.Count); err != nil {
			return nil, err
		}
		points = append(points, p)
	}
	return points, rows.Err()
}

// EventsBySeverity returns event counts grouped by severity for last 24h.
func (db *DB) EventsBySeverity(ctx context.Context) ([]map[string]interface{}, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT severity, COUNT(*) as count
		FROM events
		WHERE time > NOW() - INTERVAL '24 hours'
		GROUP BY severity
		ORDER BY severity
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	labels := map[int]string{1: "Info", 2: "Low", 3: "Medium", 4: "High", 5: "Critical"}
	var result []map[string]interface{}
	for rows.Next() {
		var sev int
		var count int64
		rows.Scan(&sev, &count)
		result = append(result, map[string]interface{}{
			"severity": sev,
			"label":    labels[sev],
			"count":    count,
		})
	}
	return result, rows.Err()
}

// EventsByType returns event counts grouped by event_type for last 24h.
func (db *DB) EventsByType(ctx context.Context) ([]map[string]interface{}, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT event_type, COUNT(*) as count
		FROM events
		WHERE time > NOW() - INTERVAL '24 hours'
		GROUP BY event_type
		ORDER BY count DESC
		LIMIT 10
	`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []map[string]interface{}
	for rows.Next() {
		var evType string
		var count int64
		rows.Scan(&evType, &count)
		result = append(result, map[string]interface{}{
			"event_type": evType,
			"count":      count,
		})
	}
	return result, rows.Err()
}

// Summary returns top-level counts for the dashboard header.
func (db *DB) Summary(ctx context.Context) (map[string]interface{}, error) {
	var totalEvents, eventsToday, highSeverityToday int64

	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events`).Scan(&totalEvents)
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE time > NOW() - INTERVAL '24 hours'`).Scan(&eventsToday)
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM events WHERE severity >= 4 AND time > NOW() - INTERVAL '24 hours'`).Scan(&highSeverityToday)

	var totalAgents, onlineAgents int64
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM agents`).Scan(&totalAgents)
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM agents WHERE last_seen > NOW() - INTERVAL '2 minutes'`).Scan(&onlineAgents)

	var openAlerts int64
	db.QueryRowContext(ctx, `SELECT COUNT(*) FROM alerts WHERE status = 'open'`).Scan(&openAlerts)

	return map[string]interface{}{
		"total_events":        totalEvents,
		"events_today":        eventsToday,
		"high_severity_today": highSeverityToday,
		"total_agents":        totalAgents,
		"online_agents":       onlineAgents,
		"open_alerts":         openAlerts,
	}, nil
}

// ThreatIntel returns DNS domain query counts, top source IPs, top processes, top users.
func (db *DB) ThreatIntel(ctx context.Context) (map[string]interface{}, error) {
	result := map[string]interface{}{}

	// Top queried DNS domains
	rows, err := db.QueryContext(ctx, `
		SELECT raw->>'query_name' as domain, COUNT(*) as count
		FROM events
		WHERE source = 'DNS-Client'
		  AND raw->>'query_name' IS NOT NULL
		  AND time > NOW() - INTERVAL '24 hours'
		GROUP BY raw->>'query_name'
		ORDER BY count DESC
		LIMIT 20
	`)
	if err == nil {
		var domains []map[string]interface{}
		for rows.Next() {
			var domain string
			var count int64
			rows.Scan(&domain, &count)
			domains = append(domains, map[string]interface{}{"domain": domain, "count": count})
		}
		rows.Close()
		result["top_domains"] = domains
	}

	// Top source IPs
	rows, err = db.QueryContext(ctx, `
		SELECT src_ip, COUNT(*) as count
		FROM events
		WHERE src_ip IS NOT NULL AND src_ip != ''
		  AND time > NOW() - INTERVAL '24 hours'
		GROUP BY src_ip
		ORDER BY count DESC
		LIMIT 15
	`)
	if err == nil {
		var ips []map[string]interface{}
		for rows.Next() {
			var ip string
			var count int64
			rows.Scan(&ip, &count)
			ips = append(ips, map[string]interface{}{"ip": ip, "count": count})
		}
		rows.Close()
		result["top_src_ips"] = ips
	}

	// Top destination IPs
	rows, err = db.QueryContext(ctx, `
		SELECT dst_ip, COUNT(*) as count
		FROM events
		WHERE dst_ip IS NOT NULL AND dst_ip != ''
		  AND time > NOW() - INTERVAL '24 hours'
		GROUP BY dst_ip
		ORDER BY count DESC
		LIMIT 15
	`)
	if err == nil {
		var ips []map[string]interface{}
		for rows.Next() {
			var ip string
			var count int64
			rows.Scan(&ip, &count)
			ips = append(ips, map[string]interface{}{"ip": ip, "count": count})
		}
		rows.Close()
		result["top_dst_ips"] = ips
	}

	// Top processes
	rows, err = db.QueryContext(ctx, `
		SELECT process_name, COUNT(*) as count
		FROM events
		WHERE process_name IS NOT NULL
		  AND time > NOW() - INTERVAL '24 hours'
		GROUP BY process_name
		ORDER BY count DESC
		LIMIT 15
	`)
	if err == nil {
		var procs []map[string]interface{}
		for rows.Next() {
			var proc string
			var count int64
			rows.Scan(&proc, &count)
			procs = append(procs, map[string]interface{}{"process": proc, "count": count})
		}
		rows.Close()
		result["top_processes"] = procs
	}

	// Top users
	rows, err = db.QueryContext(ctx, `
		SELECT user_name, COUNT(*) as count
		FROM events
		WHERE user_name IS NOT NULL AND user_name != ''
		  AND time > NOW() - INTERVAL '24 hours'
		GROUP BY user_name
		ORDER BY count DESC
		LIMIT 15
	`)
	if err == nil {
		var users []map[string]interface{}
		for rows.Next() {
			var user string
			var count int64
			rows.Scan(&user, &count)
			users = append(users, map[string]interface{}{"user": user, "count": count})
		}
		rows.Close()
		result["top_users"] = users
	}

	// Suspicious domains (known bad patterns)
	suspicious := []string{"rustdesk", "urban-vpn", "ngrok", "cobalt", "metasploit"}
	rows, err = db.QueryContext(ctx, `
		SELECT raw->>'query_name' as domain, COUNT(*) as count
		FROM events
		WHERE source = 'DNS-Client'
		  AND time > NOW() - INTERVAL '24 hours'
		  AND (
			raw->>'query_name' ILIKE '%rustdesk%' OR
			raw->>'query_name' ILIKE '%urban-vpn%' OR
			raw->>'query_name' ILIKE '%ngrok%' OR
			raw->>'query_name' ILIKE '%cobalt%' OR
			raw->>'query_name' ILIKE '%.onion%'
		  )
		GROUP BY raw->>'query_name'
		ORDER BY count DESC
	`)
	_ = suspicious
	if err == nil {
		var flagged []map[string]interface{}
		for rows.Next() {
			var domain string
			var count int64
			rows.Scan(&domain, &count)
			flagged = append(flagged, map[string]interface{}{"domain": domain, "count": count})
		}
		rows.Close()
		result["flagged_domains"] = flagged
	}

	return result, nil
}
