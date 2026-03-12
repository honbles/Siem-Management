package api

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"obsidianwatch/management/internal/auth"
	"obsidianwatch/management/internal/store"
)

// ── WebSocket upgrader ────────────────────────────────────────────────────────

var lrUpgrader = websocket.Upgrader{
	CheckOrigin:     func(r *http.Request) bool { return true },
	ReadBufferSize:  32 * 1024,
	WriteBufferSize: 32 * 1024,
}

// ── Agent tunnel registry ─────────────────────────────────────────────────────
// Agents connect via WebSocket and register here.
// When a session is started, the tunnel is looked up and traffic flows through.

type agentTunnel struct {
	agentID string
	conn    *websocket.Conn
	mu      sync.Mutex
	// pending session channels: sessionToken → data channel
	sessions map[string]chan []byte
}

func (t *agentTunnel) send(data []byte) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.conn.WriteMessage(websocket.BinaryMessage, data)
}

func (t *agentTunnel) sendJSON(v any) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.conn.WriteJSON(v)
}

// TunnelRegistry maps agentID → active WebSocket tunnel from the agent.
type TunnelRegistry struct {
	mu      sync.RWMutex
	tunnels map[string]*agentTunnel
}

func NewTunnelRegistry() *TunnelRegistry {
	return &TunnelRegistry{tunnels: make(map[string]*agentTunnel)}
}

func (r *TunnelRegistry) Register(agentID string, t *agentTunnel) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.tunnels[agentID] = t
}

func (r *TunnelRegistry) Unregister(agentID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.tunnels, agentID)
}

func (r *TunnelRegistry) Get(agentID string) (*agentTunnel, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	t, ok := r.tunnels[agentID]
	return t, ok
}

func (r *TunnelRegistry) ConnectedAgents() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	ids := make([]string, 0, len(r.tunnels))
	for id := range r.tunnels {
		ids = append(ids, id)
	}
	return ids
}

// ── Wire message protocol ─────────────────────────────────────────────────────
// All messages between management and agent are JSON envelopes.

type wireMsg struct {
	Type    string          `json:"type"`
	Token   string          `json:"token,omitempty"`
	Payload json.RawMessage `json:"payload,omitempty"`
	Error   string          `json:"error,omitempty"`
}

// ── Live Response handlers ────────────────────────────────────────────────────

// handleAgentTunnel — agent connects here to establish its control tunnel.
// The agent authenticates with its API key (same as ingest).
// URL: GET /api/v1/live-response/agent-tunnel?agent_id=HOSTNAME
func handleAgentTunnel(db *store.DB, registry *TunnelRegistry, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agentID := r.URL.Query().Get("agent_id")
		if agentID == "" {
			http.Error(w, "agent_id required", 400)
			return
		}

		conn, err := lrUpgrader.Upgrade(w, r, nil)
		if err != nil {
			logger.Warn("lr: agent tunnel upgrade failed", "agent", agentID, "err", err)
			return
		}

		tunnel := &agentTunnel{
			agentID:  agentID,
			conn:     conn,
			sessions: make(map[string]chan []byte),
		}
		registry.Register(agentID, tunnel)
		logger.Info("lr: agent tunnel connected", "agent", agentID)

		defer func() {
			registry.Unregister(agentID)
			conn.Close()
			logger.Info("lr: agent tunnel disconnected", "agent", agentID)
		}()

		// Read loop — agent sends session data back to waiting analyst connections
		for {
			_, msg, err := conn.ReadMessage()
			if err != nil {
				break
			}
			var env wireMsg
			if err := json.Unmarshal(msg, &env); err != nil {
				continue
			}
			// Route data to the correct session channel
			if env.Type == "data" && env.Token != "" {
				tunnel.mu.Lock()
				ch, ok := tunnel.sessions[env.Token]
				tunnel.mu.Unlock()
				if ok {
					select {
					case ch <- env.Payload:
					default:
					}
				}
			}
			// Handle session_end from agent — close the data channel so guacd gets EOF
			if env.Type == "session_end" && env.Token != "" {
				tunnel.mu.Lock()
				ch, ok := tunnel.sessions[env.Token]
				if ok {
					delete(tunnel.sessions, env.Token)
					close(ch)
				}
				tunnel.mu.Unlock()
				logger.Info("lr: agent signaled session end", "token", env.Token[:8]+"...")
			}
			// Handle credential registration from agent
			if env.Type == "register_credentials" {
				var creds struct {
					Username     string `json:"username"`
					PasswordHash string `json:"password_hash"`
					Password     string `json:"password"`
				}
				if err := json.Unmarshal(env.Payload, &creds); err == nil {
					db.UpsertLRCredential(r.Context(), agentID, creds.Username, creds.PasswordHash, creds.Password)
					logger.Info("lr: credentials registered", "agent", agentID, "user", creds.Username)
				}
			}
		}
	}
}

// handleInitiateSession — analyst requests a live response session.
// Returns session token + protocol info for the frontend to open a terminal.
// URL: POST /api/v1/live-response/sessions
func handleInitiateSession(db *store.DB, registry *TunnelRegistry, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			AgentID string `json:"agent_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.AgentID == "" {
			http.Error(w, `{"error":"agent_id required"}`, 400)
			return
		}

		// Get agent info to determine protocol
		agent, err := db.GetAgent(r.Context(), req.AgentID)
		if err != nil {
			http.Error(w, `{"error":"agent not found"}`, 404)
			return
		}

		// Determine protocol from OS
		protocol := "ssh"
		if isWindows(agent.OS) {
			protocol = "rdp"
		}

		// Check agent has credentials registered
		username, _, _, err := db.GetLRCredential(r.Context(), req.AgentID)
		if err != nil {
			writeJSON(w, 503, map[string]string{
				"error": "Agent has no live response credentials. Ensure agent is running v0.3.1+.",
			})
			return
		}

		// Check agent tunnel is connected
		_, connected := registry.Get(req.AgentID)
		if !connected {
			writeJSON(w, 503, map[string]string{
				"error": "Agent tunnel not connected. Agent must be online and running.",
			})
			return
		}

		// Generate session token
		tokenBytes := make([]byte, 16)
		rand.Read(tokenBytes)
		token := hex.EncodeToString(tokenBytes)

		// Get initiator from JWT claim
		initiatedBy := "admin"
		if claims := auth.GetClaims(r); claims != nil {
			initiatedBy = claims.Username
		}

		// Record session
		sessionID, err := db.CreateLRSession(r.Context(), req.AgentID, initiatedBy, token, protocol)
		if err != nil {
			logger.Warn("lr: create session failed", "err", err)
			http.Error(w, `{"error":"db error"}`, 500)
			return
		}

		logger.Info("lr: session initiated",
			"agent", req.AgentID, "session", sessionID,
			"protocol", protocol, "by", initiatedBy)

		writeJSON(w, 200, map[string]interface{}{
			"session_id":    sessionID,
			"session_token": token,
			"agent_id":      req.AgentID,
			"protocol":      protocol,
			"username":      username,
			"hostname":      agent.Hostname,
		})
	}
}

// handleSessionTerminal — analyst WebSocket for interactive terminal.
// For SSH: proxies raw SSH bytes through the agent tunnel.
// For RDP: proxies RDP bytes through the agent tunnel.
// URL: GET /api/v1/live-response/terminal?token=TOKEN
func handleSessionTerminal(db *store.DB, registry *TunnelRegistry, logger *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.URL.Query().Get("token")
		if token == "" {
			http.Error(w, "token required", 400)
			return
		}

		// Validate session
		session, err := db.GetLRSession(r.Context(), token)
		if err != nil || session.Status == "closed" || session.Status == "failed" {
			http.Error(w, "invalid or expired session", 400)
			return
		}

		// Get agent tunnel
		tunnel, ok := registry.Get(session.AgentID)
		if !ok {
			http.Error(w, "agent tunnel not connected", 503)
			return
		}

		// Upgrade analyst connection
		analystConn, err := lrUpgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer analystConn.Close()

		// Register session data channel on tunnel
		dataCh := make(chan []byte, 256)
		tunnel.mu.Lock()
		tunnel.sessions[token] = dataCh
		tunnel.mu.Unlock()

		defer func() {
			tunnel.mu.Lock()
			delete(tunnel.sessions, token)
			tunnel.mu.Unlock()
			db.UpdateLRSessionStatus(context.Background(), token, "closed")
			logger.Info("lr: terminal session closed", "token", token[:8]+"...")
		}()

		db.UpdateLRSessionStatus(r.Context(), token, "active")
		logger.Info("lr: terminal connected", "agent", session.AgentID, "protocol", session.Protocol)

		// Analyst → Agent (forward input)
		go func() {
			for {
				_, msg, err := analystConn.ReadMessage()
				if err != nil {
					return
				}
				env := wireMsg{Type: "data", Token: token, Payload: msg}
				if err := tunnel.sendJSON(env); err != nil {
					return
				}
			}
		}()

		// Agent → Analyst (forward output)
		for {
			select {
			case data, ok := <-dataCh:
				if !ok {
					return
				}
				if err := analystConn.WriteMessage(websocket.BinaryMessage, data); err != nil {
					return
				}
			case <-time.After(30 * time.Minute):
				// Session timeout
				return
			}
		}
	}
}

// handleListSessions — list recent live response sessions.
func handleListSessions(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agentID := r.URL.Query().Get("agent_id")
		sessions, err := db.ListLRSessions(r.Context(), agentID, 100)
		if err != nil {
			http.Error(w, `{"error":"db error"}`, 500)
			return
		}
		if sessions == nil {
			sessions = []store.LRSession{}
		}
		writeJSON(w, 200, sessions)
	}
}

// handleListLRAgents — returns agents with their LR status (credentials registered + tunnel connected).
func handleListLRAgents(db *store.DB, registry *TunnelRegistry) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		agents, err := db.ListAgents(r.Context())
		if err != nil {
			http.Error(w, `{"error":"db error"}`, 500)
			return
		}
		creds, _ := db.ListLRCredentials(r.Context())
		credMap := make(map[string]store.LRCredential)
		for _, c := range creds {
			credMap[c.AgentID] = c
		}
		connected := registry.ConnectedAgents()
		connMap := make(map[string]bool)
		for _, id := range connected {
			connMap[id] = true
		}

		type lrAgent struct {
			store.Agent
			LRReady      bool   `json:"lr_ready"`       // has creds + tunnel connected
			LRUsername   string `json:"lr_username,omitempty"`
			TunnelOnline bool   `json:"tunnel_online"`
		}

		result := make([]lrAgent, 0, len(agents))
		for _, a := range agents {
			la := lrAgent{Agent: a, TunnelOnline: connMap[a.ID]}
			if c, ok := credMap[a.ID]; ok {
				la.LRUsername = c.Username
				la.LRReady = connMap[a.ID]
			}
			result = append(result, la)
		}
		writeJSON(w, 200, result)
	}
}

// handleCloseSession — explicitly close a session.
func handleCloseSession(db *store.DB) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.PathValue("token")
		if token == "" {
			http.Error(w, `{"error":"token required"}`, 400)
			return
		}
		db.UpdateLRSessionStatus(r.Context(), token, "closed")
		writeJSON(w, 200, map[string]string{"status": "closed"})
	}
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func isWindows(os string) bool {
	if os == "" {
		return false
	}
	for _, w := range []string{"windows", "win"} {
		if len(os) >= len(w) {
			match := true
			for i, c := range w {
				if os[i] != byte(c) && os[i] != byte(c-32) {
					match = false
					break
				}
			}
			if match {
				return true
			}
		}
	}
	return false
}

// tcpProxy connects two net.Conns bidirectionally (used in agent-side proxying).
func tcpProxy(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() { io.Copy(a, b); done <- struct{}{} }()
	go func() { io.Copy(b, a); done <- struct{}{} }()
	<-done
}
