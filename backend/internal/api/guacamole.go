package api

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"obsidianwatch/management/internal/store"
)

// handleGuacamole — browser connects here via Guacamole.js WebSocket.
// We:
//  1. Validate the session token
//  2. Look up the agent tunnel
//  3. Open a local TCP listener on a random port
//  4. Tell the agent to forward its RDP/SSH port to that listener (via tunnel)
//  5. Connect guacd to that local TCP port
//  6. Proxy Guacamole protocol between browser WebSocket ↔ guacd TCP
//
// URL: GET /api/v1/live-response/guacamole?token=TOKEN
func handleGuacamole(db *store.DB, registry *TunnelRegistry, logger *slog.Logger) http.HandlerFunc {
	guacdHost := os.Getenv("GUACD_HOST")
	if guacdHost == "" {
		guacdHost = "guacd"
	}
	guacdPort := os.Getenv("GUACD_PORT")
	if guacdPort == "" {
		guacdPort = "4822"
	}

	return func(w http.ResponseWriter, r *http.Request) {
		// Guacamole.WebSocketTunnel appends ?<uuid> to the URL producing
		// "?token=abc?uuid" — parse the raw query manually and strip the suffix.
		token := ""
		for _, part := range strings.Split(r.URL.RawQuery, "&") {
			if strings.HasPrefix(part, "token=") {
				v := strings.TrimPrefix(part, "token=")
				if idx := strings.Index(v, "?"); idx != -1 {
					v = v[:idx]
				}
				token = strings.TrimSpace(v)
				break
			}
		}
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

		// Get credentials for this agent
		username, passwordHash, err := db.GetLRCredential(r.Context(), session.AgentID)
		if err != nil {
			http.Error(w, "no credentials for agent", 503)
			return
		}
		_ = passwordHash // guacd uses username; password comes from agent account

		// Register data channel — agent's forwarded RDP bytes arrive here.
		dataCh := make(chan []byte, 512)
		tunnel.mu.Lock()
		tunnel.sessions[token] = dataCh
		tunnel.mu.Unlock()
		defer func() {
			tunnel.mu.Lock()
			delete(tunnel.sessions, token)
			tunnel.mu.Unlock()
		}()

		// Tell the agent to start forwarding its RDP/SSH port through the tunnel.
		tunnel.sendJSON(wireMsg{
			Type:  "forward_port",
			Token: token,
		})

		// Open a TCP listener that guacd will connect to.
		// Must bind 0.0.0.0 so guacd (different container) can reach it via "mgmt-api" hostname.
		listener, err := net.Listen("tcp", "0.0.0.0:0")
		if err != nil {
			logger.Error("lr: guac: failed to open local listener", "err", err)
			http.Error(w, "could not open local port", 500)
			return
		}
		localPort := listener.Addr().(*net.TCPAddr).Port
		defer listener.Close()
		logger.Info("lr: guac: local listener opened", "port", localPort, "agent", session.AgentID)

		// Upgrade browser to WebSocket
		upgrader := websocket.Upgrader{
			CheckOrigin:  func(r *http.Request) bool { return true },
			Subprotocols: []string{"guacamole"},
		}
		browserWS, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			logger.Warn("lr: guac: browser upgrade failed", "err", err)
			return
		}
		defer browserWS.Close()

		db.UpdateLRSessionStatus(r.Context(), token, "active")
		logger.Info("lr: guac: session started", "agent", session.AgentID, "protocol", session.Protocol, "token", token[:8]+"...")

		// Connect mgmt-api → guacd (protocol/control connection)
		guacdConn, err := net.DialTimeout("tcp", guacdHost+":"+guacdPort, 10*time.Second)
		if err != nil {
			logger.Error("lr: guac: cannot connect to guacd", "err", err)
			browserWS.WriteMessage(websocket.TextMessage, []byte("10.error,15.guacd unavailable,1.0;"))
			return
		}
		defer guacdConn.Close()

		// Tell guacd to connect to mgmt-api:localPort for the RDP data stream.
		// guacd is in a separate container — use the Docker service hostname.
		remoteHost := os.Getenv("MGMT_API_HOST")
		if remoteHost == "" {
			remoteHost = "mgmt-api"
		}
		remotePort := fmt.Sprintf("%d", localPort)

		if err := guacdHandshake(guacdConn, session.Protocol, remoteHost, remotePort, username, token); err != nil {
			logger.Error("lr: guac: handshake failed", "err", err)
			browserWS.WriteMessage(websocket.TextMessage, []byte("10.error,16.handshake failed,1.0;"))
			return
		}

		// Accept guacd's inbound data connection (guacd connects back to remoteHost:remotePort).
		listener.(*net.TCPListener).SetDeadline(time.Now().Add(15 * time.Second))
		rdpConn, err := listener.Accept()
		if err != nil {
			logger.Error("lr: guac: guacd did not connect back", "err", err)
			browserWS.WriteMessage(websocket.TextMessage, []byte("10.error,20.agent tunnel unavailable,1.0;"))
			return
		}
		defer rdpConn.Close()
		logger.Info("lr: guac: guacd connected to local listener", "port", localPort)

		// Pipe: rdpConn (guacd data socket) ↔ agent tunnel (actual RDP on the endpoint)
		// agent → guacd: drain dataCh into rdpConn
		go func() {
			for data := range dataCh {
				rdpConn.Write(data)
			}
		}()
		// guacd → agent: read rdpConn, send through tunnel as base64 JSON payload
		go func() {
			buf := make([]byte, 32*1024)
			for {
				n, err := rdpConn.Read(buf)
				if n > 0 {
					payload, _ := json.Marshal(buf[:n])
					tunnel.sendJSON(wireMsg{
						Type:    "data",
						Token:   token,
						Payload: json.RawMessage(payload),
					})
				}
				if err != nil {
					return
				}
			}
		}()

		// Proxy: browser WebSocket ↔ guacd protocol connection
		done := make(chan struct{}, 2)

		go func() {
			defer func() { done <- struct{}{} }()
			for {
				_, msg, err := browserWS.ReadMessage()
				if err != nil {
					return
				}
				if _, err := guacdConn.Write(msg); err != nil {
					return
				}
			}
		}()

		go func() {
			defer func() { done <- struct{}{} }()
			buf := make([]byte, 32*1024)
			for {
				n, err := guacdConn.Read(buf)
				if err != nil {
					return
				}
				if err := browserWS.WriteMessage(websocket.TextMessage, buf[:n]); err != nil {
					return
				}
			}
		}()

		<-done

		db.UpdateLRSessionStatus(r.Context(), token, "closed")
		logger.Info("lr: guac: session ended", "token", token[:8]+"...")
	}
}

// guacdHandshake performs the Guacamole protocol handshake with guacd.
// See: https://guacamole.apache.org/doc/gug/guacamole-protocol.html
func guacdHandshake(conn net.Conn, protocol, host, port, username, token string) error {
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetDeadline(time.Time{})

	reader := bufio.NewReader(conn)

	// Send: select <protocol>
	send := func(instruction string) error {
		_, err := fmt.Fprint(conn, instruction)
		return err
	}
	recv := func() (string, error) {
		// Guacamole instructions end with ';'
		line, err := reader.ReadString(';')
		return strings.TrimSpace(line), err
	}

	// 1. Select protocol
	if err := send(guacInstr("select", protocol)); err != nil {
		return fmt.Errorf("select: %w", err)
	}

	// 2. Receive args list from guacd
	argsMsg, err := recv()
	if err != nil || !strings.HasPrefix(argsMsg, "4.args") {
		return fmt.Errorf("expected args, got: %q err: %v", argsMsg, err)
	}

	// 3. Send connect instruction with connection params
	// Build params based on protocol
	var connectInstr string
	if protocol == "rdp" {
		connectInstr = guacInstr("connect",
			host,        // hostname
			port,        // port
			username,    // username
			"",          // password (empty — Windows NLA uses token-based auth via account)
			"",          // domain
			"nla",       // security
			"true",      // ignore-cert
			"",          // client-name
			"1280",      // width
			"800",       // height
			"96",        // dpi
			"en-us-qwerty", // server-layout
			"true",      // enable-font-smoothing
			"false",     // enable-full-window-drag
			"false",     // enable-desktop-composition
			"false",     // enable-menu-animations
			"false",     // disable-bitmap-caching
			"false",     // disable-offscreen-caching
			"false",     // disable-glyph-caching
		)
	} else {
		connectInstr = guacInstr("connect",
			host,     // hostname
			port,     // port
			username, // username
			"",       // password
			"",       // private-key
			"",       // passphrase
		)
	}

	if err := send(connectInstr); err != nil {
		return fmt.Errorf("connect: %w", err)
	}

	// 4. Expect "ready" from guacd
	readyMsg, err := recv()
	if err != nil {
		return fmt.Errorf("ready recv: %w", err)
	}
	if !strings.HasPrefix(readyMsg, "5.ready") {
		return fmt.Errorf("expected ready, got: %q", readyMsg)
	}

	return nil
}

// guacInstr formats a Guacamole protocol instruction.
// Format: LEN.VALUE,LEN.VALUE,...;
func guacInstr(opcode string, args ...string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, fmt.Sprintf("%d.%s", len(opcode), opcode))
	for _, a := range args {
		parts = append(parts, fmt.Sprintf("%d.%s", len(a), a))
	}
	return strings.Join(parts, ",") + ";"
}

