package api

import (
	"bufio"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"obsidianwatch/management/internal/store"
)

// handleGuacamole proxies between the browser (Guacamole.js WebSocket) and guacd (TCP).
//
// Architecture:
//   Browser (Guacamole.js) <--WS--> mgmt-api <--TCP--> guacd <--TCP--> agent RDP port
//
// guacd connects to the agent's RDP port directly — BUT the agent's RDP port is only
// reachable via the agent tunnel (WebSocket). So we open a local TCP listener, accept
// guacd's RDP connection on it, and pipe that to the agent tunnel.
//
// Correct flow:
//  1. Upgrade browser WebSocket
//  2. Connect mgmt-api → guacd (control+data on same conn)
//  3. Tell guacd: "RDP host = mgmt-api, port = localPort"
//  4. In parallel: accept guacd's inbound RDP connection on localPort
//  5. Pipe: guacd-rdp-conn ↔ agent tunnel
//  6. Proxy: browser-WS ↔ guacd-control-conn (Guacamole protocol)
func handleGuacamole(db *store.DB, registry *TunnelRegistry, logger *slog.Logger) http.HandlerFunc {
	guacdAddr := "guacd:4822"

	return func(w http.ResponseWriter, r *http.Request) {
		// Parse token — Guacamole.WebSocketTunnel appends ?<uuid> to URL,
		// turning ?token=abc into ?token=abc?uuid. Strip it manually.
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

		// Get credentials
		username, _, err := db.GetLRCredential(r.Context(), session.AgentID)
		if err != nil {
			http.Error(w, "no credentials for agent", 503)
			return
		}

		// Step 1: Upgrade browser connection to WebSocket
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

		// Step 2: Open local listener — guacd will connect here for the RDP data stream
		listener, err := net.Listen("tcp", "0.0.0.0:0")
		if err != nil {
			logger.Error("lr: guac: listener failed", "err", err)
			browserWS.WriteMessage(websocket.TextMessage, []byte("10.error,14.internal error,1.0;"))
			return
		}
		defer listener.Close()
		localPort := listener.Addr().(*net.TCPAddr).Port
		logger.Info("lr: guac: rdp listener opened", "port", localPort)

		// Step 3: Register agent data channel BEFORE telling agent to forward
		dataCh := make(chan []byte, 512)
		tunnel.mu.Lock()
		tunnel.sessions[token] = dataCh
		tunnel.mu.Unlock()
		defer func() {
			tunnel.mu.Lock()
			delete(tunnel.sessions, token)
			tunnel.mu.Unlock()
		}()

		// Tell agent to start forwarding its RDP/SSH port through the tunnel
		tunnel.sendJSON(wireMsg{Type: "forward_port", Token: token})

		// Step 4: Connect to guacd (this is the Guacamole protocol connection)
		guacdConn, err := net.DialTimeout("tcp", guacdAddr, 10*time.Second)
		if err != nil {
			logger.Error("lr: guac: cannot connect to guacd", "err", err)
			browserWS.WriteMessage(websocket.TextMessage, []byte("10.error,15.guacd unavailable,1.0;"))
			return
		}
		defer guacdConn.Close()

		// Step 5: Handshake — tell guacd to connect to mgmt-api:localPort for RDP
		// guacd will open a NEW TCP connection to mgmt-api:localPort for the actual RDP bytes
		if err := guacdHandshake(guacdConn, session.Protocol, "mgmt-api", fmt.Sprintf("%d", localPort), username); err != nil {
			logger.Error("lr: guac: handshake failed", "err", err)
			browserWS.WriteMessage(websocket.TextMessage, []byte("10.error,16.handshake failed,1.0;"))
			return
		}

		// Step 6: Accept guacd's inbound RDP connection (guacd connects to mgmt-api:localPort)
		listener.(*net.TCPListener).SetDeadline(time.Now().Add(15 * time.Second))
		rdpConn, err := listener.Accept()
		if err != nil {
			logger.Error("lr: guac: guacd rdp connect timeout", "err", err)
			browserWS.WriteMessage(websocket.TextMessage, []byte("10.error,20.rdp connect timeout,1.0;"))
			return
		}
		defer rdpConn.Close()
		listener.(*net.TCPListener).SetDeadline(time.Time{}) // clear deadline
		logger.Info("lr: guac: guacd connected for rdp", "port", localPort)

		// Step 7: Pipe agent tunnel ↔ guacd RDP socket
		// agent → guacd RDP
		go func() {
			for data := range dataCh {
				rdpConn.Write(data)
			}
		}()
		// guacd RDP → agent
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

		// Step 8: Proxy Guacamole protocol — browser WS ↔ guacd control conn
		done := make(chan struct{}, 2)

		// Browser → guacd
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

		// guacd → browser
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
// After this, guacd will open a NEW TCP connection to host:port to get the RDP stream.
// See: https://guacamole.apache.org/doc/gug/guacamole-protocol.html
func guacdHandshake(conn net.Conn, protocol, host, port, username string) error {
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetDeadline(time.Time{})

	reader := bufio.NewReader(conn)

	// Send: select <protocol>
	if _, err := fmt.Fprintf(conn, guacInstr("select", protocol)); err != nil {
		return fmt.Errorf("select: %w", err)
	}

	// Read: args response
	argsLine, err := reader.ReadString(';')
	if err != nil {
		return fmt.Errorf("read args: %w", err)
	}
	_ = argsLine // we don't need to parse all args for basic RDP

	// Build connection args based on protocol
	var connectArgs []string
	if protocol == "rdp" {
		connectArgs = []string{
			host,        // hostname
			port,        // port
			"false",     // ignore-cert? No, use NLA
			username,    // username
			"",          // password (agent account; NLA handles it)
			"",          // domain
			"nla",       // security
			"true",      // ignore-cert
			"",          // client-name
			"1280",      // width
			"800",       // height
			"96",        // dpi
			"en-us-qwerty", // keyboard-layout
			"",          // timezone
			"true",      // enable-font-smoothing
			"true",      // enable-full-window-drag
			"true",      // enable-desktop-composition
			"true",      // enable-menu-animations
		}
	} else {
		// SSH
		connectArgs = []string{
			host,     // hostname
			port,     // port
			username, // username
			"",       // password
			"",       // private-key
			"",       // passphrase
		}
	}

	// Send: connect args
	if _, err := fmt.Fprintf(conn, guacInstr("connect", connectArgs...)); err != nil {
		return fmt.Errorf("connect: %w", err)
	}

	// Read: ready response
	readyLine, err := reader.ReadString(';')
	if err != nil {
		return fmt.Errorf("read ready: %w", err)
	}
	if !strings.Contains(readyLine, "ready") {
		return fmt.Errorf("expected ready, got: %s", readyLine)
	}

	return nil
}

// guacInstr formats a Guacamole protocol instruction.
func guacInstr(opcode string, args ...string) string {
	parts := make([]string, 0, len(args)+1)
	parts = append(parts, fmt.Sprintf("%d.%s", len(opcode), opcode))
	for _, a := range args {
		parts = append(parts, fmt.Sprintf("%d.%s", len(a), a))
	}
	return strings.Join(parts, ",") + ";"
}
