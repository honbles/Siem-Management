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
// How guacd works:
//   mgmt-api connects to guacd:4822, does a handshake telling it "RDP target = host:port",
//   then guacd connects to that host:port and the SAME mgmt-api↔guacd connection becomes
//   the bidirectional Guacamole protocol stream.
//
// Since the agent's RDP port is only reachable through the agent WebSocket tunnel,
// we open a local TCP listener and tell guacd to connect there. Our listener accepts
// guacd's RDP connection and pipes it through the agent tunnel.
//
// Flow:
//   Browser <--WS(guacamole protocol)--> mgmt-api <--TCP(guacamole protocol)--> guacd
//                                                                                  |
//   Agent RDP (3389) <--agent tunnel--> mgmt-api listener <--TCP(raw RDP)-----> guacd
func handleGuacamole(db *store.DB, registry *TunnelRegistry, logger *slog.Logger) http.HandlerFunc {
	guacdAddr := "guacd:4822"

	return func(w http.ResponseWriter, r *http.Request) {
		// Parse token — Guacamole.WebSocketTunnel appends ?<uuid> to the URL.
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

		session, err := db.GetLRSession(r.Context(), token)
		if err != nil || session.Status == "closed" || session.Status == "failed" {
			http.Error(w, "invalid or expired session", 400)
			return
		}

		tunnel, ok := registry.Get(session.AgentID)
		if !ok {
			http.Error(w, "agent tunnel not connected", 503)
			return
		}

		username, _, err := db.GetLRCredential(r.Context(), session.AgentID)
		if err != nil {
			http.Error(w, "no credentials for agent", 503)
			return
		}

		// Open local TCP listener FIRST — guacd will connect here as the RDP target.
		// Must bind 0.0.0.0 so guacd container can reach it via "mgmt-api" hostname.
		listener, err := net.Listen("tcp", "0.0.0.0:0")
		if err != nil {
			logger.Error("lr: guac: listener failed", "err", err)
			http.Error(w, "internal error", 500)
			return
		}
		defer listener.Close()
		localPort := listener.Addr().(*net.TCPAddr).Port
		logger.Info("lr: guac: rdp listener opened", "port", localPort)

		// Register agent data channel
		dataCh := make(chan []byte, 512)
		tunnel.mu.Lock()
		tunnel.sessions[token] = dataCh
		tunnel.mu.Unlock()
		defer func() {
			tunnel.mu.Lock()
			delete(tunnel.sessions, token)
			tunnel.mu.Unlock()
		}()

		// Tell agent to forward its RDP/SSH port through the tunnel
		tunnel.sendJSON(wireMsg{Type: "forward_port", Token: token})

		// Accept guacd's connection IN A GOROUTINE so we don't block the handshake.
		// guacd connects to mgmt-api:localPort when it starts the RDP session.
		rdpConnCh := make(chan net.Conn, 1)
		rdpErrCh := make(chan error, 1)
		go func() {
			listener.(*net.TCPListener).SetDeadline(time.Now().Add(20 * time.Second))
			conn, err := listener.Accept()
			if err != nil {
				rdpErrCh <- err
				return
			}
			listener.(*net.TCPListener).SetDeadline(time.Time{})
			rdpConnCh <- conn
		}()

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

		// Connect to guacd
		guacdConn, err := net.DialTimeout("tcp", guacdAddr, 10*time.Second)
		if err != nil {
			logger.Error("lr: guac: cannot connect to guacd", "err", err)
			browserWS.WriteMessage(websocket.TextMessage, []byte("10.error,15.guacd unavailable,1.0;"))
			return
		}
		defer guacdConn.Close()

		// Handshake: tell guacd the RDP target is mgmt-api:localPort
		// guacd will connect to that address to get the RDP stream
		rdpPort := fmt.Sprintf("%d", localPort)
		if err := guacdHandshake(guacdConn, session.Protocol, "mgmt-api", rdpPort, username); err != nil {
			logger.Error("lr: guac: handshake failed", "err", err)
			browserWS.WriteMessage(websocket.TextMessage, []byte("10.error,16.handshake failed,1.0;"))
			return
		}
		logger.Info("lr: guac: handshake done, waiting for guacd to connect", "port", localPort)

		// Wait for guacd to connect to our local listener
		var rdpConn net.Conn
		select {
		case rdpConn = <-rdpConnCh:
			logger.Info("lr: guac: guacd connected for rdp", "port", localPort)
		case err := <-rdpErrCh:
			logger.Error("lr: guac: guacd did not connect", "err", err)
			browserWS.WriteMessage(websocket.TextMessage, []byte("10.error,20.rdp connect timeout,1.0;"))
			return
		}
		defer rdpConn.Close()

		// Pipe: agent tunnel ↔ guacd RDP socket
		go func() {
			for data := range dataCh {
				rdpConn.Write(data)
			}
		}()
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

		// Proxy: browser WS ↔ guacd Guacamole protocol
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

// guacdHandshake performs the Guacamole protocol handshake.
// After this guacd connects to host:port to start the RDP/SSH session.
func guacdHandshake(conn net.Conn, protocol, host, port, username string) error {
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetDeadline(time.Time{})

	reader := bufio.NewReader(conn)

	// 1. Select protocol
	if _, err := fmt.Fprintf(conn, guacInstr("select", protocol)); err != nil {
		return fmt.Errorf("select: %w", err)
	}

	// 2. Read args
	argsLine, err := reader.ReadString(';')
	if err != nil {
		return fmt.Errorf("read args: %w", err)
	}
	_ = argsLine

	// 3. Send size hint
	if _, err := fmt.Fprintf(conn, guacInstr("size", "1280", "800", "96")); err != nil {
		return fmt.Errorf("size: %w", err)
	}

	// 4. Send audio/video/image capabilities
	if _, err := fmt.Fprintf(conn, guacInstr("audio")); err != nil {
		return fmt.Errorf("audio: %w", err)
	}
	if _, err := fmt.Fprintf(conn, guacInstr("video")); err != nil {
		return fmt.Errorf("video: %w", err)
	}
	if _, err := fmt.Fprintf(conn, guacInstr("image", "image/png", "image/jpeg")); err != nil {
		return fmt.Errorf("image: %w", err)
	}

	// 5. Connect with RDP params
	var connectArgs []string
	if protocol == "rdp" {
		connectArgs = []string{
			host, port, username, "",
			"nla",    // security
			"true",   // ignore-cert
			"", "", "", "", "",
			"true",   // enable-font-smoothing
			"", "", "", "", "", "", "", "", "",
			"", "", "", "", "", "", "", "", "",
		}
	} else {
		connectArgs = []string{host, port, username, "", "", ""}
	}

	if _, err := fmt.Fprintf(conn, guacInstr("connect", connectArgs...)); err != nil {
		return fmt.Errorf("connect: %w", err)
	}

	// 6. Read ready
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
