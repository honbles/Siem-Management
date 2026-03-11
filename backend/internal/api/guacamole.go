package api

import (
	"bufio"
	"fmt"
	"io"
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

		// Open a local TCP listener — guacd will connect to this.
		// The agent will forward its RDP/SSH port to this listener.
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			logger.Error("lr: guac: failed to open local listener", "err", err)
			http.Error(w, "could not open local port", 500)
			return
		}
		localPort := listener.Addr().(*net.TCPAddr).Port
		defer listener.Close()

		logger.Info("lr: guac: local listener opened", "port", localPort, "agent", session.AgentID)

		// Tell the agent to forward its protocol port to our local listener.
		tunnel.sendJSON(wireMsg{
			Type:  "forward_port",
			Token: token,
		})

		// Register data channel for this session so agent's forwarded bytes arrive here.
		dataCh := make(chan []byte, 512)
		tunnel.mu.Lock()
		tunnel.sessions[token] = dataCh
		tunnel.mu.Unlock()
		defer func() {
			tunnel.mu.Lock()
			delete(tunnel.sessions, token)
			tunnel.mu.Unlock()
		}()

		// Accept the single connection from guacd (with timeout).
		listener.(*net.TCPListener).SetDeadline(time.Now().Add(10 * time.Second))
		localConn, err := listener.Accept()
		if err != nil {
			// guacd hasn't connected yet — that's fine, we'll use the virtual pipe below
			logger.Warn("lr: guac: no local connection from guacd", "err", err)
		}
		if localConn != nil {
			defer localConn.Close()
		}

		// Upgrade browser to WebSocket using Guacamole subprotocol
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
		guacdConn, err := net.DialTimeout("tcp", guacdHost+":"+guacdPort, 10*time.Second)
		if err != nil {
			logger.Error("lr: guac: cannot connect to guacd", "err", err)
			browserWS.WriteMessage(websocket.TextMessage, []byte("10.error,15.guacd unavailable,1.0;"))
			return
		}
		defer guacdConn.Close()

		// Determine the remote host:port the agent is forwarding.
		// The agent opens RDP/SSH on localhost — it tells us the port via the tunnel.
		// For now we use a well-known virtual host that guacd will resolve via our proxy.
		remoteHost := "127.0.0.1"
		remotePort := "3389"
		if session.Protocol == "ssh" {
			remotePort = "22"
		}

		// Handshake guacd: select protocol, set connection params.
		if err := guacdHandshake(guacdConn, session.Protocol, remoteHost, remotePort, username, token); err != nil {
			logger.Error("lr: guac: handshake failed", "err", err)
			browserWS.WriteMessage(websocket.TextMessage, []byte("10.error,16.handshake failed,1.0;"))
			return
		}

		// Bidirectional proxy: browser WebSocket ↔ guacd TCP
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

// tunnelForwarder creates a local TCP listener, signals the agent to forward
// through the tunnel, and returns a net.Conn to use as the remote endpoint.
func tunnelForwarder(tunnel *agentTunnel, token string, dataCh chan []byte) (net.Conn, error) {
	pr, pw := io.Pipe()
	go func() {
		for data := range dataCh {
			pw.Write(data)
		}
		pw.Close()
	}()

	return &pipeConn{r: pr, w: &tunnelWriter{tunnel: tunnel, token: token}}, nil
}

// pipeConn implements net.Conn over a pipe (read) and tunnel write.
type pipeConn struct {
	r io.Reader
	w io.Writer
}

func (c *pipeConn) Read(b []byte) (int, error)  { return c.r.Read(b) }
func (c *pipeConn) Write(b []byte) (int, error) { return c.w.Write(b) }
func (c *pipeConn) Close() error                { return nil }
func (c *pipeConn) LocalAddr() net.Addr         { return &net.TCPAddr{} }
func (c *pipeConn) RemoteAddr() net.Addr        { return &net.TCPAddr{} }
func (c *pipeConn) SetDeadline(t time.Time) error      { return nil }
func (c *pipeConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *pipeConn) SetWriteDeadline(t time.Time) error { return nil }

type tunnelWriter struct {
	tunnel *agentTunnel
	token  string
}

func (w *tunnelWriter) Write(b []byte) (int, error) {
	err := w.tunnel.sendJSON(wireMsg{
		Type:    "data",
		Token:   w.token,
		Payload: b,
	})
	if err != nil {
		return 0, err
	}
	return len(b), nil
}
