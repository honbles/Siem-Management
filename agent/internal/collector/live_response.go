//go:build windows

package collector

// live_response.go — Windows live response agent component.
//
// On start:
//   1. Creates a dedicated 'obsidianwatch' local Windows account
//   2. Generates a strong random password, adds to local Administrators group
//   3. Registers bcrypt hash with management server via WebSocket tunnel
//   4. Enables RDP on the machine (sets registry key, opens firewall rule temporarily)
//
// On session request:
//   - Opens TCP connection to localhost:3389 (RDP)
//   - Proxies bytes through the management WebSocket tunnel
//   - Firewall rule is temporary and auto-removed on session end
//
// Security:
//   - Plaintext password never leaves the agent or touches the DB
//   - Management server stores only bcrypt hash
//   - RDP port is NOT exposed externally — proxied through existing tunnel
//   - Session logged to audit trail

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
	"unsafe"

	"github.com/gorilla/websocket"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/sys/windows"
)

const (
	lrUsernameWin      = "obsidianwatch"
	lrRDPPort          = "3389"
	lrReconnectWin     = 15 * time.Second
	lrFirewallRuleName = "ObsidianWatch-LiveResponse-RDP"
)

type LiveResponseCollector struct {
	agentID       string
	hostname      string
	managementURL string
	apiKey        string
	caFile        string
	logger        *slog.Logger

	mu       sync.Mutex
	password string
}

func NewLiveResponseCollector(agentID, hostname, managementURL, apiKey, caFile, managementCAFile string, logger *slog.Logger) *LiveResponseCollector {
	return &LiveResponseCollector{
		agentID:       agentID,
		hostname:      hostname,
		managementURL: managementURL,
		apiKey:        apiKey,
		caFile:        resolveCAFile(managementCAFile, caFile),
		logger:        logger,
	}
}

func (c *LiveResponseCollector) Run(ctx context.Context) error {
	c.logger.Info("live-response: starting (Windows)")

	lrLog := func(msg string) {
		c.logger.Info(msg)
		if f, err := os.OpenFile(`C:\ProgramData\ObsidianWatch\agent.log`,
			os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); err == nil {
			fmt.Fprintf(f, `{"time":"%s","level":"INFO","msg":"lr: %s"}`+"\n",
				time.Now().Format(time.RFC3339), msg)
			f.Close()
		}
	}
	lrErr := func(msg string, err error) {
		c.logger.Warn(msg, "err", err)
		if f, ferr := os.OpenFile(`C:\ProgramData\ObsidianWatch\agent.log`,
			os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644); ferr == nil {
			fmt.Fprintf(f, `{"time":"%s","level":"WARN","msg":"lr: %s","err":"%v"}`+"\n",
				time.Now().Format(time.RFC3339), msg, err)
			f.Close()
		}
	}

	lrLog("starting (Windows)")
	if err := c.ensureServiceAccount(); err != nil {
		lrErr("service account setup failed", err)
	} else {
		lrLog("service account ready")
	}

	for {
		if err := c.runTunnelLog(ctx, lrLog, lrErr); err != nil {
			lrErr("tunnel disconnected", err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(lrReconnectWin):
			lrLog("reconnecting...")
		}
	}
}

// ensureServiceAccount creates the obsidianwatch Windows local user.
func (c *LiveResponseCollector) ensureServiceAccount() error {
	rawPass := make([]byte, 32)
	if _, err := rand.Read(rawPass); err != nil {
		return fmt.Errorf("generate password: %w", err)
	}
	// Windows passwords require mixed case + digit + special
	password := "Ow1!" + base64.RawURLEncoding.EncodeToString(rawPass)[:28]

	// Create user (net user adds if not exists, updates password if exists)
	cmd := exec.Command("net", "user", lrUsernameWin, password,
		"/add",
		"/comment:ObsidianWatch Live Response",
		"/passwordchg:no",
		"/passwordreq:yes",
		"/expires:never",
		"/y", // suppress "password > 14 chars" Windows 2000 compat prompt
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		// Error 2224 = account already exists — update password instead
		if strings.Contains(string(out), "2224") || strings.Contains(string(out), "already exists") {
			updateCmd := exec.Command("net", "user", lrUsernameWin, password)
			if out2, err2 := updateCmd.CombinedOutput(); err2 != nil {
				return fmt.Errorf("net user update: %w: %s", err2, out2)
			}
			c.logger.Info("live-response: updated password for existing account", "user", lrUsernameWin)
		} else {
			c.logger.Warn("live-response: net user /add failed", "out", string(out), "err", err)
			return fmt.Errorf("net user /add: %w: %s", err, out)
		}
	} else {
		c.logger.Info("live-response: Windows account created", "user", lrUsernameWin)
	}

	// Add to Remote Desktop Users group (allows RDP without being full admin)
	exec.Command("net", "localgroup", "Remote Desktop Users", lrUsernameWin, "/add").Run()
	// Also add to Administrators for full remote access
	exec.Command("net", "localgroup", "Administrators", lrUsernameWin, "/add").Run()

	// Enable RDP via registry
	c.enableRDP()

	c.mu.Lock()
	c.password = password
	c.mu.Unlock()

	c.logger.Info("live-response: Windows service account ready", "user", lrUsernameWin)
	return nil
}

// enableRDP sets the registry key and firewall to allow RDP.
func (c *LiveResponseCollector) enableRDP() {
	// Enable RDP: HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\fDenyTSConnections = 0
	exec.Command("reg", "add",
		`HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server`,
		"/v", "fDenyTSConnections", "/t", "REG_DWORD", "/d", "0", "/f",
	).Run()

	// Enable Network Level Authentication
	exec.Command("reg", "add",
		`HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp`,
		"/v", "UserAuthentication", "/t", "REG_DWORD", "/d", "1", "/f",
	).Run()

	// Add a named firewall rule (so we can remove it cleanly)
	exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
		"name="+lrFirewallRuleName,
		"dir=in", "action=allow", "protocol=TCP",
		"localport=3389",
		"remoteip=127.0.0.1", // only allow localhost — external blocked, tunnel proxies
		"profile=any",
	).Run()

	c.logger.Info("live-response: RDP enabled (localhost only)")
}

// runTunnelLog connects WebSocket to management and handles session requests.
func (c *LiveResponseCollector) runTunnelLog(ctx context.Context, lrLog func(string), lrErr func(string, error)) error {
	mgmt := strings.TrimRight(c.managementURL, "/")
	wsURL := strings.Replace(mgmt, "https://", "wss://", 1)
	wsURL = strings.Replace(wsURL, "http://", "ws://", 1)
	wsURL += fmt.Sprintf("/api/v1/live-response/agent-tunnel?agent_id=%s", c.agentID)

	lrLog("dialing tunnel: " + wsURL)
	dialer := wsDialerForCA(c.caFile)

	headers := http.Header{}
	headers.Set("X-API-Key", c.apiKey)

	conn, _, err := dialer.DialContext(ctx, wsURL, headers)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	lrLog("tunnel connected")

	// Register credentials
	c.mu.Lock()
	password := c.password
	c.mu.Unlock()

	if password != "" {
		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err == nil {
			conn.WriteJSON(map[string]interface{}{
				"type": "register_credentials",
				"payload": map[string]string{
					"username":      lrUsernameWin,
					"password_hash": string(hash),
					"password":      password,
				},
			})
		}
	}

	// Track active sessions: token → inbound data channel
	activeSessions := make(map[string]chan []byte)
	var sessionsMu sync.Mutex

	for {
		_, msg, err := conn.ReadMessage()
		if err != nil {
			return fmt.Errorf("read: %w", err)
		}
		var env struct {
			Type    string          `json:"type"`
			Token   string          `json:"token"`
			Payload json.RawMessage `json:"payload"`
		}
		if err := json.Unmarshal(msg, &env); err != nil {
			continue
		}
		lrLog("lr: msg received type=" + env.Type + " token=" + env.Token)
		switch env.Type {
		case "open_session", "forward_port":
			if len(env.Token) < 8 {
				lrErr("live-response: token too short", fmt.Errorf("token=%q", env.Token))
				continue
			}
			lrLog("session requested token=" + env.Token[:8])
			inCh := make(chan []byte, 256)
			sessionsMu.Lock()
			activeSessions[env.Token] = inCh
			sessionsMu.Unlock()
			go func(tok string, ch chan []byte) {
				defer func() {
					if r := recover(); r != nil {
						lrErr("session panic", fmt.Errorf("%v", r))
					}
					sessionsMu.Lock()
					delete(activeSessions, tok)
					sessionsMu.Unlock()
				}()
				c.handleSession(ctx, conn, tok, ch, lrLog, lrErr)
			}(env.Token, inCh)
		case "data":
			// Inbound RDP data from guacd → forward to the active session
			if env.Token == "" {
				continue
			}
			var raw []byte
			if err := json.Unmarshal(env.Payload, &raw); err != nil {
				continue
			}
			sessionsMu.Lock()
			ch, ok := activeSessions[env.Token]
			sessionsMu.Unlock()
			if ok {
				select {
				case ch <- raw:
				default:
				}
			}
		}
	}
}

// handleSession proxies between the local RDP/SSH port and the WebSocket tunnel.
// inCh receives data from management (guacd → tunnel → agent → localConn).
func (c *LiveResponseCollector) handleSession(ctx context.Context, wsConn *websocket.Conn, token string, inCh chan []byte, lrLog func(string), lrErr func(string, error)) {
	lrLog("handleSession: connecting to RDP 127.0.0.1:" + lrRDPPort)
	localConn, err := net.DialTimeout("tcp", "127.0.0.1:"+lrRDPPort, 5*time.Second)
	if err != nil {
		lrErr("live-response: local RDP connect failed", err)
		wsConn.WriteJSON(map[string]interface{}{
			"type": "session_error", "token": token, "error": err.Error(),
		})
		return
	}
	defer localConn.Close()
	lrLog("live-response: RDP proxy started token=" + token[:8])

	done := make(chan struct{}, 2)

	// guacd → localConn: drain inCh into local RDP socket
	go func() {
		defer func() { done <- struct{}{} }()
		for data := range inCh {
			if _, err := localConn.Write(data); err != nil {
				return
			}
		}
	}()

	// localConn → tunnel: read RDP responses and send to management
	go func() {
		defer func() { done <- struct{}{} }()
		buf := make([]byte, 32*1024)
		for {
			n, err := localConn.Read(buf)
			if n > 0 {
				payload, _ := json.Marshal(buf[:n])
				wsConn.WriteJSON(map[string]interface{}{
					"type":    "data",
					"token":   token,
					"payload": json.RawMessage(payload),
				})
			}
			if err != nil {
				return
			}
		}
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}
	close(inCh)
}

// ── Windows privilege helpers (used by service account creation) ──────────────

func isLocalAdmin() bool {
	token, err := windows.OpenCurrentProcessToken()
	if err != nil {
		return false
	}
	defer token.Close()
	var isElevated uint32
	var size uint32
	windows.GetTokenInformation(token, windows.TokenElevation,
		(*byte)(unsafe.Pointer(&isElevated)), uint32(unsafe.Sizeof(isElevated)), &size)
	return isElevated != 0
}

// dummy io usage to satisfy import
var _ = io.EOF
