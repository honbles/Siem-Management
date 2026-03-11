import { useEffect, useState, useRef, useCallback } from 'react'
import { Terminal, Monitor, Server, Globe, Wifi, WifiOff,
         Play, Square, Clock, User, Shield, AlertTriangle, RefreshCw,
         ChevronRight, X, Activity } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import api from '../api/client'

// ── OS helpers ────────────────────────────────────────────────────────────────
function getProtocol(os) {
  return (os || '').toLowerCase().includes('win') ? 'rdp' : 'ssh'
}

function OSIcon({ os }) {
  const l = (os || '').toLowerCase()
  if (l.includes('win'))   return <Monitor size={14} className="text-blue-400" />
  if (l.includes('linux')) return <Server  size={14} className="text-orange-400" />
  return                          <Globe   size={14} className="text-siem-muted" />
}

// ── Status badge ──────────────────────────────────────────────────────────────
function StatusBadge({ status }) {
  const map = {
    active:  'bg-emerald-950/40 text-emerald-400 border-emerald-700',
    pending: 'bg-yellow-950/40 text-yellow-400 border-yellow-700',
    closed:  'bg-siem-surface text-siem-muted border-siem-border',
    failed:  'bg-red-950/40 text-red-400 border-red-700',
  }
  return (
    <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${map[status] || map.closed}`}>
      {status}
    </span>
  )
}

// ── SSH Terminal via xterm.js ─────────────────────────────────────────────────
function SSHTerminal({ session, token, onClose }) {
  const termRef = useRef(null)
  const xtermRef = useRef(null)
  const wsRef = useRef(null)
  const [connected, setConnected] = useState(false)
  const [error, setError] = useState(null)

  useEffect(() => {
    if (!termRef.current || !session) return

    // Load xterm.js from CDN
    const loadXterm = async () => {
      if (!window.Terminal) {
        await Promise.all([
          new Promise(res => {
            const link = document.createElement('link')
            link.rel = 'stylesheet'
            link.href = 'https://cdnjs.cloudflare.com/ajax/libs/xterm/5.3.0/xterm.min.css'
            link.onload = res
            document.head.appendChild(link)
          }),
          new Promise(res => {
            const s = document.createElement('script')
            s.src = 'https://cdnjs.cloudflare.com/ajax/libs/xterm/5.3.0/xterm.min.js'
            s.onload = res
            document.head.appendChild(s)
          }),
        ])
      }

      const term = new window.Terminal({
        cursorBlink: true,
        fontSize: 13,
        fontFamily: '"JetBrains Mono", "Fira Code", "Courier New", monospace',
        theme: {
          background: '#0a0f1a',
          foreground: '#e2e8f0',
          cursor:     '#34d399',
          black:      '#1e293b',
          red:        '#f87171',
          green:      '#34d399',
          yellow:     '#fbbf24',
          blue:       '#60a5fa',
          magenta:    '#c084fc',
          cyan:       '#22d3ee',
          white:      '#e2e8f0',
          brightBlack:'#475569',
        },
        rows: 30,
        cols: 120,
      })

      term.open(termRef.current)
      term.writeln('\r\n\x1b[32m ObsidianWatch Live Response\x1b[0m')
      term.writeln(` Connecting to \x1b[36m${session.hostname}\x1b[0m via ${session.protocol.toUpperCase()}...`)
      term.writeln('')
      xtermRef.current = term

      // Connect WebSocket to management terminal endpoint
      const proto = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      const wsURL = `${proto}//${window.location.host}/api/v1/live-response/terminal?token=${session.session_token}`

      // Get JWT token from localStorage for auth
      const jwtToken = localStorage.getItem('token')
      const ws = new WebSocket(wsURL + `&auth=${jwtToken}`)
      ws.binaryType = 'arraybuffer'
      wsRef.current = ws

      ws.onopen = () => {
        setConnected(true)
        term.writeln('\x1b[32m✓ Tunnel established\x1b[0m\r\n')
      }

      ws.onmessage = (evt) => {
        const data = evt.data instanceof ArrayBuffer
          ? new Uint8Array(evt.data)
          : new TextEncoder().encode(evt.data)
        term.write(data)
      }

      ws.onerror = () => {
        setError('WebSocket connection failed')
        term.writeln('\r\n\x1b[31m✗ Connection failed\x1b[0m')
      }

      ws.onclose = () => {
        setConnected(false)
        term.writeln('\r\n\x1b[33m● Session closed\x1b[0m')
      }

      // Terminal input → WebSocket
      term.onData(data => {
        if (ws.readyState === WebSocket.OPEN) {
          ws.send(new TextEncoder().encode(data))
        }
      })
    }

    loadXterm()

    return () => {
      if (wsRef.current) wsRef.current.close()
      if (xtermRef.current) xtermRef.current.dispose()
    }
  }, [session])

  return (
    <div className="flex flex-col h-full bg-[#0a0f1a]">
      {/* Terminal header */}
      <div className="flex items-center justify-between px-4 py-2 bg-siem-surface border-b border-siem-border flex-shrink-0">
        <div className="flex items-center gap-3">
          <div className="flex gap-1.5">
            <span className="w-3 h-3 rounded-full bg-red-500" />
            <span className="w-3 h-3 rounded-full bg-yellow-500" />
            <span className="w-3 h-3 rounded-full bg-emerald-500" />
          </div>
          <span className="text-xs font-mono text-siem-muted">
            {session.hostname} — {session.protocol.toUpperCase()} — {session.username}@{session.hostname}
          </span>
          {connected && (
            <span className="flex items-center gap-1 text-[10px] text-emerald-400">
              <Activity size={10} className="animate-pulse" /> Live
            </span>
          )}
        </div>
        <button
          onClick={onClose}
          className="flex items-center gap-1.5 text-[11px] text-red-400 hover:text-red-300 px-2 py-1 rounded border border-red-800 hover:border-red-600 transition-colors"
        >
          <Square size={10} /> End Session
        </button>
      </div>

      {error && (
        <div className="flex-shrink-0 px-4 py-2 bg-red-950/30 border-b border-red-800 text-xs text-red-300 flex items-center gap-2">
          <AlertTriangle size={12} /> {error}
        </div>
      )}

      {/* xterm.js container */}
      <div ref={termRef} className="flex-1 p-2 overflow-hidden" />
    </div>
  )
}

// ── RDP info panel (Windows) ──────────────────────────────────────────────────
function RDPPanel({ session, onClose }) {
  const [copied, setCopied] = useState('')

  const copy = (text, key) => {
    navigator.clipboard.writeText(text)
    setCopied(key)
    setTimeout(() => setCopied(''), 2000)
  }

  // Generate .rdp file content
  const rdpContent = [
    `full address:s:${session.hostname}`,
    `username:s:${session.username}`,
    `authentication level:i:0`,
    `enablecredsspsupport:i:1`,
    `screen mode id:i:2`,
    `use multimon:i:0`,
    `desktopwidth:i:1920`,
    `desktopheight:i:1080`,
    `session bpp:i:32`,
    `compression:i:1`,
    `keyboardhook:i:2`,
    `audiocapturemode:i:0`,
    `videoplaybackmode:i:1`,
    `connection type:i:7`,
    `networkautodetect:i:1`,
    `bandwidthautodetect:i:1`,
    `displayconnectionbar:i:1`,
    `enableworkspacereconnect:i:0`,
    `disable wallpaper:i:0`,
    `allow font smoothing:i:0`,
    `allow desktop composition:i:0`,
    `disable full window drag:i:1`,
    `disable menu anims:i:1`,
    `disable themes:i:0`,
    `disable cursor setting:i:0`,
    `bitmapcachepersistenable:i:1`,
    `redirectprinters:i:0`,
    `redirectcomports:i:0`,
    `redirectsmartcards:i:0`,
    `redirectclipboard:i:1`,
    `redirectposdevices:i:0`,
    `autoreconnection enabled:i:1`,
    `prompt for credentials:i:1`,
  ].join('\r\n')

  const downloadRDP = () => {
    const blob = new Blob([rdpContent], { type: 'application/rdp' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${session.hostname}-obsidianwatch.rdp`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="flex flex-col h-full bg-siem-bg p-6 overflow-y-auto">
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-blue-950/40 border border-blue-700 flex items-center justify-center">
            <Monitor size={20} className="text-blue-400" />
          </div>
          <div>
            <div className="font-semibold text-siem-text">{session.hostname}</div>
            <div className="text-xs text-siem-muted">Windows RDP Session</div>
          </div>
        </div>
        <button onClick={onClose} className="text-siem-muted hover:text-siem-text">
          <X size={18} />
        </button>
      </div>

      <div className="space-y-4 max-w-lg">
        <div className="p-4 rounded-lg bg-blue-950/20 border border-blue-800">
          <div className="text-xs font-mono text-blue-300 mb-3 uppercase tracking-wider">Quick Connect</div>
          <div className="space-y-3">
            <div>
              <div className="text-[10px] text-siem-muted mb-1">Host</div>
              <div className="flex items-center gap-2">
                <code className="flex-1 text-xs font-mono bg-siem-bg px-2 py-1.5 rounded border border-siem-border text-siem-text">
                  {session.hostname}
                </code>
                <button onClick={() => copy(session.hostname, 'host')}
                  className="text-[10px] text-siem-muted hover:text-siem-text px-2 py-1 rounded border border-siem-border">
                  {copied === 'host' ? '✓' : 'Copy'}
                </button>
              </div>
            </div>
            <div>
              <div className="text-[10px] text-siem-muted mb-1">Username</div>
              <div className="flex items-center gap-2">
                <code className="flex-1 text-xs font-mono bg-siem-bg px-2 py-1.5 rounded border border-siem-border text-siem-text">
                  {session.username}
                </code>
                <button onClick={() => copy(session.username, 'user')}
                  className="text-[10px] text-siem-muted hover:text-siem-text px-2 py-1 rounded border border-siem-border">
                  {copied === 'user' ? '✓' : 'Copy'}
                </button>
              </div>
            </div>
          </div>
        </div>

        <button
          onClick={downloadRDP}
          className="w-full flex items-center justify-center gap-2 py-3 rounded-lg bg-blue-600 hover:bg-blue-500 text-white text-sm font-medium transition-colors"
        >
          <Monitor size={16} />
          Download .rdp File & Connect
        </button>

        <div className="p-3 rounded bg-yellow-950/20 border border-yellow-800 text-xs text-yellow-300 space-y-1">
          <div className="font-medium flex items-center gap-1.5"><AlertTriangle size={11} /> Note</div>
          <div>Password will be prompted by the RDP client. Use the credential shown on the agent's install panel, or the obsidianwatch account password set during agent deployment.</div>
        </div>

        <div className="text-[10px] text-siem-muted">
          Session ID: {session.session_id} · Token: {session.session_token?.slice(0,8)}...
        </div>
      </div>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────
export default function LiveResponse() {
  const [agents, setAgents]           = useState([])
  const [sessions, setSessions]       = useState([])
  const [activeSession, setActiveSession] = useState(null)
  const [loading, setLoading]         = useState(true)
  const [connecting, setConnecting]   = useState(null)
  const [error, setError]             = useState(null)

  const fetchData = useCallback(async () => {
    try {
      const [{ data: agentData }, { data: sessionData }] = await Promise.all([
        api.get('/api/v1/live-response/agents'),
        api.get('/api/v1/live-response/sessions'),
      ])
      setAgents(Array.isArray(agentData) ? agentData : [])
      setSessions(Array.isArray(sessionData) ? sessionData : [])
      setError(null)
    } catch (e) {
      setError(e.message)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetchData()
    const id = setInterval(fetchData, 15_000)
    return () => clearInterval(id)
  }, [fetchData])

  const initiateSession = async (agent) => {
    setConnecting(agent.id)
    setError(null)
    try {
      const { data } = await api.post('/api/v1/live-response/sessions', { agent_id: agent.id })
      setActiveSession(data)
      fetchData()
    } catch (e) {
      setError(e.response?.data?.error || e.message || 'Failed to start session')
    } finally {
      setConnecting(null)
    }
  }

  const closeSession = async () => {
    if (activeSession?.session_token) {
      await api.delete(`/api/v1/live-response/sessions/${activeSession.session_token}`).catch(() => {})
    }
    setActiveSession(null)
    fetchData()
  }

  const lrReady   = agents.filter(a => a.lr_ready).length
  const tunnelOn  = agents.filter(a => a.tunnel_online).length
  const activeSess = sessions.filter(s => s.status === 'active').length

  return (
    <div className="flex h-screen bg-siem-bg text-siem-text overflow-hidden">

      {/* Left panel — agent list + session history */}
      <div className="w-80 flex-shrink-0 flex flex-col border-r border-siem-border">

        {/* Header */}
        <div className="flex-shrink-0 px-4 py-3 border-b border-siem-border bg-siem-surface">
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <Terminal size={16} className="text-emerald-400" />
              <span className="text-sm font-semibold">Live Response</span>
            </div>
            <button onClick={fetchData} className="text-siem-muted hover:text-siem-text">
              <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
            </button>
          </div>
          <div className="flex gap-3 text-[10px] text-siem-muted">
            <span className="flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-400" />{lrReady} ready
            </span>
            <span className="flex items-center gap-1">
              <span className="w-1.5 h-1.5 rounded-full bg-blue-400" />{tunnelOn} tunnels
            </span>
            <span className="flex items-center gap-1">
              <Activity size={9} className="text-yellow-400" />{activeSess} active
            </span>
          </div>
        </div>

        {error && (
          <div className="flex-shrink-0 mx-3 mt-2 p-2 rounded bg-red-950/30 border border-red-800 text-[11px] text-red-300 flex items-center gap-1.5">
            <AlertTriangle size={11} />{error}
          </div>
        )}

        {/* Agent list */}
        <div className="flex-shrink-0 px-3 pt-3 pb-1 text-[10px] font-mono uppercase tracking-wider text-siem-muted">
          Endpoints ({agents.length})
        </div>
        <div className="flex-1 overflow-y-auto min-h-0">
          {agents.map(agent => {
            const protocol = getProtocol(agent.os)
            const isConnecting = connecting === agent.id
            const isActive = activeSession?.agent_id === agent.id

            return (
              <div key={agent.id}
                className={`mx-2 mb-1.5 rounded-lg border transition-colors
                  ${isActive ? 'border-emerald-700 bg-emerald-950/20' : 'border-siem-border bg-siem-surface hover:border-siem-text/30'}`}
              >
                <div className="flex items-center gap-2 px-3 py-2.5">
                  <OSIcon os={agent.os} />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-1.5">
                      <span className="text-xs font-medium truncate">{agent.hostname}</span>
                      <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${agent.online ? 'bg-emerald-400' : 'bg-siem-muted'}`} />
                    </div>
                    <div className="flex items-center gap-1.5 text-[10px] text-siem-muted mt-0.5">
                      <span className="font-mono uppercase">{protocol}</span>
                      {agent.lr_username && <span>· {agent.lr_username}</span>}
                      {agent.tunnel_online
                        ? <span className="text-emerald-400 flex items-center gap-0.5"><Wifi size={8} /> tunnel</span>
                        : <span className="text-siem-muted flex items-center gap-0.5"><WifiOff size={8} /> no tunnel</span>
                      }
                    </div>
                  </div>
                </div>

                <div className="px-3 pb-2.5">
                  {!agent.lr_ready ? (
                    <div className="flex items-center gap-1.5 text-[10px] text-yellow-400 bg-yellow-950/20 px-2 py-1 rounded border border-yellow-800">
                      <AlertTriangle size={9} />
                      {!agent.lr_username ? 'No credentials — update agent' : 'Tunnel offline'}
                    </div>
                  ) : isActive ? (
                    <div className="flex items-center gap-1.5 text-[10px] text-emerald-400">
                      <Activity size={10} className="animate-pulse" /> Session active
                    </div>
                  ) : (
                    <button
                      onClick={() => initiateSession(agent)}
                      disabled={isConnecting}
                      className="w-full flex items-center justify-center gap-1.5 text-[11px] py-1.5 rounded
                        bg-emerald-950/30 text-emerald-400 border border-emerald-800
                        hover:bg-emerald-900/40 hover:border-emerald-600 transition-colors
                        disabled:opacity-50 disabled:cursor-wait"
                    >
                      {isConnecting
                        ? <><RefreshCw size={10} className="animate-spin" /> Connecting…</>
                        : <><Play size={10} /> Start {protocol.toUpperCase()} Session</>
                      }
                    </button>
                  )}
                </div>
              </div>
            )
          })}

          {!loading && agents.length === 0 && (
            <div className="flex flex-col items-center justify-center h-32 text-siem-muted text-xs gap-2">
              <Terminal size={20} className="opacity-30" />
              No agents found
            </div>
          )}
        </div>

        {/* Session history */}
        <div className="flex-shrink-0 border-t border-siem-border">
          <div className="px-3 py-2 text-[10px] font-mono uppercase tracking-wider text-siem-muted">
            Recent Sessions
          </div>
          <div className="max-h-48 overflow-y-auto">
            {sessions.slice(0, 10).map(s => (
              <div key={s.id} className="flex items-center gap-2 px-3 py-1.5 hover:bg-siem-surface border-b border-siem-border/50">
                <StatusBadge status={s.status} />
                <div className="flex-1 min-w-0">
                  <div className="text-[11px] truncate">{s.agent_id}</div>
                  <div className="text-[9px] text-siem-muted flex items-center gap-1">
                    <User size={8} />{s.initiated_by}
                    <Clock size={8} className="ml-1" />
                    {formatDistanceToNow(new Date(s.created_at), { addSuffix: true })}
                  </div>
                </div>
                <span className="text-[9px] font-mono text-siem-muted uppercase">{s.protocol}</span>
              </div>
            ))}
            {sessions.length === 0 && (
              <div className="px-3 py-3 text-[10px] text-siem-muted text-center">No sessions yet</div>
            )}
          </div>
        </div>
      </div>

      {/* Right panel — terminal or welcome */}
      <div className="flex-1 min-w-0">
        {activeSession ? (
          activeSession.protocol === 'ssh' ? (
            <SSHTerminal session={activeSession} onClose={closeSession} />
          ) : (
            <RDPPanel session={activeSession} onClose={closeSession} />
          )
        ) : (
          <div className="flex flex-col items-center justify-center h-full text-siem-muted gap-4">
            <div className="w-16 h-16 rounded-2xl bg-siem-surface border border-siem-border flex items-center justify-center">
              <Terminal size={32} className="opacity-40" />
            </div>
            <div className="text-center">
              <div className="text-sm font-medium text-siem-text mb-1">Live Response</div>
              <div className="text-xs max-w-xs text-center">
                Select an endpoint on the left and click <strong>Start Session</strong> to open an interactive terminal.
              </div>
            </div>
            <div className="flex items-center gap-4 text-[10px] mt-2">
              <span className="flex items-center gap-1.5 text-blue-400"><Monitor size={11} /> Windows → RDP</span>
              <span className="flex items-center gap-1.5 text-orange-400"><Server size={11} /> Linux → SSH</span>
            </div>
            <div className="text-[10px] text-siem-muted/60 max-w-xs text-center mt-2 p-3 rounded border border-siem-border bg-siem-surface">
              <Shield size={10} className="inline mr-1" />
              All sessions are encrypted, tunnelled through the existing agent connection, and logged to the audit trail.
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
