import { useEffect, useState, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { Monitor, Wifi, WifiOff, Shield, ShieldOff, ShieldAlert,
         Key, Copy, Check, ChevronRight, X, Lock, Unlock, Globe,
         Apple, Server, Router, Search, AlertTriangle, Eye, RefreshCw } from 'lucide-react'
import { formatDistanceToNow, format } from 'date-fns'
import api from '../api/client'

// ─── OS classification ────────────────────────────────────────────────────────
function getOSCategory(os) {
  if (!os) return 'other'
  const l = os.toLowerCase()
  if (l.includes('win')) return 'windows'
  if (l.includes('linux') || l.includes('ubuntu') || l.includes('debian') || l.includes('centos') || l.includes('rhel')) return 'linux'
  if (l.includes('mac') || l.includes('darwin')) return 'macos'
  if (l.includes('cisco') || l.includes('juniper') || l.includes('fortinet') || l.includes('palo') || l.includes('network')) return 'network'
  return 'other'
}

const OS_GROUPS = {
  windows: { label: 'Windows',        icon: Monitor,    color: 'text-blue-400',    border: 'border-blue-800',    bg: 'bg-blue-950/20' },
  linux:   { label: 'Linux',          icon: Server,     color: 'text-orange-400',  border: 'border-orange-800',  bg: 'bg-orange-950/20' },
  macos:   { label: 'macOS',          icon: Apple,      color: 'text-purple-400',  border: 'border-purple-800',  bg: 'bg-purple-950/20' },
  network: { label: 'Network Devices',icon: Router,     color: 'text-cyan-400',    border: 'border-cyan-800',    bg: 'bg-cyan-950/20' },
  other:   { label: 'Other',          icon: Globe,      color: 'text-siem-muted',  border: 'border-siem-border', bg: 'bg-siem-bg' },
}

// ─── Tamper Protection Side Panel ─────────────────────────────────────────────
function TamperPanel({ agent, onClose, onUpdated }) {
  const [copied, setCopied] = useState(false)
  const [toggling, setToggling] = useState(false)

  const copy = () => {
    navigator.clipboard.writeText(agent.install_key || '')
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const toggleTamper = async () => {
    setToggling(true)
    try {
      await api.patch(`/api/v1/agents/${agent.id}/tamper`, { locked: !agent.tamper_locked })
      onUpdated()
    } finally { setToggling(false) }
  }

  const installCmd = `${agent.hostname}-agent.exe -config agent.yaml install`

  return (
    <div className="fixed inset-0 z-50 flex justify-end" onClick={onClose}>
      <div className="w-full max-w-lg bg-siem-surface border-l border-siem-border h-full overflow-y-auto shadow-2xl"
           onClick={e => e.stopPropagation()}>

        {/* Header */}
        <div className="flex items-center gap-2 px-5 py-4 border-b border-siem-border sticky top-0 bg-siem-surface z-10">
          <ShieldAlert size={16} className="text-siem-accent" />
          <span className="font-semibold text-siem-text text-sm">Tamper Protection</span>
          <span className="ml-2 text-[10px] text-siem-muted font-mono">{agent.hostname}</span>
          <button onClick={onClose} className="ml-auto text-siem-muted hover:text-siem-text"><X size={16}/></button>
        </div>

        <div className="p-5 space-y-5">
          {/* Status card */}
          <div className={`rounded-xl border p-4 flex items-center gap-4 ${
            agent.tamper_locked
              ? 'bg-emerald-950/20 border-emerald-800'
              : 'bg-siem-bg border-siem-border'
          }`}>
            <div className={`w-10 h-10 rounded-xl flex items-center justify-center border ${
              agent.tamper_locked ? 'bg-emerald-900/40 border-emerald-700' : 'bg-siem-surface border-siem-border'
            }`}>
              {agent.tamper_locked ? <Lock size={18} className="text-emerald-400"/> : <Unlock size={18} className="text-siem-muted"/>}
            </div>
            <div className="flex-1">
              <div className={`text-sm font-semibold ${agent.tamper_locked ? 'text-emerald-400' : 'text-siem-text'}`}>
                {agent.tamper_locked ? 'Tamper Protection: ENABLED' : 'Tamper Protection: DISABLED'}
              </div>
              <div className="text-[10px] text-siem-muted mt-0.5">
                {agent.tamper_locked
                  ? 'Agent service cannot be stopped or uninstalled without the install key'
                  : 'Agent can be stopped or uninstalled by any administrator'
                }
              </div>
            </div>
            <button onClick={toggleTamper} disabled={toggling}
              className={`text-xs px-3 py-1.5 rounded-lg border font-medium transition-colors ${
                agent.tamper_locked
                  ? 'border-red-800 text-red-400 hover:bg-red-900/20'
                  : 'border-emerald-800 text-emerald-400 hover:bg-emerald-900/20'
              }`}>
              {toggling ? '…' : agent.tamper_locked ? 'Disable' : 'Enable'}
            </button>
          </div>

          {/* Install key */}
          <div>
            <div className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold mb-2 flex items-center gap-1">
              <Key size={9}/> Tamper Protection Password
            </div>
            <div className="bg-siem-bg border border-siem-border rounded-xl p-3 flex items-center gap-2">
              <code className="text-emerald-300 font-mono text-sm flex-1 truncate">
                {agent.install_key || 'Not yet set — will appear after first install'}
              </code>
              {agent.install_key && (
                <button onClick={copy}
                  className="shrink-0 p-1.5 rounded border border-siem-border hover:border-siem-accent/40 text-siem-muted hover:text-siem-text transition-colors">
                  {copied ? <Check size={13} className="text-emerald-400"/> : <Copy size={13}/>}
                </button>
              )}
            </div>
            <p className="text-[9px] text-siem-muted mt-1.5">
              This password is set by the operator at install time and required to uninstall.
            </p>
          </div>

          {/* How to install */}
          <div>
            <div className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold mb-2">
              How to Install with Tamper Protection
            </div>
            <div className="space-y-3">
              <div className="bg-siem-bg border border-siem-border rounded-lg p-3">
                <div className="text-[9px] text-siem-muted mb-1.5 font-semibold">1. Run the install command</div>
                <code className="text-[10px] font-mono text-emerald-300 block break-all">
                  .\obsidianwatch-win-agent-V1.0.exe -config "agent.yaml" install
                </code>
              </div>
              <div className="bg-siem-bg border border-siem-border rounded-lg p-3">
                <div className="text-[9px] text-siem-muted mb-1.5 font-semibold">2. Enter a tamper protection password when prompted</div>
                <code className="text-[10px] font-mono text-cyan-300 block">
                  Enter tamper protection password: ••••••••••••
                </code>
                <p className="text-[9px] text-siem-muted mt-1">
                  Choose a strong password (8+ chars). It will be sent to this dashboard and shown above.
                  Save it — you need it to uninstall.
                </p>
              </div>
              <div className="bg-siem-bg border border-siem-border rounded-lg p-3">
                <div className="text-[9px] text-siem-muted mb-1.5 font-semibold">3. To uninstall — password is required</div>
                <code className="text-[10px] font-mono text-red-300 block break-all">
                  .\obsidianwatch-win-agent-V1.0.exe -config "agent.yaml" uninstall
                </code>
                <code className="text-[10px] font-mono text-siem-muted block mt-1">
                  Enter Install Key: ••••••••••••
                </code>
              </div>
              <div className="bg-amber-950/20 border border-amber-800/40 rounded-lg p-3">
                <div className="flex items-start gap-2">
                  <AlertTriangle size={11} className="text-amber-400 mt-0.5 shrink-0"/>
                  <div className="text-[9px] text-amber-400/80">
                    Running without <code className="text-amber-300">install</code> verb does NOT check the password.
                    Tamper protection only applies to the Windows Service installation.
                  </div>
                </div>
              </div>
              <div className="bg-red-950/20 border border-red-800/40 rounded-lg p-3">
                <div className="flex items-start gap-2">
                  <Lock size={11} className="text-red-400 mt-0.5 shrink-0"/>
                  <div className="text-[9px] text-red-400/80">
                    Once installed with tamper protection, the service DACL is locked.
                    Even administrators cannot stop or delete the service via SCM without the password.
                  </div>
                </div>
              </div>
            </div>
          </div>

          {/* Agent details */}
          <div>
            <div className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold mb-2">Agent Details</div>
            <div className="bg-siem-bg border border-siem-border rounded-xl overflow-hidden">
              {[
                ['Agent ID',   agent.id],
                ['Hostname',   agent.hostname],
                ['OS',         agent.os || '—'],
                ['Version',    agent.version || '—'],
                ['Last IP',    agent.last_ip || '—'],
                ['Last Seen',  agent.last_seen ? format(new Date(agent.last_seen), 'yyyy-MM-dd HH:mm:ss') : '—'],
                ['Events',     agent.event_count?.toLocaleString() || '0'],
              ].map(([label, value], i) => (
                <div key={label} className={`flex gap-3 px-4 py-2 text-xs ${i%2===0?'':'bg-white/[0.02]'}`}>
                  <span className="text-siem-muted w-24 shrink-0">{label}</span>
                  <span className="font-mono text-siem-text text-[10px] break-all">{value}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Agent Row (inside a group) ───────────────────────────────────────────────
function AgentRow({ agent, onViewTamper }) {
  const navigate = useNavigate()
  return (
    <tr className="border-b border-siem-border/30 hover:bg-white/[0.02] group transition-colors">
      <td className="px-4 py-2.5">
        <div className="flex items-center gap-2">
          {agent.online
            ? <Wifi size={12} className="text-emerald-400 shrink-0"/>
            : <WifiOff size={12} className="text-siem-muted/50 shrink-0"/>}
          <div>
            <div className="text-siem-text font-medium text-sm">{agent.hostname}</div>
            <div className="text-siem-muted text-[9px] font-mono">{agent.id?.slice(0,16)}…</div>
          </div>
        </div>
      </td>
      <td className="px-4 py-2.5">
        <span className={`text-[9px] px-2 py-0.5 rounded-full border font-medium ${
          agent.online ? 'bg-emerald-900/30 text-emerald-400 border-emerald-800' : 'bg-siem-bg text-siem-muted border-siem-border'
        }`}>
          {agent.online ? 'Online' : 'Offline'}
        </span>
      </td>
      <td className="px-4 py-2.5 text-siem-muted text-xs">{agent.os}</td>
      <td className="px-4 py-2.5 text-siem-muted text-xs">{agent.version}</td>
      <td className="px-4 py-2.5 text-siem-muted text-xs font-mono">{agent.last_ip}</td>
      <td className="px-4 py-2.5 text-siem-muted text-[10px]">
        {agent.last_seen ? formatDistanceToNow(new Date(agent.last_seen), { addSuffix: true }) : '—'}
      </td>
      <td className="px-4 py-2.5 text-siem-text text-xs text-right">{agent.event_count?.toLocaleString()}</td>
      <td className="px-4 py-2.5">
        <div className="flex items-center gap-1 justify-end">
          {/* Tamper status icon */}
          <button onClick={() => onViewTamper(agent)} title="Tamper Protection"
            className="p-1 rounded hover:bg-siem-accent/10 transition-colors">
            {agent.tamper_locked
              ? <Shield size={13} className="text-emerald-400"/>
              : <ShieldOff size={13} className="text-siem-muted/50"/>}
          </button>
          {/* Threat intel */}
          <button onClick={() => navigate(`/threat-intel?host=${agent.hostname}`)}
            title="View Threat Intel"
            className="p-1 rounded hover:bg-siem-accent/10 transition-colors">
            <Eye size={13} className="text-siem-muted hover:text-siem-accent"/>
          </button>
          <ChevronRight size={12} className="text-siem-muted/30 group-hover:text-siem-muted" />
        </div>
      </td>
    </tr>
  )
}

// ─── OS Group Section ─────────────────────────────────────────────────────────
function OSGroup({ category, agents, onViewTamper }) {
  const [collapsed, setCollapsed] = useState(false)
  const style = OS_GROUPS[category] || OS_GROUPS.other
  const Icon = style.icon
  const online = agents.filter(a => a.online).length

  return (
    <div className={`bg-siem-surface border rounded-xl overflow-hidden ${style.border}`}>
      {/* Group header */}
      <div
        className={`flex items-center gap-3 px-4 py-3 cursor-pointer ${style.bg} border-b border-siem-border/50`}
        onClick={() => setCollapsed(c => !c)}>
        <div className={`w-7 h-7 rounded-lg flex items-center justify-center border ${style.border} ${style.bg}`}>
          <Icon size={14} className={style.color}/>
        </div>
        <span className={`text-sm font-bold ${style.color}`}>{style.label}</span>
        <div className="flex items-center gap-2 ml-2 text-[10px]">
          <span className="text-emerald-400">{online} online</span>
          <span className="text-siem-muted">/ {agents.length} total</span>
        </div>
        <ChevronRight size={13} className={`ml-auto text-siem-muted transition-transform ${collapsed ? '' : 'rotate-90'}`}/>
      </div>

      {!collapsed && (
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-siem-border/30 text-siem-muted text-[9px] uppercase tracking-wider">
                <th className="text-left px-4 py-2">Agent</th>
                <th className="text-left px-4 py-2">Status</th>
                <th className="text-left px-4 py-2">OS</th>
                <th className="text-left px-4 py-2">Version</th>
                <th className="text-left px-4 py-2">Last IP</th>
                <th className="text-left px-4 py-2">Last Seen</th>
                <th className="text-right px-4 py-2">Events</th>
                <th className="text-right px-4 py-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {agents.map(a => (
                <AgentRow key={a.id} agent={a} onViewTamper={onViewTamper}/>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────
export default function Agents() {
  const [agents, setAgents]         = useState([])
  const [loading, setLoading]       = useState(true)
  const [tamperAgent, setTamperAgent] = useState(null)
  const [search, setSearch]         = useState('')

  const load = async () => {
    setLoading(true)
    try {
      const { data } = await api.get('/api/v1/agents')
      setAgents(data.agents || [])
    } finally { setLoading(false) }
  }

  useEffect(() => {
    load()
    const id = setInterval(load, 15000)
    return () => clearInterval(id)
  }, [])

  const filtered = useMemo(() =>
    agents.filter(a => !search ||
      a.hostname?.toLowerCase().includes(search.toLowerCase()) ||
      a.last_ip?.includes(search) ||
      a.os?.toLowerCase().includes(search.toLowerCase())
    ), [agents, search])

  const byCategory = useMemo(() => {
    const m = {}
    filtered.forEach(a => {
      const cat = getOSCategory(a.os)
      if (!m[cat]) m[cat] = []
      m[cat].push(a)
    })
    return m
  }, [filtered])

  const categoryOrder = ['windows', 'linux', 'macos', 'network', 'other']
  const online  = agents.filter(a => a.online).length
  const offline = agents.length - online
  const locked  = agents.filter(a => a.tamper_locked).length

  const handleTamperClose = () => { setTamperAgent(null); load() }

  return (
    <div className="p-5 space-y-5">
      {tamperAgent && (
        <TamperPanel agent={tamperAgent} onClose={handleTamperClose} onUpdated={load}/>
      )}

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-siem-text">Agent Fleet</h1>
          <p className="text-[10px] text-siem-muted mt-0.5">Manage endpoints, tamper protection, and threat intelligence</p>
        </div>
        <button onClick={load}
          className="flex items-center gap-1.5 text-xs text-siem-muted hover:text-siem-text border border-siem-border rounded-lg px-3 py-1.5">
          <RefreshCw size={12}/> Refresh
        </button>
      </div>

      {/* Summary pills */}
      <div className="flex gap-3 flex-wrap">
        {[
          { label: 'Total', value: agents.length, color: 'text-siem-text' },
          { label: 'Online', value: online, color: 'text-emerald-400' },
          { label: 'Offline', value: offline, color: 'text-siem-muted' },
          { label: 'Tamper Protected', value: locked, color: 'text-blue-400', icon: Shield },
        ].map(({ label, value, color, icon: Icon }) => (
          <div key={label} className="bg-siem-surface border border-siem-border rounded-xl px-4 py-3 flex items-center gap-3">
            {Icon && <Icon size={14} className={color}/>}
            <div>
              <div className={`text-xl font-bold font-mono ${color}`}>{value}</div>
              <div className="text-[9px] text-siem-muted uppercase tracking-wider">{label}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Search */}
      <div className="relative max-w-sm">
        <Search size={12} className="absolute left-3 top-1/2 -translate-y-1/2 text-siem-muted"/>
        <input value={search} onChange={e => setSearch(e.target.value)}
          placeholder="Search hostname, IP, OS..."
          className="w-full bg-siem-surface border border-siem-border rounded-lg pl-8 pr-3 py-2 text-sm text-siem-text placeholder-siem-muted/40 outline-none focus:border-siem-accent/50"/>
        {search && <button onClick={() => setSearch('')} className="absolute right-3 top-1/2 -translate-y-1/2"><X size={11} className="text-siem-muted"/></button>}
      </div>

      {/* OS Groups */}
      {loading ? (
        <div className="text-center py-16 text-siem-muted">Loading agents…</div>
      ) : filtered.length === 0 ? (
        <div className="text-center py-16 text-siem-muted">
          {search ? `No agents match "${search}"` : 'No agents registered yet'}
        </div>
      ) : (
        <div className="space-y-4">
          {categoryOrder.filter(cat => byCategory[cat]?.length > 0).map(cat => (
            <OSGroup key={cat} category={cat} agents={byCategory[cat]}
              onViewTamper={agent => setTamperAgent(agent)}/>
          ))}
        </div>
      )}
    </div>
  )
}
