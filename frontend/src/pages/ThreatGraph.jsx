import { useState, useEffect, useRef, useCallback } from 'react'
import { Monitor, ChevronRight, ChevronDown, Activity, AlertTriangle,
         Shield, Globe, FileText, Database, Cpu, Terminal,
         GitBranch, X, Clock, Hash, User, Layers } from 'lucide-react'
import { format } from 'date-fns'
import api from '../api/client'

// ── App classification ────────────────────────────────────────────────────────
const WINDOWS_LEGIT = new Set([
  'svchost.exe','lsass.exe','winlogon.exe','services.exe','csrss.exe',
  'smss.exe','wininit.exe','explorer.exe','taskhostw.exe','spoolsv.exe',
  'SearchIndexer.exe','RuntimeBroker.exe','sihost.exe','fontdrvhost.exe',
  'dwm.exe','conhost.exe','dllhost.exe','msdtc.exe','WmiPrvSE.exe',
  'audiodg.exe','SearchHost.exe','StartMenuExperienceHost.exe',
  'ShellExperienceHost.exe','ctfmon.exe','MsMpEng.exe','NisSrv.exe',
  'SecurityHealthSystray.exe','SgrmBroker.exe','Registry','Idle','System',
  'memory compression','antimalware service executable','windows defender',
])

const CORPORATE = new Set([
  'chrome.exe','firefox.exe','msedge.exe','iexplore.exe',
  'outlook.exe','OUTLOOK.EXE','Teams.exe','teams.exe',
  'Slack.exe','slack.exe','zoom.exe','Zoom.exe',
  'code.exe','Code.exe','devenv.exe','rider64.exe',
  'git.exe','node.exe','python.exe','python3.exe',
  'java.exe','javaw.exe','dotnet.exe',
  'OneDrive.exe','Dropbox.exe','Box.exe',
  'notepad.exe','notepad++.exe','wordpad.exe',
  'WINWORD.EXE','EXCEL.EXE','POWERPNT.EXE',
  'AnyDesk.exe','mstsc.exe','putty.exe','winscp.exe',
])

function classifyProcess(name) {
  if (!name) return 'other'
  const lower = name.toLowerCase()
  if ([...WINDOWS_LEGIT].some(w => lower === w.toLowerCase())) return 'windows'
  if ([...CORPORATE].some(c => lower === c.toLowerCase())) return 'corporate'
  return 'other'
}

const SEV_COLOR = {
  5: { bg: 'bg-red-900/40', border: 'border-red-500', text: 'text-red-400', dot: '#ef4444' },
  4: { bg: 'bg-orange-900/30', border: 'border-orange-500', text: 'text-orange-400', dot: '#f97316' },
  3: { bg: 'bg-yellow-900/20', border: 'border-yellow-600', text: 'text-yellow-400', dot: '#eab308' },
  2: { bg: 'bg-blue-900/20', border: 'border-blue-700', text: 'text-blue-400', dot: '#3b82f6' },
  1: { bg: 'bg-siem-bg', border: 'border-siem-border', text: 'text-siem-muted', dot: '#475569' },
}

const GROUP_STYLE = {
  windows:   { color: 'text-blue-400',   border: 'border-blue-800',   bg: 'bg-blue-950/30',   icon: Shield,   label: 'Windows System' },
  corporate: { color: 'text-emerald-400',border: 'border-emerald-800',bg: 'bg-emerald-950/30',icon: Layers,   label: 'Corporate Apps' },
  other:     { color: 'text-orange-400', border: 'border-orange-800', bg: 'bg-orange-950/20', icon: AlertTriangle, label: 'Other / Unknown' },
}

// ── Process Tree Node ─────────────────────────────────────────────────────────
function ProcessNode({ proc, depth = 0, allEvents, onSelect, selected }) {
  const [open, setOpen] = useState(depth < 2)
  const hasChildren = proc.children && proc.children.length > 0
  const sev = SEV_COLOR[proc.maxSeverity] || SEV_COLOR[1]
  const isSelected = selected?.pid === proc.pid && selected?.name === proc.name

  // Count related events
  const related = allEvents.filter(e =>
    e.pid === proc.pid || e.process_name === proc.name
  )
  const fileEvents = related.filter(e => e.event_type === 'file')
  const netEvents  = related.filter(e => e.event_type === 'network' || e.event_type === 'dns')
  const regEvents  = related.filter(e => e.event_type === 'registry')

  return (
    <div style={{ marginLeft: depth > 0 ? 24 : 0 }} className="relative">
      {/* Vertical connector line */}
      {depth > 0 && (
        <div className="absolute left-[-16px] top-0 bottom-0 w-px bg-siem-border/40" />
      )}
      {depth > 0 && (
        <div className="absolute left-[-16px] top-[20px] w-4 h-px bg-siem-border/40" />
      )}

      {/* Node */}
      <div
        className={`group flex items-start gap-2 mb-1 p-2 rounded-lg border cursor-pointer transition-all duration-150 ${
          isSelected
            ? `${sev.bg} ${sev.border} ring-1 ring-current`
            : `hover:bg-white/[0.03] border-transparent hover:border-siem-border/50`
        }`}
        onClick={() => { onSelect(proc); if (hasChildren) setOpen(o => !o) }}
      >
        {/* Expand toggle */}
        <div className="mt-0.5 shrink-0 w-4">
          {hasChildren
            ? open
              ? <ChevronDown size={12} className="text-siem-muted" />
              : <ChevronRight size={12} className="text-siem-muted" />
            : <div className="w-2 h-2 rounded-full mt-1 ml-1" style={{ background: sev.dot }} />
          }
        </div>

        {/* Process info */}
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`text-xs font-mono font-semibold ${sev.text}`}>
              {proc.name}
            </span>
            {proc.pid > 0 && (
              <span className="text-[10px] text-siem-muted font-mono">PID:{proc.pid}</span>
            )}
            {proc.maxSeverity >= 4 && (
              <span className={`text-[9px] px-1.5 py-0.5 rounded-full border ${sev.border} ${sev.text} font-bold`}>
                SEV {proc.maxSeverity}
              </span>
            )}
          </div>

          {/* Command line - most important field */}
          {proc.commandLine && (
            <div className="text-[10px] text-siem-muted font-mono mt-0.5 truncate max-w-lg"
                 title={proc.commandLine}>
              {proc.commandLine}
            </div>
          )}

          {/* Event badges */}
          {(fileEvents.length > 0 || netEvents.length > 0 || regEvents.length > 0) && (
            <div className="flex gap-2 mt-1">
              {fileEvents.length > 0 && (
                <span className="flex items-center gap-1 text-[9px] text-yellow-500/70">
                  <FileText size={8} /> {fileEvents.length} files
                </span>
              )}
              {netEvents.length > 0 && (
                <span className="flex items-center gap-1 text-[9px] text-blue-400/70">
                  <Globe size={8} /> {netEvents.length} net
                </span>
              )}
              {regEvents.length > 0 && (
                <span className="flex items-center gap-1 text-[9px] text-purple-400/70">
                  <Database size={8} /> {regEvents.length} reg
                </span>
              )}
            </div>
          )}
        </div>

        {/* Event count */}
        <div className="text-[10px] text-siem-muted shrink-0 mt-0.5">
          {proc.events} evt{proc.events !== 1 ? 's' : ''}
        </div>
      </div>

      {/* Children */}
      {hasChildren && open && (
        <div>
          {proc.children.map((child, i) => (
            <ProcessNode key={i} proc={child} depth={depth + 1}
              allEvents={allEvents} onSelect={onSelect} selected={selected} />
          ))}
        </div>
      )}
    </div>
  )
}

// ── Process Detail Panel ──────────────────────────────────────────────────────
function ProcessDetail({ proc, allEvents, onClose }) {
  if (!proc) return null
  const related = allEvents.filter(e =>
    e.pid === proc.pid || e.process_name === proc.name
  )
  const fileEvents = related.filter(e => e.event_type === 'file')
  const netEvents  = related.filter(e => e.event_type === 'network' || e.event_type === 'dns')
  const regEvents  = related.filter(e => e.event_type === 'registry')
  const cmdEvents  = related.filter(e => e.command_line && e.command_line !== proc.commandLine)
  const sev = SEV_COLOR[proc.maxSeverity] || SEV_COLOR[1]

  const Section = ({ title, icon: Icon, color, items, render }) => items.length === 0 ? null : (
    <div className="mb-4">
      <div className={`flex items-center gap-1.5 text-xs font-semibold mb-2 ${color}`}>
        <Icon size={11} /> {title} <span className="ml-1 opacity-60">({items.length})</span>
      </div>
      <div className="space-y-1">
        {items.slice(0, 15).map((item, i) => (
          <div key={i} className="bg-siem-bg border border-siem-border/30 rounded px-3 py-1.5 text-[10px] font-mono text-siem-muted">
            {render(item)}
          </div>
        ))}
        {items.length > 15 && (
          <div className="text-[10px] text-siem-muted pl-1">+{items.length - 15} more</div>
        )}
      </div>
    </div>
  )

  return (
    <div className="w-96 shrink-0 bg-siem-surface border-l border-siem-border flex flex-col overflow-hidden">
      {/* Header */}
      <div className={`px-4 py-3 border-b border-siem-border flex items-start gap-2 ${sev.bg}`}>
        <Terminal size={14} className={`mt-0.5 shrink-0 ${sev.text}`} />
        <div className="flex-1 min-w-0">
          <div className={`text-sm font-mono font-bold ${sev.text} truncate`}>{proc.name}</div>
          <div className="text-[10px] text-siem-muted mt-0.5">
            PID {proc.pid} · {proc.events} events · Max sev {proc.maxSeverity}
          </div>
        </div>
        <button onClick={onClose} className="text-siem-muted hover:text-siem-text shrink-0">
          <X size={14} />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-4 space-y-1">
        {/* Command line */}
        {proc.commandLine && (
          <div className="mb-4">
            <div className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold mb-1.5 flex items-center gap-1">
              <Hash size={9} /> Command Line
            </div>
            <div className="bg-siem-bg border border-siem-border/50 rounded-lg p-3 text-[10px] font-mono text-emerald-300 break-all">
              {proc.commandLine}
            </div>
          </div>
        )}

        {/* User */}
        {proc.user && (
          <div className="flex items-center gap-2 text-xs mb-3">
            <User size={10} className="text-siem-muted" />
            <span className="text-siem-muted">User:</span>
            <span className="text-siem-text font-mono">{proc.user}</span>
          </div>
        )}

        {/* File activity */}
        <Section title="Files Written / Accessed" icon={FileText} color="text-yellow-400"
          items={fileEvents}
          render={e => e.file_path || e.raw?.path || '—'} />

        {/* Network activity */}
        <Section title="Network Connections" icon={Globe} color="text-blue-400"
          items={netEvents}
          render={e => {
            if (e.event_type === 'dns') return `DNS → ${e.dst_ip || '?'}`
            return `${e.dst_ip || '?'}:${e.dst_port || '?'} (${e.proto || 'tcp'})`
          }} />

        {/* Registry activity */}
        <Section title="Registry Changes" icon={Database} color="text-purple-400"
          items={regEvents}
          render={e => e.reg_key || '—'} />

        {/* Additional commands */}
        <Section title="Additional Commands Executed" icon={Terminal} color="text-emerald-400"
          items={cmdEvents}
          render={e => e.command_line} />

        {/* Timeline */}
        {related.length > 0 && (
          <div>
            <div className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold mb-1.5 flex items-center gap-1">
              <Clock size={9} /> Recent Activity
            </div>
            <div className="space-y-1">
              {related.slice(0, 10).map((e, i) => (
                <div key={i} className="flex gap-2 text-[10px]">
                  <span className="text-siem-muted font-mono w-16 shrink-0">
                    {format(new Date(e.time), 'HH:mm:ss')}
                  </span>
                  <span className={`w-14 shrink-0 ${
                    e.event_type === 'network' || e.event_type === 'dns' ? 'text-blue-400' :
                    e.event_type === 'file' ? 'text-yellow-400' :
                    e.event_type === 'registry' ? 'text-purple-400' :
                    'text-siem-muted'
                  }`}>{e.event_type}</span>
                  <span className="text-siem-muted truncate">
                    {e.command_line || e.dst_ip || e.file_path || e.reg_key || '—'}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// ── App Group Card ────────────────────────────────────────────────────────────
function AppGroupCard({ group, type, onClick, selected }) {
  const style = GROUP_STYLE[type]
  const Icon = style.icon
  const maxSev = Math.max(...group.map(p => p.maxSeverity || 1))
  const sev = SEV_COLOR[maxSev] || SEV_COLOR[1]
  const isSelected = selected === type

  return (
    <div
      onClick={() => onClick(type)}
      className={`cursor-pointer rounded-xl border p-4 transition-all duration-200 ${
        isSelected
          ? `${style.bg} ${style.border} ring-1 ring-current shadow-lg`
          : 'bg-siem-surface border-siem-border hover:border-siem-border/80 hover:bg-white/[0.02]'
      }`}
    >
      <div className="flex items-center gap-3 mb-3">
        <div className={`w-8 h-8 rounded-lg flex items-center justify-center ${style.bg} border ${style.border}`}>
          <Icon size={14} className={style.color} />
        </div>
        <div>
          <div className={`text-sm font-semibold ${style.color}`}>{style.label}</div>
          <div className="text-[10px] text-siem-muted">{group.length} processes</div>
        </div>
        {maxSev >= 4 && (
          <div className={`ml-auto text-[10px] font-bold px-2 py-0.5 rounded-full border ${sev.border} ${sev.text}`}>
            SEV {maxSev}
          </div>
        )}
      </div>

      {/* Process list preview */}
      <div className="space-y-1">
        {group.slice(0, 5).map((proc, i) => (
          <div key={i} className="flex items-center gap-2 text-[10px]">
            <div className="w-1.5 h-1.5 rounded-full shrink-0"
                 style={{ background: (SEV_COLOR[proc.maxSeverity] || SEV_COLOR[1]).dot }} />
            <span className="font-mono text-siem-muted truncate flex-1">{proc.name}</span>
            <span className="text-siem-muted/50">{proc.events}</span>
          </div>
        ))}
        {group.length > 5 && (
          <div className="text-[10px] text-siem-muted/50 pl-3">+{group.length - 5} more</div>
        )}
      </div>
    </div>
  )
}

// ── Host Card ─────────────────────────────────────────────────────────────────
function HostCard({ agent, onClick, selected }) {
  const isSelected = selected?.id === agent.id
  const isOnline = agent.online

  return (
    <div
      onClick={() => onClick(agent)}
      className={`cursor-pointer rounded-xl border p-5 transition-all duration-200 group ${
        isSelected
          ? 'bg-siem-accent/10 border-siem-accent ring-1 ring-siem-accent/50 shadow-lg shadow-siem-accent/10'
          : 'bg-siem-surface border-siem-border hover:border-siem-accent/40 hover:bg-white/[0.02]'
      }`}
    >
      {/* Host icon */}
      <div className="flex items-start gap-3 mb-4">
        <div className={`w-10 h-10 rounded-xl flex items-center justify-center border transition-colors ${
          isSelected ? 'bg-siem-accent/20 border-siem-accent' : 'bg-siem-bg border-siem-border group-hover:border-siem-accent/40'
        }`}>
          <Monitor size={18} className={isSelected ? 'text-siem-accent' : 'text-siem-muted'} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="text-sm font-bold text-siem-text truncate">{agent.hostname}</div>
          <div className="text-[10px] text-siem-muted mt-0.5">{agent.os || 'windows'}</div>
        </div>
        {/* Status dot */}
        <div className={`w-2 h-2 rounded-full mt-1.5 shrink-0 ${
          isOnline ? 'bg-emerald-400 shadow-sm shadow-emerald-400' : 'bg-red-500'
        }`} />
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 gap-2">
        {[
          { label: 'Events (24h)', value: agent.event_count || '—', icon: Activity },
          { label: 'IP Address',   value: agent.last_ip || '—',              icon: Globe },
        ].map(({ label, value, icon: Icon }) => (
          <div key={label} className="bg-siem-bg/60 rounded-lg p-2">
            <div className="text-[9px] uppercase tracking-wider text-siem-muted/70 mb-0.5">{label}</div>
            <div className="text-xs font-mono text-siem-text truncate">{value}</div>
          </div>
        ))}
      </div>

      <div className="mt-3 text-[10px] text-siem-muted truncate font-mono">
        {agent.id?.slice(0, 16)}…
      </div>
    </div>
  )
}

// ── Build process tree from flat event list ───────────────────────────────────
function buildProcessTree(events) {
  const procMap = {}

  // Use process_name as the grouping key (names are more stable than PIDs)
  events.filter(e => e.event_type === 'process' && e.process_name).forEach(e => {
    const name = e.process_name || '?'
    const pid  = e.pid || 0
    const key  = `${name}:${pid}`

    if (!procMap[key]) {
      procMap[key] = {
        name,
        pid,
        ppid:        e.ppid || 0,
        commandLine: e.command_line || '',
        user:        e.user_name || '',
        maxSeverity: e.severity || 1,
        events:      0,
        children:    [],
        _key:        key,
      }
    }
    const proc = procMap[key]
    proc.events++
    if ((e.severity || 1) > proc.maxSeverity) proc.maxSeverity = e.severity
    if (!proc.commandLine && e.command_line) proc.commandLine = e.command_line
    if (!proc.user && e.user_name) proc.user = e.user_name
  })

  // If no structured process events, synthesize from all events with process_name
  if (Object.keys(procMap).length === 0) {
    events.filter(e => e.process_name).forEach(e => {
      const name = e.process_name
      const key  = name
      if (!procMap[key]) {
        procMap[key] = {
          name, pid: 0, ppid: 0,
          commandLine: e.command_line || '',
          user: e.user_name || '',
          maxSeverity: e.severity || 1,
          events: 0, children: [], _key: key,
        }
      }
      procMap[key].events++
      if ((e.severity||1) > procMap[key].maxSeverity) procMap[key].maxSeverity = e.severity
    })
  }

  // Build tree by PPID
  const roots = []
  const byPid = {}
  Object.values(procMap).forEach(p => { if (p.pid) byPid[p.pid] = p })
  Object.values(procMap).forEach(p => {
    const parent = byPid[p.ppid]
    if (parent && parent._key !== p._key) {
      parent.children.push(p)
    } else {
      roots.push(p)
    }
  })

  const sortProcs = arr => {
    arr.sort((a, b) => b.maxSeverity - a.maxSeverity || a.name.localeCompare(b.name))
    arr.forEach(p => sortProcs(p.children))
  }
  sortProcs(roots)

  return roots
}

// ── Group processes by type ───────────────────────────────────────────────────
function groupByType(roots) {
  const groups = { windows: [], corporate: [], other: [] }
  const seen = new Set()
  const flatten = (nodes) => {
    nodes.forEach(n => {
      if (!seen.has(n._key)) {
        seen.add(n._key)
        groups[classifyProcess(n.name)].push(n)
      }
      flatten(n.children)
    })
  }
  flatten(roots)
  return groups
}

// ── Main ThreatGraph Page ─────────────────────────────────────────────────────
export default function ThreatGraph() {
  const [agents, setAgents]         = useState([])
  const [selectedHost, setSelectedHost] = useState(null)
  const [hostData, setHostData]     = useState(null)
  const [loadingHost, setLoadingHost] = useState(false)
  const [selectedGroup, setSelectedGroup] = useState(null)  // 'windows'|'corporate'|'other'
  const [selectedProc, setSelectedProc]   = useState(null)
  const [timeRange, setTimeRange]   = useState(24)
  const [error, setError]           = useState(null)

  // Load agents
  useEffect(() => {
    api.get('/api/v1/agents')
      .then(r => setAgents(r.data.agents || []))
      .catch(() => setError('Failed to load agents'))
  }, [])

  // Load host data when agent selected
  const loadHost = useCallback(async (agent) => {
    setSelectedHost(agent)
    setSelectedGroup(null)
    setSelectedProc(null)
    setHostData(null)
    setLoadingHost(true)
    try {
      const r = await api.get(`/api/v1/threat-graph/${encodeURIComponent(agent.hostname)}`, {
        params: { since_hours: timeRange }
      })
      setHostData(r.data)
    } catch {
      setError('Failed to load host data')
    } finally {
      setLoadingHost(false)
    }
  }, [timeRange])

  // Build tree and groups from hostData
  const processTree = hostData ? buildProcessTree(hostData.processes || []) : []
  const groups      = groupByType(processTree)
  const allEvents   = hostData?.all_events || []

  // Processes to show in tree (filtered by selected group)
  const visibleRoots = selectedGroup
    ? processTree.filter(p => classifyProcess(p.name) === selectedGroup ||
        p.children.some(c => classifyProcess(c.name) === selectedGroup))
    : processTree

  const totalProcesses = (hostData?.processes || []).length

  return (
    <div className="flex h-screen overflow-hidden bg-siem-bg">

      {/* ── Level 1: Host list ──────────────────────────────────────────── */}
      <div className="w-72 shrink-0 bg-siem-surface border-r border-siem-border flex flex-col">
        <div className="px-4 py-4 border-b border-siem-border">
          <div className="flex items-center gap-2 mb-1">
            <GitBranch size={14} className="text-siem-accent" />
            <span className="text-sm font-bold text-siem-text">Threat Graph</span>
          </div>
          <div className="text-[10px] text-siem-muted">Select a host to explore its process tree</div>
        </div>

        {/* Time range */}
        <div className="px-4 py-2 border-b border-siem-border flex items-center gap-2">
          <Clock size={11} className="text-siem-muted" />
          <span className="text-[10px] text-siem-muted">Last</span>
          {[6, 24, 48, 168].map(h => (
            <button key={h} onClick={() => { setTimeRange(h); if (selectedHost) loadHost(selectedHost) }}
              className={`text-[10px] px-2 py-0.5 rounded transition-colors ${
                timeRange === h
                  ? 'bg-siem-accent text-white'
                  : 'text-siem-muted hover:text-siem-text'
              }`}>
              {h < 24 ? `${h}h` : h === 168 ? '7d' : `${h/24}d`}
            </button>
          ))}
        </div>

        {/* Agent list */}
        <div className="flex-1 overflow-y-auto p-3 space-y-2">
          {agents.length === 0 ? (
            <div className="text-center text-siem-muted text-xs py-8">No agents found</div>
          ) : (
            agents.map(agent => (
              <HostCard key={agent.id} agent={agent}
                onClick={loadHost} selected={selectedHost} />
            ))
          )}
        </div>
      </div>

      {/* ── Level 2: App groups + Process tree ─────────────────────────── */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">

        {!selectedHost ? (
          <div className="flex-1 flex flex-col items-center justify-center text-siem-muted select-none">
            <GitBranch size={52} className="opacity-10 mb-4" />
            <div className="text-base font-semibold text-siem-text/40 mb-1">No host selected</div>
            <div className="text-sm">Choose a host from the left panel to visualize its process tree</div>
          </div>
        ) : loadingHost ? (
          <div className="flex-1 flex items-center justify-center gap-3 text-siem-muted">
            <div className="w-5 h-5 border-2 border-siem-accent/30 border-t-siem-accent rounded-full animate-spin" />
            <span className="text-sm">Loading process graph for <span className="text-siem-accent">{selectedHost.host}</span>…</span>
          </div>
        ) : (
          <>
            {/* Host header */}
            <div className="px-5 py-3 border-b border-siem-border bg-siem-surface flex items-center gap-3 shrink-0">
              <Monitor size={16} className="text-siem-accent" />
              <div>
                <span className="text-sm font-bold text-siem-text">{selectedHost.hostname}</span>
                <span className="text-siem-muted text-xs ml-2">
                  {totalProcesses} process events · {allEvents.length} total events
                </span>
              </div>
              {selectedGroup && (
                <button onClick={() => setSelectedGroup(null)}
                  className="ml-auto text-[10px] text-siem-muted hover:text-siem-text border border-siem-border rounded px-2 py-1 flex items-center gap-1">
                  <X size={9} /> Show all groups
                </button>
              )}
            </div>

            <div className="flex flex-1 overflow-hidden">
              {/* Group cards + tree */}
              <div className="flex-1 flex flex-col overflow-hidden">

                {/* App group cards */}
                {!selectedGroup && (
                  <div className="grid grid-cols-3 gap-3 p-4 shrink-0 border-b border-siem-border">
                    {Object.entries(groups).map(([type, procs]) => (
                      procs.length > 0 && (
                        <AppGroupCard key={type} group={procs} type={type}
                          onClick={setSelectedGroup} selected={selectedGroup} />
                      )
                    ))}
                  </div>
                )}

                {/* Selected group header */}
                {selectedGroup && (
                  <div className={`px-5 py-2.5 border-b border-siem-border shrink-0 flex items-center gap-2 ${GROUP_STYLE[selectedGroup].bg}`}>
                    {(() => { const Icon = GROUP_STYLE[selectedGroup].icon; return <Icon size={13} className={GROUP_STYLE[selectedGroup].color} /> })()}
                    <span className={`text-xs font-semibold ${GROUP_STYLE[selectedGroup].color}`}>
                      {GROUP_STYLE[selectedGroup].label}
                    </span>
                    <span className="text-[10px] text-siem-muted">
                      — {groups[selectedGroup]?.length || 0} processes · click any node to see details
                    </span>
                  </div>
                )}

                {/* Process tree */}
                <div className="flex-1 overflow-y-auto p-4">
                  {processTree.length === 0 ? (
                    <div className="flex flex-col items-center justify-center h-full text-siem-muted">
                      <Cpu size={32} className="opacity-20 mb-3" />
                      <div className="text-sm">No process events found in the last {timeRange}h</div>
                      <div className="text-xs mt-1">Try extending the time range</div>
                    </div>
                  ) : (
                    <div className="font-mono">
                      {(selectedGroup
                        ? groups[selectedGroup] || []
                        : processTree
                      ).map((proc, i) => (
                        <ProcessNode key={i} proc={proc} depth={0}
                          allEvents={allEvents}
                          onSelect={setSelectedProc}
                          selected={selectedProc} />
                      ))}
                    </div>
                  )}
                </div>
              </div>

              {/* ── Level 3: Process detail panel ─────────────────────── */}
              {selectedProc && (
                <ProcessDetail
                  proc={selectedProc}
                  allEvents={allEvents}
                  onClose={() => setSelectedProc(null)}
                />
              )}
            </div>
          </>
        )}
      </div>
    </div>
  )
}
