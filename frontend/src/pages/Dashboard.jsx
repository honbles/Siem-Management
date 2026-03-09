import { useEffect, useState, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Activity, Monitor, Bell, TrendingUp, Wifi, AlertTriangle,
  Shield, Globe, Cpu, ChevronRight, Clock, ArrowUpRight,
  CheckCircle, XCircle, Zap, FileText, Database, RefreshCw,
  Eye
} from 'lucide-react'
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis,
  Tooltip, ResponsiveContainer, Cell, CartesianGrid
} from 'recharts'
import { format, formatDistanceToNow } from 'date-fns'
import api from '../api/client'
import { useLiveFeed } from '../api/useLiveFeed'
import { SeverityBadge } from '../components/SeverityBadge'

// ── Palette ───────────────────────────────────────────────────────────────────
const SEV_COLOR = { 5:'#ef4444', 4:'#f97316', 3:'#eab308', 2:'#3b82f6', 1:'#475569' }
const SEV_LABEL = { 5:'Critical', 4:'High', 3:'Medium', 2:'Low', 1:'Info' }
const TYPE_COLOR = {
  registry:'#a855f7', dns:'#06b6d4', network:'#3b82f6',
  process:'#8b949e', file:'#eab308', logon:'#22c55e', health:'#475569',
}
const SUSPICIOUS = ['rustdesk','ngrok','anydesk','cobalt','mimikatz','meterpreter']
const isSusp = v => v && SUSPICIOUS.some(k => v.toLowerCase().includes(k))

// ── Small reusable components ─────────────────────────────────────────────────

function StatCard({ icon: Icon, label, value, sub, color = 'text-siem-accent', onClick, warn }) {
  return (
    <div onClick={onClick}
      className={`bg-siem-surface border rounded-xl p-4 transition-all duration-200 ${
        onClick ? 'cursor-pointer hover:border-siem-accent/50 hover:bg-white/[0.02] active:scale-[0.98]' : ''
      } ${warn ? 'border-red-800/60' : 'border-siem-border'}`}>
      <div className="flex items-center justify-between mb-2">
        <span className="text-[10px] uppercase tracking-wider text-siem-muted">{label}</span>
        <Icon size={15} className={color} />
      </div>
      <div className={`text-3xl font-bold font-mono ${color}`}>{value?.toLocaleString() ?? '—'}</div>
      {sub && <div className="text-[10px] text-siem-muted mt-1">{sub}</div>}
      {onClick && <div className="text-[9px] text-siem-muted/40 mt-2 flex items-center gap-1">click to view <ChevronRight size={8}/></div>}
    </div>
  )
}

function SectionCard({ title, icon: Icon, iconColor = 'text-siem-accent', children, action, count }) {
  return (
    <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden flex flex-col">
      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-siem-border shrink-0">
        <Icon size={13} className={iconColor} />
        <span className="text-xs font-semibold text-siem-text">{title}</span>
        {count != null && <span className="text-[9px] text-siem-muted ml-0.5">({count})</span>}
        {action && <div className="ml-auto">{action}</div>}
      </div>
      <div className="flex-1 overflow-hidden">{children}</div>
    </div>
  )
}

// ── Host Health Row ───────────────────────────────────────────────────────────
function HostRow({ host, onClick }) {
  const sev = SEV_COLOR[host.max_severity] || SEV_COLOR[1]
  const isOnline = host.online
  return (
    <div onClick={() => onClick(host)}
      className="flex items-center gap-3 px-4 py-2 hover:bg-white/[0.02] cursor-pointer border-b border-siem-border/30 last:border-0 group transition-colors">
      <div className={`w-1.5 h-1.5 rounded-full shrink-0 ${isOnline ? 'bg-emerald-400' : 'bg-red-500/60'}`} />
      <Monitor size={12} className="text-siem-muted shrink-0" />
      <span className="text-xs font-mono text-siem-text truncate flex-1">{host.hostname || host.host}</span>
      <div className="flex items-center gap-1.5">
        {host.max_severity >= 4 && (
          <span className="text-[8px] px-1.5 py-0.5 rounded border border-red-800 text-red-400 font-bold">
            {SEV_LABEL[host.max_severity]}
          </span>
        )}
        <span className="text-[10px] font-mono text-siem-muted">{Number(host.event_count).toLocaleString()}</span>
      </div>
      <ChevronRight size={10} className="text-siem-muted/30 group-hover:text-siem-muted transition-colors shrink-0" />
    </div>
  )
}

// ── Alert Row ─────────────────────────────────────────────────────────────────
function AlertRow({ alert, onClick }) {
  return (
    <div onClick={() => onClick(alert)}
      className="flex items-start gap-3 px-4 py-2.5 hover:bg-white/[0.02] cursor-pointer border-b border-siem-border/30 last:border-0 group transition-colors">
      <div className="w-1.5 h-1.5 rounded-full mt-1.5 shrink-0" style={{ background: SEV_COLOR[alert.severity] || '#475569' }} />
      <div className="flex-1 min-w-0">
        <div className="text-xs text-siem-text truncate font-medium">{alert.title}</div>
        <div className="flex gap-2 mt-0.5">
          <span className="text-[9px] text-siem-muted font-mono">{alert.host}</span>
          <span className="text-[9px] text-siem-muted/50">
            {formatDistanceToNow(new Date(alert.created_at), { addSuffix: true })}
          </span>
        </div>
      </div>
      <ChevronRight size={10} className="text-siem-muted/30 group-hover:text-siem-muted mt-1 shrink-0" />
    </div>
  )
}

// ── Threat Feed Row ───────────────────────────────────────────────────────────
function ThreatRow({ event, onClick }) {
  const susp = isSusp(event.process_name) || isSusp(event.dst_ip) || isSusp(event.command_line)
  return (
    <div onClick={() => onClick(event)}
      className="flex items-start gap-2 px-4 py-2 hover:bg-white/[0.02] cursor-pointer border-b border-siem-border/20 last:border-0 group transition-colors">
      <div className="w-1 h-1 rounded-full mt-1.5 shrink-0" style={{ background: SEV_COLOR[event.severity] || '#475569' }} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2">
          <span className={`text-[9px] font-mono ${TYPE_COLOR[event.event_type] ? '' : 'text-siem-muted'}`}
                style={{ color: TYPE_COLOR[event.event_type] }}>
            {event.event_type}
          </span>
          <span className="text-[10px] font-mono text-siem-text truncate">
            {event.process_name || event.source}
          </span>
          {susp && <AlertTriangle size={9} className="text-red-400 shrink-0" />}
        </div>
        <div className="text-[9px] text-siem-muted/60 truncate font-mono">
          {event.command_line || event.dst_ip || event.file_path || event.host}
        </div>
      </div>
      <span className="text-[8px] text-siem-muted/40 shrink-0 font-mono">
        {format(new Date(event.time), 'HH:mm:ss')}
      </span>
    </div>
  )
}

// ── Mini bar ──────────────────────────────────────────────────────────────────
function MiniBar({ value, max, color }) {
  return (
    <div className="h-1 bg-siem-border/30 rounded-full overflow-hidden flex-1">
      <div className="h-full rounded-full" style={{ width:`${Math.round((value/max)*100)}%`, background: color || '#00d4ff' }} />
    </div>
  )
}

// ── Custom tooltip ────────────────────────────────────────────────────────────
const TooltipStyle = { background:'#161b22', border:'1px solid #30363d', borderRadius:6, fontSize:10 }

// ── MAIN DASHBOARD ────────────────────────────────────────────────────────────
export default function Dashboard() {
  const [stats, setStats]     = useState(null)
  const [loading, setLoading] = useState(true)
  const [lastRefresh, setLastRefresh] = useState(null)
  const { events: liveEvents, connected } = useLiveFeed(30)
  const navigate = useNavigate()

  const load = async () => {
    try {
      const r = await api.get('/api/v1/stats')
      setStats(r.data)
      setLastRefresh(new Date())
    } finally { setLoading(false) }
  }

  useEffect(() => {
    load()
    const id = setInterval(load, 30000)
    return () => clearInterval(id)
  }, [])

  const s   = stats?.summary
  const d   = stats?.dashboard
  const raw = stats

  // Timeline — stack high/medium/low
  const timeline = useMemo(() =>
    (d?.timeline_48h || []).map(p => ({
      time:   format(new Date(p.hour), 'HH:mm'),
      high:   Number(p.high   || 0),
      medium: Number(p.medium || 0),
      low:    Number(p.low    || 0),
    })), [d]
  )

  const eventTypes = useMemo(() =>
    (d?.by_type || raw?.by_type || []).map(e => ({
      name: e.event_type, count: Number(e.count),
      color: TYPE_COLOR[e.event_type] || '#8b949e'
    })), [d, raw]
  )
  const maxTypeCount = Math.max(...eventTypes.map(e => e.count), 1)

  const hostsActivity = useMemo(() =>
    (d?.hosts_activity || []).map(h => ({
      ...h,
      hostname:    h.host,
      event_count: Number(h.event_count),
      max_severity:Number(h.max_severity),
      online:      true, // approximation from 24h activity
    })), [d]
  )

  const topProcesses = useMemo(() =>
    (d?.top_processes || []).slice(0, 10), [d]
  )
  const maxProcCount = Math.max(...topProcesses.map(p => Number(p.count)), 1)

  const topDomains = useMemo(() =>
    (d?.top_domains || []).slice(0, 10), [d]
  )
  const maxDomCount = Math.max(...topDomains.map(p => Number(p.count)), 1)

  const threatFeed   = d?.threat_feed   || []
  const recentAlerts = d?.recent_alerts || []

  // Severity distribution for pill row
  const sevDist = raw?.by_severity || []

  if (loading) return (
    <div className="flex items-center justify-center h-full gap-3">
      <div className="w-5 h-5 border-2 border-siem-accent/30 border-t-siem-accent rounded-full animate-spin" />
      <span className="text-sm text-siem-muted">Loading dashboard…</span>
    </div>
  )

  return (
    <div className="h-screen overflow-y-auto bg-siem-bg">
      <div className="p-5 space-y-4 max-w-[1600px]">

        {/* ── Header ── */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-lg font-bold text-siem-text">Dashboard</h1>
            {lastRefresh && (
              <p className="text-[10px] text-siem-muted mt-0.5">
                Refreshed {format(lastRefresh, 'HH:mm:ss')} · auto-refresh 30s
              </p>
            )}
          </div>
          <div className="flex items-center gap-3">
            {/* Live indicator */}
            <div className={`flex items-center gap-1.5 text-[10px] ${connected ? 'text-emerald-400' : 'text-siem-muted'}`}>
              <div className={`w-1.5 h-1.5 rounded-full ${connected ? 'bg-emerald-400 animate-pulse' : 'bg-siem-muted'}`} />
              {connected ? 'Live' : 'Reconnecting…'}
            </div>
            <button onClick={load}
              className="flex items-center gap-1.5 text-[10px] text-siem-muted hover:text-siem-text border border-siem-border rounded-lg px-2.5 py-1.5 transition-colors">
              <RefreshCw size={10} /> Refresh
            </button>
          </div>
        </div>

        {/* ── Stat cards row ── */}
        <div className="grid grid-cols-2 xl:grid-cols-4 gap-3">
          <StatCard icon={Activity}   label="Events (24h)"
            value={s?.events_today} sub={`${s?.total_events?.toLocaleString()} total`}
            onClick={() => navigate('/events')} />
          <StatCard icon={AlertTriangle} label="High Severity (24h)"
            value={s?.high_severity_today} color="text-orange-400"
            warn={s?.high_severity_today > 0}
            onClick={() => navigate('/alerts')} />
          <StatCard icon={Monitor}    label="Agents Online"
            value={s?.online_agents} sub={`of ${s?.total_agents} total`}
            color="text-emerald-400"
            onClick={() => navigate('/agents')} />
          <StatCard icon={Bell}       label="Open Alerts"
            value={s?.open_alerts} color="text-red-400"
            warn={s?.open_alerts > 0}
            onClick={() => navigate('/alerts')} />
        </div>

        {/* ── Severity pills ── */}
        {sevDist.length > 0 && (
          <div className="flex gap-2 flex-wrap">
            {sevDist.map(e => (
              <button key={e.severity}
                onClick={() => navigate(`/events?severity=${e.severity}`)}
                className="flex items-center gap-1.5 px-2.5 py-1 rounded-full border border-siem-border bg-siem-surface hover:border-siem-accent/40 transition-colors text-[10px]">
                <div className="w-1.5 h-1.5 rounded-full" style={{ background: SEV_COLOR[e.severity] }} />
                <span className="text-siem-text font-medium">{SEV_LABEL[e.severity] || e.label}</span>
                <span className="text-siem-muted">{Number(e.count).toLocaleString()}</span>
              </button>
            ))}
          </div>
        )}

        {/* ── Timeline (stacked) ── */}
        <div className="bg-siem-surface border border-siem-border rounded-xl p-4">
          <div className="flex items-center gap-2 mb-3">
            <Activity size={13} className="text-siem-accent" />
            <span className="text-xs font-semibold text-siem-text">Event Timeline — last 48h</span>
            <div className="ml-auto flex gap-3 text-[9px]">
              {[['High','#ef4444'],['Medium','#eab308'],['Low','#3b82f6']].map(([l,c])=>(
                <span key={l} className="flex items-center gap-1">
                  <span className="w-2 h-2 rounded-sm inline-block" style={{background:c}} />{l}
                </span>
              ))}
            </div>
          </div>
          <ResponsiveContainer width="100%" height={130}>
            <AreaChart data={timeline} margin={{ top:0, right:0, left:-20, bottom:0 }}>
              <defs>
                {[['high','#ef4444'],['medium','#eab308'],['low','#3b82f6']].map(([k,c])=>(
                  <linearGradient key={k} id={`g_${k}`} x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%"  stopColor={c} stopOpacity={0.4}/>
                    <stop offset="95%" stopColor={c} stopOpacity={0}/>
                  </linearGradient>
                ))}
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#21262d" vertical={false} />
              <XAxis dataKey="time" tick={{ fontSize:9, fill:'#8b949e' }} interval="preserveStartEnd" />
              <YAxis tick={{ fontSize:9, fill:'#8b949e' }} />
              <Tooltip contentStyle={TooltipStyle} />
              <Area type="monotone" dataKey="low"    stackId="1" stroke="#3b82f6" fill="url(#g_low)"    strokeWidth={1} />
              <Area type="monotone" dataKey="medium" stackId="1" stroke="#eab308" fill="url(#g_medium)" strokeWidth={1} />
              <Area type="monotone" dataKey="high"   stackId="1" stroke="#ef4444" fill="url(#g_high)"   strokeWidth={1.5} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* ── Middle row: Hosts | Alerts | Event types ── */}
        <div className="grid grid-cols-3 gap-4">

          {/* Host activity */}
          <SectionCard title="Host Activity (24h)" icon={Monitor}
            count={hostsActivity.length}
            action={
              <button onClick={() => navigate('/agents')}
                className="text-[9px] text-siem-muted hover:text-siem-accent flex items-center gap-0.5">
                All agents <ChevronRight size={9}/>
              </button>
            }>
            <div className="overflow-y-auto max-h-52">
              {hostsActivity.length === 0
                ? <div className="text-center text-[10px] text-siem-muted py-6">No activity</div>
                : hostsActivity.map((h, i) => (
                    <HostRow key={i} host={h}
                      onClick={() => navigate(`/threat-intel?host=${h.hostname}`)} />
                  ))
              }
            </div>
          </SectionCard>

          {/* Open alerts */}
          <SectionCard title="Open Alerts" icon={Bell} iconColor="text-red-400"
            count={recentAlerts.length}
            action={
              <button onClick={() => navigate('/alerts')}
                className="text-[9px] text-siem-muted hover:text-siem-accent flex items-center gap-0.5">
                All alerts <ChevronRight size={9}/>
              </button>
            }>
            <div className="overflow-y-auto max-h-52">
              {recentAlerts.length === 0
                ? <div className="text-center text-[10px] text-siem-muted py-6 flex flex-col items-center gap-2">
                    <CheckCircle size={20} className="text-emerald-400/40"/>
                    No open alerts
                  </div>
                : recentAlerts.map((a, i) => (
                    <AlertRow key={i} alert={a} onClick={() => navigate(`/alerts`)} />
                  ))
              }
            </div>
          </SectionCard>

          {/* Event types */}
          <SectionCard title="Event Types (24h)" icon={Database} iconColor="text-purple-400">
            <div className="p-3 space-y-1.5">
              {eventTypes.map((e, i) => (
                <div key={i} onClick={() => navigate(`/events?type=${e.name}`)}
                  className="flex items-center gap-2 cursor-pointer hover:bg-white/[0.02] rounded px-1 py-0.5 group transition-colors">
                  <div className="w-1.5 h-1.5 rounded-full shrink-0" style={{ background: e.color }} />
                  <span className="text-[10px] text-siem-muted w-20 shrink-0">{e.name}</span>
                  <MiniBar value={e.count} max={maxTypeCount} color={e.color} />
                  <span className="text-[9px] font-mono text-siem-muted shrink-0">{e.count.toLocaleString()}</span>
                  <ChevronRight size={8} className="text-siem-muted/20 group-hover:text-siem-muted/60 shrink-0" />
                </div>
              ))}
            </div>
          </SectionCard>
        </div>

        {/* ── Bottom row: Threat feed | Top processes | Top domains ── */}
        <div className="grid grid-cols-3 gap-4">

          {/* Threat feed */}
          <SectionCard title="Threat Feed" icon={Zap} iconColor="text-orange-400"
            count={threatFeed.length}
            action={
              <button onClick={() => navigate('/search')}
                className="text-[9px] text-siem-muted hover:text-siem-accent flex items-center gap-0.5">
                Search <ChevronRight size={9}/>
              </button>
            }>
            <div className="overflow-y-auto max-h-64">
              {threatFeed.length === 0
                ? <div className="text-center text-[10px] text-siem-muted py-6">No threats detected</div>
                : threatFeed.map((e, i) => (
                    <ThreatRow key={i} event={e} onClick={() => navigate('/search')} />
                  ))
              }
            </div>
          </SectionCard>

          {/* Top processes */}
          <SectionCard title="Top Processes (24h)" icon={Cpu} iconColor="text-blue-400"
            action={
              <button onClick={() => navigate('/threat-graph')}
                className="text-[9px] text-siem-muted hover:text-siem-accent flex items-center gap-0.5">
                Graph <ChevronRight size={9}/>
              </button>
            }>
            <div className="p-3 space-y-1.5 overflow-y-auto max-h-64">
              {topProcesses.map((p, i) => {
                const count = Number(p.count)
                const susp  = isSusp(p.process_name)
                return (
                  <div key={i}
                    onClick={() => navigate(`/search?q=${encodeURIComponent(p.process_name)}`)}
                    className="flex items-center gap-2 cursor-pointer hover:bg-white/[0.02] rounded px-1 py-0.5 group transition-colors">
                    <div className="w-1 h-1 rounded-full shrink-0" style={{ background: SEV_COLOR[p.max_severity] || '#475569' }} />
                    <span className={`text-[10px] font-mono truncate flex-1 ${susp ? 'text-red-400' : 'text-siem-text'}`}>
                      {susp && <AlertTriangle size={8} className="inline mr-1" />}
                      {p.process_name}
                    </span>
                    <MiniBar value={count} max={maxProcCount} color={SEV_COLOR[p.max_severity] || '#8b949e'} />
                    <span className="text-[9px] font-mono text-siem-muted shrink-0 w-10 text-right">{count.toLocaleString()}</span>
                    <ChevronRight size={8} className="text-siem-muted/20 group-hover:text-siem-muted/60 shrink-0" />
                  </div>
                )
              })}
            </div>
          </SectionCard>

          {/* Top domains */}
          <SectionCard title="Top DNS Domains (24h)" icon={Globe} iconColor="text-cyan-400"
            action={
              <button onClick={() => navigate('/threat-intel')}
                className="text-[9px] text-siem-muted hover:text-siem-accent flex items-center gap-0.5">
                Intel <ChevronRight size={9}/>
              </button>
            }>
            <div className="p-3 space-y-1.5 overflow-y-auto max-h-64">
              {topDomains.map((d, i) => {
                const count = Number(d.count)
                const susp  = isSusp(d.domain)
                return (
                  <div key={i}
                    onClick={() => navigate(`/threat-intel?host=${d.host}`)}
                    className="flex items-center gap-2 cursor-pointer hover:bg-white/[0.02] rounded px-1 py-0.5 group transition-colors">
                    <div className={`w-1 h-1 rounded-full shrink-0 ${susp ? 'bg-red-400' : 'bg-cyan-400/40'}`} />
                    <span className={`text-[10px] font-mono truncate flex-1 ${susp ? 'text-red-400' : 'text-siem-text'}`}>
                      {susp && <AlertTriangle size={8} className="inline mr-1" />}
                      {d.domain}
                    </span>
                    <MiniBar value={count} max={maxDomCount} color={susp ? '#ef4444' : '#06b6d4'} />
                    <span className="text-[9px] font-mono text-siem-muted shrink-0 w-10 text-right">{count.toLocaleString()}</span>
                    <ChevronRight size={8} className="text-siem-muted/20 group-hover:text-siem-muted/60 shrink-0" />
                  </div>
                )
              })}
              {topDomains.length === 0 && <div className="text-center text-[10px] text-siem-muted py-4">No DNS data</div>}
            </div>
          </SectionCard>
        </div>

        {/* ── Live event feed ── */}
        <SectionCard title="Live Event Feed" icon={Activity}
          iconColor={connected ? 'text-emerald-400' : 'text-siem-muted'}
          action={
            <button onClick={() => navigate('/events')}
              className="text-[9px] text-siem-muted hover:text-siem-accent flex items-center gap-0.5">
              All events <ChevronRight size={9}/>
            </button>
          }>
          <div className="overflow-x-auto">
            <div className="min-w-[500px]">
              {liveEvents.length === 0 ? (
                <div className="text-center text-[10px] text-siem-muted py-6">Waiting for live events…</div>
              ) : (
                liveEvents.map((ev, i) => (
                  <div key={ev.id || i}
                    onClick={() => navigate('/events')}
                    className="flex items-center gap-3 px-4 py-1.5 text-[10px] border-b border-siem-border/20 last:border-0 hover:bg-white/[0.02] cursor-pointer transition-colors">
                    <div className="w-1 h-1 rounded-full shrink-0" style={{ background: SEV_COLOR[ev.severity] || '#475569' }} />
                    <span className="font-mono text-siem-muted/60 w-16 shrink-0">{format(new Date(ev.time), 'HH:mm:ss')}</span>
                    <span className="font-mono text-siem-text w-28 truncate shrink-0">{ev.host}</span>
                    <span className="shrink-0" style={{ color: TYPE_COLOR[ev.event_type] || '#8b949e' }}>{ev.event_type}</span>
                    <span className="text-siem-muted/60 truncate flex-1 font-mono">
                      {ev.process_name || ev.source || '—'}
                    </span>
                    <SeverityBadge severity={ev.severity} />
                  </div>
                ))
              )}
            </div>
          </div>
        </SectionCard>

      </div>
    </div>
  )
}
