import { useEffect, useState, useMemo } from 'react'
import { Globe, Cpu, User, AlertTriangle, RefreshCw, Monitor,
         Search, X, Clock, Wifi, FileText, Key, ChevronRight,
         ArrowUpRight, Shield, Activity, Database } from 'lucide-react'
import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, BarChart, Bar, Cell } from 'recharts'
import { format } from 'date-fns'
import api from '../api/client'

const SUSPICIOUS = ['rustdesk','urban-vpn','ngrok','teamviewer','anydesk','wpad','onion',
  'cobalt','meterpreter','mimikatz','pastebin','ngrok','duckdns','no-ip','ddns']
const isSusp = v => v && SUSPICIOUS.some(k => v.toLowerCase().includes(k))

const SEV_DOT = { 5:'#ef4444',4:'#f97316',3:'#eab308',2:'#3b82f6',1:'#475569' }
const TYPE_COLOR = {
  registry:'#a855f7', dns:'#06b6d4', network:'#3b82f6',
  process:'#8b949e', file:'#eab308', logon:'#22c55e',
}

function HostCard({ agent, onClick, selected }) {
  const isSel = selected?.id === agent.id
  return (
    <div onClick={() => onClick(agent)}
      className={`cursor-pointer rounded-lg border p-3 transition-all ${
        isSel ? 'bg-siem-accent/10 border-siem-accent' : 'bg-siem-surface border-siem-border hover:border-siem-accent/30'
      }`}>
      <div className="flex items-center gap-2.5">
        <div className={`w-7 h-7 rounded-lg flex items-center justify-center border shrink-0 ${
          isSel ? 'bg-siem-accent/20 border-siem-accent' : 'bg-siem-bg border-siem-border'
        }`}>
          <Monitor size={13} className={isSel ? 'text-siem-accent' : 'text-siem-muted'} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="text-xs font-bold text-siem-text truncate">{agent.hostname}</div>
          <div className="text-[9px] text-siem-muted">{agent.last_ip || '—'}</div>
        </div>
        <div className={`w-1.5 h-1.5 rounded-full shrink-0 ${agent.online ? 'bg-emerald-400' : 'bg-red-500'}`} />
      </div>
      <div className="flex gap-1.5 mt-1.5">
        <div className="bg-siem-bg/60 rounded px-1.5 py-0.5 text-[9px] text-siem-muted flex-1 text-center">
          {(agent.event_count || 0).toLocaleString()} events
        </div>
        <div className="bg-siem-bg/60 rounded px-1.5 py-0.5 text-[9px] text-siem-muted">{agent.os || 'win'}</div>
      </div>
    </div>
  )
}

function RankBar({ rows, keyField, valueField, colorFn, onClick, selectedKey }) {
  if (!rows?.length) return <div className="text-[10px] text-siem-muted text-center py-6">No data</div>
  const max = rows[0]?.[valueField] || 1
  return (
    <div className="space-y-1.5">
      {rows.map((row, i) => {
        const label = row[keyField]
        const count = Number(row[valueField])
        const pct   = Math.round((count / max) * 100)
        const susp  = isSusp(label)
        const isSel = selectedKey === label
        return (
          <div key={i} onClick={() => onClick?.(row)}
            className={`rounded-lg px-2 py-1.5 cursor-pointer transition-all ${
              isSel ? 'bg-siem-accent/10 border border-siem-accent/40' : 'hover:bg-white/[0.02] border border-transparent'
            }`}>
            <div className="flex items-center justify-between mb-1">
              <span className={`text-[10px] font-mono truncate flex-1 mr-2 ${susp ? 'text-red-400' : 'text-siem-text'}`}>
                {susp && <AlertTriangle size={8} className="inline mr-1 text-red-400" />}
                {label || '—'}
              </span>
              <span className="text-[9px] text-siem-muted shrink-0">{count.toLocaleString()}</span>
            </div>
            <div className="h-1 bg-siem-border/30 rounded-full overflow-hidden">
              <div className="h-full rounded-full transition-all"
                style={{ width:`${pct}%`, background: susp ? '#ef4444' : (colorFn?.(row) || '#00d4ff') }} />
            </div>
          </div>
        )
      })}
    </div>
  )
}

function Section({ title, icon: Icon, color = 'text-siem-accent', children, count }) {
  const [open, setOpen] = useState(true)
  return (
    <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden">
      <div className="flex items-center gap-2 px-4 py-3 border-b border-siem-border cursor-pointer"
           onClick={() => setOpen(o => !o)}>
        <Icon size={13} className={color} />
        <span className="text-xs font-semibold text-siem-text">{title}</span>
        {count != null && <span className="text-[9px] text-siem-muted ml-1">({count})</span>}
        <ChevronRight size={12} className={`ml-auto text-siem-muted transition-transform ${open ? 'rotate-90' : ''}`} />
      </div>
      {open && <div className="p-3">{children}</div>}
    </div>
  )
}

export default function ThreatIntel() {
  const [agents, setAgents]   = useState([])
  const [search, setSearch]   = useState('')
  const [selected, setSelected] = useState(null)
  const [data, setData]       = useState(null)
  const [loading, setLoading] = useState(false)
  const [hours, setHours]     = useState(24)
  const [drilldown, setDrilldown] = useState(null) // {type, value}

  useEffect(() => {
    api.get('/api/v1/agents').then(r => setAgents(r.data.agents || []))
  }, [])

  const load = async (agent, h = hours) => {
    setSelected(agent); setData(null); setDrilldown(null); setLoading(true)
    try {
      const r = await api.get(`/api/v1/threat-intel/${encodeURIComponent(agent.hostname)}`, { params: { hours: h } })
      setData(r.data)
    } catch(e) { console.error(e) }
    finally { setLoading(false) }
  }

  const filteredAgents = useMemo(() =>
    agents.filter(a => !search || a.hostname?.toLowerCase().includes(search.toLowerCase()) || a.last_ip?.includes(search)),
    [agents, search]
  )

  const timeline = useMemo(() =>
    (data?.timeline || []).map(p => ({
      time: format(new Date(p.hour), 'HH:mm'),
      count: Number(p.count)
    })), [data]
  )

  const eventTypes = useMemo(() =>
    (data?.event_types || []).map(e => ({
      name: e.event_type, count: Number(e.count), color: TYPE_COLOR[e.event_type] || '#8b949e'
    })), [data]
  )

  const totalEvents = eventTypes.reduce((s, e) => s + e.count, 0)

  return (
    <div className="flex h-screen overflow-hidden bg-siem-bg">

      {/* Sidebar */}
      <div className="w-60 shrink-0 bg-siem-surface border-r border-siem-border flex flex-col">
        <div className="px-3 py-3 border-b border-siem-border">
          <div className="flex items-center gap-2 mb-2">
            <Shield size={12} className="text-siem-accent" />
            <span className="text-xs font-bold text-siem-text">Threat Intel</span>
            <span className="ml-auto text-[9px] text-siem-muted">{agents.length} hosts</span>
          </div>
          <div className="relative">
            <Search size={9} className="absolute left-2 top-1/2 -translate-y-1/2 text-siem-muted" />
            <input value={search} onChange={e => setSearch(e.target.value)}
              placeholder="Search hosts or IPs..."
              className="w-full bg-siem-bg border border-siem-border rounded-lg pl-5 pr-7 py-1.5
                         text-[9px] text-siem-text placeholder-siem-muted/40 outline-none
                         focus:border-siem-accent/50 transition-colors" />
            {search && <button onClick={() => setSearch('')} className="absolute right-2 top-1/2 -translate-y-1/2"><X size={8} className="text-siem-muted" /></button>}
          </div>
        </div>
        <div className="px-3 py-1.5 border-b border-siem-border flex items-center gap-1">
          <Clock size={8} className="text-siem-muted shrink-0" />
          <span className="text-[8px] text-siem-muted mr-1">Last</span>
          {[6, 24, 48, 168].map(h => (
            <button key={h} onClick={() => { setHours(h); if (selected) load(selected, h) }}
              className={`text-[8px] px-1.5 py-0.5 rounded ${hours === h ? 'bg-siem-accent text-white' : 'text-siem-muted hover:text-siem-text'}`}>
              {h < 24 ? `${h}h` : h === 168 ? '7d' : `${h/24}d`}
            </button>
          ))}
        </div>
        <div className="flex-1 overflow-y-auto p-2 space-y-1.5">
          {filteredAgents.length === 0
            ? <div className="text-center text-[9px] text-siem-muted py-8">{search ? 'No hosts match' : 'No agents'}</div>
            : filteredAgents.map(a => <HostCard key={a.id} agent={a} onClick={load} selected={selected} />)
          }
        </div>
      </div>

      {/* Main */}
      <div className="flex-1 overflow-y-auto">
        {!selected ? (
          <div className="flex flex-col items-center justify-center h-full text-siem-muted select-none">
            <Shield size={44} className="opacity-10 mb-4" />
            <div className="text-sm font-semibold text-siem-text/30 mb-1">Select a host</div>
            <div className="text-xs opacity-50">Choose an endpoint to view its threat intelligence</div>
          </div>
        ) : loading ? (
          <div className="flex items-center justify-center h-full gap-3">
            <div className="w-4 h-4 border-2 border-siem-accent/30 border-t-siem-accent rounded-full animate-spin" />
            <span className="text-sm text-siem-muted">Analysing <span className="text-siem-accent">{selected.hostname}</span>…</span>
          </div>
        ) : data && (
          <div className="p-4 space-y-4">
            {/* Header */}
            <div className="flex items-center gap-3">
              <Monitor size={16} className="text-siem-accent" />
              <div>
                <h1 className="text-base font-bold text-siem-text">{selected.hostname}</h1>
                <p className="text-[10px] text-siem-muted">{selected.last_ip} · Threat Intelligence · Last {hours}h</p>
              </div>
              <button onClick={() => load(selected)}
                className="ml-auto flex items-center gap-1.5 text-[10px] text-siem-muted hover:text-siem-text border border-siem-border rounded-lg px-2.5 py-1.5">
                <RefreshCw size={10} /> Refresh
              </button>
            </div>

            {/* Stat pills */}
            <div className="grid grid-cols-4 gap-3">
              {eventTypes.slice(0, 4).map(e => (
                <div key={e.name} onClick={() => setDrilldown({ type: e.name })}
                  className="bg-siem-surface border border-siem-border rounded-xl p-3 cursor-pointer hover:border-siem-accent/40 transition-colors">
                  <div className="text-2xl font-bold font-mono" style={{ color: e.color }}>{e.count.toLocaleString()}</div>
                  <div className="text-[9px] text-siem-muted uppercase tracking-wider mt-0.5">{e.name}</div>
                  <div className="mt-1.5 h-0.5 bg-siem-border/30 rounded-full">
                    <div className="h-full rounded-full" style={{ width:`${Math.round((e.count/totalEvents)*100)}%`, background: e.color }} />
                  </div>
                </div>
              ))}
            </div>

            {/* Timeline + Event types */}
            <div className="grid grid-cols-3 gap-4">
              <div className="col-span-2 bg-siem-surface border border-siem-border rounded-xl p-4">
                <div className="text-xs font-semibold text-siem-text mb-3 flex items-center gap-2">
                  <Activity size={12} className="text-siem-accent" /> Activity Timeline
                </div>
                <ResponsiveContainer width="100%" height={140}>
                  <AreaChart data={timeline}>
                    <defs>
                      <linearGradient id="tg" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="5%" stopColor="#00d4ff" stopOpacity={0.3} />
                        <stop offset="95%" stopColor="#00d4ff" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <XAxis dataKey="time" tick={{ fontSize: 9, fill: '#8b949e' }} interval="preserveStartEnd" />
                    <YAxis tick={{ fontSize: 9, fill: '#8b949e' }} width={30} />
                    <Tooltip contentStyle={{ background:'#161b22', border:'1px solid #30363d', borderRadius:6, fontSize:10 }} />
                    <Area type="monotone" dataKey="count" stroke="#00d4ff" fill="url(#tg)" strokeWidth={1.5} />
                  </AreaChart>
                </ResponsiveContainer>
              </div>

              <div className="bg-siem-surface border border-siem-border rounded-xl p-4">
                <div className="text-xs font-semibold text-siem-text mb-3 flex items-center gap-2">
                  <Database size={12} className="text-siem-accent" /> Event Breakdown
                </div>
                <ResponsiveContainer width="100%" height={140}>
                  <BarChart data={eventTypes} layout="vertical">
                    <XAxis type="number" tick={{ fontSize: 9, fill:'#8b949e' }} />
                    <YAxis dataKey="name" type="category" width={55} tick={{ fontSize: 9, fill:'#8b949e' }} />
                    <Tooltip contentStyle={{ background:'#161b22', border:'1px solid #30363d', borderRadius:6, fontSize:10 }} />
                    <Bar dataKey="count" radius={[0,3,3,0]}>
                      {eventTypes.map((e,i) => <Cell key={i} fill={e.color} />)}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </div>
            </div>

            {/* High severity */}
            {data.high_severity?.length > 0 && (
              <Section title="High Severity Events" icon={AlertTriangle} color="text-red-400" count={data.high_severity.length}>
                <div className="space-y-1">
                  {data.high_severity.slice(0, 10).map((e, i) => (
                    <div key={i} className="flex items-start gap-3 bg-siem-bg/60 rounded-lg px-3 py-2 text-[10px]">
                      <div className="w-1.5 h-1.5 rounded-full mt-1 shrink-0" style={{ background: SEV_DOT[e.severity] || '#475569' }} />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-siem-text">{e.event_type}</span>
                          {e.process_name && <span className="text-siem-muted">{e.process_name}</span>}
                          <span className="text-siem-muted/50 ml-auto shrink-0">{format(new Date(e.time), 'HH:mm:ss')}</span>
                        </div>
                        {(e.command_line || e.dst_ip || e.file_path) && (
                          <div className="font-mono text-[9px] text-siem-muted/70 truncate mt-0.5">
                            {e.command_line || e.dst_ip || e.file_path}
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </Section>
            )}

            {/* 3-col grid */}
            <div className="grid grid-cols-3 gap-4">
              <Section title="Top DNS / Domains" icon={Globe} color="text-cyan-400" count={data.top_domains?.length}>
                <RankBar rows={data.top_domains} keyField="domain" valueField="count"
                  colorFn={r => isSusp(r.domain) ? '#ef4444' : '#06b6d4'}
                  onClick={r => setDrilldown({ type:'domain', value: r.domain })}
                  selectedKey={drilldown?.type==='domain' ? drilldown.value : null} />
              </Section>

              <Section title="Top Connections" icon={Wifi} color="text-blue-400" count={data.top_connections?.length}>
                <RankBar
                  rows={(data.top_connections || []).map(r => ({
                    ...r, label: `${r.dst_ip}:${r.dst_port}`
                  }))}
                  keyField="label" valueField="count"
                  colorFn={() => '#3b82f6'}
                  onClick={r => setDrilldown({ type:'ip', value: r.dst_ip })}
                  selectedKey={drilldown?.type==='ip' ? `${drilldown.value}:${drilldown.port}` : null} />
              </Section>

              <Section title="Top Processes" icon={Cpu} color="text-purple-400" count={data.top_processes?.length}>
                <RankBar rows={data.top_processes} keyField="process_name" valueField="count"
                  colorFn={r => SEV_DOT[r.max_severity] || '#a855f7'}
                  onClick={r => setDrilldown({ type:'process', value: r.process_name })}
                  selectedKey={drilldown?.type==='process' ? drilldown.value : null} />
              </Section>

              <Section title="Top Users" icon={User} color="text-emerald-400" count={data.top_users?.length}>
                <RankBar rows={data.top_users} keyField="user_name" valueField="count"
                  colorFn={() => '#22c55e'}
                  onClick={r => setDrilldown({ type:'user', value: r.user_name })}
                  selectedKey={drilldown?.type==='user' ? drilldown.value : null} />
              </Section>

              <Section title="Top Registry Keys" icon={Key} color="text-orange-400" count={data.top_registry?.length}>
                <RankBar rows={(data.top_registry||[]).filter(r=>r.reg_key)} keyField="reg_key" valueField="count"
                  colorFn={() => '#f97316'}
                  onClick={r => setDrilldown({ type:'reg', value: r.reg_key })}
                  selectedKey={drilldown?.type==='reg' ? drilldown.value : null} />
              </Section>

              <Section title="Top Files" icon={FileText} color="text-yellow-400" count={data.top_files?.length}>
                <RankBar rows={(data.top_files||[]).filter(r=>r.file_path)} keyField="file_path" valueField="count"
                  colorFn={() => '#eab308'}
                  onClick={r => setDrilldown({ type:'file', value: r.file_path })}
                  selectedKey={drilldown?.type==='file' ? drilldown.value : null} />
              </Section>
            </div>

            {/* Drilldown panel */}
            {drilldown && (
              <div className="bg-siem-surface border border-siem-accent/30 rounded-xl p-4">
                <div className="flex items-center gap-2 mb-3">
                  <ArrowUpRight size={13} className="text-siem-accent" />
                  <span className="text-xs font-semibold text-siem-text">
                    Drilldown: <span className="text-siem-accent font-mono">{drilldown.value || drilldown.type}</span>
                  </span>
                  <button onClick={() => setDrilldown(null)} className="ml-auto text-siem-muted hover:text-siem-text"><X size={12} /></button>
                </div>
                <div className="text-[10px] text-siem-muted">
                  Use the <span className="text-siem-accent">Search</span> page to investigate this indicator — filter by
                  {drilldown.type === 'domain'  && <> <code className="text-cyan-400">type:dns search:{drilldown.value}</code></>}
                  {drilldown.type === 'ip'      && <> <code className="text-blue-400">host:{selected.hostname} {drilldown.value}</code></>}
                  {drilldown.type === 'process' && <> <code className="text-purple-400">host:{selected.hostname} cmd:{drilldown.value}</code></>}
                  {drilldown.type === 'user'    && <> <code className="text-emerald-400">user:{drilldown.value}</code></>}
                  {drilldown.type === 'file'    && <> <code className="text-yellow-400">host:{selected.hostname} {drilldown.value}</code></>}
                  {drilldown.type === 'reg'     && <> <code className="text-orange-400">type:registry host:{selected.hostname}</code></>}
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
