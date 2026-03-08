import { useEffect, useState } from 'react'
import { Activity, Monitor, Bell, TrendingUp, Wifi } from 'lucide-react'
import {
  AreaChart, Area, BarChart, Bar, PieChart, Pie, Cell,
  XAxis, YAxis, Tooltip, ResponsiveContainer
} from 'recharts'
import { format } from 'date-fns'
import api from '../api/client'
import { useLiveFeed } from '../api/useLiveFeed'
import { SeverityBadge } from '../components/SeverityBadge'

const SEV_COLORS = { 1: '#8b949e', 2: '#58a6ff', 3: '#d29922', 4: '#db6d28', 5: '#f85149' }

function StatCard({ icon: Icon, label, value, sub, color = 'text-siem-accent' }) {
  return (
    <div className="bg-siem-surface border border-siem-border rounded-xl p-5">
      <div className="flex items-center justify-between mb-3">
        <span className="text-siem-muted text-sm">{label}</span>
        <Icon size={18} className={color} />
      </div>
      <div className="text-3xl font-bold text-siem-text">{value?.toLocaleString() ?? '—'}</div>
      {sub && <div className="text-xs text-siem-muted mt-1">{sub}</div>}
    </div>
  )
}

export default function Dashboard() {
  const [stats, setStats] = useState(null)
  const { events: liveEvents, connected } = useLiveFeed(50)

  useEffect(() => {
    const load = () => api.get('/api/v1/stats').then(r => setStats(r.data))
    load()
    const id = setInterval(load, 30000)
    return () => clearInterval(id)
  }, [])

  const s = stats?.summary
  const timeline = (stats?.timeline || []).map(p => ({
    time: format(new Date(p.time), 'HH:mm'),
    count: p.count,
  }))

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-siem-text">Dashboard</h1>
        <div className={`flex items-center gap-1.5 text-xs ${connected ? 'text-siem-green' : 'text-siem-muted'}`}>
          <Wifi size={13} />
          {connected ? 'Live' : 'Reconnecting...'}
        </div>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 xl:grid-cols-3 gap-4">
        <StatCard icon={Activity}  label="Events today"       value={s?.events_today}        sub={`${s?.total_events?.toLocaleString()} total`} />
        <StatCard icon={TrendingUp} label="High severity (24h)" value={s?.high_severity_today} color="text-siem-orange" />
        <StatCard icon={Monitor}   label="Agents online"      value={s?.online_agents}        sub={`of ${s?.total_agents} total`} color="text-siem-green" />
        <StatCard icon={Bell}      label="Open alerts"        value={s?.open_alerts}          color="text-siem-red" />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        {/* Timeline */}
        <div className="xl:col-span-2 bg-siem-surface border border-siem-border rounded-xl p-5">
          <h2 className="text-sm font-medium text-siem-text mb-4">Events over time (24h)</h2>
          <ResponsiveContainer width="100%" height={180}>
            <AreaChart data={timeline}>
              <defs>
                <linearGradient id="evGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#58a6ff" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#58a6ff" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="time" tick={{ fontSize: 11, fill: '#8b949e' }} />
              <YAxis tick={{ fontSize: 11, fill: '#8b949e' }} />
              <Tooltip contentStyle={{ background: '#161b22', border: '1px solid #30363d', borderRadius: 8 }} />
              <Area type="monotone" dataKey="count" stroke="#58a6ff" fill="url(#evGrad)" strokeWidth={2} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        {/* Severity pie */}
        <div className="bg-siem-surface border border-siem-border rounded-xl p-5">
          <h2 className="text-sm font-medium text-siem-text mb-4">By severity (24h)</h2>
          <ResponsiveContainer width="100%" height={180}>
            <PieChart>
              <Pie data={stats?.by_severity || []} dataKey="count" nameKey="label" cx="50%" cy="50%" outerRadius={70}>
                {(stats?.by_severity || []).map(entry => (
                  <Cell key={entry.severity} fill={SEV_COLORS[entry.severity] || '#8b949e'} />
                ))}
              </Pie>
              <Tooltip contentStyle={{ background: '#161b22', border: '1px solid #30363d', borderRadius: 8 }} />
            </PieChart>
          </ResponsiveContainer>
          <div className="flex flex-wrap gap-2 mt-2">
            {(stats?.by_severity || []).map(e => (
              <span key={e.severity} className="text-xs text-siem-muted">
                <span style={{ color: SEV_COLORS[e.severity] }}>●</span> {e.label}: {e.count}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Event type bar + Live feed */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
        <div className="bg-siem-surface border border-siem-border rounded-xl p-5">
          <h2 className="text-sm font-medium text-siem-text mb-4">Top event types (24h)</h2>
          <ResponsiveContainer width="100%" height={200}>
            <BarChart data={stats?.by_type || []} layout="vertical">
              <XAxis type="number" tick={{ fontSize: 11, fill: '#8b949e' }} />
              <YAxis dataKey="event_type" type="category" width={80} tick={{ fontSize: 11, fill: '#8b949e' }} />
              <Tooltip contentStyle={{ background: '#161b22', border: '1px solid #30363d', borderRadius: 8 }} />
              <Bar dataKey="count" fill="#58a6ff" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Live feed */}
        <div className="bg-siem-surface border border-siem-border rounded-xl p-5">
          <h2 className="text-sm font-medium text-siem-text mb-4">Live event feed</h2>
          <div className="space-y-2 max-h-[200px] overflow-y-auto">
            {liveEvents.length === 0 ? (
              <div className="text-siem-muted text-xs text-center py-8">Waiting for events...</div>
            ) : liveEvents.map((ev, i) => (
              <div key={ev.id || i} className="flex items-center gap-3 text-xs border-b border-siem-border/50 pb-2">
                <SeverityBadge severity={ev.severity} />
                <span className="text-siem-muted shrink-0">{format(new Date(ev.time), 'HH:mm:ss')}</span>
                <span className="text-siem-text font-medium truncate">{ev.host}</span>
                <span className="text-siem-muted truncate">{ev.event_type}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
