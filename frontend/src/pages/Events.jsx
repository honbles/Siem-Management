import { useEffect, useState, useCallback } from 'react'
import { Search, Wifi, Download, X, ChevronRight } from 'lucide-react'
import { format, formatDistanceToNow } from 'date-fns'
import api from '../api/client'
import { useLiveFeed } from '../api/useLiveFeed'
import { SeverityBadge } from '../components/SeverityBadge'

const EVENT_TYPES = ['', 'process', 'network', 'logon', 'registry', 'file', 'dns', 'sysmon', 'raw']

function EventPanel({ event, onClose }) {
  const [detail, setDetail] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    setLoading(true)
    api.get(`/api/v1/events/${event.id}`).then(r => {
      setDetail(r.data)
    }).catch(() => setDetail(null)).finally(() => setLoading(false))
  }, [event.id])

  const ev = detail?.event || event
  const related = detail?.related || []

  const fields = [
    ['Time',         format(new Date(ev.time), 'yyyy-MM-dd HH:mm:ss')],
    ['Agent ID',     ev.agent_id],
    ['Host',         ev.host],
    ['OS',           ev.os],
    ['Event Type',   ev.event_type],
    ['Source',       ev.source],
    ['Severity',     ev.severity],
    ['PID',          ev.pid],
    ['Process',      ev.process_name],
    ['Command Line', ev.command_line],
    ['User',         ev.user_name],
    ['Domain',       ev.domain],
    ['Src IP',       ev.src_ip],
    ['Src Port',     ev.src_port],
    ['Dst IP',       ev.dst_ip],
    ['Dst Port',     ev.dst_port],
    ['Protocol',     ev.proto],
    ['Event ID',     ev.event_id],
    ['Channel',      ev.channel],
  ].filter(([, v]) => v !== null && v !== undefined && v !== '')

  return (
    <div className="fixed inset-0 z-50 flex justify-end" onClick={onClose}>
      <div className="w-full max-w-2xl bg-siem-surface border-l border-siem-border h-full overflow-y-auto shadow-2xl"
           onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between px-5 py-4 border-b border-siem-border sticky top-0 bg-siem-surface z-10">
          <div className="flex items-center gap-2">
            <SeverityBadge severity={ev.severity} />
            <span className="text-siem-accent text-sm font-medium">{ev.event_type}</span>
            <span className="text-siem-muted text-xs">on {ev.host}</span>
          </div>
          <button onClick={onClose} className="text-siem-muted hover:text-siem-text transition-colors">
            <X size={18} />
          </button>
        </div>

        {loading ? (
          <div className="p-6 text-siem-muted text-sm">Loading...</div>
        ) : (
          <div className="p-5 space-y-6">
            {/* Fields */}
            <div>
              <div className="text-xs uppercase tracking-wider text-siem-muted mb-3">Event Details</div>
              <div className="bg-siem-bg rounded-xl border border-siem-border overflow-hidden">
                {fields.map(([label, value], i) => (
                  <div key={label} className={`flex gap-3 px-4 py-2.5 text-sm ${i % 2 === 0 ? '' : 'bg-white/[0.02]'}`}>
                    <span className="text-siem-muted w-32 shrink-0">{label}</span>
                    <span className="text-siem-text break-all font-mono text-xs">{String(value)}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Raw JSON */}
            {ev.raw && (
              <div>
                <div className="text-xs uppercase tracking-wider text-siem-muted mb-3">Raw Data</div>
                <pre className="bg-siem-bg border border-siem-border rounded-xl p-4 text-xs text-siem-accent overflow-x-auto">
                  {JSON.stringify(typeof ev.raw === 'string' ? JSON.parse(ev.raw) : ev.raw, null, 2)}
                </pre>
              </div>
            )}

            {/* Related Events */}
            {related.length > 0 && (
              <div>
                <div className="text-xs uppercase tracking-wider text-siem-muted mb-3">
                  Related Events on {ev.host} <span className="text-siem-muted/50">(±5 min)</span>
                </div>
                <div className="space-y-1">
                  {related.map(r => (
                    <div key={r.id} className="flex items-center gap-3 bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-xs">
                      <SeverityBadge severity={r.severity} />
                      <span className="text-siem-accent">{r.event_type}</span>
                      <span className="text-siem-muted">{r.process_name || r.src_ip || '—'}</span>
                      <span className="text-siem-muted ml-auto">{formatDistanceToNow(new Date(r.time), { addSuffix: true })}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Create Alert */}
            <CreateAlertFromEvent event={ev} />
          </div>
        )}
      </div>
    </div>
  )
}

function CreateAlertFromEvent({ event }) {
  const [open, setOpen] = useState(false)
  const [title, setTitle] = useState(`Manual alert: ${event.event_type} on ${event.host}`)
  const [desc, setDesc] = useState('')
  const [severity, setSeverity] = useState(event.severity)
  const [done, setDone] = useState(false)

  const submit = async (e) => {
    e.preventDefault()
    await api.post('/api/v1/alerts', {
      title, description: desc, severity, host: event.host,
      agent_id: event.agent_id, event_type: event.event_type, event_id: event.id,
    })
    setDone(true)
    setTimeout(() => { setOpen(false); setDone(false) }, 1500)
  }

  if (!open) return (
    <button onClick={() => setOpen(true)}
      className="w-full text-xs border border-siem-border rounded-lg py-2 text-siem-muted hover:text-siem-accent hover:border-siem-accent transition-colors">
      + Create alert from this event
    </button>
  )

  return (
    <div className="bg-siem-bg border border-siem-border rounded-xl p-4">
      <div className="text-xs font-medium text-siem-text mb-3">Create Alert</div>
      {done ? <div className="text-siem-green text-xs text-center py-2">Alert created</div> : (
        <form onSubmit={submit} className="space-y-3">
          <input className="w-full bg-siem-surface border border-siem-border rounded-lg px-3 py-2 text-xs text-siem-text focus:outline-none focus:border-siem-accent"
            value={title} onChange={e => setTitle(e.target.value)} required />
          <textarea rows={2} className="w-full bg-siem-surface border border-siem-border rounded-lg px-3 py-2 text-xs text-siem-text focus:outline-none focus:border-siem-accent resize-none"
            placeholder="Description (optional)" value={desc} onChange={e => setDesc(e.target.value)} />
          <div className="flex gap-2">
            <select className="bg-siem-surface border border-siem-border rounded-lg px-2 py-1.5 text-xs text-siem-text focus:outline-none"
              value={severity} onChange={e => setSeverity(Number(e.target.value))}>
              {[1,2,3,4,5].map(s => <option key={s} value={s}>Severity {s}</option>)}
            </select>
            <button type="button" onClick={() => setOpen(false)}
              className="text-xs text-siem-muted hover:text-siem-text px-3 py-1.5 border border-siem-border rounded-lg">Cancel</button>
            <button type="submit"
              className="text-xs bg-siem-accent hover:bg-siem-accent/90 text-white px-3 py-1.5 rounded-lg ml-auto">Create</button>
          </div>
        </form>
      )}
    </div>
  )
}

export default function Events() {
  const [events, setEvents] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(false)
  const [page, setPage] = useState(0)
  const [live, setLive] = useState(false)
  const [selected, setSelected] = useState(null)
  const { events: liveEvents, connected } = useLiveFeed(200)

  const [filters, setFilters] = useState({
    search: '', agent_id: '', host: '', event_type: '', severity: '', since: '', until: ''
  })

  const limit = 100

  const fetchEvents = useCallback(async (p = 0) => {
    setLoading(true)
    try {
      const params = { limit, offset: p * limit }
      Object.entries(filters).forEach(([k, v]) => { if (v) params[k] = v })
      const { data } = await api.get('/api/v1/events', { params })
      setEvents(data.events || [])
      setTotal(data.total || 0)
    } finally {
      setLoading(false)
    }
  }, [filters])

  useEffect(() => { fetchEvents(0); setPage(0) }, [filters])

  const exportEvents = async (fmt) => {
    const params = new URLSearchParams({ format: fmt, limit: 10000 })
    Object.entries(filters).forEach(([k, v]) => { if (v) params.set(k, v) })
    const token = localStorage.getItem('token')
    const res = await fetch(`/api/v1/events/export?${params}`, { headers: { Authorization: `Bearer ${token}` } })
    const blob = await res.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `opensiem-events.${fmt}`
    a.click()
    URL.revokeObjectURL(url)
  }

  const displayed = live ? liveEvents : events

  return (
    <div className="p-6 space-y-4">
      {selected && <EventPanel event={selected} onClose={() => setSelected(null)} />}

      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-siem-text">Events</h1>
        <div className="flex items-center gap-2">
          {!live && (
            <div className="flex items-center gap-1">
              <button onClick={() => exportEvents('csv')}
                className="flex items-center gap-1 text-xs border border-siem-border text-siem-muted hover:text-siem-text rounded-lg px-2.5 py-1.5 transition-colors">
                <Download size={12} /> CSV
              </button>
              <button onClick={() => exportEvents('json')}
                className="flex items-center gap-1 text-xs border border-siem-border text-siem-muted hover:text-siem-text rounded-lg px-2.5 py-1.5 transition-colors">
                <Download size={12} /> JSON
              </button>
            </div>
          )}
          <button onClick={() => setLive(l => !l)}
            className={`flex items-center gap-1.5 text-xs px-3 py-1.5 rounded-lg border transition-colors ${
              live ? 'bg-siem-green/10 border-siem-green text-siem-green' : 'border-siem-border text-siem-muted hover:text-siem-text'
            }`}>
            <Wifi size={13} />
            {live ? (connected ? 'Live' : 'Reconnecting') : 'Historical'}
          </button>
          {!live && <span className="text-xs text-siem-muted">{total.toLocaleString()} results</span>}
        </div>
      </div>

      {!live && (
        <div className="bg-siem-surface border border-siem-border rounded-xl p-4 grid grid-cols-2 md:grid-cols-4 gap-3">
          <div className="relative col-span-2 md:col-span-1">
            <Search size={14} className="absolute left-2.5 top-2.5 text-siem-muted" />
            <input className="w-full bg-siem-bg border border-siem-border rounded-lg pl-8 pr-3 py-2 text-sm text-siem-text focus:outline-none focus:border-siem-accent"
              placeholder="Search host, user, process..."
              value={filters.search} onChange={e => setFilters(f => ({ ...f, search: e.target.value }))} />
          </div>
          <select className="bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text focus:outline-none focus:border-siem-accent"
            value={filters.event_type} onChange={e => setFilters(f => ({ ...f, event_type: e.target.value }))}>
            {EVENT_TYPES.map(t => <option key={t} value={t}>{t || 'All types'}</option>)}
          </select>
          <select className="bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text focus:outline-none focus:border-siem-accent"
            value={filters.severity} onChange={e => setFilters(f => ({ ...f, severity: e.target.value }))}>
            <option value="">All severity</option>
            <option value="5">Critical (5)</option>
            <option value="4">High+ (≥4)</option>
            <option value="3">Medium+ (≥3)</option>
            <option value="2">Low+ (≥2)</option>
          </select>
          <input className="bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text focus:outline-none focus:border-siem-accent"
            placeholder="Agent ID" value={filters.agent_id} onChange={e => setFilters(f => ({ ...f, agent_id: e.target.value }))} />
        </div>
      )}

      <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-siem-border text-siem-muted text-xs">
                <th className="text-left px-4 py-3">Time</th>
                <th className="text-left px-4 py-3">Sev</th>
                <th className="text-left px-4 py-3">Host</th>
                <th className="text-left px-4 py-3">Type</th>
                <th className="text-left px-4 py-3">User</th>
                <th className="text-left px-4 py-3">Process</th>
                <th className="text-left px-4 py-3">Src IP</th>
                <th className="px-4 py-3"></th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={8} className="text-center py-12 text-siem-muted">Loading...</td></tr>
              ) : displayed.length === 0 ? (
                <tr><td colSpan={8} className="text-center py-12 text-siem-muted">No events found</td></tr>
              ) : displayed.map((ev, i) => (
                <tr key={ev.id || i}
                  className="border-b border-siem-border/40 hover:bg-white/[0.03] cursor-pointer transition-colors"
                  onClick={() => setSelected(ev)}>
                  <td className="px-4 py-2.5 text-siem-muted whitespace-nowrap text-xs">
                    {format(new Date(ev.time), 'MM/dd HH:mm:ss')}
                  </td>
                  <td className="px-4 py-2.5"><SeverityBadge severity={ev.severity} /></td>
                  <td className="px-4 py-2.5 text-siem-text font-medium">{ev.host}</td>
                  <td className="px-4 py-2.5 text-siem-accent">{ev.event_type}</td>
                  <td className="px-4 py-2.5 text-siem-muted">{ev.user_name || '—'}</td>
                  <td className="px-4 py-2.5 text-siem-muted truncate max-w-[150px]">{ev.process_name || '—'}</td>
                  <td className="px-4 py-2.5 text-siem-muted">{ev.src_ip || '—'}</td>
                  <td className="px-4 py-2.5 text-siem-muted"><ChevronRight size={14} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {!live && total > limit && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-siem-border">
            <span className="text-xs text-siem-muted">Page {page + 1} of {Math.ceil(total / limit)}</span>
            <div className="flex gap-2">
              <button disabled={page === 0} onClick={() => { const p = page - 1; setPage(p); fetchEvents(p) }}
                className="text-xs px-3 py-1.5 border border-siem-border rounded-lg text-siem-muted hover:text-siem-text disabled:opacity-40">Previous</button>
              <button disabled={(page + 1) * limit >= total} onClick={() => { const p = page + 1; setPage(p); fetchEvents(p) }}
                className="text-xs px-3 py-1.5 border border-siem-border rounded-lg text-siem-muted hover:text-siem-text disabled:opacity-40">Next</button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
