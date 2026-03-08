import { useEffect, useState } from 'react'
import { Bell, CheckCircle, XCircle, RefreshCw, Plus, X, ChevronRight, Mail } from 'lucide-react'
import { format, formatDistanceToNow } from 'date-fns'
import api from '../api/client'
import { SeverityBadge } from '../components/SeverityBadge'

function StatusBadge({ status }) {
  const map = {
    open:         'bg-red-900/40 text-red-400 border-red-700',
    acknowledged: 'bg-yellow-900/40 text-yellow-400 border-yellow-700',
    closed:       'bg-gray-800 text-gray-500 border-gray-700',
  }
  return <span className={`text-xs px-2 py-0.5 rounded-full border capitalize ${map[status] || map.closed}`}>{status}</span>
}

function AlertPanel({ alertId, onClose, onStatusChange }) {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)

  const load = async () => {
    setLoading(true)
    try {
      const res = await api.get(`/api/v1/alerts/${alertId}`)
      setData(res.data)
    } finally { setLoading(false) }
  }

  useEffect(() => { load() }, [alertId])

  const acknowledge = async () => {
    await api.patch(`/api/v1/alerts/${alertId}/acknowledge`)
    onStatusChange()
    load()
  }

  const close = async () => {
    await api.patch(`/api/v1/alerts/${alertId}/close`)
    onStatusChange()
    load()
  }

  const alert = data?.alert
  const ev = data?.related_event

  const severityLabel = { 1:'Info', 2:'Low', 3:'Medium', 4:'High', 5:'Critical' }

  return (
    <div className="fixed inset-0 z-50 flex justify-end" onClick={onClose}>
      <div className="w-full max-w-2xl bg-siem-surface border-l border-siem-border h-full overflow-y-auto shadow-2xl"
           onClick={e => e.stopPropagation()}>

        <div className="flex items-center justify-between px-5 py-4 border-b border-siem-border sticky top-0 bg-siem-surface z-10">
          <div className="flex items-center gap-2">
            <Bell className="text-siem-accent" size={16} />
            <span className="text-siem-text font-semibold text-sm">Alert Detail</span>
          </div>
          <button onClick={onClose} className="text-siem-muted hover:text-siem-text"><X size={18} /></button>
        </div>

        {loading ? (
          <div className="p-6 text-siem-muted text-sm">Loading...</div>
        ) : !alert ? (
          <div className="p-6 text-siem-muted text-sm">Alert not found</div>
        ) : (
          <div className="p-5 space-y-5">

            {/* Header */}
            <div className="bg-siem-bg border border-siem-border rounded-xl p-4 space-y-2">
              <div className="flex items-center gap-2 flex-wrap">
                <SeverityBadge severity={alert.severity} />
                <StatusBadge status={alert.status} />
                <span className="text-xs text-siem-muted ml-auto">{formatDistanceToNow(new Date(alert.created_at), { addSuffix: true })}</span>
              </div>
              <div className="text-siem-text font-semibold">{alert.title}</div>
              <div className="text-siem-muted text-sm leading-relaxed">{alert.description}</div>
            </div>

            {/* Details */}
            <div>
              <div className="text-xs uppercase tracking-wider text-siem-muted mb-2">Details</div>
              <div className="bg-siem-bg border border-siem-border rounded-xl overflow-hidden">
                {[
                  ['Alert ID',    `#${alert.id}`],
                  ['Created',     format(new Date(alert.created_at), 'yyyy-MM-dd HH:mm:ss')],
                  ['Severity',    `${alert.severity} — ${severityLabel[alert.severity] || alert.severity}`],
                  ['Host',        alert.host || '—'],
                  ['Agent ID',    alert.agent_id || '—'],
                  ['Event Type',  alert.event_type || '—'],
                  ['Status',      alert.status],
                  alert.acknowledged_by && ['Handled by', alert.acknowledged_by],
                  alert.acknowledged_at && ['Handled at', format(new Date(alert.acknowledged_at), 'yyyy-MM-dd HH:mm:ss')],
                ].filter(Boolean).map(([label, value], i) => (
                  <div key={label} className={`flex gap-3 px-4 py-2.5 text-sm ${i % 2 === 0 ? '' : 'bg-white/[0.02]'}`}>
                    <span className="text-siem-muted w-32 shrink-0">{label}</span>
                    <span className="text-siem-text font-mono text-xs break-all">{value}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Related Event */}
            {ev && (
              <div>
                <div className="text-xs uppercase tracking-wider text-siem-muted mb-2">Triggering Event</div>
                <div className="bg-siem-bg border border-siem-accent/30 rounded-xl overflow-hidden">
                  {[
                    ['Time',         format(new Date(ev.time), 'yyyy-MM-dd HH:mm:ss')],
                    ['Host',         ev.host],
                    ['Event Type',   ev.event_type],
                    ['Process',      ev.process_name],
                    ['Command Line', ev.command_line],
                    ['User',         ev.user_name],
                    ['Src IP',       ev.src_ip],
                    ['Dst IP',       ev.dst_ip],
                  ].filter(([, v]) => v).map(([label, value], i) => (
                    <div key={label} className={`flex gap-3 px-4 py-2.5 text-sm ${i % 2 === 0 ? '' : 'bg-white/[0.02]'}`}>
                      <span className="text-siem-muted w-32 shrink-0">{label}</span>
                      <span className="text-siem-text font-mono text-xs break-all">{value}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Actions */}
            {(alert.status === 'open' || alert.status === 'acknowledged') && (
              <div>
                <div className="text-xs uppercase tracking-wider text-siem-muted mb-2">Actions</div>
                <div className="flex gap-2">
                  {alert.status === 'open' && (
                    <button onClick={acknowledge}
                      className="flex items-center gap-1.5 text-xs text-yellow-400 hover:text-yellow-300 border border-yellow-700 rounded-lg px-3 py-2 transition-colors">
                      <CheckCircle size={13} /> Acknowledge
                    </button>
                  )}
                  <button onClick={close}
                    className="flex items-center gap-1.5 text-xs text-siem-muted hover:text-siem-text border border-siem-border rounded-lg px-3 py-2 transition-colors">
                    <XCircle size={13} /> Close
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

function CreateAlertModal({ onClose, onCreated }) {
  const [form, setForm] = useState({ title: '', description: '', severity: 3, host: '', event_type: '' })
  const [error, setError] = useState('')
  const set = (k, v) => setForm(f => ({ ...f, [k]: v }))

  const submit = async (e) => {
    e.preventDefault()
    setError('')
    try {
      await api.post('/api/v1/alerts', form)
      onCreated()
      onClose()
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to create alert')
    }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60" onClick={onClose}>
      <div className="bg-siem-surface border border-siem-border rounded-2xl p-5 w-full max-w-md shadow-2xl" onClick={e => e.stopPropagation()}>
        <h2 className="text-base font-bold text-siem-text mb-4">Create Alert</h2>
        <form onSubmit={submit} className="space-y-3">
          <input className="w-full bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text focus:outline-none focus:border-siem-accent"
            placeholder="Title *" value={form.title} onChange={e => set('title', e.target.value)} required />
          <textarea rows={3} className="w-full bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text focus:outline-none focus:border-siem-accent resize-none"
            placeholder="Description" value={form.description} onChange={e => set('description', e.target.value)} />
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-siem-muted mb-1">Severity</label>
              <select className="w-full bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text focus:outline-none"
                value={form.severity} onChange={e => set('severity', Number(e.target.value))}>
                {[1,2,3,4,5].map(s => <option key={s} value={s}>{s} — {['','Info','Low','Medium','High','Critical'][s]}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs text-siem-muted mb-1">Host</label>
              <input className="w-full bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text focus:outline-none focus:border-siem-accent"
                placeholder="(optional)" value={form.host} onChange={e => set('host', e.target.value)} />
            </div>
          </div>
          {error && <div className="text-siem-red text-xs">{error}</div>}
          <div className="flex gap-2 pt-1">
            <button type="submit" className="text-xs bg-siem-accent hover:bg-siem-accent/90 text-white px-4 py-2 rounded-lg">Create</button>
            <button type="button" onClick={onClose} className="text-xs text-siem-muted hover:text-siem-text border border-siem-border rounded-lg px-4 py-2">Cancel</button>
          </div>
        </form>
      </div>
    </div>
  )
}

export default function Alerts() {
  const [alerts, setAlerts] = useState([])
  const [counts, setCounts] = useState({})
  const [filter, setFilter] = useState('open')
  const [loading, setLoading] = useState(true)
  const [showCreate, setShowCreate] = useState(false)
  const [selectedId, setSelectedId] = useState(null)

  const load = async () => {
    setLoading(true)
    try {
      const { data } = await api.get('/api/v1/alerts', { params: { status: filter, limit: 200 } })
      setAlerts(data.alerts || [])
      setCounts(data.counts || {})
    } finally { setLoading(false) }
  }

  useEffect(() => { load() }, [filter])

  return (
    <div className="p-6 space-y-5">
      {selectedId && <AlertPanel alertId={selectedId} onClose={() => setSelectedId(null)} onStatusChange={load} />}
      {showCreate && <CreateAlertModal onClose={() => setShowCreate(false)} onCreated={load} />}

      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-siem-text">Alerts</h1>
        <div className="flex gap-2">
          <button onClick={() => setShowCreate(true)}
            className="flex items-center gap-1.5 text-xs bg-siem-accent hover:bg-siem-accent/90 text-white px-3 py-1.5 rounded-lg">
            <Plus size={13} /> New alert
          </button>
          <button onClick={load}
            className="flex items-center gap-1.5 text-xs text-siem-muted hover:text-siem-text border border-siem-border rounded-lg px-3 py-1.5">
            <RefreshCw size={13} /> Refresh
          </button>
        </div>
      </div>

      <div className="flex gap-2">
        {['open', 'acknowledged', 'closed', ''].map(s => (
          <button key={s} onClick={() => setFilter(s)}
            className={`text-xs px-4 py-1.5 rounded-lg border transition-colors ${
              filter === s ? 'bg-siem-accent/10 border-siem-accent text-siem-accent' : 'border-siem-border text-siem-muted hover:text-siem-text'
            }`}>
            {s || 'All'}
            {s && counts[s] !== undefined && (
              <span className="ml-1.5 bg-siem-border rounded-full px-1.5 py-0.5">{counts[s]}</span>
            )}
          </button>
        ))}
      </div>

      <div className="space-y-2">
        {loading ? (
          <div className="text-center py-12 text-siem-muted">Loading...</div>
        ) : alerts.length === 0 ? (
          <div className="text-center py-16 text-siem-muted">
            <Bell size={32} className="mx-auto mb-3 opacity-30" />
            <div>No {filter || ''} alerts</div>
          </div>
        ) : alerts.map(alert => (
          <div key={alert.id}
            className="bg-siem-surface border border-siem-border rounded-xl p-4 flex gap-4 hover:border-siem-accent/40 cursor-pointer transition-colors"
            onClick={() => setSelectedId(alert.id)}>
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1 flex-wrap">
                <SeverityBadge severity={alert.severity} />
                <StatusBadge status={alert.status} />
                <span className="text-xs text-siem-muted">{formatDistanceToNow(new Date(alert.created_at), { addSuffix: true })}</span>
                {alert.host && <span className="text-xs text-siem-muted">· {alert.host}</span>}
              </div>
              <div className="text-siem-text font-medium text-sm mb-0.5">{alert.title}</div>
              <div className="text-siem-muted text-xs truncate">{alert.description}</div>
              {alert.acknowledged_by && (
                <div className="text-xs text-siem-muted mt-1">
                  {alert.status === 'closed' ? 'Closed' : 'Acknowledged'} by <span className="text-siem-accent">{alert.acknowledged_by}</span>
                </div>
              )}
            </div>
            <div className="shrink-0 self-center text-siem-muted">
              <ChevronRight size={16} />
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
