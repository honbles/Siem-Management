import { useEffect, useState } from 'react'
import { Bell, CheckCircle, XCircle, RefreshCw, Plus } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import api from '../api/client'
import { SeverityBadge } from '../components/SeverityBadge'

function StatusBadge({ status }) {
  const map = {
    open:         'bg-red-900/40 text-red-400 border-red-700',
    acknowledged: 'bg-yellow-900/40 text-yellow-400 border-yellow-700',
    closed:       'bg-gray-800 text-gray-500 border-gray-700',
  }
  return (
    <span className={`text-xs px-2 py-0.5 rounded-full border capitalize ${map[status] || map.closed}`}>{status}</span>
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

  const load = async () => {
    setLoading(true)
    try {
      const { data } = await api.get('/api/v1/alerts', { params: { status: filter, limit: 200 } })
      setAlerts(data.alerts || [])
      setCounts(data.counts || {})
    } finally { setLoading(false) }
  }

  useEffect(() => { load() }, [filter])

  const acknowledge = async (id) => { await api.patch(`/api/v1/alerts/${id}/acknowledge`); load() }
  const close = async (id) => { await api.patch(`/api/v1/alerts/${id}/close`); load() }

  return (
    <div className="p-6 space-y-5">
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

      <div className="space-y-3">
        {loading ? (
          <div className="text-center py-12 text-siem-muted">Loading...</div>
        ) : alerts.length === 0 ? (
          <div className="text-center py-16 text-siem-muted">
            <Bell size={32} className="mx-auto mb-3 opacity-30" />
            <div>No {filter} alerts</div>
          </div>
        ) : alerts.map(alert => (
          <div key={alert.id} className="bg-siem-surface border border-siem-border rounded-xl p-4 flex gap-4">
            <div className="flex-1 min-w-0">
              <div className="flex items-center gap-2 mb-1 flex-wrap">
                <SeverityBadge severity={alert.severity} />
                <StatusBadge status={alert.status} />
                <span className="text-xs text-siem-muted">{formatDistanceToNow(new Date(alert.created_at), { addSuffix: true })}</span>
                {alert.host && <span className="text-xs text-siem-muted">· {alert.host}</span>}
              </div>
              <div className="text-siem-text font-medium text-sm mb-1">{alert.title}</div>
              <div className="text-siem-muted text-xs">{alert.description}</div>
              {alert.acknowledged_by && (
                <div className="text-xs text-siem-muted mt-1">
                  {alert.status === 'closed' ? 'Closed' : 'Acknowledged'} by <span className="text-siem-accent">{alert.acknowledged_by}</span>
                </div>
              )}
            </div>
            {alert.status === 'open' && (
              <div className="flex flex-col gap-2 shrink-0">
                <button onClick={() => acknowledge(alert.id)}
                  className="flex items-center gap-1 text-xs text-yellow-400 hover:text-yellow-300 border border-yellow-700 rounded-lg px-2 py-1 transition-colors">
                  <CheckCircle size={12} /> Acknowledge
                </button>
                <button onClick={() => close(alert.id)}
                  className="flex items-center gap-1 text-xs text-siem-muted hover:text-siem-text border border-siem-border rounded-lg px-2 py-1 transition-colors">
                  <XCircle size={12} /> Close
                </button>
              </div>
            )}
            {alert.status === 'acknowledged' && (
              <button onClick={() => close(alert.id)}
                className="flex items-center gap-1 text-xs text-siem-muted hover:text-siem-text border border-siem-border rounded-lg px-3 py-1 shrink-0 self-start">
                <XCircle size={12} /> Close
              </button>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
