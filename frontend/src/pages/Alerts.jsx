import { useEffect, useState, useCallback } from 'react'
import { createPortal } from 'react-dom'
import { Bell, CheckCircle, XCircle, RefreshCw, Plus, X, ChevronRight,
         User, MessageSquare, Clock, AlertTriangle, UserCheck, FileText,
         Shield } from 'lucide-react'
import { format, formatDistanceToNow } from 'date-fns'
import api from '../api/client'
import { SeverityBadge } from '../components/SeverityBadge'

const SEV_COLOR = { 5:'#ef4444',4:'#f97316',3:'#eab308',2:'#3b82f6',1:'#475569' }

function StatusBadge({ status }) {
  const styles = {
    open:         'bg-red-900/30 text-red-400 border-red-800',
    acknowledged: 'bg-yellow-900/30 text-yellow-400 border-yellow-800',
    closed:       'bg-siem-bg text-siem-muted border-siem-border',
  }
  return (
    <span className={`text-[9px] px-2 py-0.5 rounded-full border font-semibold uppercase ${styles[status] || styles.closed}`}>
      {status}
    </span>
  )
}

// ─── Assign / Case modal ──────────────────────────────────────────────────────
function AssignModal({ alert, users, onClose, onDone }) {
  const [assignTo, setAssignTo] = useState(alert.assigned_to || '')
  const [notes, setNotes]       = useState(alert.case_notes || '')
  const [saving, setSaving]     = useState(false)
  const [error, setError]       = useState('')

  const save = async () => {
    if (!assignTo.trim()) { setError('Please select or enter an analyst'); return }
    setSaving(true)
    setError('')
    try {
      await api.patch(`/api/v1/alerts/${alert.id}/assign`, { assigned_to: assignTo, notes })
      onDone()
      onClose()
    } catch (e) {
      setError(e.response?.data?.error || 'Failed to assign')
    } finally { setSaving(false) }
  }

  return createPortal(
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/70"
         onClick={e => { e.stopPropagation(); onClose() }}>
      <div className="bg-siem-surface border border-siem-border rounded-2xl p-5 w-full max-w-md shadow-2xl"
           onClick={e => e.stopPropagation()}>
        <div className="flex items-center gap-2 mb-4">
          <UserCheck size={15} className="text-siem-accent"/>
          <h2 className="text-sm font-bold text-siem-text">Assign Alert to Analyst</h2>
          <button onClick={onClose} className="ml-auto text-siem-muted hover:text-siem-text"><X size={14}/></button>
        </div>

        <div className="bg-siem-bg border border-siem-border rounded-lg px-3 py-2 mb-3">
          <div className="text-[9px] text-siem-muted uppercase tracking-wider">Alert</div>
          <div className="text-xs text-siem-text font-medium truncate">{alert.title}</div>
        </div>

        <div className="space-y-3">
          <div>
            <label className="block text-[10px] uppercase tracking-wider text-siem-muted mb-1">Assign To *</label>
            {users.length > 0 ? (
              <select value={assignTo} onChange={e => setAssignTo(e.target.value)}
                className="w-full bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text focus:outline-none focus:border-siem-accent">
                <option value="">— Select analyst —</option>
                {users.map(u => (
                  <option key={u.id} value={u.username}>{u.username} ({u.role})</option>
                ))}
              </select>
            ) : (
              <input value={assignTo} onChange={e => setAssignTo(e.target.value)}
                placeholder="Enter username"
                className="w-full bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text focus:outline-none focus:border-siem-accent"/>
            )}
          </div>
          <div>
            <label className="block text-[10px] uppercase tracking-wider text-siem-muted mb-1">Initial Case Notes</label>
            <textarea rows={3} value={notes} onChange={e => setNotes(e.target.value)}
              placeholder="Initial investigation notes, context, or instructions…"
              className="w-full bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text focus:outline-none focus:border-siem-accent resize-none"/>
          </div>
          {error && <div className="text-red-400 text-xs">{error}</div>}
          <div className="flex gap-2 pt-1">
            <button onClick={save} disabled={saving || !assignTo}
              className="flex-1 text-xs bg-siem-accent hover:bg-siem-accent/90 disabled:opacity-40 text-white px-4 py-2 rounded-lg font-medium">
              {saving ? 'Assigning…' : 'Assign & Acknowledge'}
            </button>
            <button onClick={onClose} className="text-xs text-siem-muted border border-siem-border rounded-lg px-4 py-2">
              Cancel
            </button>
          </div>
        </div>
      </div>
    </div>,
    document.body
  )
}

// ─── Close with review modal ──────────────────────────────────────────────────
function CloseModal({ alert, onClose, onDone }) {
  const [comment, setComment] = useState(alert.review_comment || '')
  const [saving, setSaving]   = useState(false)
  const [error, setError]     = useState('')

  const save = async () => {
    if (!comment.trim()) { setError('Please add a review comment before closing'); return }
    setSaving(true)
    setError('')
    try {
      await api.patch(`/api/v1/alerts/${alert.id}/close-review`, { comment })
      onDone()
      onClose()
    } catch (e) {
      setError(e.response?.data?.error || 'Failed to close')
    } finally { setSaving(false) }
  }

  return createPortal(
    <div className="fixed inset-0 z-[100] flex items-center justify-center bg-black/70"
         onClick={e => { e.stopPropagation(); onClose() }}>
      <div className="bg-siem-surface border border-siem-border rounded-2xl p-5 w-full max-w-md shadow-2xl"
           onClick={e => e.stopPropagation()}>
        <div className="flex items-center gap-2 mb-4">
          <XCircle size={15} className="text-siem-muted"/>
          <h2 className="text-sm font-bold text-siem-text">Close Alert — Review Comment</h2>
          <button onClick={onClose} className="ml-auto text-siem-muted hover:text-siem-text"><X size={14}/></button>
        </div>
        <div className="space-y-3">
          <div>
            <label className="block text-[10px] uppercase tracking-wider text-siem-muted mb-1">Review Comment *</label>
            <textarea rows={4} value={comment} onChange={e => setComment(e.target.value)}
              placeholder="Describe what was found, actions taken, and resolution…"
              className="w-full bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text focus:outline-none focus:border-siem-accent resize-none"/>
          </div>
          {error && <div className="text-red-400 text-xs">{error}</div>}
          <div className="flex gap-2 pt-1">
            <button onClick={save} disabled={saving}
              className="flex-1 text-xs bg-emerald-900/40 border border-emerald-700 hover:bg-emerald-900/60 text-emerald-300 px-4 py-2 rounded-lg font-medium">
              {saving ? 'Closing…' : 'Close Alert'}
            </button>
            <button onClick={onClose} className="text-xs text-siem-muted border border-siem-border rounded-lg px-4 py-2">
              Cancel
            </button>
          </div>
        </div>
      </div>
    </div>,
    document.body
  )
}

// ─── Alert detail slide panel ─────────────────────────────────────────────────
function AlertPanel({ alertId, users, onClose, onStatusChange }) {
  const [data, setData]           = useState(null)
  const [loading, setLoading]     = useState(true)
  const [showAssign, setShowAssign] = useState(false)
  const [showClose, setShowClose]   = useState(false)
  const [editNotes, setEditNotes]   = useState(false)
  const [notes, setNotes]           = useState('')
  const [savingNotes, setSavingNotes] = useState(false)

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const res = await api.get(`/api/v1/alerts/${alertId}`)
      setData(res.data)
      setNotes(res.data.alert?.case_notes || '')
    } catch (e) {
      console.error('Failed to load alert', e)
    } finally { setLoading(false) }
  }, [alertId])

  useEffect(() => { load() }, [load])

  // Close on Escape key
  useEffect(() => {
    const handler = e => { if (e.key === 'Escape') onClose() }
    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [onClose])

  const saveNotes = async () => {
    setSavingNotes(true)
    try {
      await api.patch(`/api/v1/alerts/${alertId}/notes`, { notes })
      setEditNotes(false)
      load()
    } finally { setSavingNotes(false) }
  }

  const alert = data?.alert
  const ev    = data?.related_event

  const panel = (
    <div className="fixed inset-0 z-[80] flex justify-end">
      {/* Backdrop */}
      <div className="absolute inset-0 bg-black/60" onClick={onClose}/>
      {/* Panel — sits on top of backdrop */}
      <div className="relative z-10 h-full w-full max-w-2xl bg-siem-surface border-l border-siem-border shadow-2xl overflow-y-auto"
           onClick={e => e.stopPropagation()}>

        {/* Modals rendered inside panel area */}
        {showAssign && alert && (
          <AssignModal alert={alert} users={users}
            onClose={() => setShowAssign(false)}
            onDone={() => { onStatusChange(); load() }}/>
        )}
        {showClose && alert && (
          <CloseModal alert={alert}
            onClose={() => setShowClose(false)}
            onDone={() => { onStatusChange(); load() }}/>
        )}

        {/* Header */}
        <div className="flex items-center gap-2 px-5 py-4 border-b border-siem-border sticky top-0 bg-siem-surface z-10">
          <Bell size={15} className="text-siem-accent"/>
          <span className="font-semibold text-siem-text text-sm">Alert Detail</span>
          <button onClick={onClose} className="ml-auto text-siem-muted hover:text-siem-text p-1 rounded hover:bg-white/5">
            <X size={16}/>
          </button>
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-20 text-siem-muted text-sm">
            <RefreshCw size={16} className="animate-spin mr-2"/> Loading…
          </div>
        ) : !alert ? (
          <div className="p-6 text-siem-muted text-sm">Alert not found</div>
        ) : (
          <div className="p-5 space-y-5">

            {/* Alert header card */}
            <div className="bg-siem-bg border border-siem-border rounded-xl p-4 space-y-2">
              <div className="flex items-center gap-2 flex-wrap">
                <SeverityBadge severity={alert.severity}/>
                <StatusBadge status={alert.status}/>
                <span className="text-[9px] text-siem-muted ml-auto flex items-center gap-1">
                  <Clock size={9}/> {formatDistanceToNow(new Date(alert.created_at), { addSuffix: true })}
                </span>
              </div>
              <div className="text-siem-text font-semibold text-sm">{alert.title}</div>
              {alert.description && (
                <div className="text-siem-muted text-xs leading-relaxed">{alert.description}</div>
              )}
            </div>

            {/* Case assignment status */}
            {alert.assigned_to ? (
              <div className="bg-yellow-950/20 border border-yellow-800/40 rounded-xl p-3">
                <div className="flex items-center gap-3">
                  <div className="w-8 h-8 rounded-full bg-yellow-900/40 border border-yellow-700 flex items-center justify-center shrink-0">
                    <User size={13} className="text-yellow-400"/>
                  </div>
                  <div>
                    <div className="text-xs font-semibold text-yellow-400">
                      Working on it: <span className="font-mono">{alert.assigned_to}</span>
                    </div>
                    <div className="text-[9px] text-siem-muted mt-0.5">
                      Assigned by {alert.acknowledged_by || '—'} ·{' '}
                      {alert.acknowledged_at
                        ? format(new Date(alert.acknowledged_at), 'yyyy-MM-dd HH:mm')
                        : '—'}
                    </div>
                  </div>
                </div>
              </div>
            ) : alert.status === 'acknowledged' ? (
              <div className="bg-orange-950/20 border border-orange-800/40 rounded-xl p-3 flex items-center gap-2">
                <AlertTriangle size={13} className="text-orange-400"/>
                <span className="text-xs text-orange-400">Acknowledged but not yet assigned to an analyst</span>
              </div>
            ) : null}

            {/* Case Notes */}
            <div>
              <div className="flex items-center gap-2 mb-2">
                <FileText size={11} className="text-siem-muted"/>
                <span className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold">Case Notes</span>
                {!editNotes && alert.status !== 'closed' && (
                  <button onClick={() => setEditNotes(true)}
                    className="ml-auto text-[9px] text-siem-muted hover:text-siem-accent transition-colors border border-siem-border rounded px-2 py-0.5">
                    Edit
                  </button>
                )}
              </div>
              {editNotes ? (
                <div>
                  <textarea rows={4} value={notes} onChange={e => setNotes(e.target.value)}
                    className="w-full bg-siem-bg border border-siem-accent/40 rounded-lg px-3 py-2 text-sm text-siem-text focus:outline-none resize-none"/>
                  <div className="flex gap-2 mt-2">
                    <button onClick={saveNotes} disabled={savingNotes}
                      className="text-xs bg-siem-accent/20 border border-siem-accent/40 text-siem-accent rounded-lg px-3 py-1">
                      {savingNotes ? 'Saving…' : 'Save Notes'}
                    </button>
                    <button onClick={() => { setEditNotes(false); setNotes(alert.case_notes || '') }}
                      className="text-xs text-siem-muted border border-siem-border rounded-lg px-3 py-1">
                      Cancel
                    </button>
                  </div>
                </div>
              ) : (
                <div className="bg-siem-bg border border-siem-border rounded-xl p-3 min-h-[60px]">
                  {alert.case_notes
                    ? <p className="text-xs text-siem-text leading-relaxed whitespace-pre-wrap">{alert.case_notes}</p>
                    : <p className="text-[10px] text-siem-muted/50 italic">No case notes yet.{alert.status !== 'closed' && ' Click Edit to add notes.'}</p>
                  }
                </div>
              )}
            </div>

            {/* Review comment (if closed) */}
            {alert.review_comment && (
              <div>
                <div className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold mb-2 flex items-center gap-1">
                  <MessageSquare size={9}/> Review Comment
                </div>
                <div className="bg-emerald-950/20 border border-emerald-800/30 rounded-xl p-3">
                  <p className="text-xs text-siem-text leading-relaxed whitespace-pre-wrap">{alert.review_comment}</p>
                  {alert.closed_by && (
                    <p className="text-[9px] text-siem-muted mt-2">
                      Closed by <span className="text-emerald-400">{alert.closed_by}</span>
                      {alert.closed_at && <> · {format(new Date(alert.closed_at), 'yyyy-MM-dd HH:mm')}</>}
                    </p>
                  )}
                </div>
              </div>
            )}

            {/* Details table */}
            <div>
              <div className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold mb-2">Details</div>
              <div className="bg-siem-bg border border-siem-border rounded-xl overflow-hidden">
                {[
                  ['Alert ID',    `#${alert.id}`],
                  ['Host',        alert.host || '—'],
                  ['Event Type',  alert.event_type || '—'],
                  ['Status',      alert.status],
                  ['Assigned To', alert.assigned_to || 'Unassigned'],
                  ['Created',     format(new Date(alert.created_at), 'yyyy-MM-dd HH:mm:ss')],
                ].map(([label, value], i) => (
                  <div key={label} className={`flex gap-3 px-4 py-2 text-xs ${i % 2 === 0 ? '' : 'bg-white/[0.02]'}`}>
                    <span className="text-siem-muted w-28 shrink-0">{label}</span>
                    <span className="text-siem-text font-mono text-[10px] break-all">{value}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Triggering event */}
            {ev && (
              <div>
                <div className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold mb-2">Triggering Event</div>
                <div className="bg-siem-bg border border-siem-accent/20 rounded-xl overflow-hidden">
                  {[
                    ['Time',       format(new Date(ev.time), 'yyyy-MM-dd HH:mm:ss')],
                    ['Host',       ev.host],
                    ['Event Type', ev.event_type],
                    ['Process',    ev.process_name],
                    ['Command',    ev.command_line],
                    ['User',       ev.user_name],
                    ['Src IP',     ev.src_ip],
                    ['Dst IP',     ev.dst_ip],
                  ].filter(([, v]) => v).map(([label, value], i) => (
                    <div key={label} className={`flex gap-3 px-4 py-2 text-xs ${i % 2 === 0 ? '' : 'bg-white/[0.02]'}`}>
                      <span className="text-siem-muted w-28 shrink-0">{label}</span>
                      <span className="text-siem-text font-mono text-[10px] break-all">{value}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Actions */}
            {alert.status !== 'closed' && (
              <div>
                <div className="text-[10px] uppercase tracking-wider text-siem-muted font-semibold mb-2">Actions</div>
                <div className="flex gap-2 flex-wrap">
                  {(alert.status === 'open' || (alert.status === 'acknowledged' && !alert.assigned_to)) && (
                    <button onClick={() => setShowAssign(true)}
                      className="flex items-center gap-1.5 text-xs text-yellow-400 border border-yellow-800 hover:bg-yellow-900/20 rounded-lg px-3 py-2 transition-colors">
                      <UserCheck size={12}/> Assign to Analyst
                    </button>
                  )}
                  <button onClick={() => setShowClose(true)}
                    className="flex items-center gap-1.5 text-xs text-siem-muted border border-siem-border hover:border-siem-accent/40 hover:text-siem-text rounded-lg px-3 py-2 transition-colors">
                    <XCircle size={12}/> Close with Review
                  </button>
                </div>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )

  return createPortal(panel, document.body)
}

// ─── Create alert modal ───────────────────────────────────────────────────────
function CreateAlertModal({ onClose, onCreated }) {
  const [form, setForm] = useState({ title: '', description: '', severity: 3, host: '', event_type: '' })
  const [error, setError] = useState('')
  const set = (k, v) => setForm(f => ({ ...f, [k]: v }))

  const submit = async e => {
    e.preventDefault()
    setError('')
    try {
      await api.post('/api/v1/alerts', form)
      onCreated()
      onClose()
    } catch (err) {
      setError(err.response?.data?.error || 'Failed')
    }
  }

  return createPortal(
    <div className="fixed inset-0 z-[80] flex items-center justify-center bg-black/60"
         onClick={e => { e.stopPropagation(); onClose() }}>
      <div className="bg-siem-surface border border-siem-border rounded-2xl p-5 w-full max-w-md shadow-2xl"
           onClick={e => e.stopPropagation()}>
        <div className="flex items-center gap-2 mb-4">
          <Bell size={14} className="text-siem-accent"/>
          <h2 className="text-sm font-bold text-siem-text">Create Alert</h2>
          <button onClick={onClose} className="ml-auto text-siem-muted hover:text-siem-text"><X size={14}/></button>
        </div>
        <form onSubmit={submit} className="space-y-3">
          <input className="w-full bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text focus:outline-none focus:border-siem-accent"
            placeholder="Title *" value={form.title} onChange={e => set('title', e.target.value)} required/>
          <textarea rows={3} className="w-full bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text focus:outline-none focus:border-siem-accent resize-none"
            placeholder="Description" value={form.description} onChange={e => set('description', e.target.value)}/>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="block text-xs text-siem-muted mb-1">Severity</label>
              <select className="w-full bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text focus:outline-none"
                value={form.severity} onChange={e => set('severity', Number(e.target.value))}>
                {[1,2,3,4,5].map(s => (
                  <option key={s} value={s}>{s} — {['','Info','Low','Medium','High','Critical'][s]}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs text-siem-muted mb-1">Host</label>
              <input className="w-full bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-sm text-siem-text focus:outline-none focus:border-siem-accent"
                placeholder="(optional)" value={form.host} onChange={e => set('host', e.target.value)}/>
            </div>
          </div>
          {error && <div className="text-red-400 text-xs">{error}</div>}
          <div className="flex gap-2 pt-1">
            <button type="submit" className="text-xs bg-siem-accent text-white px-4 py-2 rounded-lg font-medium">Create</button>
            <button type="button" onClick={onClose} className="text-xs text-siem-muted border border-siem-border rounded-lg px-4 py-2">Cancel</button>
          </div>
        </form>
      </div>
    </div>,
    document.body
  )
}

// ─── Main Alerts page ─────────────────────────────────────────────────────────
export default function Alerts() {
  const [alerts, setAlerts]         = useState([])
  const [counts, setCounts]         = useState({})
  const [filter, setFilter]         = useState('open')
  const [loading, setLoading]       = useState(true)
  const [showCreate, setShowCreate] = useState(false)
  const [selectedId, setSelectedId] = useState(null)
  const [users, setUsers]           = useState([])

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const { data } = await api.get('/api/v1/alerts', { params: { status: filter, limit: 200 } })
      setAlerts(data.alerts || [])
      setCounts(data.counts || {})
    } finally { setLoading(false) }
  }, [filter])

  useEffect(() => {
    api.get('/api/v1/users')
      .then(r => setUsers(r.data.users || []))
      .catch(() => {})
  }, [])

  useEffect(() => { load() }, [load])

  const openAlert = useCallback((id, e) => {
    e.stopPropagation()
    setSelectedId(id)
  }, [])

  return (
    <div className="p-5 space-y-5">
      {/* Panels rendered via portals — no z-index conflicts */}
      {selectedId && (
        <AlertPanel
          alertId={selectedId}
          users={users}
          onClose={() => setSelectedId(null)}
          onStatusChange={load}
        />
      )}
      {showCreate && (
        <CreateAlertModal onClose={() => setShowCreate(false)} onCreated={load}/>
      )}

      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-siem-text">Alerts</h1>
          <p className="text-[10px] text-siem-muted mt-0.5">
            Assign alerts to analysts, track cases, and close with review
          </p>
        </div>
        <div className="flex gap-2">
          <button onClick={() => setShowCreate(true)}
            className="flex items-center gap-1.5 text-xs bg-siem-accent text-white px-3 py-1.5 rounded-lg hover:bg-siem-accent/90">
            <Plus size={12}/> New Alert
          </button>
          <button onClick={load}
            className="flex items-center gap-1.5 text-xs text-siem-muted border border-siem-border rounded-lg px-3 py-1.5 hover:text-siem-text">
            <RefreshCw size={12}/> Refresh
          </button>
        </div>
      </div>

      {/* Status tabs */}
      <div className="flex gap-2">
        {[
          { key: 'open',         label: 'Open' },
          { key: 'acknowledged', label: 'Acknowledged' },
          { key: 'closed',       label: 'Closed' },
          { key: '',             label: 'All' },
        ].map(({ key, label }) => (
          <button key={key} onClick={() => setFilter(key)}
            className={`text-xs px-4 py-1.5 rounded-lg border transition-colors ${
              filter === key
                ? 'bg-siem-accent/10 border-siem-accent text-siem-accent'
                : 'border-siem-border text-siem-muted hover:text-siem-text'
            }`}>
            {label}
            {key && counts[key] !== undefined && (
              <span className="ml-1.5 bg-siem-border rounded-full px-1.5 py-0.5 text-[9px]">
                {counts[key]}
              </span>
            )}
          </button>
        ))}
      </div>

      {/* Alert list */}
      <div className="space-y-2">
        {loading ? (
          <div className="text-center py-12 text-siem-muted text-sm flex items-center justify-center gap-2">
            <RefreshCw size={14} className="animate-spin"/> Loading…
          </div>
        ) : alerts.length === 0 ? (
          <div className="text-center py-16 text-siem-muted">
            <Bell size={32} className="mx-auto mb-3 opacity-20"/>
            <div className="text-sm">No {filter || ''} alerts</div>
          </div>
        ) : (
          alerts.map(alert => (
            <div key={alert.id}
              className="bg-siem-surface border border-siem-border rounded-xl p-4 flex gap-4 hover:border-siem-accent/30 cursor-pointer transition-colors group"
              onClick={e => openAlert(alert.id, e)}>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1 flex-wrap">
                  <SeverityBadge severity={alert.severity}/>
                  <StatusBadge status={alert.status}/>
                  {alert.assigned_to && (
                    <span className="flex items-center gap-1 text-[9px] text-yellow-400 bg-yellow-950/20 border border-yellow-800/30 rounded-full px-2 py-0.5">
                      <User size={8}/> {alert.assigned_to}
                    </span>
                  )}
                  <span className="text-[9px] text-siem-muted ml-auto">
                    {formatDistanceToNow(new Date(alert.created_at), { addSuffix: true })}
                  </span>
                  {alert.host && (
                    <span className="text-[9px] text-siem-muted">· {alert.host}</span>
                  )}
                </div>
                <div className="text-siem-text font-medium text-sm">{alert.title}</div>
                <div className="text-siem-muted text-xs truncate mt-0.5">{alert.description}</div>
                {alert.case_notes && (
                  <div className="flex items-center gap-1 mt-1.5">
                    <MessageSquare size={9} className="text-siem-muted/50 shrink-0"/>
                    <span className="text-[9px] text-siem-muted/70 truncate">{alert.case_notes}</span>
                  </div>
                )}
                {alert.review_comment && (
                  <div className="flex items-center gap-1 mt-1">
                    <CheckCircle size={9} className="text-emerald-400/60 shrink-0"/>
                    <span className="text-[9px] text-emerald-400/60 truncate">{alert.review_comment}</span>
                  </div>
                )}
              </div>
              <ChevronRight size={15} className="text-siem-muted/30 group-hover:text-siem-accent self-center shrink-0 transition-colors"/>
            </div>
          ))
        )}
      </div>
    </div>
  )
}
