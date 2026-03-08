import { useEffect, useState } from 'react'
import { Zap, Shield, ChevronDown, ChevronUp, ExternalLink } from 'lucide-react'
import api from '../api/client'

const SEV_LABEL = { 1:'Info', 2:'Low', 3:'Medium', 4:'High', 5:'Critical' }
const SEV_COLOR = {
  1: 'text-gray-400 bg-gray-800/40 border-gray-700',
  2: 'text-blue-400 bg-blue-900/30 border-blue-700',
  3: 'text-yellow-400 bg-yellow-900/30 border-yellow-700',
  4: 'text-orange-400 bg-orange-900/30 border-orange-700',
  5: 'text-red-400 bg-red-900/30 border-red-700',
}
const CAT_COLOR = {
  'Execution':            'text-purple-400',
  'Discovery':            'text-blue-400',
  'Privilege Escalation': 'text-orange-400',
  'Credential Access':    'text-red-400',
  'Lateral Movement':     'text-yellow-400',
  'Persistence':          'text-pink-400',
  'Defence Evasion':      'text-indigo-400',
  'Command & Control':    'text-cyan-400',
  'Exfiltration':         'text-green-400',
  'Impact':               'text-red-500',
}

export default function Detections() {
  const [sigs, setSigs] = useState([])
  const [loading, setLoading] = useState(true)
  const [expanded, setExpanded] = useState(null)
  const [catFilter, setCatFilter] = useState('')
  const [sevFilter, setSevFilter] = useState(0)

  useEffect(() => {
    api.get('/api/v1/detections').then(r => {
      setSigs(r.data.signatures || [])
    }).finally(() => setLoading(false))
  }, [])

  const categories = [...new Set(sigs.map(s => s.category))]
  const filtered = sigs.filter(s =>
    (catFilter === '' || s.category === catFilter) &&
    (sevFilter === 0 || s.severity >= sevFilter)
  )

  const byCat = {}
  filtered.forEach(s => {
    if (!byCat[s.category]) byCat[s.category] = []
    byCat[s.category].push(s)
  })

  return (
    <div className="p-6 space-y-5">
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <Zap className="text-siem-accent" size={20} />
          <h1 className="text-xl font-bold text-siem-text">Threat Detection Library</h1>
          <span className="text-xs text-siem-muted bg-siem-border/40 rounded px-2 py-0.5">{sigs.length} signatures</span>
        </div>
        <div className="flex gap-2">
          <select className="bg-siem-bg border border-siem-border rounded-lg px-3 py-1.5 text-xs text-siem-text focus:outline-none"
            value={catFilter} onChange={e => setCatFilter(e.target.value)}>
            <option value="">All categories</option>
            {categories.map(c => <option key={c} value={c}>{c}</option>)}
          </select>
          <select className="bg-siem-bg border border-siem-border rounded-lg px-3 py-1.5 text-xs text-siem-text focus:outline-none"
            value={sevFilter} onChange={e => setSevFilter(Number(e.target.value))}>
            <option value={0}>All severities</option>
            <option value={3}>Medium+</option>
            <option value={4}>High+</option>
            <option value={5}>Critical only</option>
          </select>
        </div>
      </div>

      <div className="grid grid-cols-5 gap-3">
        {Object.entries(CAT_COLOR).map(([cat, color]) => {
          const count = sigs.filter(s => s.category === cat).length
          if (!count) return null
          return (
            <button key={cat} onClick={() => setCatFilter(catFilter === cat ? '' : cat)}
              className={`bg-siem-surface border rounded-xl p-3 text-left transition-colors ${
                catFilter === cat ? 'border-siem-accent bg-siem-accent/10' : 'border-siem-border hover:border-siem-accent/40'
              }`}>
              <div className={`text-xs font-bold ${color}`}>{count}</div>
              <div className="text-[10px] text-siem-muted mt-0.5 leading-tight">{cat}</div>
            </button>
          )
        })}
      </div>

      {loading ? (
        <div className="text-siem-muted text-sm text-center py-12">Loading signatures...</div>
      ) : (
        <div className="space-y-4">
          {Object.entries(byCat).map(([cat, catSigs]) => (
            <div key={cat}>
              <div className={`flex items-center gap-2 mb-2 text-sm font-semibold ${CAT_COLOR[cat] || 'text-siem-text'}`}>
                <Shield size={14} />
                {cat}
                <span className="text-siem-muted text-xs font-normal">({catSigs.length})</span>
              </div>
              <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden">
                {catSigs.map((sig, i) => (
                  <div key={sig.id} className={`border-b border-siem-border/40 last:border-0`}>
                    <button
                      className="w-full flex items-center gap-3 px-4 py-3 hover:bg-white/[0.02] transition-colors text-left"
                      onClick={() => setExpanded(expanded === sig.id ? null : sig.id)}>
                      <span className={`text-xs px-2 py-0.5 rounded-full border font-medium whitespace-nowrap ${SEV_COLOR[sig.severity]}`}>
                        {SEV_LABEL[sig.severity]}
                      </span>
                      <span className="text-siem-text text-sm font-medium flex-1">{sig.name}</span>
                      <span className="text-siem-muted text-xs font-mono">{sig.mitre}</span>
                      {expanded === sig.id ? <ChevronUp size={14} className="text-siem-muted shrink-0" /> : <ChevronDown size={14} className="text-siem-muted shrink-0" />}
                    </button>
                    {expanded === sig.id && (
                      <div className="px-4 pb-4 pt-1 bg-siem-bg/40 border-t border-siem-border/30">
                        <p className="text-siem-muted text-sm mb-3">{sig.description}</p>
                        <div className="flex items-center gap-3 flex-wrap">
                          <span className="text-xs text-siem-muted">MITRE ATT&CK:</span>
                          <a href={`https://attack.mitre.org/techniques/${sig.mitre.replace('.','/')}/`}
                            target="_blank" rel="noopener noreferrer"
                            className="flex items-center gap-1 text-xs text-siem-accent hover:underline">
                            {sig.mitre} <ExternalLink size={10} />
                          </a>
                          <span className="text-xs text-siem-muted ml-2">Category: <span className="text-siem-text">{sig.category}</span></span>
                          <span className="text-xs text-siem-muted ml-2">Engine: <span className="text-siem-green">Active (45s cycle)</span></span>
                        </div>
                      </div>
                    )}
                  </div>
                ))}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
