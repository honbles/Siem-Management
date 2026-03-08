import { useEffect, useState } from 'react'
import { Globe, Cpu, User, AlertTriangle, RefreshCw, Server } from 'lucide-react'
import api from '../api/client'

const SUSPICIOUS_KEYWORDS = ['rustdesk', 'urban-vpn', 'ngrok', 'teamviewer', 'anydesk', 'wpad', 'onion']

function isSuspicious(value) {
  if (!value) return false
  const v = value.toLowerCase()
  return SUSPICIOUS_KEYWORDS.some(k => v.includes(k))
}

function RankTable({ title, icon: Icon, rows, keyLabel, valueLabel, keyField, valueField, flagFn }) {
  if (!rows || rows.length === 0) return null
  const max = rows[0]?.[valueField] || 1
  return (
    <div className="bg-siem-surface border border-siem-border rounded-xl p-5">
      <div className="flex items-center gap-2 mb-4">
        <Icon size={16} className="text-siem-accent" />
        <h2 className="text-sm font-semibold text-siem-text">{title}</h2>
        <span className="ml-auto text-xs text-siem-muted">24h</span>
      </div>
      <div className="space-y-2">
        {rows.map((row, i) => {
          const label = row[keyField]
          const count = row[valueField]
          const pct = Math.round((count / max) * 100)
          const suspicious = flagFn?.(label)
          return (
            <div key={i} className="group">
              <div className="flex items-center justify-between mb-1">
                <span className={`text-xs font-mono truncate max-w-[220px] ${suspicious ? 'text-siem-red' : 'text-siem-text'}`}>
                  {suspicious && <AlertTriangle size={10} className="inline mr-1 text-siem-red" />}
                  {label}
                </span>
                <span className="text-xs text-siem-muted ml-2 shrink-0">{count.toLocaleString()}</span>
              </div>
              <div className="h-1.5 bg-siem-border rounded-full overflow-hidden">
                <div
                  className={`h-full rounded-full transition-all ${suspicious ? 'bg-siem-red' : 'bg-siem-accent'}`}
                  style={{ width: `${pct}%` }}
                />
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

export default function ThreatIntel() {
  const [data, setData] = useState(null)
  const [loading, setLoading] = useState(true)

  const load = async () => {
    setLoading(true)
    try {
      const { data: d } = await api.get('/api/v1/threat-intel')
      setData(d)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const flagged = data?.flagged_domains || []

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold text-siem-text">Threat Intelligence</h1>
          <p className="text-xs text-siem-muted mt-0.5">Network and endpoint activity analysis — last 24 hours</p>
        </div>
        <button
          onClick={load}
          className="flex items-center gap-1.5 text-xs text-siem-muted hover:text-siem-text border border-siem-border rounded-lg px-3 py-1.5 transition-colors"
        >
          <RefreshCw size={13} className={loading ? 'animate-spin' : ''} /> Refresh
        </button>
      </div>

      {/* Flagged domains banner */}
      {flagged.length > 0 && (
        <div className="bg-red-900/20 border border-red-700/50 rounded-xl p-4">
          <div className="flex items-center gap-2 mb-2">
            <AlertTriangle size={16} className="text-siem-red" />
            <span className="text-sm font-semibold text-siem-red">Suspicious domains detected</span>
          </div>
          <div className="flex flex-wrap gap-2">
            {flagged.map((f, i) => (
              <span key={i} className="text-xs font-mono bg-red-900/40 text-red-300 px-2 py-1 rounded-md border border-red-700/50">
                {f.domain} <span className="text-red-500 ml-1">×{f.count}</span>
              </span>
            ))}
          </div>
        </div>
      )}

      {loading && !data ? (
        <div className="text-center py-20 text-siem-muted">Loading threat intelligence data...</div>
      ) : (
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
          <RankTable
            title="Top Queried Domains (DNS)"
            icon={Globe}
            rows={data?.top_domains}
            keyField="domain"
            valueField="count"
            flagFn={isSuspicious}
          />
          <RankTable
            title="Top Processes"
            icon={Cpu}
            rows={data?.top_processes}
            keyField="process"
            valueField="count"
          />
          <RankTable
            title="Top Source IPs"
            icon={Server}
            rows={data?.top_src_ips}
            keyField="ip"
            valueField="count"
          />
          <RankTable
            title="Top Destination IPs / Hosts"
            icon={Globe}
            rows={data?.top_dst_ips}
            keyField="ip"
            valueField="count"
            flagFn={isSuspicious}
          />
          <RankTable
            title="Top Users"
            icon={User}
            rows={data?.top_users}
            keyField="user"
            valueField="count"
          />
        </div>
      )}
    </div>
  )
}
