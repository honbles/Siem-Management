import { useEffect, useState } from 'react'
import { Monitor, Wifi, WifiOff, RefreshCw } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import api from '../api/client'

function AgentRow({ agent }) {
  return (
    <tr className="border-b border-siem-border/40 hover:bg-white/[0.02]">
      <td className="px-4 py-3">
        <div className="flex items-center gap-2">
          {agent.online
            ? <Wifi size={14} className="text-siem-green shrink-0" />
            : <WifiOff size={14} className="text-siem-muted shrink-0" />
          }
          <div>
            <div className="text-siem-text font-medium text-sm">{agent.hostname}</div>
            <div className="text-siem-muted text-xs">{agent.id}</div>
          </div>
        </div>
      </td>
      <td className="px-4 py-3">
        <span className={`text-xs px-2 py-0.5 rounded-full border ${
          agent.online
            ? 'bg-green-900/40 text-green-400 border-green-700'
            : 'bg-gray-800 text-gray-500 border-gray-700'
        }`}>
          {agent.online ? 'Online' : 'Offline'}
        </span>
      </td>
      <td className="px-4 py-3 text-siem-muted text-sm">{agent.os}</td>
      <td className="px-4 py-3 text-siem-muted text-sm">{agent.version}</td>
      <td className="px-4 py-3 text-siem-muted text-sm">{agent.last_ip}</td>
      <td className="px-4 py-3 text-siem-muted text-sm">
        {formatDistanceToNow(new Date(agent.last_seen), { addSuffix: true })}
      </td>
      <td className="px-4 py-3 text-siem-text text-sm text-right">
        {agent.event_count?.toLocaleString()}
      </td>
    </tr>
  )
}

export default function Agents() {
  const [agents, setAgents] = useState([])
  const [loading, setLoading] = useState(true)

  const load = async () => {
    setLoading(true)
    try {
      const { data } = await api.get('/api/v1/agents')
      setAgents(data.agents || [])
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
    const id = setInterval(load, 15000)
    return () => clearInterval(id)
  }, [])

  const online = agents.filter(a => a.online).length
  const offline = agents.length - online

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-bold text-siem-text">Agent Fleet</h1>
        <button
          onClick={load}
          className="flex items-center gap-1.5 text-xs text-siem-muted hover:text-siem-text border border-siem-border rounded-lg px-3 py-1.5 transition-colors"
        >
          <RefreshCw size={13} /> Refresh
        </button>
      </div>

      {/* Summary */}
      <div className="flex gap-4">
        <div className="bg-siem-surface border border-siem-border rounded-xl px-5 py-4 flex items-center gap-3">
          <Monitor size={20} className="text-siem-accent" />
          <div>
            <div className="text-2xl font-bold text-siem-text">{agents.length}</div>
            <div className="text-xs text-siem-muted">Total agents</div>
          </div>
        </div>
        <div className="bg-siem-surface border border-siem-border rounded-xl px-5 py-4 flex items-center gap-3">
          <Wifi size={20} className="text-siem-green" />
          <div>
            <div className="text-2xl font-bold text-siem-green">{online}</div>
            <div className="text-xs text-siem-muted">Online</div>
          </div>
        </div>
        <div className="bg-siem-surface border border-siem-border rounded-xl px-5 py-4 flex items-center gap-3">
          <WifiOff size={20} className="text-siem-muted" />
          <div>
            <div className="text-2xl font-bold text-siem-muted">{offline}</div>
            <div className="text-xs text-siem-muted">Offline</div>
          </div>
        </div>
      </div>

      {/* Table */}
      <div className="bg-siem-surface border border-siem-border rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-siem-border text-siem-muted text-xs">
              <th className="text-left px-4 py-3">Agent</th>
              <th className="text-left px-4 py-3">Status</th>
              <th className="text-left px-4 py-3">OS</th>
              <th className="text-left px-4 py-3">Version</th>
              <th className="text-left px-4 py-3">Last IP</th>
              <th className="text-left px-4 py-3">Last Seen</th>
              <th className="text-right px-4 py-3">Events</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr><td colSpan={7} className="text-center py-12 text-siem-muted">Loading...</td></tr>
            ) : agents.length === 0 ? (
              <tr><td colSpan={7} className="text-center py-12 text-siem-muted">No agents registered yet</td></tr>
            ) : agents.map(a => <AgentRow key={a.id} agent={a} />)}
          </tbody>
        </table>
      </div>
    </div>
  )
}
