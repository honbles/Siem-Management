import { useState, useCallback } from 'react'
import { Search as SearchIcon, Play, ChevronRight, BookOpen, X, Filter } from 'lucide-react'
import { format } from 'date-fns'
import api from '../api/client'
import { SeverityBadge } from '../components/SeverityBadge'

// ── 100 Saved Queries ────────────────────────────────────────────────────────

const SAVED_QUERIES = [

  // PROCESS EXECUTION (20)
  { cat: 'Process Execution', label: 'All PowerShell executions', params: { process_name: 'powershell', event_type: 'process' } },
  { cat: 'Process Execution', label: 'PowerShell encoded commands', params: { event_type: 'process', command_line: '-enc' } },
  { cat: 'Process Execution', label: 'PowerShell download cradles', params: { event_type: 'process', command_line: 'downloadstring' } },
  { cat: 'Process Execution', label: 'CMD suspicious execution', params: { event_type: 'process', process_name: 'cmd.exe' } },
  { cat: 'Process Execution', label: 'Rundll32 executions', params: { event_type: 'process', process_name: 'rundll32' } },
  { cat: 'Process Execution', label: 'MSHTA executions', params: { event_type: 'process', process_name: 'mshta' } },
  { cat: 'Process Execution', label: 'WScript/CScript executions', params: { event_type: 'process', search: 'wscript' } },
  { cat: 'Process Execution', label: 'Regsvr32 executions', params: { event_type: 'process', process_name: 'regsvr32' } },
  { cat: 'Process Execution', label: 'Certutil abuse', params: { event_type: 'process', process_name: 'certutil' } },
  { cat: 'Process Execution', label: 'BITSAdmin executions', params: { event_type: 'process', search: 'bitsadmin' } },
  { cat: 'Process Execution', label: 'Scheduled task creation (schtasks)', params: { event_type: 'process', command_line: 'schtasks' } },
  { cat: 'Process Execution', label: 'New service creation (sc create)', params: { event_type: 'process', command_line: 'sc create' } },
  { cat: 'Process Execution', label: 'PsExec remote execution', params: { event_type: 'process', search: 'psexec' } },
  { cat: 'Process Execution', label: 'All high-severity process events', params: { event_type: 'process', severity: '4' } },
  { cat: 'Process Execution', label: 'Net.exe account commands', params: { event_type: 'process', search: 'net user' } },
  { cat: 'Process Execution', label: 'whoami execution', params: { event_type: 'process', command_line: 'whoami' } },
  { cat: 'Process Execution', label: 'Windows Scripting Host', params: { event_type: 'process', search: 'cscript' } },
  { cat: 'Process Execution', label: 'Shadow copy deletion (vssadmin)', params: { event_type: 'process', command_line: 'vssadmin' } },
  { cat: 'Process Execution', label: 'bcdedit — recovery disabled', params: { event_type: 'process', command_line: 'bcdedit' } },
  { cat: 'Process Execution', label: 'WMIC command execution', params: { event_type: 'process', process_name: 'wmic' } },

  // CREDENTIAL ACCESS (10)
  { cat: 'Credential Access', label: 'Failed logon events (Event 4625)', params: { event_type: 'logon', event_id: '4625' } },
  { cat: 'Credential Access', label: 'Successful logon events (Event 4624)', params: { event_type: 'logon', event_id: '4624' } },
  { cat: 'Credential Access', label: 'Logon with explicit credentials (Event 4648)', params: { event_type: 'logon', event_id: '4648' } },
  { cat: 'Credential Access', label: 'LSASS access attempts', params: { event_type: 'process', search: 'lsass' } },
  { cat: 'Credential Access', label: 'Mimikatz indicators', params: { event_type: 'process', search: 'mimikatz' } },
  { cat: 'Credential Access', label: 'Procdump usage', params: { event_type: 'process', search: 'procdump' } },
  { cat: 'Credential Access', label: 'SAM registry access', params: { event_type: 'registry', reg_key: 'SAM' } },
  { cat: 'Credential Access', label: 'Credential file search', params: { event_type: 'process', command_line: 'password' } },
  { cat: 'Credential Access', label: 'All high-severity logon events', params: { event_type: 'logon', severity: '4' } },
  { cat: 'Credential Access', label: 'Logoff events (Event 4634)', params: { event_type: 'logon', event_id: '4634' } },

  // NETWORK ACTIVITY (15)
  { cat: 'Network Activity', label: 'All outbound RDP (port 3389)', params: { event_type: 'network', dst_port: '3389' } },
  { cat: 'Network Activity', label: 'All outbound SMB (port 445)', params: { event_type: 'network', dst_port: '445' } },
  { cat: 'Network Activity', label: 'All outbound SSH (port 22)', params: { event_type: 'network', dst_port: '22' } },
  { cat: 'Network Activity', label: 'Outbound FTP (port 21)', params: { event_type: 'network', dst_port: '21' } },
  { cat: 'Network Activity', label: 'HTTP outbound traffic (port 80)', params: { event_type: 'network', dst_port: '80' } },
  { cat: 'Network Activity', label: 'HTTPS outbound traffic (port 443)', params: { event_type: 'network', dst_port: '443' } },
  { cat: 'Network Activity', label: 'DNS queries (port 53)', params: { event_type: 'network', dst_port: '53' } },
  { cat: 'Network Activity', label: 'SMTP outbound (port 25/587)', params: { event_type: 'network', dst_port: '587' } },
  { cat: 'Network Activity', label: 'High-severity network events', params: { event_type: 'network', severity: '4' } },
  { cat: 'Network Activity', label: 'All TCP connections', params: { event_type: 'network', proto: 'tcp' } },
  { cat: 'Network Activity', label: 'All UDP traffic', params: { event_type: 'network', proto: 'udp' } },
  { cat: 'Network Activity', label: 'WinRM (port 5985/5986)', params: { event_type: 'network', dst_port: '5985' } },
  { cat: 'Network Activity', label: 'LDAP traffic (port 389)', params: { event_type: 'network', dst_port: '389' } },
  { cat: 'Network Activity', label: 'Kerberos (port 88)', params: { event_type: 'network', dst_port: '88' } },
  { cat: 'Network Activity', label: 'Database ports (1433/3306/5432)', params: { event_type: 'network', dst_port: '1433' } },

  // DNS QUERIES (10)
  { cat: 'DNS Queries', label: 'All DNS events', params: { event_type: 'dns' } },
  { cat: 'DNS Queries', label: 'RustDesk DNS queries', params: { event_type: 'dns', search: 'rustdesk' } },
  { cat: 'DNS Queries', label: 'WPAD proxy discovery', params: { event_type: 'dns', search: 'wpad' } },
  { cat: 'DNS Queries', label: 'Urban VPN queries', params: { event_type: 'dns', search: 'urban-vpn' } },
  { cat: 'DNS Queries', label: 'ngrok tunnel queries', params: { event_type: 'dns', search: 'ngrok' } },
  { cat: 'DNS Queries', label: 'Pastebin DNS lookups', params: { event_type: 'dns', search: 'pastebin' } },
  { cat: 'DNS Queries', label: 'TOR-related DNS', params: { event_type: 'dns', search: '.onion' } },
  { cat: 'DNS Queries', label: 'AnyDesk DNS queries', params: { event_type: 'dns', search: 'anydesk' } },
  { cat: 'DNS Queries', label: 'TeamViewer DNS queries', params: { event_type: 'dns', search: 'teamviewer' } },
  { cat: 'DNS Queries', label: 'High-severity DNS events', params: { event_type: 'dns', severity: '4' } },

  // FILE ACTIVITY (10)
  { cat: 'File Activity', label: 'All file events', params: { event_type: 'file' } },
  { cat: 'File Activity', label: 'Temp directory writes', params: { event_type: 'file', file_path: '\\temp\\' } },
  { cat: 'File Activity', label: 'AppData writes', params: { event_type: 'file', file_path: 'appdata' } },
  { cat: 'File Activity', label: 'Desktop file drops', params: { event_type: 'file', file_path: '\\desktop\\' } },
  { cat: 'File Activity', label: 'Executable files written (.exe)', params: { event_type: 'file', file_path: '.exe' } },
  { cat: 'File Activity', label: 'Script files written (.ps1/.bat/.vbs)', params: { event_type: 'file', file_path: '.ps1' } },
  { cat: 'File Activity', label: 'Startup folder writes', params: { event_type: 'file', file_path: 'startup' } },
  { cat: 'File Activity', label: 'System32 writes', params: { event_type: 'file', file_path: 'system32' } },
  { cat: 'File Activity', label: 'Encrypted file extensions', params: { event_type: 'file', search: '.locked' } },
  { cat: 'File Activity', label: 'High-severity file events', params: { event_type: 'file', severity: '4' } },

  // REGISTRY (10)
  { cat: 'Registry', label: 'All registry events', params: { event_type: 'registry' } },
  { cat: 'Registry', label: 'Run key modifications', params: { event_type: 'registry', reg_key: 'CurrentVersion\\Run' } },
  { cat: 'Registry', label: 'RunOnce key modifications', params: { event_type: 'registry', reg_key: 'RunOnce' } },
  { cat: 'Registry', label: 'Security policy registry changes', params: { event_type: 'registry', reg_key: 'Policies' } },
  { cat: 'Registry', label: 'Service registry modifications', params: { event_type: 'registry', reg_key: 'Services' } },
  { cat: 'Registry', label: 'LSA registry modifications', params: { event_type: 'registry', reg_key: 'Lsa' } },
  { cat: 'Registry', label: 'Winlogon key modifications', params: { event_type: 'registry', reg_key: 'Winlogon' } },
  { cat: 'Registry', label: 'AppInit DLLs modifications', params: { event_type: 'registry', reg_key: 'AppInit_DLLs' } },
  { cat: 'Registry', label: 'Internet Explorer zone settings', params: { event_type: 'registry', reg_key: 'ZoneMap' } },
  { cat: 'Registry', label: 'High-severity registry events', params: { event_type: 'registry', severity: '4' } },

  // USER ACTIVITY (10)
  { cat: 'User Activity', label: 'All events for a user (admin)', params: { user_name: 'admin' } },
  { cat: 'User Activity', label: 'All events for SYSTEM account', params: { user_name: 'SYSTEM' } },
  { cat: 'User Activity', label: 'Guest account activity', params: { user_name: 'guest' } },
  { cat: 'User Activity', label: 'Network service account', params: { user_name: 'NETWORK SERVICE' } },
  { cat: 'User Activity', label: 'Events with no user context', params: { event_type: 'process', user_name: '' } },
  { cat: 'User Activity', label: 'All user logon events', params: { event_type: 'logon' } },
  { cat: 'User Activity', label: 'High-severity user events', params: { severity: '4', user_name: '' } },
  { cat: 'User Activity', label: 'Service account logons', params: { event_type: 'logon', search: 'svc' } },
  { cat: 'User Activity', label: 'Interactive logons (Type 2)', params: { event_type: 'logon', event_id: '4624' } },
  { cat: 'User Activity', label: 'Account management events (4720+)', params: { channel: 'Security', event_id: '4720' } },

  // SYSMON / ADVANCED (15)
  { cat: 'Sysmon & Advanced', label: 'All Sysmon events', params: { event_type: 'sysmon' } },
  { cat: 'Sysmon & Advanced', label: 'Sysmon process creation (ID 1)', params: { event_type: 'sysmon', event_id: '1' } },
  { cat: 'Sysmon & Advanced', label: 'Sysmon network connection (ID 3)', params: { event_type: 'sysmon', event_id: '3' } },
  { cat: 'Sysmon & Advanced', label: 'Sysmon file creation (ID 11)', params: { event_type: 'sysmon', event_id: '11' } },
  { cat: 'Sysmon & Advanced', label: 'Sysmon registry event (ID 12)', params: { event_type: 'sysmon', event_id: '12' } },
  { cat: 'Sysmon & Advanced', label: 'Sysmon image loaded (ID 7)', params: { event_type: 'sysmon', event_id: '7' } },
  { cat: 'Sysmon & Advanced', label: 'Sysmon process access (ID 10)', params: { event_type: 'sysmon', event_id: '10' } },
  { cat: 'Sysmon & Advanced', label: 'All critical severity events', params: { severity: '5' } },
  { cat: 'Sysmon & Advanced', label: 'All high severity events (last 24h)', params: { severity: '4' } },
  { cat: 'Sysmon & Advanced', label: 'Windows Security channel events', params: { channel: 'Security' } },
  { cat: 'Sysmon & Advanced', label: 'Windows System channel events', params: { channel: 'System' } },
  { cat: 'Sysmon & Advanced', label: 'PowerShell Operational events', params: { channel: 'PowerShell' } },
  { cat: 'Sysmon & Advanced', label: 'Event log cleared (ID 1102)', params: { event_id: '1102' } },
  { cat: 'Sysmon & Advanced', label: 'AppLocker block events (ID 8004)', params: { event_id: '8004' } },
  { cat: 'Sysmon & Advanced', label: 'All raw events', params: { event_type: 'raw' } },
]

const CATEGORIES = [...new Set(SAVED_QUERIES.map(q => q.cat))]

const FIELD_LABELS = {
  event_type: 'Event Type', process_name: 'Process', command_line: 'Command Line',
  user_name: 'User', src_ip: 'Src IP', dst_ip: 'Dst IP', dst_port: 'Dst Port',
  src_port: 'Src Port', proto: 'Protocol', file_path: 'File Path', reg_key: 'Registry Key',
  channel: 'Channel', event_id: 'Event ID', severity: 'Min Severity', search: 'Free Text',
  image_path: 'Image Path', agent_id: 'Agent ID', host: 'Host',
}

// ── Component ────────────────────────────────────────────────────────────────

export default function Search() {
  const [activeCat, setActiveCat] = useState('Process Execution')
  const [params, setParams] = useState({})
  const [results, setResults] = useState([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(false)
  const [ran, setRan] = useState(false)
  const [error, setError] = useState('')
  const [activeQuery, setActiveQuery] = useState(null)
  const [customField, setCustomField] = useState('search')
  const [customValue, setCustomValue] = useState('')

  const runQuery = useCallback(async (p = params) => {
    const cleaned = Object.fromEntries(Object.entries(p).filter(([, v]) => v !== '' && v !== undefined))
    if (Object.keys(cleaned).length === 0) { setError('Add at least one filter'); return }
    setError('')
    setLoading(true)
    setRan(true)
    try {
      const { data } = await api.get('/api/v1/events', { params: { ...cleaned, limit: 200 } })
      setResults(data.events || [])
      setTotal(data.total || 0)
    } catch (e) {
      setError('Query failed')
    } finally { setLoading(false) }
  }, [params])

  const loadSaved = (q) => {
    setParams(q.params)
    setActiveQuery(q.label)
    setResults([])
    setRan(false)
    setError('')
  }

  const addParam = () => {
    if (!customValue) return
    setParams(p => ({ ...p, [customField]: customValue }))
    setCustomValue('')
  }

  const removeParam = (key) => {
    setParams(p => { const n = { ...p }; delete n[key]; return n })
  }

  const sevColor = { 5: 'text-red-400', 4: 'text-orange-400', 3: 'text-yellow-400', 2: 'text-blue-400', 1: 'text-gray-400' }

  return (
    <div className="flex h-screen overflow-hidden">

      {/* Sidebar — saved queries */}
      <div className="w-72 bg-siem-surface border-r border-siem-border flex flex-col overflow-hidden">
        <div className="px-4 py-3 border-b border-siem-border">
          <div className="flex items-center gap-2">
            <BookOpen size={15} className="text-siem-accent" />
            <span className="text-sm font-semibold text-siem-text">Saved Queries</span>
            <span className="ml-auto text-[10px] text-siem-muted bg-siem-border/40 rounded px-1.5 py-0.5">{SAVED_QUERIES.length}</span>
          </div>
        </div>

        {/* Category tabs */}
        <div className="flex overflow-x-auto gap-1 px-2 py-2 border-b border-siem-border scrollbar-hide">
          {CATEGORIES.map(c => (
            <button key={c} onClick={() => setActiveCat(c)}
              className={`text-[10px] whitespace-nowrap px-2 py-1 rounded transition-colors ${
                activeCat === c ? 'bg-siem-accent/20 text-siem-accent' : 'text-siem-muted hover:text-siem-text'
              }`}>
              {c.split(' ')[0]}
            </button>
          ))}
        </div>

        {/* Query list */}
        <div className="flex-1 overflow-y-auto py-1">
          {SAVED_QUERIES.filter(q => q.cat === activeCat).map((q, i) => (
            <button key={i} onClick={() => loadSaved(q)}
              className={`w-full text-left px-4 py-2 text-xs hover:bg-white/[0.04] transition-colors border-b border-siem-border/20 ${
                activeQuery === q.label ? 'bg-siem-accent/10 text-siem-accent border-l-2 border-l-siem-accent' : 'text-siem-muted'
              }`}>
              {q.label}
            </button>
          ))}
        </div>
      </div>

      {/* Main area */}
      <div className="flex-1 flex flex-col overflow-hidden">

        {/* Query builder */}
        <div className="bg-siem-surface border-b border-siem-border px-5 py-4 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <SearchIcon size={16} className="text-siem-accent" />
              <span className="text-sm font-semibold text-siem-text">Query Builder</span>
            </div>
            <button onClick={() => { setParams({}); setResults([]); setRan(false); setActiveQuery(null) }}
              className="text-xs text-siem-muted hover:text-siem-text border border-siem-border rounded px-2 py-1">
              Clear
            </button>
          </div>

          {/* Active params */}
          <div className="flex flex-wrap gap-2 min-h-[28px]">
            {Object.entries(params).map(([k, v]) => (
              <div key={k} className="flex items-center gap-1 bg-siem-accent/10 border border-siem-accent/30 rounded-full px-2.5 py-1 text-xs">
                <span className="text-siem-accent font-medium">{FIELD_LABELS[k] || k}:</span>
                <span className="text-siem-text">{v}</span>
                <button onClick={() => removeParam(k)} className="text-siem-muted hover:text-siem-red ml-1"><X size={10} /></button>
              </div>
            ))}
            {Object.keys(params).length === 0 && (
              <span className="text-xs text-siem-muted italic">Select a saved query or add filters below</span>
            )}
          </div>

          {/* Add filter row */}
          <div className="flex gap-2">
            <select
              className="bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-xs text-siem-text focus:outline-none focus:border-siem-accent"
              value={customField} onChange={e => setCustomField(e.target.value)}>
              {Object.entries(FIELD_LABELS).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </select>
            <input
              className="flex-1 bg-siem-bg border border-siem-border rounded-lg px-3 py-2 text-xs text-siem-text focus:outline-none focus:border-siem-accent"
              placeholder={`Value for ${FIELD_LABELS[customField] || customField}...`}
              value={customValue}
              onChange={e => setCustomValue(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && addParam()}
            />
            <button onClick={addParam}
              className="flex items-center gap-1 text-xs border border-siem-border text-siem-muted hover:text-siem-text rounded-lg px-3 py-2">
              <Filter size={12} /> Add
            </button>
            <button onClick={() => runQuery()}
              disabled={loading}
              className="flex items-center gap-2 text-xs bg-siem-accent hover:bg-siem-accent/90 text-white px-4 py-2 rounded-lg disabled:opacity-50 transition-colors">
              <Play size={12} fill="currentColor" />
              {loading ? 'Running...' : 'Run Query'}
            </button>
          </div>

          {error && <div className="text-siem-red text-xs">{error}</div>}
        </div>

        {/* Results */}
        <div className="flex-1 overflow-y-auto">
          {!ran ? (
            <div className="flex flex-col items-center justify-center h-full text-siem-muted">
              <SearchIcon size={40} className="opacity-20 mb-4" />
              <div className="text-sm">Select a saved query or build your own, then click Run Query</div>
              <div className="text-xs mt-2 opacity-60">{SAVED_QUERIES.length} saved queries across {CATEGORIES.length} categories</div>
            </div>
          ) : loading ? (
            <div className="flex items-center justify-center h-32 text-siem-muted text-sm">Searching...</div>
          ) : (
            <div>
              <div className="flex items-center gap-3 px-5 py-2.5 border-b border-siem-border/50 bg-siem-surface/50 sticky top-0">
                <span className="text-xs text-siem-muted">
                  {results.length === 0 ? 'No results found' : `Showing ${results.length} of ${total.toLocaleString()} results`}
                </span>
                {activeQuery && <span className="text-xs text-siem-accent">"{activeQuery}"</span>}
              </div>
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-siem-border text-siem-muted text-xs bg-siem-surface">
                    <th className="text-left px-4 py-2.5">Time</th>
                    <th className="text-left px-4 py-2.5">Sev</th>
                    <th className="text-left px-4 py-2.5">Host</th>
                    <th className="text-left px-4 py-2.5">Type</th>
                    <th className="text-left px-4 py-2.5">User</th>
                    <th className="text-left px-4 py-2.5">Process / Key / IP</th>
                    <th className="text-left px-4 py-2.5 max-w-xs">Command / Value</th>
                    <th className="px-4 py-2.5"></th>
                  </tr>
                </thead>
                <tbody>
                  {results.map((ev, i) => (
                    <tr key={ev.id || i} className="border-b border-siem-border/30 hover:bg-white/[0.02] transition-colors">
                      <td className="px-4 py-2 text-siem-muted text-xs whitespace-nowrap">
                        {format(new Date(ev.time), 'MM/dd HH:mm:ss')}
                      </td>
                      <td className="px-4 py-2">
                        <span className={`text-xs font-bold ${sevColor[ev.severity] || 'text-siem-muted'}`}>{ev.severity}</span>
                      </td>
                      <td className="px-4 py-2 text-siem-text text-xs font-medium">{ev.host}</td>
                      <td className="px-4 py-2 text-siem-accent text-xs">{ev.event_type}</td>
                      <td className="px-4 py-2 text-siem-muted text-xs">{ev.user_name || '—'}</td>
                      <td className="px-4 py-2 text-siem-muted text-xs truncate max-w-[160px]">
                        {ev.process_name || ev.reg_key || ev.src_ip || ev.file_path || '—'}
                      </td>
                      <td className="px-4 py-2 text-siem-muted text-xs truncate max-w-[220px]">
                        {ev.command_line || ev.reg_value || ev.dst_ip || '—'}
                      </td>
                      <td className="px-4 py-2 text-siem-muted"><ChevronRight size={13} /></td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
