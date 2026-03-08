import { useState, useCallback, useRef } from 'react'
import { Search as SearchIcon, Play, BookOpen, X, ChevronRight, Clock, Filter } from 'lucide-react'
import { format } from 'date-fns'
import api from '../api/client'
import { SeverityBadge } from '../components/SeverityBadge'

// ── 100 Saved Queries ─────────────────────────────────────────────────────────
const SAVED_QUERIES = [
  // PROCESS EXECUTION
  { cat: 'Process', label: 'All processes on all hosts',          params: { event_type: 'process' } },
  { cat: 'Process', label: 'All PowerShell executions',           params: { event_type: 'process', process_name: 'powershell' } },
  { cat: 'Process', label: 'PowerShell encoded commands',         params: { event_type: 'process', command_line: '-enc' } },
  { cat: 'Process', label: 'PowerShell download cradles',         params: { event_type: 'process', command_line: 'downloadstring' } },
  { cat: 'Process', label: 'CMD executions',                      params: { event_type: 'process', process_name: 'cmd.exe' } },
  { cat: 'Process', label: 'Rundll32 executions',                 params: { event_type: 'process', process_name: 'rundll32' } },
  { cat: 'Process', label: 'MSHTA executions',                    params: { event_type: 'process', process_name: 'mshta' } },
  { cat: 'Process', label: 'WScript / CScript',                   params: { event_type: 'process', search: 'wscript' } },
  { cat: 'Process', label: 'Regsvr32 executions',                 params: { event_type: 'process', process_name: 'regsvr32' } },
  { cat: 'Process', label: 'Certutil abuse',                      params: { event_type: 'process', process_name: 'certutil' } },
  { cat: 'Process', label: 'BITSAdmin executions',                params: { event_type: 'process', search: 'bitsadmin' } },
  { cat: 'Process', label: 'Scheduled task creation',             params: { event_type: 'process', command_line: 'schtasks' } },
  { cat: 'Process', label: 'New service (sc create)',             params: { event_type: 'process', command_line: 'sc create' } },
  { cat: 'Process', label: 'PsExec remote execution',             params: { event_type: 'process', search: 'psexec' } },
  { cat: 'Process', label: 'High severity process events',        params: { event_type: 'process', severity: '4' } },
  { cat: 'Process', label: 'Net.exe account commands',            params: { event_type: 'process', search: 'net user' } },
  { cat: 'Process', label: 'whoami execution',                    params: { event_type: 'process', command_line: 'whoami' } },
  { cat: 'Process', label: 'Shadow copy deletion',                params: { event_type: 'process', command_line: 'vssadmin' } },
  { cat: 'Process', label: 'WMIC command execution',              params: { event_type: 'process', process_name: 'wmic' } },
  { cat: 'Process', label: 'bcdedit (recovery disabled)',         params: { event_type: 'process', command_line: 'bcdedit' } },

  // CREDENTIAL
  { cat: 'Credential', label: 'All logon events',                 params: { event_type: 'logon' } },
  { cat: 'Credential', label: 'Failed logons (Event 4625)',        params: { event_type: 'logon', event_id: '4625' } },
  { cat: 'Credential', label: 'Successful logons (Event 4624)',    params: { event_type: 'logon', event_id: '4624' } },
  { cat: 'Credential', label: 'Logon with explicit creds (4648)', params: { event_type: 'logon', event_id: '4648' } },
  { cat: 'Credential', label: 'LSASS access attempts',            params: { event_type: 'process', search: 'lsass' } },
  { cat: 'Credential', label: 'Mimikatz indicators',              params: { event_type: 'process', search: 'mimikatz' } },
  { cat: 'Credential', label: 'Procdump usage',                   params: { event_type: 'process', search: 'procdump' } },
  { cat: 'Credential', label: 'SAM registry access',              params: { event_type: 'registry', reg_key: 'SAM' } },
  { cat: 'Credential', label: 'Password string search',           params: { event_type: 'process', command_line: 'password' } },
  { cat: 'Credential', label: 'High severity logon events',       params: { event_type: 'logon', severity: '4' } },

  // NETWORK
  { cat: 'Network', label: 'All network connections',             params: { event_type: 'network' } },
  { cat: 'Network', label: 'Outbound RDP (port 3389)',            params: { event_type: 'network', dst_port: '3389' } },
  { cat: 'Network', label: 'Outbound SMB (port 445)',             params: { event_type: 'network', dst_port: '445' } },
  { cat: 'Network', label: 'Outbound SSH (port 22)',              params: { event_type: 'network', dst_port: '22' } },
  { cat: 'Network', label: 'Outbound FTP (port 21)',              params: { event_type: 'network', dst_port: '21' } },
  { cat: 'Network', label: 'HTTP traffic (port 80)',              params: { event_type: 'network', dst_port: '80' } },
  { cat: 'Network', label: 'HTTPS traffic (port 443)',            params: { event_type: 'network', dst_port: '443' } },
  { cat: 'Network', label: 'DNS traffic (port 53)',               params: { event_type: 'network', dst_port: '53' } },
  { cat: 'Network', label: 'SMTP outbound (port 587)',            params: { event_type: 'network', dst_port: '587' } },
  { cat: 'Network', label: 'WinRM (port 5985)',                   params: { event_type: 'network', dst_port: '5985' } },
  { cat: 'Network', label: 'LDAP (port 389)',                     params: { event_type: 'network', dst_port: '389' } },
  { cat: 'Network', label: 'Kerberos (port 88)',                  params: { event_type: 'network', dst_port: '88' } },
  { cat: 'Network', label: 'SQL Server (port 1433)',              params: { event_type: 'network', dst_port: '1433' } },
  { cat: 'Network', label: 'All TCP connections',                 params: { event_type: 'network', proto: 'tcp' } },
  { cat: 'Network', label: 'High severity network events',        params: { event_type: 'network', severity: '4' } },

  // DNS / WEBSITES
  { cat: 'DNS / Web', label: 'All DNS queries (websites visited)',params: { event_type: 'dns' } },
  { cat: 'DNS / Web', label: 'RustDesk DNS queries',              params: { event_type: 'dns', search: 'rustdesk' } },
  { cat: 'DNS / Web', label: 'WPAD proxy discovery',             params: { event_type: 'dns', search: 'wpad' } },
  { cat: 'DNS / Web', label: 'Urban VPN queries',                params: { event_type: 'dns', search: 'urban-vpn' } },
  { cat: 'DNS / Web', label: 'ngrok tunnel queries',             params: { event_type: 'dns', search: 'ngrok' } },
  { cat: 'DNS / Web', label: 'Pastebin lookups',                 params: { event_type: 'dns', search: 'pastebin' } },
  { cat: 'DNS / Web', label: 'TOR / .onion domains',             params: { event_type: 'dns', search: '.onion' } },
  { cat: 'DNS / Web', label: 'AnyDesk DNS queries',              params: { event_type: 'dns', search: 'anydesk' } },
  { cat: 'DNS / Web', label: 'TeamViewer DNS queries',           params: { event_type: 'dns', search: 'teamviewer' } },
  { cat: 'DNS / Web', label: 'High severity DNS events',         params: { event_type: 'dns', severity: '4' } },

  // FILE
  { cat: 'File', label: 'All file events',                       params: { event_type: 'file' } },
  { cat: 'File', label: 'Temp directory writes',                 params: { event_type: 'file', file_path: '\\temp\\' } },
  { cat: 'File', label: 'AppData writes',                        params: { event_type: 'file', file_path: 'appdata' } },
  { cat: 'File', label: 'Desktop file drops',                    params: { event_type: 'file', file_path: '\\desktop\\' } },
  { cat: 'File', label: 'Executable files written (.exe)',       params: { event_type: 'file', file_path: '.exe' } },
  { cat: 'File', label: 'PowerShell scripts written (.ps1)',     params: { event_type: 'file', file_path: '.ps1' } },
  { cat: 'File', label: 'Startup folder writes',                 params: { event_type: 'file', file_path: 'startup' } },
  { cat: 'File', label: 'System32 writes',                       params: { event_type: 'file', file_path: 'system32' } },
  { cat: 'File', label: 'Encrypted file extensions',             params: { event_type: 'file', search: '.locked' } },
  { cat: 'File', label: 'High severity file events',             params: { event_type: 'file', severity: '4' } },

  // REGISTRY
  { cat: 'Registry', label: 'All registry events',               params: { event_type: 'registry' } },
  { cat: 'Registry', label: 'Run key modifications',             params: { event_type: 'registry', reg_key: 'CurrentVersion\\Run' } },
  { cat: 'Registry', label: 'RunOnce key modifications',         params: { event_type: 'registry', reg_key: 'RunOnce' } },
  { cat: 'Registry', label: 'Security policy changes',           params: { event_type: 'registry', reg_key: 'Policies' } },
  { cat: 'Registry', label: 'Service registry changes',          params: { event_type: 'registry', reg_key: 'Services' } },
  { cat: 'Registry', label: 'LSA registry changes',              params: { event_type: 'registry', reg_key: 'Lsa' } },
  { cat: 'Registry', label: 'Winlogon key changes',              params: { event_type: 'registry', reg_key: 'Winlogon' } },
  { cat: 'Registry', label: 'AppInit DLLs',                      params: { event_type: 'registry', reg_key: 'AppInit_DLLs' } },
  { cat: 'Registry', label: 'IE Zone settings',                  params: { event_type: 'registry', reg_key: 'ZoneMap' } },
  { cat: 'Registry', label: 'High severity registry events',     params: { event_type: 'registry', severity: '4' } },

  // USER
  { cat: 'User', label: 'All events for SYSTEM account',         params: { user_name: 'SYSTEM' } },
  { cat: 'User', label: 'All events for administrator',          params: { user_name: 'administrator' } },
  { cat: 'User', label: 'Guest account activity',                params: { user_name: 'guest' } },
  { cat: 'User', label: 'Network service account',               params: { user_name: 'NETWORK SERVICE' } },
  { cat: 'User', label: 'All logon events',                      params: { event_type: 'logon' } },
  { cat: 'User', label: 'Service account logons',                params: { event_type: 'logon', search: 'svc' } },
  { cat: 'User', label: 'Account creation (Event 4720)',         params: { event_id: '4720' } },
  { cat: 'User', label: 'High severity user events',             params: { severity: '4', user_name: 'admin' } },

  // SYSMON / ADVANCED
  { cat: 'Sysmon', label: 'All Sysmon events',                   params: { event_type: 'sysmon' } },
  { cat: 'Sysmon', label: 'Sysmon process creation (ID 1)',       params: { event_type: 'sysmon', event_id: '1' } },
  { cat: 'Sysmon', label: 'Sysmon network connection (ID 3)',     params: { event_type: 'sysmon', event_id: '3' } },
  { cat: 'Sysmon', label: 'Sysmon file creation (ID 11)',         params: { event_type: 'sysmon', event_id: '11' } },
  { cat: 'Sysmon', label: 'Sysmon registry event (ID 12)',        params: { event_type: 'sysmon', event_id: '12' } },
  { cat: 'Sysmon', label: 'Sysmon image loaded (ID 7)',           params: { event_type: 'sysmon', event_id: '7' } },
  { cat: 'Sysmon', label: 'Sysmon process access (ID 10)',        params: { event_type: 'sysmon', event_id: '10' } },
  { cat: 'Sysmon', label: 'All critical severity events',        params: { severity: '5' } },
  { cat: 'Sysmon', label: 'All high severity events',            params: { severity: '4' } },
  { cat: 'Sysmon', label: 'Windows Security channel',            params: { channel: 'Security' } },
  { cat: 'Sysmon', label: 'Windows System channel',              params: { channel: 'System' } },
  { cat: 'Sysmon', label: 'PowerShell Operational channel',      params: { channel: 'PowerShell' } },
  { cat: 'Sysmon', label: 'Event log cleared (ID 1102)',         params: { event_id: '1102' } },
  { cat: 'Sysmon', label: 'AppLocker block events (8004)',       params: { event_id: '8004' } },
  { cat: 'Sysmon', label: 'All raw events',                      params: { event_type: 'raw' } },
]

const CATEGORIES = [...new Set(SAVED_QUERIES.map(q => q.cat))]

// ── Quick search parser: "host:CORP-VAPT type:process user:admin" ─────────────
function parseQuickSearch(raw) {
  const params = {}
  const tokens = raw.trim().split(/\s+/)
  const leftover = []
  const map = {
    host: 'host', type: 'event_type', process: 'process_name', user: 'user_name',
    cmd: 'command_line', ip: 'search', src: 'src_ip', dst: 'dst_ip',
    port: 'dst_port', proto: 'proto', file: 'file_path', reg: 'reg_key',
    channel: 'channel', id: 'event_id', sev: 'severity', severity: 'severity',
  }
  for (const token of tokens) {
    const colon = token.indexOf(':')
    if (colon > 0) {
      const key = token.slice(0, colon).toLowerCase()
      const val = token.slice(colon + 1)
      if (map[key] && val) { params[map[key]] = val; continue }
    }
    leftover.push(token)
  }
  if (leftover.length > 0) params.search = leftover.join(' ')
  return params
}

const SEV_COLOR = { 5:'text-red-400', 4:'text-orange-400', 3:'text-yellow-400', 2:'text-blue-400', 1:'text-gray-400' }
const TYPE_COLOR = {
  process:'text-purple-400', network:'text-blue-400', logon:'text-green-400',
  dns:'text-cyan-400', registry:'text-orange-400', file:'text-yellow-400',
  sysmon:'text-pink-400', raw:'text-gray-400',
}

function ResultRow({ ev }) {
  // Pick the most interesting value for the "detail" column based on event type
  const detail = ev.command_line || ev.dst_ip || ev.reg_key || ev.file_path || ev.src_ip || '—'
  const subject = ev.process_name || ev.reg_key || ev.file_path || ev.dst_ip || '—'

  return (
    <tr className="border-b border-siem-border/20 hover:bg-white/[0.03] transition-colors group">
      <td className="px-4 py-2.5 text-siem-muted text-xs whitespace-nowrap font-mono">
        {format(new Date(ev.time), 'MM/dd HH:mm:ss')}
      </td>
      <td className="px-3 py-2.5">
        <span className={`text-xs font-bold ${SEV_COLOR[ev.severity] || 'text-siem-muted'}`}>{ev.severity}</span>
      </td>
      <td className="px-3 py-2.5 text-siem-text text-xs font-medium whitespace-nowrap">{ev.host}</td>
      <td className="px-3 py-2.5">
        <span className={`text-xs font-medium ${TYPE_COLOR[ev.event_type] || 'text-siem-muted'}`}>{ev.event_type}</span>
      </td>
      <td className="px-3 py-2.5 text-siem-muted text-xs">{ev.user_name || '—'}</td>
      <td className="px-3 py-2.5 text-siem-muted text-xs max-w-[180px] truncate" title={subject}>{subject}</td>
      <td className="px-3 py-2.5 text-siem-muted text-xs max-w-[280px] truncate font-mono text-[11px]" title={detail}>{detail}</td>
    </tr>
  )
}

// ── Main Component ────────────────────────────────────────────────────────────
export default function Search() {
  const [activeCat, setActiveCat] = useState('Process')
  const [quickText, setQuickText]   = useState('')
  const [chips, setChips]           = useState({})   // active filter chips
  const [results, setResults]       = useState([])
  const [total, setTotal]           = useState(0)
  const [loading, setLoading]       = useState(false)
  const [ran, setRan]               = useState(false)
  const [activeLabel, setActiveLabel] = useState('')
  const inputRef = useRef(null)

  // Build final params from chips (no default time range — search all data)
  const buildParams = useCallback((extra = {}) => {
    const p = { ...chips, ...extra, limit: 200 }
    // Strip empty values
    return Object.fromEntries(Object.entries(p).filter(([, v]) => v !== '' && v !== undefined))
  }, [chips])

  const runQuery = useCallback(async (overrideParams) => {
    const p = overrideParams || buildParams()
    if (Object.keys(p).length <= 1 && p.limit) { return } // nothing useful
    setLoading(true)
    setRan(true)
    try {
      const { data } = await api.get('/api/v1/events', { params: p })
      setResults(data.events || [])
      setTotal(data.total || 0)
    } catch (e) {
      setResults([])
    } finally { setLoading(false) }
  }, [buildParams])

  // Click saved query → load chips and immediately run
  const loadSaved = (q) => {
    setChips(q.params)
    setActiveLabel(q.label)
    setQuickText('')
    runQuery({ ...q.params, limit: 200 })
  }

  // Quick search bar — parse and run
  const handleQuickSearch = (e) => {
    e.preventDefault()
    if (!quickText.trim()) return
    const parsed = parseQuickSearch(quickText)
    setChips(parsed)
    setActiveLabel(quickText)
    runQuery({ ...parsed, limit: 200 })
  }

  const removeChip = (key) => {
    const next = { ...chips }
    delete next[key]
    setChips(next)
    runQuery({ ...next, limit: 200 })
  }

  const clearAll = () => { setChips({}); setResults([]); setRan(false); setActiveLabel(''); setQuickText('') }

  const CHIP_LABEL = {
    event_type:'Type', process_name:'Process', command_line:'Cmd',
    user_name:'User', src_ip:'Src IP', dst_ip:'Dst IP', dst_port:'Port',
    proto:'Proto', file_path:'File', reg_key:'Reg', channel:'Channel',
    event_id:'Event ID', severity:'Sev ≥', search:'Search', host:'Host',
    image_path:'Image', agent_id:'Agent',
  }

  return (
    <div className="flex h-[calc(100vh-0px)] overflow-hidden bg-siem-bg">

      {/* ── Left sidebar ──────────────────────────────────────────────── */}
      <div className="w-64 bg-siem-surface border-r border-siem-border flex flex-col shrink-0">
        <div className="px-4 py-3 border-b border-siem-border flex items-center gap-2">
          <BookOpen size={14} className="text-siem-accent" />
          <span className="text-xs font-semibold text-siem-text">Saved Queries</span>
          <span className="ml-auto text-[10px] text-siem-muted bg-siem-border/50 rounded px-1.5 py-0.5">{SAVED_QUERIES.length}</span>
        </div>

        {/* Category tabs */}
        <div className="flex flex-wrap gap-1 px-2 py-2 border-b border-siem-border">
          {CATEGORIES.map(c => (
            <button key={c} onClick={() => setActiveCat(c)}
              className={`text-[10px] px-2 py-0.5 rounded transition-colors ${
                activeCat === c ? 'bg-siem-accent text-white' : 'text-siem-muted hover:text-siem-text hover:bg-white/[0.04]'
              }`}>
              {c}
            </button>
          ))}
        </div>

        {/* Query list */}
        <div className="flex-1 overflow-y-auto">
          {SAVED_QUERIES.filter(q => q.cat === activeCat).map((q, i) => (
            <button key={i} onClick={() => loadSaved(q)}
              className={`w-full text-left px-4 py-2.5 text-xs border-b border-siem-border/20 transition-colors ${
                activeLabel === q.label
                  ? 'bg-siem-accent/15 text-siem-accent border-l-2 border-l-siem-accent pl-3'
                  : 'text-siem-muted hover:bg-white/[0.04] hover:text-siem-text'
              }`}>
              {q.label}
            </button>
          ))}
        </div>
      </div>

      {/* ── Right panel ───────────────────────────────────────────────── */}
      <div className="flex-1 flex flex-col overflow-hidden">

        {/* Search bar */}
        <div className="bg-siem-surface border-b border-siem-border px-5 py-4 space-y-3">

          {/* Quick search */}
          <form onSubmit={handleQuickSearch} className="flex gap-2">
            <div className="relative flex-1">
              <SearchIcon size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-siem-muted pointer-events-none" />
              <input ref={inputRef}
                className="w-full bg-siem-bg border border-siem-border rounded-lg pl-9 pr-4 py-2.5 text-sm text-siem-text placeholder-siem-muted focus:outline-none focus:border-siem-accent transition-colors"
                placeholder='host:CORP-VAPT type:process   or   type:dns   or   user:admin   or just free text'
                value={quickText}
                onChange={e => setQuickText(e.target.value)}
              />
            </div>
            <button type="submit"
              className="flex items-center gap-2 bg-siem-accent hover:bg-siem-accent/90 text-white text-sm px-5 py-2.5 rounded-lg transition-colors shrink-0">
              <Play size={13} fill="currentColor" /> Search
            </button>
            {(Object.keys(chips).length > 0 || ran) && (
              <button type="button" onClick={clearAll}
                className="text-xs text-siem-muted hover:text-siem-text border border-siem-border rounded-lg px-3 py-2">
                Clear
              </button>
            )}
          </form>

          {/* Syntax hint */}
          <div className="flex flex-wrap gap-2 text-[10px] text-siem-muted">
            {[
              ['host:CORP-VAPT type:process', 'All processes on a host'],
              ['type:dns', 'All websites visited'],
              ['type:logon user:admin', 'Admin logon history'],
              ['port:3389', 'RDP connections'],
              ['cmd:powershell -enc', 'Encoded PowerShell'],
              ['type:network dst:8.8.8.8', 'Connections to specific IP'],
            ].map(([ex, tip]) => (
              <button key={ex} onClick={() => { setQuickText(ex); inputRef.current?.focus() }}
                className="bg-siem-bg border border-siem-border/50 rounded px-2 py-1 hover:border-siem-accent/40 hover:text-siem-accent transition-colors"
                title={tip}>
                {ex}
              </button>
            ))}
          </div>

          {/* Active chips */}
          {Object.keys(chips).length > 0 && (
            <div className="flex flex-wrap gap-1.5">
              {Object.entries(chips).map(([k, v]) => (
                <span key={k} className="flex items-center gap-1 bg-siem-accent/10 border border-siem-accent/30 rounded-full px-2.5 py-0.5 text-xs">
                  <span className="text-siem-accent font-medium">{CHIP_LABEL[k] || k}:</span>
                  <span className="text-siem-text">{v}</span>
                  <button onClick={() => removeChip(k)} className="text-siem-muted hover:text-red-400 ml-0.5">
                    <X size={9} />
                  </button>
                </span>
              ))}
              <button onClick={() => runQuery()}
                className="flex items-center gap-1 text-xs text-siem-accent border border-siem-accent/40 rounded-full px-2.5 py-0.5 hover:bg-siem-accent/10 transition-colors">
                <Play size={9} fill="currentColor" /> Re-run
              </button>
            </div>
          )}
        </div>

        {/* Results */}
        <div className="flex-1 overflow-y-auto">
          {!ran ? (
            <div className="flex flex-col items-center justify-center h-full text-siem-muted select-none">
              <SearchIcon size={48} className="opacity-10 mb-5" />
              <div className="text-base font-medium text-siem-text/50 mb-2">Search your endpoint telemetry</div>
              <div className="text-sm mb-6">Click a saved query on the left, or type in the search bar above</div>
              <div className="grid grid-cols-2 gap-2 text-xs max-w-lg w-full px-4">
                {[
                  { label: '🖥  All processes on a host',   action: () => { setQuickText('host:CORP-VAPT type:process'); runQuery({ host:'CORP-VAPT', event_type:'process', limit:200 }); setActiveLabel('All processes on CORP-VAPT') } },
                  { label: '🌐 Websites visited (DNS)',      action: () => loadSaved({ label:'All DNS queries (websites visited)', params:{ event_type:'dns' } }) },
                  { label: '🔐 Failed logon attempts',       action: () => loadSaved({ label:'Failed logons (Event 4625)', params:{ event_type:'logon', event_id:'4625' } }) },
                  { label: '⚡ Critical severity events',   action: () => loadSaved({ label:'All critical severity events', params:{ severity:'5' } }) },
                  { label: '🔌 RDP connections',             action: () => loadSaved({ label:'Outbound RDP (port 3389)', params:{ event_type:'network', dst_port:'3389' } }) },
                  { label: '📋 Registry persistence keys',  action: () => loadSaved({ label:'Run key modifications', params:{ event_type:'registry', reg_key:'CurrentVersion\\Run' } }) },
                ].map(({ label, action }) => (
                  <button key={label} onClick={action}
                    className="text-left bg-siem-surface border border-siem-border rounded-lg px-3 py-2.5 hover:border-siem-accent/40 hover:bg-white/[0.03] transition-colors text-siem-muted hover:text-siem-text">
                    {label}
                  </button>
                ))}
              </div>
            </div>
          ) : loading ? (
            <div className="flex items-center justify-center h-32 gap-2 text-siem-muted text-sm">
              <div className="w-4 h-4 border-2 border-siem-accent/30 border-t-siem-accent rounded-full animate-spin" />
              Searching...
            </div>
          ) : (
            <>
              {/* Result count bar */}
              <div className="flex items-center gap-3 px-5 py-2 border-b border-siem-border/40 bg-siem-surface/60 sticky top-0 z-10">
                <span className="text-xs text-siem-muted">
                  {results.length === 0
                    ? '⚠ No results — try a wider time range or different filter'
                    : <><span className="text-siem-text font-medium">{results.length.toLocaleString()}</span> of <span className="text-siem-text font-medium">{total.toLocaleString()}</span> events</>
                  }
                </span>
                {activeLabel && <span className="text-xs text-siem-accent/80 truncate max-w-xs">"{activeLabel}"</span>}
                {results.length === 0 && Object.values(chips).some(v => v) && (
                  <button onClick={() => {
                    const wider = { ...chips }
                    delete wider.since; delete wider.until
                    setChips(wider)
                    runQuery({ ...wider, limit: 200 })
                  }} className="ml-auto text-xs text-siem-accent border border-siem-accent/30 rounded px-2 py-0.5 hover:bg-siem-accent/10">
                    Search all time →
                  </button>
                )}
              </div>

              {results.length > 0 && (
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-siem-border text-siem-muted text-xs bg-siem-surface/80 sticky top-[33px] z-10">
                      <th className="text-left px-4 py-2.5 font-medium">Time</th>
                      <th className="text-left px-3 py-2.5 font-medium">Sev</th>
                      <th className="text-left px-3 py-2.5 font-medium">Host</th>
                      <th className="text-left px-3 py-2.5 font-medium">Type</th>
                      <th className="text-left px-3 py-2.5 font-medium">User</th>
                      <th className="text-left px-3 py-2.5 font-medium">Process / Key / IP</th>
                      <th className="text-left px-3 py-2.5 font-medium">Command Line / Domain / Value</th>
                    </tr>
                  </thead>
                  <tbody>
                    {results.map((ev, i) => <ResultRow key={ev.id || i} ev={ev} />)}
                  </tbody>
                </table>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  )
}
