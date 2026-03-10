import { useState, useEffect, useCallback, useMemo, useRef } from 'react'
import { Monitor, ChevronRight, ChevronDown, Activity, AlertTriangle,
         Shield, Globe, FileText, Database, Cpu, Terminal, GitBranch,
         X, Clock, Hash, User, Layers, Search, Wifi, Key,
         ArrowUpRight, RefreshCw } from 'lucide-react'
import { format } from 'date-fns'
import api from '../api/client'

// Windows System: core OS processes + shells/terminals
const WINDOWS_LEGIT = new Set([
  // Core OS
  'svchost.exe','lsass.exe','winlogon.exe','services.exe','csrss.exe','smss.exe',
  'wininit.exe','explorer.exe','taskhostw.exe','spoolsv.exe','searchindexer.exe',
  'runtimebroker.exe','sihost.exe','fontdrvhost.exe','dwm.exe','conhost.exe',
  'dllhost.exe','msdtc.exe','wmiprvse.exe','audiodg.exe','searchhost.exe',
  'startmenuexperiencehost.exe','shellexperiencehost.exe','ctfmon.exe',
  'msmpeng.exe','nissrv.exe','securityhealthsystray.exe','sgrmbroker.exe',
  'registry','idle','system','memory compression','backgroundtaskhost.exe',
  'textinputhost.exe','lockapp.exe','lsaiso.exe','sppsvc.exe','msiexec.exe',
  'ntoskrnl.exe','lsm.exe','taskeng.exe','taskschd.exe','schtasks.exe',
  'sc.exe','net.exe','net1.exe','cmd.exe','wscript.exe','cscript.exe',
  // Shells & terminals — belong in Windows group
  'powershell.exe','powershell_ise.exe','pwsh.exe',
  'windowsterminal.exe','wt.exe','bash.exe','wsl.exe',
])
// Corporate: productivity, browsers, dev tools, comms, remote access
const CORPORATE = new Set([
  // Browsers
  'chrome.exe','firefox.exe','msedge.exe','iexplore.exe','opera.exe','brave.exe',
  // Comms & collab
  'outlook.exe','teams.exe','slack.exe','zoom.exe','webex.exe','skype.exe',
  'msteams.exe','discord.exe','thunderbird.exe',
  // Dev tools
  'code.exe','devenv.exe','rider64.exe','git.exe','node.exe','python.exe',
  'python3.exe','java.exe','javaw.exe','dotnet.exe','notepad++.exe',
  // Office
  'winword.exe','excel.exe','powerpnt.exe','onenote.exe','msaccess.exe',
  'visio.exe','publisher.exe','acrobat.exe','acrord32.exe',
  // Cloud & file sync
  'onedrive.exe','dropbox.exe','googledrivesync.exe',
  // Remote & VPN
  'anydesk.exe','mstsc.exe','putty.exe','winscp.exe','filezilla.exe',
  'fortisslvpndaemon.exe','globalprotect.exe','vpnui.exe','openvpn.exe',
  // VM & security tools
  'vmware.exe','virtualboxvm.exe','wireshark.exe','burpsuite.exe',
  'procexp.exe','procmon.exe','autoruns.exe','tcpview.exe',
  // Notepad & basic
  'notepad.exe','wordpad.exe','mspaint.exe','calc.exe','snippingtool.exe',
])
const BROWSERS = new Set([
  'chrome.exe','msedge.exe','firefox.exe','iexplore.exe','opera.exe','brave.exe',
  // bare names (no .exe)
  'chrome','msedge','firefox','iexplore','opera','brave',
])

function classify(name) {
  if (!name) return 'other'
  const l = name.toLowerCase()
  // Match with and without .exe suffix
  const withExe = l.endsWith('.exe') ? l : l + '.exe'
  const bare    = l.endsWith('.exe') ? l.slice(0, -4) : l
  if (WINDOWS_LEGIT.has(withExe) || WINDOWS_LEGIT.has(bare)) return 'windows'
  if (CORPORATE.has(withExe) || CORPORATE.has(bare)) return 'corporate'
  return 'other'
}

const SEV = {
  5:{bg:'bg-red-900/40',    border:'border-red-500',    text:'text-red-400',    dot:'#ef4444',label:'Critical'},
  4:{bg:'bg-orange-900/30', border:'border-orange-500', text:'text-orange-400', dot:'#f97316',label:'High'},
  3:{bg:'bg-yellow-900/20', border:'border-yellow-600', text:'text-yellow-400', dot:'#eab308',label:'Medium'},
  2:{bg:'bg-blue-900/20',   border:'border-blue-700',   text:'text-blue-400',   dot:'#3b82f6',label:'Low'},
  1:{bg:'bg-siem-bg',       border:'border-siem-border',text:'text-siem-muted', dot:'#475569',label:'Info'},
}
const GROUP = {
  windows:  {color:'text-blue-400',    border:'border-blue-800',    bg:'bg-blue-950/30',    icon:Shield,       label:'Windows System'},
  corporate:{color:'text-emerald-400', border:'border-emerald-800', bg:'bg-emerald-950/30', icon:Layers,       label:'Corporate Apps'},
  other:    {color:'text-orange-400',  border:'border-orange-800',  bg:'bg-orange-950/20',  icon:AlertTriangle,label:'Other / Unknown'},
}
const TYPE_COLOR = {
  process:'text-siem-muted', network:'text-blue-400', dns:'text-cyan-400',
  file:'text-yellow-400', registry:'text-purple-400', logon:'text-emerald-400',
}

function isWebDomain(d) {
  return d && !d.endsWith('.local') && !d.match(/^\d+\.\d+\.\d+\.\d+$/) && d.includes('.')
}

function ActivityBar({ events, height=20 }) {
  if (!events?.length) return <div style={{height}} className="bg-siem-border/20 rounded-sm" />
  const B=24, now=Date.now(), win=24*3600*1000
  const counts = Array(B).fill(0)
  events.forEach(e => {
    const b = Math.floor(((now - new Date(e.time).getTime()) / win) * B)
    if (b>=0 && b<B) counts[B-1-b]++
  })
  const max = Math.max(...counts, 1)
  return (
    <div className="flex items-end gap-px" style={{height}}>
      {counts.map((c,i) => (
        <div key={i} className="flex-1 rounded-sm transition-all"
          style={{height:`${Math.max(2,(c/max)*height)}px`,
                  background:c>0?'rgba(0,212,255,0.5)':'rgba(255,255,255,0.05)'}} />
      ))}
    </div>
  )
}

function ProcessNode({proc, depth=0, allEvents, onSelect, selected}) {
  const [open, setOpen] = useState(depth<1)
  const hasKids = proc.children?.length > 0
  const sev = SEV[proc.maxSeverity]||SEV[1]
  const isSel = selected?._key === proc._key
  const rel = useMemo(()=>{const n=proc.name?.toLowerCase();const ps=new Set(proc.allPids||[]);return allEvents.filter(e=>(e.process_name&&e.process_name.toLowerCase()===n)||(e.pid&&ps.has(e.pid)))},[allEvents,proc])
  const netN  = rel.filter(e=>e.event_type==='network'||e.event_type==='dns').length
  const fileN = rel.filter(e=>e.event_type==='file').length
  const regN  = rel.filter(e=>e.event_type==='registry').length
  const isBrowser = BROWSERS.has(proc.name?.toLowerCase())
  // DNS events have no process_name — match by pid if available, else show all for browsers
  const allDns = allEvents.filter(e=>e.event_type==='dns'&&e.dst_ip&&isWebDomain(e.dst_ip))
  const nodePids = new Set(proc.allPids||[])
  const procDns = nodePids.size>0 ? allDns.filter(e=>nodePids.has(e.pid)) : isBrowser ? allDns : []
  const webDoms = [...new Set(procDns.map(e=>e.dst_ip))].slice(0,3)

  return (
    <div style={{marginLeft:depth>0?18:0}} className="relative">
      {depth>0&&<div className="absolute left-[-10px] top-0 bottom-0 w-px bg-siem-border/25"/>}
      {depth>0&&<div className="absolute left-[-10px] top-[16px] w-2.5 h-px bg-siem-border/25"/>}
      <div
        className={`flex items-start gap-1.5 mb-px px-2 py-1.5 rounded-lg border cursor-pointer transition-all duration-100 ${
          isSel ? `${sev.bg} ${sev.border} shadow-sm` : 'border-transparent hover:bg-white/[0.02] hover:border-siem-border/25'
        }`}
        onClick={()=>{onSelect(proc);if(hasKids)setOpen(o=>!o)}}
      >
        <div className="mt-1 shrink-0 w-3">
          {hasKids
            ? open ? <ChevronDown size={9} className="text-siem-muted"/>
                   : <ChevronRight size={9} className="text-siem-muted"/>
            : <div className="w-1.5 h-1.5 rounded-full mt-0.5" style={{background:sev.dot}}/>
          }
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-1.5 flex-wrap">
            <span className={`text-xs font-mono font-semibold ${isSel?sev.text:'text-siem-text'}`}>{proc.name}</span>
            {proc.pid>0&&<span className="text-[9px] text-siem-muted/50 font-mono">:{proc.pid}</span>}
            {proc.user&&!proc.user.includes('$')&&<span className="text-[9px] text-siem-muted/40">{proc.user.split('\\').pop()}</span>}
            {proc.maxSeverity>=4&&<span className={`text-[8px] px-1 py-px rounded border ${sev.border} ${sev.text} font-bold`}>{sev.label}</span>}
          </div>
          {proc.allCommands?.length>0&&(
            <div className="text-[9px] text-siem-muted/60 font-mono mt-0.5 truncate"
              title={proc.allCommands.join('\n')}>
              {proc.allCommands[0]}
              {proc.allCommands.length>1&&<span className="text-siem-muted/30 ml-1">+{proc.allCommands.length-1} cmds</span>}
            </div>
          )}
          {(netN>0||fileN>0||regN>0||webDoms.length>0)&&(
            <div className="flex gap-2 mt-0.5">
              {netN>0&&<span className="flex items-center gap-0.5 text-[8px] text-blue-400/60"><Wifi size={7}/>{netN}</span>}
              {fileN>0&&<span className="flex items-center gap-0.5 text-[8px] text-yellow-400/60"><FileText size={7}/>{fileN}</span>}
              {regN>0&&<span className="flex items-center gap-0.5 text-[8px] text-purple-400/60"><Key size={7}/>{regN}</span>}
              {webDoms.length>0&&<span className="flex items-center gap-0.5 text-[8px] text-cyan-400/60"><Globe size={7}/>{webDoms.join(', ')}</span>}
            </div>
          )}
        </div>
        <span className="text-[9px] text-siem-muted/30 shrink-0 mt-0.5">{proc.events}</span>
      </div>
      {hasKids&&open&&(
        <div>{proc.children.map((c,i)=><ProcessNode key={i} proc={c} depth={depth+1} allEvents={allEvents} onSelect={onSelect} selected={selected}/>)}</div>
      )}
    </div>
  )
}

function ProcessDetail({proc, allEvents, onClose}) {
  const [tab, setTab] = useState('overview')
  if (!proc) return null
  // Match events by process name (case-insensitive) OR any known pid for this process
  const procNameLower = proc.name?.toLowerCase()
  const pidSet = new Set(proc.allPids||[])
  const rel = allEvents.filter(e=>
    (e.process_name&&e.process_name.toLowerCase()===procNameLower) ||
    (e.pid&&pidSet.has(e.pid))
  )
  const net  = rel.filter(e=>e.event_type==='network')
  const file = rel.filter(e=>e.event_type==='file')
  const reg  = rel.filter(e=>e.event_type==='registry')
  const sev  = SEV[proc.maxSeverity]||SEV[1]
  const isBrowser = BROWSERS.has(proc.name?.toLowerCase())
  const allDnsEvents = allEvents.filter(e=>e.event_type==='dns'&&e.dst_ip)
  const pidSet2 = new Set(proc.allPids||[])
  const dns = pidSet2.size>0 ? allDnsEvents.filter(e=>pidSet2.has(e.pid)) : isBrowser ? allDnsEvents : []
  const webVisits = [...new Set(dns.filter(e=>isWebDomain(e.dst_ip)).map(e=>e.dst_ip))]
  const extIPs = [...new Map(net.filter(e=>e.dst_ip&&!e.dst_ip.startsWith('192.168')&&!e.dst_ip.startsWith('10.')).map(e=>[`${e.dst_ip}:${e.dst_port}`,e])).values()]
  const files = [...new Set(file.map(e=>e.file_path).filter(Boolean))]
  const regKeys = reg.slice(0,50)

  const cmdEvents = rel.filter(e=>e.command_line&&e.command_line.trim())
  const uniqueCmds = [...new Map(cmdEvents.map(e=>[e.command_line.trim(),e])).values()]
  const isShell = ['powershell.exe','pwsh.exe','cmd.exe','bash.exe','wsl.exe','powershell','cmd','bash'].includes(proc.name?.toLowerCase())

  const TABS = [
    {id:'overview', label:'Overview'},
    ...(uniqueCmds.length>0||isShell?[{id:'commands',label:'Commands',n:uniqueCmds.length}]:[]),
    {id:'network',  label:'Network',  n:net.length+dns.length},
    {id:'files',    label:'Files',    n:file.length},
    {id:'registry', label:'Registry', n:reg.length},
    {id:'timeline', label:'Timeline', n:rel.length},
    ...(isBrowser?[{id:'web',label:'Web Activity',n:webVisits.length}]:[]),
  ]

  return (
    <div className="w-[420px] shrink-0 bg-siem-surface border-l border-siem-border flex flex-col overflow-hidden">
      <div className={`px-3 pt-3 pb-2 border-b border-siem-border ${sev.bg}`}>
        <div className="flex items-start gap-2">
          <Terminal size={13} className={`mt-1 shrink-0 ${sev.text}`}/>
          <div className="flex-1 min-w-0">
            <div className={`text-sm font-mono font-bold ${sev.text}`}>{proc.name}</div>
            <div className="flex gap-3 mt-0.5 text-[9px] text-siem-muted">
              {proc.pid>0&&<span>PID {proc.pid}</span>}
              {proc.ppid>0&&<span>PPID {proc.ppid}</span>}
              {proc.user&&<span><User size={7} className="inline mr-0.5"/>{proc.user.split('\\').pop()}</span>}
              <span className={sev.text}>{sev.label}</span>
            </div>
          </div>
          <button onClick={onClose} className="text-siem-muted hover:text-siem-text mt-0.5"><X size={12}/></button>
        </div>
        <div className="grid grid-cols-4 gap-1 mt-2">
          {[['Net',net.length+dns.length,'text-blue-400'],['Files',file.length,'text-yellow-400'],['Reg',reg.length,'text-purple-400'],['Total',rel.length,'text-siem-text']].map(([l,v,c])=>(
            <div key={l} className="bg-black/20 rounded p-1.5 text-center">
              <div className={`text-sm font-bold font-mono ${c}`}>{v}</div>
              <div className="text-[8px] text-siem-muted uppercase">{l}</div>
            </div>
          ))}
        </div>
      </div>

      <div className="flex border-b border-siem-border shrink-0 overflow-x-auto">
        {TABS.map(t=>(
          <button key={t.id} onClick={()=>setTab(t.id)}
            className={`px-3 py-1.5 text-[9px] font-medium whitespace-nowrap border-b-2 transition-colors ${
              tab===t.id?'border-siem-accent text-siem-accent':'border-transparent text-siem-muted hover:text-siem-text'
            }`}>
            {t.label}{t.n>0&&<span className="ml-0.5 opacity-50">({t.n})</span>}
          </button>
        ))}
      </div>

      <div className="flex-1 overflow-y-auto">
        {tab==='overview'&&(
          <div className="p-3 space-y-3">
            {proc.allCommands?.length>0&&(
              <div>
                <div className="text-[8px] uppercase tracking-wider text-siem-muted font-semibold mb-1 flex items-center gap-1">
                  <Hash size={7}/>Commands Run ({proc.allCommands.length})
                </div>
                <div className="space-y-1 max-h-48 overflow-y-auto">
                  {proc.allCommands.map((cmd,i)=>(
                    <div key={i} className="bg-siem-bg border border-siem-border/50 rounded px-2 py-1.5 text-[9px] font-mono text-emerald-300 break-all leading-relaxed">
                      {cmd}
                    </div>
                  ))}
                </div>
              </div>
            )}
            <div>
              <div className="text-[8px] uppercase tracking-wider text-siem-muted font-semibold mb-1">Activity (24h)</div>
              <ActivityBar events={rel} height={28}/>
            </div>
            <div className="space-y-1.5">
              {webVisits.length>0&&<div className="flex items-start gap-2 text-[10px]"><Globe size={9} className="text-cyan-400 mt-0.5 shrink-0"/><div><span className="text-siem-muted">Web: </span><span className="text-cyan-300">{webVisits.slice(0,5).join(', ')}{webVisits.length>5&&` +${webVisits.length-5} more`}</span></div></div>}
              {extIPs.length>0&&<div className="flex items-start gap-2 text-[10px]"><ArrowUpRight size={9} className="text-blue-400 mt-0.5 shrink-0"/><div><span className="text-siem-muted">Connections: </span><span className="text-blue-300">{extIPs.slice(0,3).map(e=>`${e.dst_ip}:${e.dst_port}`).join(', ')}{extIPs.length>3&&` +${extIPs.length-3} more`}</span></div></div>}
              {files.length>0&&<div className="flex items-start gap-2 text-[10px]"><FileText size={9} className="text-yellow-400 mt-0.5 shrink-0"/><div><span className="text-siem-muted">Files: </span><span className="text-yellow-300 font-mono text-[9px]">{files[0]}{files.length>1&&` +${files.length-1} more`}</span></div></div>}
              {regKeys.length>0&&<div className="flex items-start gap-2 text-[10px]"><Key size={9} className="text-purple-400 mt-0.5 shrink-0"/><div><span className="text-siem-muted">Registry: </span><span className="text-purple-300 font-mono text-[9px]">{regKeys[0].reg_key}{regKeys.length>1&&` +${regKeys.length-1} more`}</span></div></div>}
            </div>
            {proc.children?.length>0&&(
              <div>
                <div className="text-[8px] uppercase tracking-wider text-siem-muted font-semibold mb-1">Spawned Processes ({proc.children.length})</div>
                <div className="space-y-0.5">
                  {proc.children.map((c,i)=>(
                    <div key={i} className="flex items-center gap-2 text-[9px] bg-siem-bg/60 rounded px-2 py-1">
                      <div className="w-1 h-1 rounded-full shrink-0" style={{background:(SEV[c.maxSeverity]||SEV[1]).dot}}/>
                      <span className="font-mono text-siem-text">{c.name}</span>
                      {c.commandLine&&<span className="text-siem-muted/50 truncate font-mono flex-1 text-[8px]">{c.commandLine}</span>}
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {tab==='commands'&&(
          <div className="p-3">
            <div className="text-[8px] uppercase tracking-wider text-emerald-400/70 font-semibold mb-2">
              Commands / Scripts ({uniqueCmds.length})
            </div>
            {uniqueCmds.length===0
              ? <div className="text-center text-siem-muted text-xs py-8">No commands recorded</div>
              : <div className="space-y-1.5">
                  {uniqueCmds.map((e,i)=>(
                    <div key={i} className="bg-siem-bg border border-siem-border/50 rounded p-2">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="text-[8px] font-mono text-siem-muted/40">{new Date(e.time).toLocaleTimeString()}</span>
                        {e.user_name&&<span className="text-[8px] text-siem-muted/50">{e.user_name.split('\\').pop()}</span>}
                        <div className="ml-auto w-1.5 h-1.5 rounded-full shrink-0" style={{background:(SEV[e.severity]||SEV[1]).dot}}/>
                      </div>
                      <div className="text-[9px] font-mono text-emerald-300 break-all leading-relaxed whitespace-pre-wrap max-h-32 overflow-y-auto">
                        {e.command_line.trim()}
                      </div>
                    </div>
                  ))}
                </div>
            }
          </div>
        )}

        {tab==='web'&&(
          <div className="p-3">
            <div className="text-[8px] uppercase tracking-wider text-cyan-400/70 font-semibold mb-2">Websites Visited ({webVisits.length})</div>
            {webVisits.length===0
              ? <div className="text-center text-siem-muted text-xs py-8">No web activity</div>
              : <div className="space-y-0.5">
                  {webVisits.map((d,i)=>{
                    const n=dns.filter(e=>e.dst_ip===d).length
                    return (
                      <div key={i} className="flex items-center gap-2 bg-siem-bg/60 rounded px-2 py-1.5">
                        <Globe size={10} className="text-cyan-400 shrink-0"/>
                        <span className="font-mono text-[10px] text-cyan-300 flex-1 truncate">{d}</span>
                        <span className="text-[9px] text-siem-muted">{n}x</span>
                      </div>
                    )
                  })}
                </div>
            }
          </div>
        )}

        {tab==='network'&&(
          <div className="p-3 space-y-3">
            {dns.length>0&&(
              <div>
                <div className="text-[8px] uppercase tracking-wider text-cyan-400/70 font-semibold mb-1.5">DNS Queries ({dns.length})</div>
                <div className="space-y-0.5">
                  {[...new Set(dns.map(e=>e.dst_ip).filter(Boolean))].map((d,i)=>(
                    <div key={i} className="flex items-center gap-2 bg-siem-bg/60 rounded px-2 py-1 text-[9px]">
                      <div className={`w-1 h-1 rounded-full ${isWebDomain(d)?'bg-cyan-400':'bg-siem-muted'}`}/>
                      <span className="font-mono text-cyan-300 flex-1 truncate">{d}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {net.length>0&&(
              <div>
                <div className="text-[8px] uppercase tracking-wider text-blue-400/70 font-semibold mb-1.5">Connections ({net.length})</div>
                <div className="space-y-0.5">
                  {[...new Map(net.map(e=>[`${e.dst_ip}:${e.dst_port}`,e])).values()].map((e,i)=>(
                    <div key={i} className="bg-siem-bg/60 rounded px-2 py-1 text-[9px]">
                      <div className="flex items-center gap-2">
                        <ArrowUpRight size={8} className="text-blue-400 shrink-0"/>
                        <span className="font-mono text-blue-300">{e.dst_ip}</span>
                        <span className="text-siem-muted">:{e.dst_port}</span>
                        {e.proto&&<span className="text-[8px] text-siem-muted/40 ml-auto">{e.proto.toUpperCase()}</span>}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}
            {dns.length===0&&net.length===0&&<div className="text-center text-siem-muted text-xs py-8">No network activity</div>}
          </div>
        )}

        {tab==='files'&&(
          <div className="p-3">
            <div className="text-[8px] uppercase tracking-wider text-yellow-400/70 font-semibold mb-1.5">Files ({file.length})</div>
            {files.length===0
              ? <div className="text-center text-siem-muted text-xs py-8">No file activity</div>
              : <div className="space-y-0.5">{files.map((f,i)=><div key={i} className="bg-siem-bg/60 rounded px-2 py-1.5 text-[9px] font-mono text-yellow-300/80 break-all">{f}</div>)}</div>
            }
          </div>
        )}

        {tab==='registry'&&(
          <div className="p-3">
            <div className="text-[8px] uppercase tracking-wider text-purple-400/70 font-semibold mb-1.5">Registry ({reg.length})</div>
            {regKeys.length===0
              ? <div className="text-center text-siem-muted text-xs py-8">No registry activity</div>
              : <div className="space-y-0.5">{regKeys.map((e,i)=>(
                  <div key={i} className="bg-siem-bg/60 rounded px-2 py-1.5">
                    <div className="text-[9px] font-mono text-purple-300/80 break-all">{e.reg_key}</div>
                    {e.reg_data&&<div className="text-[8px] text-siem-muted/50 mt-0.5 truncate">{e.reg_data}</div>}
                  </div>
                ))}</div>
            }
          </div>
        )}

        {tab==='timeline'&&(
          <div className="p-3">
            <div className="text-[8px] uppercase tracking-wider text-siem-muted font-semibold mb-1.5">Timeline ({rel.length})</div>
            <div className="space-y-px">
              {rel.slice(0,100).map((e,i)=>(
                <div key={i} className="flex gap-2 items-start py-1 border-b border-siem-border/10">
                  <span className="text-[8px] font-mono text-siem-muted/50 shrink-0 w-12">{format(new Date(e.time),'HH:mm:ss')}</span>
                  <span className={`text-[8px] shrink-0 w-14 ${TYPE_COLOR[e.event_type]||'text-siem-muted'}`}>{e.event_type}</span>
                  <span className="text-[8px] font-mono text-siem-muted/60 truncate flex-1">{e.command_line||e.dst_ip||e.file_path||e.reg_key||'—'}</span>
                  <div className="w-1 h-1 rounded-full mt-1 shrink-0" style={{background:(SEV[e.severity]||SEV[1]).dot}}/>
                </div>
              ))}
              {rel.length>100&&<div className="text-[9px] text-siem-muted text-center py-2">+{rel.length-100} more</div>}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

function AppGroupCard({group, type, allEvents, onClick, selected}) {
  const style = GROUP[type], Icon = style.icon
  const maxSev = Math.max(...group.map(p=>p.maxSeverity||1))
  const sev = SEV[maxSev]||SEV[1]
  const isSel = selected===type
  const groupEvents = allEvents.filter(e=>group.some(p=>p.name===e.process_name))
  const netN = groupEvents.filter(e=>e.event_type==='network'||e.event_type==='dns').length

  return (
    <div onClick={()=>onClick(isSel?null:type)}
      className={`cursor-pointer rounded-xl border p-3 transition-all duration-200 ${
        isSel ? `${style.bg} ${style.border} ring-1 ring-current shadow-lg`
              : 'bg-siem-surface border-siem-border hover:border-siem-border/80 hover:bg-white/[0.02]'
      }`}>
      <div className="flex items-center gap-2.5 mb-2.5">
        <div className={`w-7 h-7 rounded-lg flex items-center justify-center ${style.bg} border ${style.border}`}>
          <Icon size={13} className={style.color}/>
        </div>
        <div>
          <div className={`text-xs font-bold ${style.color}`}>{style.label}</div>
          <div className="text-[9px] text-siem-muted">{group.length} processes</div>
        </div>
        {maxSev>=4&&<div className={`ml-auto text-[8px] font-bold px-1.5 py-0.5 rounded border ${sev.border} ${sev.text}`}>{sev.label}</div>}
      </div>
      <ActivityBar events={groupEvents} height={14}/>
      <div className="space-y-0.5 mt-2">
        {group.slice(0,4).map((p,i)=>(
          <div key={i} className="flex items-center gap-1.5 text-[9px]">
            <div className="w-1 h-1 rounded-full shrink-0" style={{background:(SEV[p.maxSeverity]||SEV[1]).dot}}/>
            <span className="font-mono text-siem-muted truncate flex-1">{p.name}</span>
            <span className="text-siem-muted/30">{p.events}</span>
          </div>
        ))}
        {group.length>4&&<div className="text-[9px] text-siem-muted/30 pl-2.5">+{group.length-4} more</div>}
      </div>
      {netN>0&&<div className="mt-1.5 text-[8px] text-blue-400/50 flex items-center gap-1"><Wifi size={7}/>{netN} net events</div>}
    </div>
  )
}

function HostCard({agent, onClick, selected}) {
  const isSel = selected?.id===agent.id
  return (
    <div onClick={()=>onClick(agent)}
      className={`cursor-pointer rounded-lg border p-2.5 transition-all ${
        isSel?'bg-siem-accent/10 border-siem-accent':'bg-siem-surface border-siem-border hover:border-siem-accent/30 hover:bg-white/[0.01]'
      }`}>
      <div className="flex items-center gap-2">
        <div className={`w-6 h-6 rounded-md flex items-center justify-center border shrink-0 ${
          isSel?'bg-siem-accent/20 border-siem-accent':'bg-siem-bg border-siem-border'
        }`}>
          <Monitor size={11} className={isSel?'text-siem-accent':'text-siem-muted'}/>
        </div>
        <div className="flex-1 min-w-0">
          <div className="text-xs font-bold text-siem-text truncate">{agent.hostname}</div>
          <div className="text-[9px] text-siem-muted">{agent.last_ip||'—'}</div>
        </div>
        <div className={`w-1.5 h-1.5 rounded-full ${agent.online?'bg-emerald-400':'bg-red-500'}`}/>
      </div>
      <div className="flex gap-1.5 mt-1.5">
        <div className="bg-siem-bg/60 rounded px-1.5 py-0.5 text-[9px] text-siem-muted flex-1 text-center">{(agent.event_count||0).toLocaleString()} evt</div>
        <div className="bg-siem-bg/60 rounded px-1.5 py-0.5 text-[9px] text-siem-muted">{agent.os||'win'}</div>
      </div>
    </div>
  )
}

function buildTree(events) {
  const map = {}
  // Group by process name only — pid changes per execution, we want one node per process.
  events.filter(e=>e.process_name).forEach(e=>{
    const key = e.process_name.toLowerCase()
    if (!map[key]) map[key]={
      name:e.process_name, pid:e.pid||0, ppid:e.ppid||0,
      commandLine:e.command_line||'', user:e.user_name||'',
      maxSeverity:e.severity||1, events:0, children:[], _key:key,
      commands: new Set(), // unique commands run
    }
    const p=map[key]; p.events++
    if((e.severity||1)>p.maxSeverity) p.maxSeverity=e.severity
    if(e.command_line && e.command_line.trim()) p.commands.add(e.command_line.trim())
    if(!p.user&&e.user_name) p.user=e.user_name
    if(!p.pid&&e.pid) p.pid=e.pid
    if(!p.ppid&&e.ppid) p.ppid=e.ppid
  })
  // Convert commands Set to sorted array, pick first as display commandLine
  Object.values(map).forEach(p=>{
    p.allCommands = [...p.commands].sort()
    p.commandLine = p.allCommands[0]||''
    delete p.commands
  })
  // Track all PIDs seen per process name (processes spawn multiple instances)
  events.filter(e=>e.process_name&&e.pid).forEach(e=>{
    const key = e.process_name.toLowerCase()
    if (map[key]) {
      if (!map[key].allPids) map[key].allPids = new Set()
      map[key].allPids.add(e.pid)
    }
  })
  Object.values(map).forEach(p=>{
    p.allPids = p.allPids ? [...p.allPids] : (p.pid ? [p.pid] : [])
  })
  const roots=[], byPid={}
  Object.values(map).forEach(p=>{if(p.pid)byPid[p.pid]=p})
  Object.values(map).forEach(p=>{const par=byPid[p.ppid];if(par&&par._key!==p._key)par.children.push(p);else roots.push(p)})
  const sort=arr=>{arr.sort((a,b)=>b.maxSeverity-a.maxSeverity||a.name.localeCompare(b.name));arr.forEach(p=>sort(p.children))}
  sort(roots); return roots
}

function groupByType(roots) {
  const g={windows:[],corporate:[],other:[]}, seen=new Set()
  const flat=nodes=>nodes.forEach(n=>{if(!seen.has(n._key)){seen.add(n._key);g[classify(n.name)].push(n)}flat(n.children)})
  flat(roots); return g
}

function filterTree(nodes, q) {
  if(!q) return nodes
  return nodes.reduce((acc,n)=>{
    const match=n.name.toLowerCase().includes(q)||n.commandLine?.toLowerCase().includes(q)
    const kids=filterTree(n.children,q)
    if(match||kids.length) acc.push({...n,children:kids})
    return acc
  },[])
}

export default function ThreatGraph() {
  const [agents,setAgents]=useState([])
  const [hostSearch,setHostSearch]=useState('')
  const [selectedHost,setSelectedHost]=useState(null)
  const [hostData,setHostData]=useState(null)
  const [loading,setLoading]=useState(false)
  const [selectedGroup,setSelectedGroup]=useState(null)
  const [selectedProc,setSelectedProc]=useState(null)
  const [timeRange,setTimeRange]=useState(24)
  const [procSearch,setProcSearch]=useState('')

  useEffect(()=>{api.get('/api/v1/agents').then(r=>setAgents(r.data.agents||[]))},[])

  const loadHost=useCallback(async(agent)=>{
    setSelectedHost(agent); setSelectedGroup(null); setSelectedProc(null); setHostData(null); setLoading(true)
    try{const r=await api.get(`/api/v1/threat-graph/${encodeURIComponent(agent.hostname)}`,{params:{since_hours:timeRange}});setHostData(r.data)}
    catch(e){console.error(e)} finally{setLoading(false)}
  },[timeRange])

  const filteredAgents=useMemo(()=>agents.filter(a=>!hostSearch||a.hostname?.toLowerCase().includes(hostSearch.toLowerCase())||a.last_ip?.includes(hostSearch)),[agents,hostSearch])
  const processTree=useMemo(()=>hostData?buildTree(hostData.processes||[]):[]  ,[hostData])
  const groups=useMemo(()=>groupByType(processTree),[processTree])
  const allEvents=hostData?.all_events||[]
  const stats=useMemo(()=>({
    net:allEvents.filter(e=>e.event_type==='network').length,
    dns:allEvents.filter(e=>e.event_type==='dns').length,
    file:allEvents.filter(e=>e.event_type==='file').length,
    crit:allEvents.filter(e=>e.severity>=4).length,
  }),[allEvents])

  const displayRoots=useMemo(()=>{
    const base=selectedGroup?groups[selectedGroup]||[]:processTree
    return procSearch?filterTree(base,procSearch.toLowerCase()):base
  },[processTree,groups,selectedGroup,procSearch])

  return (
    <div className="flex h-screen overflow-hidden bg-siem-bg">

      {/* Sidebar */}
      <div className="w-60 shrink-0 bg-siem-surface border-r border-siem-border flex flex-col">
        <div className="px-3 py-3 border-b border-siem-border">
          <div className="flex items-center gap-2 mb-2">
            <GitBranch size={12} className="text-siem-accent"/>
            <span className="text-xs font-bold text-siem-text">Threat Graph</span>
            <span className="ml-auto text-[9px] text-siem-muted">{agents.length} hosts</span>
          </div>
          <div className="relative">
            <Search size={9} className="absolute left-2 top-1/2 -translate-y-1/2 text-siem-muted"/>
            <input value={hostSearch} onChange={e=>setHostSearch(e.target.value)}
              placeholder="Search hosts or IPs..."
              className="w-full bg-siem-bg border border-siem-border rounded-lg pl-5 pr-7 py-1.5 text-[9px] text-siem-text placeholder-siem-muted/40 outline-none focus:border-siem-accent/50 transition-colors"/>
            {hostSearch&&<button onClick={()=>setHostSearch('')} className="absolute right-2 top-1/2 -translate-y-1/2"><X size={8} className="text-siem-muted"/></button>}
          </div>
        </div>
        <div className="px-3 py-1.5 border-b border-siem-border flex items-center gap-1">
          <Clock size={8} className="text-siem-muted shrink-0"/>
          <span className="text-[8px] text-siem-muted mr-1">Last</span>
          {[6,24,48,168].map(h=>(
            <button key={h} onClick={()=>{setTimeRange(h);if(selectedHost)loadHost({...selectedHost})}}
              className={`text-[8px] px-1.5 py-0.5 rounded ${timeRange===h?'bg-siem-accent text-white':'text-siem-muted hover:text-siem-text'}`}>
              {h<24?`${h}h`:h===168?'7d':`${h/24}d`}
            </button>
          ))}
        </div>
        <div className="flex-1 overflow-y-auto p-2 space-y-1.5">
          {filteredAgents.length===0
            ? <div className="text-center text-[9px] text-siem-muted py-8">{hostSearch?'No hosts match':'No agents found'}</div>
            : filteredAgents.map(a=><HostCard key={a.id} agent={a} onClick={loadHost} selected={selectedHost}/>)
          }
        </div>
      </div>

      {/* Main */}
      <div className="flex-1 flex flex-col min-w-0 overflow-hidden">
        {!selectedHost?(
          <div className="flex-1 flex flex-col items-center justify-center text-siem-muted select-none">
            <GitBranch size={44} className="opacity-10 mb-4"/>
            <div className="text-sm font-semibold text-siem-text/30 mb-1">Select a host</div>
            <div className="text-xs opacity-50">Choose an endpoint to explore its process tree</div>
          </div>
        ):loading?(
          <div className="flex-1 flex items-center justify-center gap-3">
            <div className="w-4 h-4 border-2 border-siem-accent/30 border-t-siem-accent rounded-full animate-spin"/>
            <span className="text-sm text-siem-muted">Loading <span className="text-siem-accent">{selectedHost.hostname}</span>…</span>
          </div>
        ):(
          <>
            {/* Top bar */}
            <div className="px-4 py-2 border-b border-siem-border bg-siem-surface flex items-center gap-3 shrink-0">
              <Monitor size={13} className="text-siem-accent"/>
              <span className="text-sm font-bold text-siem-text">{selectedHost.hostname}</span>
              <span className="text-[10px] text-siem-muted">{(hostData?.processes||[]).length} proc · {allEvents.length} events</span>
              <div className="flex gap-1.5 ml-1">
                {stats.crit>0&&<span className="text-[8px] px-1.5 py-0.5 rounded-full bg-red-900/40 text-red-400 border border-red-800">{stats.crit} high sev</span>}
                {(stats.net+stats.dns)>0&&<span className="text-[8px] px-1.5 py-0.5 rounded-full bg-blue-900/20 text-blue-400/70 border border-blue-900/40"><Wifi size={6} className="inline mr-0.5"/>{stats.net+stats.dns} net</span>}
                {stats.file>0&&<span className="text-[8px] px-1.5 py-0.5 rounded-full bg-yellow-900/20 text-yellow-400/70 border border-yellow-900/40"><FileText size={6} className="inline mr-0.5"/>{stats.file} files</span>}
              </div>
              <div className="ml-auto flex items-center gap-2">
                <div className="relative">
                  <Search size={8} className="absolute left-2 top-1/2 -translate-y-1/2 text-siem-muted"/>
                  <input value={procSearch} onChange={e=>setProcSearch(e.target.value)}
                    placeholder="Filter processes..."
                    className="bg-siem-bg border border-siem-border rounded pl-5 pr-2 py-1 text-[9px] text-siem-text placeholder-siem-muted/40 outline-none focus:border-siem-accent/40 w-36"/>
                  {procSearch&&<button onClick={()=>setProcSearch('')} className="absolute right-1.5 top-1/2 -translate-y-1/2"><X size={7} className="text-siem-muted"/></button>}
                </div>
                <button onClick={()=>loadHost(selectedHost)} className="p-1.5 rounded border border-siem-border text-siem-muted hover:text-siem-text transition-colors">
                  <RefreshCw size={10}/>
                </button>
                {selectedGroup&&<button onClick={()=>setSelectedGroup(null)} className="flex items-center gap-1 text-[9px] text-siem-muted border border-siem-border rounded px-1.5 py-1"><X size={8}/> All</button>}
              </div>
            </div>

            {/* Group cards */}
            <div className="grid grid-cols-3 gap-3 p-3 shrink-0 border-b border-siem-border">
              {Object.entries(groups).map(([type,procs])=>procs.length>0&&(
                <AppGroupCard key={type} group={procs} type={type} allEvents={allEvents}
                  onClick={setSelectedGroup} selected={selectedGroup}/>
              ))}
            </div>

            {/* Tree + detail */}
            <div className="flex flex-1 overflow-hidden">
              <div className="flex-1 overflow-y-auto p-3">
                {displayRoots.length===0
                  ? <div className="flex flex-col items-center justify-center h-full text-siem-muted"><Cpu size={24} className="opacity-20 mb-2"/><div className="text-xs">{procSearch?`No processes matching "${procSearch}"`:`No process events in last ${timeRange}h`}</div></div>
                  : <div>
                      {selectedGroup&&(
                        <div className="flex items-center gap-2 mb-2 pb-2 border-b border-siem-border/20">
                          {(()=>{const Icon=GROUP[selectedGroup].icon;return <Icon size={10} className={GROUP[selectedGroup].color}/>})()}
                          <span className={`text-[9px] font-semibold ${GROUP[selectedGroup].color}`}>{GROUP[selectedGroup].label}</span>
                          <span className="text-[9px] text-siem-muted">{groups[selectedGroup]?.length} processes</span>
                        </div>
                      )}
                      {displayRoots.map((p,i)=><ProcessNode key={i} proc={p} depth={0} allEvents={allEvents} onSelect={setSelectedProc} selected={selectedProc}/>)}
                    </div>
                }
              </div>
              {selectedProc&&<ProcessDetail proc={selectedProc} allEvents={allEvents} onClose={()=>setSelectedProc(null)}/>}
            </div>
          </>
        )}
      </div>
    </div>
  )
}
