import { NavLink, useNavigate } from 'react-router-dom'
import { LayoutDashboard, Activity, Monitor, Bell, LogOut, Crosshair, BookOpen,
         Users, ClipboardList, Key, Settings, Search, Zap, GitBranch, Sun, Moon, MapPin, Terminal } from 'lucide-react'
import { useTheme } from '../api/useTheme'

const links = [
  { to: '/',             label: 'Dashboard',    icon: LayoutDashboard },
  { to: '/events',       label: 'Events',       icon: Activity },
  { to: '/search',       label: 'Search',       icon: Search },
  { to: '/detections',   label: 'Detections',   icon: Zap },
  { to: '/threat-graph', label: 'Threat Graph', icon: GitBranch },
  { to: '/agents',       label: 'Agents',       icon: Monitor },
  { to: '/locations',    label: 'Locations',    icon: MapPin },
  { to: '/live-response', label: 'Live Response', icon: Terminal },
  { to: '/alerts',       label: 'Alerts',       icon: Bell },
  { to: '/alert-rules',  label: 'Alert Rules',  icon: BookOpen },
  { to: '/threat-intel', label: 'Threat Intel', icon: Crosshair },
]

const adminLinks = [
  { to: '/users',     label: 'Users',     icon: Users },
  { to: '/audit-log', label: 'Audit Log', icon: ClipboardList },
  { to: '/settings',  label: 'Settings',  icon: Settings },
]

export function Navbar({ user }) {
  const navigate = useNavigate()
  const { theme, toggle } = useTheme()

  const logout = () => {
    localStorage.removeItem('token')
    localStorage.removeItem('user')
    localStorage.removeItem('require_password_change')
    navigate('/login')
  }

  return (
    <aside className="w-56 min-h-screen bg-siem-surface border-r border-siem-border flex flex-col">
      <div className="flex items-center gap-3 px-4 py-4 border-b border-siem-border">
        <svg width="36" height="36" viewBox="0 0 220 220" xmlns="http://www.w3.org/2000/svg" className="shrink-0">
          <defs>
            <radialGradient id="nb-glow" cx="50%" cy="50%" r="50%">
              <stop offset="0%" stopColor="#00d4ff" stopOpacity="0.35"/>
              <stop offset="100%" stopColor="#00d4ff" stopOpacity="0"/>
            </radialGradient>
            <radialGradient id="nb-lens" cx="38%" cy="35%" r="60%">
              <stop offset="0%" stopColor="#1a3a4a"/>
              <stop offset="60%" stopColor="#0a1a22"/>
              <stop offset="100%" stopColor="#040e14"/>
            </radialGradient>
            <radialGradient id="nb-iris" cx="40%" cy="38%" r="55%">
              <stop offset="0%" stopColor="#1e5a6e"/>
              <stop offset="50%" stopColor="#0d3040"/>
              <stop offset="100%" stopColor="#061820"/>
            </radialGradient>
            <radialGradient id="nb-pupil" cx="42%" cy="40%" r="55%">
              <stop offset="0%" stopColor="#00d4ff" stopOpacity="0.9"/>
              <stop offset="40%" stopColor="#0088aa"/>
              <stop offset="100%" stopColor="#003344"/>
            </radialGradient>
          </defs>
          <circle cx="110" cy="110" r="95" fill="url(#nb-glow)"/>
          <polygon points="110,12 193,59 193,161 110,208 27,161 27,59" fill="#06111a" stroke="#1a3a4a" strokeWidth="1.5"/>
          <polygon points="110,22 183,65 183,155 110,198 37,155 37,65" fill="none" stroke="#00d4ff" strokeWidth="0.5" strokeOpacity="0.3"/>
          <circle cx="110" cy="108" r="62" fill="url(#nb-lens)"/>
          <circle cx="110" cy="108" r="62" fill="none" stroke="#00d4ff" strokeWidth="1.2" strokeOpacity="0.6"/>
          <circle cx="110" cy="108" r="42" fill="url(#nb-iris)"/>
          <circle cx="110" cy="108" r="42" fill="none" stroke="#00d4ff" strokeWidth="0.8" strokeOpacity="0.5"/>
          <circle cx="110" cy="108" r="22" fill="url(#nb-pupil)"/>
          <circle cx="110" cy="108" r="22" fill="none" stroke="#00d4ff" strokeWidth="1" strokeOpacity="0.8"/>
          <circle cx="110" cy="108" r="10" fill="#001822"/>
          <ellipse cx="96" cy="92" rx="9" ry="6" fill="white" fillOpacity="0.1" transform="rotate(-30 96 92)"/>
        </svg>
        <div>
          <div className="font-bold text-siem-text text-sm tracking-wide leading-tight">ObsidianWatch</div>
          <div className="text-[10px] text-siem-muted tracking-widest uppercase">v0.3.1</div>
        </div>
      </div>

      <nav className="flex-1 py-4 px-2 space-y-0.5 overflow-y-auto">
        {links.map(({ to, label, icon: Icon }) => (
          <NavLink key={to} to={to} end={to === '/'}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${
                isActive ? 'bg-siem-accent/10 text-siem-accent' : 'text-siem-muted hover:text-siem-text hover:bg-white/5'
              }`
            }
          >
            <Icon size={15} />{label}
          </NavLink>
        ))}

        {user?.role === 'admin' && (
          <>
            <div className="pt-3 pb-1 px-3 text-[10px] uppercase tracking-widest text-siem-muted/50">Admin</div>
            {adminLinks.map(({ to, label, icon: Icon }) => (
              <NavLink key={to} to={to}
                className={({ isActive }) =>
                  `flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${
                    isActive ? 'bg-siem-accent/10 text-siem-accent' : 'text-siem-muted hover:text-siem-text hover:bg-white/5'
                  }`
                }
              >
                <Icon size={15} />{label}
              </NavLink>
            ))}
          </>
        )}
      </nav>

      <div className="px-4 py-4 border-t border-siem-border space-y-3">
        {/* Theme toggle */}
        <button onClick={toggle}
          className="flex items-center gap-2 w-full px-3 py-1.5 rounded-lg border border-siem-border hover:border-siem-accent/40 text-siem-muted hover:text-siem-text transition-all text-xs">
          {theme === 'dark'
            ? <><Sun size={13} className="text-yellow-400" /> Light mode</>
            : <><Moon size={13} className="text-siem-accent" /> Dark mode</>
          }
        </button>

        <div className="text-xs text-siem-muted">{user?.username}</div>
        <div className="text-xs text-siem-muted/60 -mt-2 capitalize">{user?.role}</div>
        <NavLink to="/change-password" className="flex items-center gap-2 text-xs text-siem-muted hover:text-siem-text transition-colors">
          <Key size={13} /> Change password
        </NavLink>
        <button onClick={logout} className="flex items-center gap-2 text-xs text-siem-muted hover:text-siem-red transition-colors">
          <LogOut size={14} /> Sign out
        </button>
      </div>
    </aside>
  )
}
