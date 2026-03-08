import { NavLink, useNavigate } from 'react-router-dom'
import { LayoutDashboard, Activity, Monitor, Bell, LogOut, Crosshair, BookOpen, Users, ClipboardList, Settings, Search, Zap } from 'lucide-react'
import logo from '../assets/logo.svg'

const links = [
  { to: '/',             label: 'Dashboard',    icon: LayoutDashboard },
  { to: '/events',       label: 'Events',       icon: Activity },
  { to: '/search',        label: 'Search',       icon: Search },
  { to: '/detections',    label: 'Detections',   icon: Zap },
  { to: '/agents',       label: 'Agents',       icon: Monitor },
  { to: '/alerts',       label: 'Alerts',       icon: Bell },
  { to: '/alert-rules',  label: 'Alert Rules',  icon: BookOpen },
  { to: '/threat-intel', label: 'Threat Intel', icon: Crosshair },
]

const adminLinks = [
  { to: '/users',        label: 'Users',        icon: Users },
  { to: '/audit-log',    label: 'Audit Log',    icon: ClipboardList },
  { to: '/settings',     label: 'Settings',     icon: Settings },
]

export function Navbar({ user }) {
  const navigate = useNavigate()

  const logout = () => {
    localStorage.removeItem('token')
    localStorage.removeItem('user')
    localStorage.removeItem('require_password_change')
    navigate('/login')
  }

  return (
    <aside className="w-56 min-h-screen bg-siem-surface border-r border-siem-border flex flex-col">
      <div className="flex items-center gap-3 px-4 py-4 border-b border-siem-border">
        <img src={logo} alt="ObsidianWatch" className="w-9 h-9 shrink-0" />
        <div>
          <div className="font-bold text-siem-text text-sm tracking-wide leading-tight">ObsidianWatch</div>
          <div className="text-[10px] text-siem-muted tracking-widest uppercase">v0.3.1</div>
        </div>
      </div>

      <nav className="flex-1 py-4 px-2 space-y-1 overflow-y-auto">
        {links.map(({ to, label, icon: Icon }) => (
          <NavLink key={to} to={to} end={to === '/'}
            className={({ isActive }) =>
              `flex items-center gap-3 px-3 py-2 rounded-md text-sm transition-colors ${
                isActive ? 'bg-siem-accent/10 text-siem-accent' : 'text-siem-muted hover:text-siem-text hover:bg-white/5'
              }`
            }
          >
            <Icon size={16} />{label}
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
                <Icon size={16} />{label}
              </NavLink>
            ))}
          </>
        )}
      </nav>

      <div className="px-4 py-4 border-t border-siem-border">
        <div className="text-xs text-siem-muted mb-0.5">{user?.username}</div>
        <div className="text-xs text-siem-muted/60 mb-3 capitalize">{user?.role}</div>
        <NavLink to="/change-password" className="flex items-center gap-2 text-xs text-siem-muted hover:text-siem-text mb-2 transition-colors">
          <Key size={13} /> Change password
        </NavLink>
        <button onClick={logout} className="flex items-center gap-2 text-xs text-siem-muted hover:text-siem-red transition-colors">
          <LogOut size={14} /> Sign out
        </button>
      </div>
    </aside>
  )
}
