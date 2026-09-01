import { useState, useEffect } from 'react'
import { Link, useLocation } from 'react-router-dom'
import {
  LayoutDashboard, AlertTriangle, FileSearch, Radio, Upload,
  Shield, Bot, Settings, ChevronLeft, ChevronRight, ShieldAlert
} from 'lucide-react'
import { api } from '../../services/api'

interface NavItem {
  path: string
  icon: React.ElementType
  label: string
  badge?: boolean
}

const navItems: NavItem[] = [
  { path: '/',         icon: LayoutDashboard, label: 'Dashboard' },
  { path: '/alerts',   icon: AlertTriangle,   label: 'Alerts',       badge: true },
  { path: '/logs',     icon: FileSearch,      label: 'Log Explorer' },
  { path: '/live',     icon: Radio,           label: 'Live Ingestion' },
  { path: '/upload',   icon: Upload,          label: 'File Upload' },
  { path: '/incidents',icon: Shield,          label: 'Incidents' },
  { path: '/ai',       icon: Bot,             label: 'AI Copilot' },
  { path: '/settings', icon: Settings,        label: 'Settings' },
]

export default function Sidebar({ onCollapse }: { onCollapse?: (c: boolean) => void }) {
  const [collapsed, setCollapsed]   = useState(false)
  const [alertCount, setAlertCount] = useState(0)
  const location = useLocation()

  useEffect(() => {
    const fetchAlertCount = async () => {
      try {
        const data = await api.alerts.getStats()
        setAlertCount(data?.by_status?.new ?? 0)
      } catch { /* silently ignore */ }
    }
    fetchAlertCount()
    const interval = setInterval(fetchAlertCount, 15000)
    return () => clearInterval(interval)
  }, [])

  const toggle = (c: boolean) => {
    setCollapsed(c)
    onCollapse?.(c)
  }

  return (
    <aside className={`
      ${collapsed ? 'w-16' : 'w-64'}
      h-screen bg-soc-card border-r border-white/5
      flex flex-col fixed left-0 top-0 z-40
      transition-[width] duration-200 ease-in-out
    `}>

      {/* Logo */}
      <div className={`h-14 border-b border-white/5 flex items-center gap-3 flex-shrink-0 overflow-hidden
                       ${collapsed ? 'px-4 justify-center' : 'px-4'}`}>
        <div className="w-8 h-8 bg-gradient-to-br from-violet-600 to-blue-600 rounded-lg
                        flex items-center justify-center flex-shrink-0 shadow-lg shadow-violet-500/20">
          <ShieldAlert size={17} className="text-white" />
        </div>
        {!collapsed && (
          <div className="min-w-0 animate-fade-in">
            <h1 className="text-sm font-bold text-white leading-tight tracking-tight">AI SOC</h1>
            <p className="text-[10px] text-gray-500 leading-tight">Security Dashboard</p>
          </div>
        )}
      </div>

      {/* Nav label */}
      {!collapsed && (
        <p className="px-4 pt-4 pb-1.5 text-[9px] font-semibold uppercase tracking-widest text-gray-600">
          Navigation
        </p>
      )}

      {/* Navigation */}
      <nav className="flex-1 px-2 pb-2 space-y-0.5 overflow-y-auto overflow-x-hidden">
        {navItems.map((item) => {
          const Icon    = item.icon
          const isActive = location.pathname === item.path
          const count   = item.badge ? alertCount : 0

          return (
            <Link
              key={item.path}
              to={item.path}
              title={collapsed ? item.label : undefined}
              className={`
                flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm
                transition-all duration-150 group relative select-none
                ${isActive
                  ? 'bg-violet-600/15 text-violet-300'
                  : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'
                }
              `}
            >
              {/* Active left bar */}
              {isActive && (
                <span className="absolute left-0 top-1.5 bottom-1.5 w-0.5 rounded-r-full bg-violet-500" />
              )}

              <Icon
                size={17}
                className={`flex-shrink-0 transition-transform group-hover:scale-105 ${isActive ? 'text-violet-400' : ''}`}
              />

              {!collapsed && (
                <span className="flex-1 font-medium text-[13px]">{item.label}</span>
              )}

              {/* Alert badge */}
              {count > 0 && !collapsed && (
                <span className="ml-auto min-w-[18px] h-[18px] px-1 bg-red-500/90 text-white
                                 text-[9px] font-bold rounded-full flex items-center justify-center
                                 border border-red-400/30">
                  {count > 99 ? '99+' : count}
                </span>
              )}
              {count > 0 && collapsed && (
                <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-red-500 rounded-full
                                 border border-soc-card" />
              )}

              {/* Tooltip when collapsed */}
              {collapsed && (
                <div className="absolute left-full ml-3 px-2.5 py-1.5 bg-gray-800 text-white text-xs
                               rounded-lg opacity-0 group-hover:opacity-100 pointer-events-none
                               whitespace-nowrap z-50 border border-white/10 shadow-xl
                               transition-opacity duration-150">
                  {item.label}
                  {count > 0 && <span className="ml-1.5 text-red-400">({count})</span>}
                  {/* Arrow */}
                  <span className="absolute top-1/2 -translate-y-1/2 -left-1 border-4 border-transparent border-r-gray-800" />
                </div>
              )}
            </Link>
          )
        })}
      </nav>

      {/* Collapse toggle */}
      <div className="p-2 border-t border-white/5 flex-shrink-0">
        <button
          onClick={() => toggle(!collapsed)}
          className="w-full flex items-center justify-center gap-2 p-2.5 rounded-lg
                     text-gray-500 hover:text-gray-300 hover:bg-white/5 transition-all text-xs"
          title={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        >
          {collapsed
            ? <ChevronRight size={15} />
            : <><ChevronLeft size={15} /><span>Collapse</span></>
          }
        </button>
      </div>
    </aside>
  )
}
