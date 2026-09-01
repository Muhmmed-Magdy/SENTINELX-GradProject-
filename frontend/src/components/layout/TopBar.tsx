import { useState, useRef, useEffect } from 'react'
import { Search, Bell, User, Clock, Wifi, WifiOff, X, LogOut, Settings, ChevronDown, Shield } from 'lucide-react'
import { useNavigate } from 'react-router-dom'

interface TopBarProps {
  alertCount?: number
  connected?: boolean
}

export default function TopBar({ alertCount = 0, connected = true }: TopBarProps) {
  const [searchQuery, setSearchQuery]         = useState('')
  const [timeRange, setTimeRange]             = useState('15m')
  const [notifOpen, setNotifOpen]             = useState(false)
  const [profileOpen, setProfileOpen]         = useState(false)
  const notifRef   = useRef<HTMLDivElement>(null)
  const profileRef = useRef<HTMLDivElement>(null)
  const navigate   = useNavigate()

  const userEmail = localStorage.getItem('user_email') || 'admin@soc.local'
  const userName  = localStorage.getItem('user_name')  || 'SOC Analyst'
  const userRole  = localStorage.getItem('user_role')  || 'analyst'
  const initials  = userName.split(' ').map(w => w[0]).join('').toUpperCase().slice(0, 2) || 'SA'

  // Close dropdowns when clicking outside
  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (notifRef.current   && !notifRef.current.contains(e.target as Node))   setNotifOpen(false)
      if (profileRef.current && !profileRef.current.contains(e.target as Node)) setProfileOpen(false)
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  const handleLogout = () => {
    localStorage.removeItem('token')
    localStorage.removeItem('user_email')
    localStorage.removeItem('user_role')
    localStorage.removeItem('user_name')
    window.location.href = '/'
  }

  return (
    <header className="relative h-14 bg-soc-card/80 border-b border-white/5 flex items-center justify-between px-6 backdrop-blur-sm sticky top-0 z-30 gap-4">

      {/* Search */}
      <div className="flex-1 max-w-sm">
        <div className="relative">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-600 pointer-events-none" />
          <input
            type="text"
            placeholder="Search logs, alerts, IPs… (Ctrl+K)"
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full bg-gray-900/60 border border-white/8 hover:border-white/15 focus:border-violet-500/70
                       text-gray-300 text-xs rounded-lg pl-9 pr-4 py-2 outline-none transition-colors
                       placeholder:text-gray-600"
          />
        </div>
      </div>

      {/* Right cluster */}
      <div className="flex items-center gap-1">

        {/* Connection pill */}
        <div className={`flex items-center gap-1.5 text-[11px] font-medium px-2.5 py-1.5 rounded-lg ${
          connected
            ? 'text-green-400 bg-green-500/8'
            : 'text-red-400 bg-red-500/8'
        }`}>
          {connected
            ? <><span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse inline-block" /> Live</>
            : <><WifiOff size={12} /> Offline</>
          }
        </div>

        {/* Time range */}
        <div className="flex items-center gap-1.5 text-[11px] text-gray-400 bg-gray-800/60 border border-white/5 hover:border-white/10 px-2.5 py-1.5 rounded-lg transition-colors ml-1">
          <Clock size={12} className="text-gray-500" />
          <select
            value={timeRange}
            onChange={(e) => setTimeRange(e.target.value)}
            className="bg-transparent text-gray-300 text-[11px] outline-none cursor-pointer"
          >
            <option value="15m">Last 15 min</option>
            <option value="1h">Last 1 hour</option>
            <option value="24h">Last 24 hours</option>
            <option value="7d">Last 7 days</option>
            <option value="30d">Last 30 days</option>
          </select>
        </div>

        {/* Divider */}
        <div className="w-px h-6 bg-white/8 mx-2" />

        {/* Notifications bell */}
        <div className="relative" ref={notifRef}>
          <button
            onClick={() => { setNotifOpen(p => !p); setProfileOpen(false) }}
            className={`relative p-2 rounded-lg transition-all ${
              notifOpen
                ? 'bg-violet-500/15 text-violet-300'
                : 'text-gray-400 hover:text-gray-200 hover:bg-white/6'
            }`}
            aria-label="Notifications"
          >
            <Bell size={17} />
            {alertCount > 0 && (
              <span className="absolute -top-0.5 -right-0.5 min-w-[16px] h-4 px-0.5 bg-red-500 rounded-full
                               text-[9px] text-white flex items-center justify-center font-bold leading-none
                               ring-2 ring-soc-card animate-pulse">
                {alertCount > 9 ? '9+' : alertCount}
              </span>
            )}
          </button>

          {notifOpen && (
            <div className="absolute right-0 top-full mt-2 w-72 rounded-xl border border-white/10 bg-soc-card
                            shadow-2xl shadow-black/50 overflow-hidden z-50 animate-fade-in">
              {/* Header */}
              <div className="flex items-center justify-between px-4 py-3 border-b border-white/5">
                <span className="text-xs font-semibold text-white flex items-center gap-2">
                  <Bell size={13} className="text-violet-400" /> Notifications
                </span>
                <button onClick={() => setNotifOpen(false)} className="text-gray-500 hover:text-gray-300 p-1 rounded transition-colors">
                  <X size={13} />
                </button>
              </div>
              {/* Body */}
              <div className="p-3">
                {alertCount > 0 ? (
                  <>
                    <div className="flex items-start gap-3 p-3 bg-red-500/8 border border-red-500/20 rounded-lg mb-2">
                      <div className="w-7 h-7 bg-red-500/15 rounded-lg flex items-center justify-center flex-shrink-0 mt-0.5">
                        <Bell size={14} className="text-red-400" />
                      </div>
                      <div>
                        <p className="text-xs font-medium text-red-300">
                          {alertCount} active alert{alertCount !== 1 ? 's' : ''}
                        </p>
                        <p className="text-[11px] text-gray-500 mt-0.5">Requires analyst attention</p>
                      </div>
                    </div>
                    <button
                      onClick={() => { navigate('/alerts'); setNotifOpen(false) }}
                      className="w-full text-xs text-violet-400 hover:text-violet-300 bg-violet-500/8 hover:bg-violet-500/15
                                 border border-violet-500/20 rounded-lg px-3 py-2 transition-all text-center"
                    >
                      View all alerts →
                    </button>
                  </>
                ) : (
                  <div className="text-center py-4">
                    <div className="w-10 h-10 bg-green-500/10 rounded-full flex items-center justify-center mx-auto mb-2">
                      <Shield size={18} className="text-green-400" />
                    </div>
                    <p className="text-xs text-green-400 font-medium">All clear</p>
                    <p className="text-[11px] text-gray-500 mt-0.5">No active alerts</p>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>

        {/* Profile button */}
        <div className="relative" ref={profileRef}>
          <button
            onClick={() => { setProfileOpen(p => !p); setNotifOpen(false) }}
            className={`flex items-center gap-2 px-2.5 py-1.5 rounded-lg border transition-all ${
              profileOpen
                ? 'bg-violet-500/15 border-violet-500/30 text-white'
                : 'border-white/8 hover:border-white/15 hover:bg-white/5 text-gray-300'
            }`}
            aria-label="Profile menu"
          >
            <div className="w-6 h-6 bg-gradient-to-br from-violet-500 to-blue-500 rounded-full
                            flex items-center justify-center text-[10px] font-bold text-white flex-shrink-0">
              {initials}
            </div>
            <span className="text-[11px] font-medium hidden sm:block max-w-[80px] truncate">{userName}</span>
            <ChevronDown size={12} className={`text-gray-500 transition-transform hidden sm:block ${profileOpen ? 'rotate-180' : ''}`} />
          </button>

          {profileOpen && (
            <div className="absolute right-0 top-full mt-2 w-56 rounded-xl border border-white/10 bg-soc-card
                            shadow-2xl shadow-black/50 overflow-hidden z-50 animate-fade-in">
              {/* User info */}
              <div className="px-4 py-3 border-b border-white/5 bg-gradient-to-b from-violet-500/5 to-transparent">
                <div className="flex items-center gap-3">
                  <div className="w-9 h-9 bg-gradient-to-br from-violet-500 to-blue-500 rounded-full
                                  flex items-center justify-center text-sm font-bold text-white flex-shrink-0">
                    {initials}
                  </div>
                  <div className="min-w-0">
                    <p className="text-xs font-semibold text-white truncate">{userName}</p>
                    <p className="text-[10px] text-gray-500 truncate">{userEmail}</p>
                    <span className="inline-block mt-0.5 text-[9px] font-semibold px-1.5 py-0.5 rounded
                                     bg-violet-500/15 text-violet-300 border border-violet-500/20 uppercase tracking-wide">
                      {userRole.replace('_', ' ')}
                    </span>
                  </div>
                </div>
              </div>
              {/* Menu items */}
              <div className="p-1.5">
                <button
                  onClick={() => { navigate('/settings'); setProfileOpen(false) }}
                  className="w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs text-gray-300
                             hover:text-white hover:bg-white/6 transition-all text-left"
                >
                  <Settings size={14} className="text-gray-500" /> Settings
                </button>
                <div className="my-1 border-t border-white/5" />
                <button
                  onClick={handleLogout}
                  className="w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-xs text-red-400
                             hover:text-red-300 hover:bg-red-500/8 transition-all text-left"
                >
                  <LogOut size={14} /> Sign Out
                </button>
              </div>
            </div>
          )}
        </div>
      </div>
    </header>
  )
}
