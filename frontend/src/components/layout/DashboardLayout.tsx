import { ReactNode, useState, useEffect } from 'react'
import Sidebar from './Sidebar'
import TopBar from './TopBar'
import { io } from 'socket.io-client'
import { getSocketUrl } from '../../services/api'

interface DashboardLayoutProps {
  children: ReactNode
}

export default function DashboardLayout({ children }: DashboardLayoutProps) {
  const [collapsed, setCollapsed]     = useState(false)
  const [alertCount, setAlertCount]   = useState(0)
  const [wsConnected, setWsConnected] = useState(false)

  useEffect(() => {
    // Fetch initial alert count
    const fetchCount = async () => {
      try {
        const token = localStorage.getItem('token')
        const res = await fetch('/api/alerts/stats', {
          headers: { Authorization: `Bearer ${token}` },
        })
        if (res.ok) {
          const data = await res.json()
          setAlertCount(data?.by_status?.new ?? 0)
        }
      } catch { /* ignore */ }
    }
    fetchCount()
    const interval = setInterval(fetchCount, 15000)
    // Refresh bell count immediately when an alert status changes
    window.addEventListener('soc:alert-updated', fetchCount)

    // WebSocket connectivity probe
    const token = localStorage.getItem('token') || ''
    const socket = io(getSocketUrl(), {
      auth: { token },
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionDelay: 3000,
    })
    socket.on('connect',    () => setWsConnected(true))
    socket.on('disconnect', () => setWsConnected(false))
    socket.on('new_alert',  () => fetchCount())

    return () => {
      clearInterval(interval)
      window.removeEventListener('soc:alert-updated', fetchCount)
      socket.disconnect()
    }
  }, [])

  const sidebarWidth = collapsed ? 64 : 256

  return (
    <div className="min-h-screen bg-soc-bg flex">
      <Sidebar onCollapse={setCollapsed} />

      <div
        className="flex-1 flex flex-col min-w-0 transition-[margin] duration-200 ease-in-out"
        style={{ marginLeft: sidebarWidth }}
      >
        <TopBar alertCount={alertCount} connected={wsConnected} />
        <main className="flex-1 p-6 overflow-auto">
          {children}
        </main>
      </div>
    </div>
  )
}
