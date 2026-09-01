import { Routes, Route, Navigate } from 'react-router-dom'
import { useEffect, useState } from 'react'
import DashboardLayout from './components/layout/DashboardLayout'
import { api } from './services/api'
import Dashboard from './pages/Dashboard'
import Alerts from './pages/Alerts'
import LogExplorer from './pages/LogExplorer'
import LiveIngestion from './pages/LiveIngestion'
import FileUpload from './pages/FileUpload'
import Incidents from './pages/Incidents'
import AICopilot from './pages/AICopilot'
import Settings from './pages/Settings'
import Login from './pages/Login'

function App() {
  const [isAuthenticated, setIsAuthenticated] = useState(false)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const validateSession = async () => {
      const token = localStorage.getItem('token')
      if (!token) {
        setIsAuthenticated(false)
        setLoading(false)
        return
      }

      try {
        await api.auth.me()
        setIsAuthenticated(true)
      } catch {
        localStorage.removeItem('token')
        localStorage.removeItem('user_email')
        localStorage.removeItem('user_role')
        localStorage.removeItem('user_name')
        setIsAuthenticated(false)
      } finally {
        setLoading(false)
      }
    }

    validateSession()
  }, [])

  if (loading) {
    return (
      <div className="min-h-screen bg-soc-bg flex items-center justify-center">
        <div className="text-center">
          <div className="text-4xl mb-4">🛡️</div>
          <p className="text-gray-400">Loading SOC Dashboard...</p>
        </div>
      </div>
    )
  }

  if (!isAuthenticated) {
    return <Login onLogin={() => setIsAuthenticated(true)} />
  }

  return (
    <DashboardLayout>
      <Routes>
        <Route path="/" element={<Dashboard />} />
        <Route path="/alerts" element={<Alerts />} />
        <Route path="/logs" element={<LogExplorer />} />
        <Route path="/live" element={<LiveIngestion />} />
        <Route path="/upload" element={<FileUpload />} />
        <Route path="/incidents" element={<Incidents />} />
        <Route path="/ai" element={<AICopilot />} />
        <Route path="/settings" element={<Settings />} />
        <Route path="*" element={<Navigate to="/" />} />
      </Routes>
    </DashboardLayout>
  )
}

export default App
