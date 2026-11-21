import { useState } from 'react'
import axios from 'axios'
import { ShieldAlert, Eye, EyeOff, Wifi } from 'lucide-react'
import { api, API_BASE } from '../services/api'

interface LoginProps {
  onLogin: () => void
}

const DEMO_ACCOUNTS = [
  { email: 'admin@soc.local', role: 'Admin' },
  { email: 'analyst@soc.local', role: 'Senior Analyst' },
  { email: 'junior@soc.local', role: 'Junior Analyst' },
]
const DEMO_MODE = import.meta.env.VITE_DEMO_MODE === 'true'

export default function Login({ onLogin }: LoginProps) {
  const [email,    setEmail]    = useState('')
  const [password, setPassword] = useState('')
  const [showPass, setShowPass] = useState(false)
  const [error,    setError]    = useState('')
  const [loading,  setLoading]  = useState(false)

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    setError('')
    try {
      const data = await api.auth.login(email, password)
      localStorage.setItem('token',      data.access_token)
      localStorage.setItem('user_email', data.user?.email || email)
      localStorage.setItem('user_role',  data.user?.role  || 'analyst')
      localStorage.setItem('user_name',  data.user?.full_name || 'Analyst')
      onLogin()
    } catch (error: unknown) {
      if (axios.isAxiosError(error) && error.response?.status === 401) {
        setError('Invalid email or password.')
      } else {
        setError('Unable to connect to the API. Start the backend or check the API URL.')
      }
    } finally {
      setLoading(false)
    }
  }

    const fill = (acc: typeof DEMO_ACCOUNTS[0]) => {
        setEmail(acc.email)
        setPassword('')
        setError('')
    }

  return (
    <div className="min-h-screen bg-soc-bg flex items-center justify-center p-4"
         style={{ backgroundImage: 'radial-gradient(ellipse at 20% 50%, rgba(139,92,246,.07) 0%, transparent 60%), radial-gradient(ellipse at 80% 50%, rgba(59,130,246,.05) 0%, transparent 60%)' }}>

      <div className="w-full max-w-md">

        {/* Brand */}
        <div className="text-center mb-8">
          <div className="w-16 h-16 bg-gradient-to-br from-violet-600 to-blue-600 rounded-2xl flex items-center justify-center mx-auto mb-4 shadow-lg shadow-violet-500/20">
            <ShieldAlert size={30} className="text-white" />
          </div>
          <h1 className="text-2xl font-bold text-white tracking-tight">AI SOC Dashboard</h1>
          <p className="text-sm text-gray-500 mt-1">Security Operations Center</p>
        </div>

        {/* Form card */}
        <form onSubmit={handleLogin} className="card space-y-4 shadow-2xl">
          <div>
            <label className="text-xs text-gray-400 font-medium mb-1.5 block">Email</label>
            <input
              type="email"
              value={email}
              onChange={e => setEmail(e.target.value)}
              className="input"
              placeholder="user@soc.local"
              autoComplete="username"
              required
            />
          </div>

          <div>
            <label className="text-xs text-gray-400 font-medium mb-1.5 block">Password</label>
            <div className="relative">
              <input
                type={showPass ? 'text' : 'password'}
                value={password}
                onChange={e => setPassword(e.target.value)}
                className="input pr-10"
                placeholder="••••••••"
                autoComplete="current-password"
                required
              />
              <button type="button" tabIndex={-1}
                onClick={() => setShowPass(s => !s)}
                className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300 transition-colors">
                {showPass ? <EyeOff size={15} /> : <Eye size={15} />}
              </button>
            </div>
          </div>

          {error && (
            <p className="text-xs text-red-400 bg-red-500/10 border border-red-500/20 rounded-lg px-3 py-2">
              {error}
            </p>
          )}

          <button type="submit" disabled={loading} className="btn-primary w-full justify-center py-2.5 text-sm">
            {loading
              ? <><span className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin" /> Signing in…</>
              : 'Sign In'}
          </button>
        </form>

        {/* Demo accounts */}
        {DEMO_MODE && <div className="mt-5">
          <p className="text-[11px] text-gray-600 text-center mb-3 uppercase tracking-wider">Demo Accounts</p>
          <div className="grid grid-cols-3 gap-2">
            {DEMO_ACCOUNTS.map(acc => (
              <button key={acc.email} onClick={() => fill(acc)}
                className="p-2.5 bg-soc-card border border-white/5 hover:border-white/15 rounded-lg text-left transition-all group">
                <p className="text-[10px] font-semibold text-gray-300 group-hover:text-white">{acc.role}</p>
                <p className="text-[9px] text-gray-600 mt-0.5 truncate">{acc.email}</p>
              </button>
            ))}
          </div>
        </div>}

        {/* Connection indicator */}
        <div className="flex items-center justify-center gap-1.5 mt-6 text-[10px] text-gray-700">
          <Wifi size={11} />
          <span>Connecting to {API_BASE.startsWith('http') ? new URL(API_BASE).host : window.location.host}</span>
        </div>
      </div>
    </div>
  )
}
