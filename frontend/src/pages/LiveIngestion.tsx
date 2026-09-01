import { useState, useEffect, useRef, useCallback } from 'react'
import { io, Socket } from 'socket.io-client'
import { api, getSocketUrl } from '../services/api'
import { LogEntry, Alert } from '../types'
import {
  Radio, Wifi, WifiOff, Terminal, Play, Pause, Trash2,
  Copy, Server, AlertTriangle, CheckCircle, Activity,
  ChevronDown, ChevronUp, RefreshCw
} from 'lucide-react'

const sevColor = (sev: string) => {
  switch (sev) {
    case 'critical': return 'text-red-400'
    case 'high':     return 'text-orange-400'
    case 'medium':   return 'text-yellow-400'
    case 'low':      return 'text-blue-400'
    default:         return 'text-green-400'
  }
}

const sevBg = (sev: string) => {
  switch (sev) {
    case 'critical': return 'bg-red-500/10 text-red-400 border-red-500/20'
    case 'high':     return 'bg-orange-500/10 text-orange-400 border-orange-500/20'
    case 'medium':   return 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20'
    case 'low':      return 'bg-blue-500/10 text-blue-400 border-blue-500/20'
    default:         return 'bg-green-500/10 text-green-400 border-green-500/20'
  }
}

export default function LiveIngestion() {
  const [logs, setLogs]             = useState<LogEntry[]>([])
  const [alerts, setAlerts]         = useState<Alert[]>([])
  const [paused, setPaused]         = useState(false)
  const [connected, setConnected]   = useState(false)
  const [stats, setStats]           = useState<Record<string, number>>({})
  const [showAlerts, setShowAlerts] = useState(true)
  const [copied, setCopied]         = useState(false)
  const socketRef  = useRef<Socket | null>(null)
  const pauseRef   = useRef(false)
  const logEndRef  = useRef<HTMLDivElement>(null)
  const firstLoad  = useRef(true)

  const endpoint = `${getSocketUrl()}/api/logs/ingest`

  useEffect(() => { pauseRef.current = paused }, [paused])

  const connectSocket = useCallback(() => {
    const socket = io(getSocketUrl(), {
      auth: { token: localStorage.getItem('token') || '' },
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionDelay: 3000,
      reconnectionAttempts: Infinity,
    })
    socket.on('connect',    () => setConnected(true))
    socket.on('disconnect', () => setConnected(false))
    socket.on('new_log', (data: LogEntry) => {
      if (!pauseRef.current) setLogs(prev => [data, ...prev].slice(0, 500))
    })
    socket.on('new_alert', (data: Alert) => {
      if (!pauseRef.current) {
        setAlerts(prev => [data, ...prev].slice(0, 100))
        loadStats()
      }
    })
    socketRef.current = socket
    return socket
  }, [])

  const loadStats = async () => {
    try { const d = await api.logs.getStats(); setStats(d.by_severity || {}) } catch { /**/ }
  }
  const loadRecentAlerts = async () => {
    try { const d = await api.alerts.list({ limit: 20 }); setAlerts(d || []) } catch { /**/ }
  }
  const loadRecentLogs = async () => {
    try { const d = await api.logs.list({ limit: 100 }); setLogs(d || []) } catch { /**/ }
  }

  useEffect(() => {
    const socket = connectSocket()
    loadStats(); loadRecentAlerts(); loadRecentLogs()
    const interval = setInterval(loadStats, 15000)
    return () => { socket.disconnect(); clearInterval(interval) }
  }, [connectSocket])

  // Only auto-scroll for NEW socket events, not on initial page load
  useEffect(() => {
    if (firstLoad.current) { firstLoad.current = false; return }
    if (!paused) logEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [logs, paused])

  const copyEndpoint = () => {
    navigator.clipboard.writeText(endpoint)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const winlogbeatConfig =
`winlogbeat.event_logs:
  - name: Security
    event_id: 4624, 4625, 4648, 4672, 4688, 4720, 4722, 4728, 4732, 4756, 7045
  - name: System
    event_id: 7045, 7034, 7040
  - name: Microsoft-Windows-PowerShell/Operational
    event_id: 4103, 4104, 4105, 4106

output.http:
  hosts: ["http://localhost:8001"]
  path: "/api/logs/ingest"`

  const totalLogs = Object.values(stats).reduce((a, b) => a + b, 0)

  return (
    <div className="space-y-4 animate-fade-in">

      {/* ── Header ── */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Radio size={22} className={connected ? 'text-green-400 animate-pulse' : 'text-gray-500'} />
            Live Log Ingestion
          </h1>
          <p className="text-sm text-gray-400 mt-0.5">Real-time monitoring of your Windows Event Logs</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => { loadRecentLogs(); loadRecentAlerts(); loadStats() }}
            className="btn-secondary text-xs flex items-center gap-1.5"
          >
            <RefreshCw size={12} /> Refresh
          </button>
          <div className={`flex items-center gap-2 px-3 py-1.5 rounded-lg text-xs border font-medium ${
            connected
              ? 'bg-green-500/10 text-green-400 border-green-500/20'
              : 'bg-red-500/10 text-red-400 border-red-500/20'
          }`}>
            {connected ? <Wifi size={13} /> : <WifiOff size={13} />}
            {connected ? 'Connected' : 'Reconnecting...'}
          </div>
        </div>
      </div>

      {/* ── Stats row ── */}
      <div className="grid grid-cols-3 lg:grid-cols-6 gap-3">
        {[
          { label: 'Total',    value: totalLogs,           color: 'text-white'      },
          { label: 'Critical', value: stats.critical || 0, color: 'text-red-400'    },
          { label: 'High',     value: stats.high     || 0, color: 'text-orange-400' },
          { label: 'Medium',   value: stats.medium   || 0, color: 'text-yellow-400' },
          { label: 'Low',      value: stats.low      || 0, color: 'text-blue-400'   },
          { label: 'Info',     value: stats.info     || 0, color: 'text-green-400'  },
        ].map(({ label, value, color }) => (
          <div key={label} className="bg-soc-card border border-white/5 rounded-xl p-3 text-center">
            <p className={`text-xl font-bold ${color}`}>{value.toLocaleString()}</p>
            <p className="text-[10px] text-gray-500 mt-0.5">{label}</p>
          </div>
        ))}
      </div>

      {/* ── Endpoint + Winlogbeat side by side ── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">

        {/* Ingestion endpoint */}
        <div className="bg-soc-card border border-white/5 rounded-xl p-4">
          <h3 className="text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2">
            <Server size={14} className="text-violet-400" />
            Ingestion Endpoint
          </h3>
          <div className="flex items-center gap-2">
            <code className="flex-1 bg-black/50 text-green-400 px-3 py-2 rounded-lg text-xs font-mono border border-green-900/30 truncate">
              POST {endpoint}
            </code>
            <button
              onClick={copyEndpoint}
              className={`px-3 py-2 rounded-lg text-xs flex items-center gap-1.5 border transition-all flex-shrink-0 ${
                copied
                  ? 'bg-green-500/20 text-green-400 border-green-500/30'
                  : 'bg-gray-800 text-gray-300 border-white/10 hover:border-white/20'
              }`}
            >
              {copied ? <CheckCircle size={12} /> : <Copy size={12} />}
              {copied ? 'Copied!' : 'Copy'}
            </button>
          </div>
          <p className="text-[10px] text-gray-600 mt-2">
            Send logs here via HTTP POST. Works with Winlogbeat, Filebeat, or the PowerShell forwarder.
          </p>
        </div>

        {/* Winlogbeat config */}
        <div className="bg-soc-card border border-white/5 rounded-xl p-4">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-semibold text-gray-300 flex items-center gap-2">
              <div className="w-5 h-5 bg-blue-500/20 rounded flex items-center justify-center">
                <span className="text-[9px] font-bold text-blue-400">W</span>
              </div>
              Winlogbeat Config
            </h3>
            <button
              onClick={() => navigator.clipboard.writeText(winlogbeatConfig)}
              className="text-[11px] text-gray-500 hover:text-gray-300 flex items-center gap-1"
            >
              <Copy size={11} /> Copy
            </button>
          </div>
          <pre className="bg-black/60 text-[10px] text-gray-300 p-3 rounded-lg overflow-x-auto font-mono border border-white/5">
            {winlogbeatConfig}
          </pre>
        </div>
      </div>

      {/* ── Alerts panel ── */}
      <div className="bg-soc-card border border-white/5 rounded-xl overflow-hidden">
        <button
          onClick={() => setShowAlerts(s => !s)}
          className="w-full flex items-center justify-between px-4 py-3 hover:bg-white/5 transition-colors"
        >
          <h3 className="text-sm font-semibold text-gray-300 flex items-center gap-2">
            <AlertTriangle size={14} className="text-orange-400" />
            Detected Alerts
            {alerts.length > 0 && (
              <span className="px-2 py-0.5 bg-orange-500/20 text-orange-400 text-[10px] rounded-full border border-orange-500/30">
                {alerts.length}
              </span>
            )}
          </h3>
          {showAlerts
            ? <ChevronUp size={14} className="text-gray-500" />
            : <ChevronDown size={14} className="text-gray-500" />}
        </button>

        {showAlerts && (
          <div className="border-t border-white/5 max-h-52 overflow-y-auto">
            {alerts.length === 0 ? (
              <div className="flex items-center justify-center py-8 text-gray-600 text-xs">
                <div className="text-center">
                  <CheckCircle size={24} className="mx-auto mb-2 opacity-40" />
                  <p>No alerts yet — monitoring for threats</p>
                </div>
              </div>
            ) : (
              alerts.map((alert, i) => (
                <div key={alert.id ?? i} className="flex items-start gap-3 px-4 py-2.5 border-b border-white/5 hover:bg-white/5">
                  <span className={`flex-shrink-0 mt-0.5 px-1.5 py-0.5 rounded text-[10px] font-medium border ${sevBg(alert.severity)}`}>
                    {alert.severity?.toUpperCase()}
                  </span>
                  <div className="flex-1 min-w-0">
                    <p className="text-xs text-gray-200 font-medium truncate">{alert.title}</p>
                    <p className="text-[10px] text-gray-500 mt-0.5">
                      {alert.rule_name}
                      {alert.source && ` · ${alert.source}`}
                      {alert.source_ip && ` · ${alert.source_ip}`}
                      {alert.created_at && ` · ${new Date(alert.created_at).toLocaleTimeString()}`}
                    </p>
                  </div>
                  <span className={`flex-shrink-0 text-[10px] px-1.5 py-0.5 rounded border ${
                    alert.status === 'new'
                      ? 'bg-red-500/10 text-red-400 border-red-500/20'
                      : 'bg-gray-800 text-gray-500 border-white/5'
                  }`}>{alert.status}</span>
                </div>
              ))
            )}
          </div>
        )}
      </div>

      {/* ── Live Log Stream ── */}
      <div className="bg-soc-card border border-white/5 rounded-xl overflow-hidden">
        <div className="flex items-center justify-between px-4 py-3 border-b border-white/5">
          <h3 className="text-sm font-semibold text-gray-300 flex items-center gap-2">
            <Activity size={14} className={connected && !paused ? 'text-green-400 animate-pulse' : 'text-gray-500'} />
            Live Log Stream
            {logs.length > 0 && (
              <span className="text-[10px] text-gray-500">{logs.length.toLocaleString()} events</span>
            )}
          </h3>
          <div className="flex gap-2">
            <button
              onClick={() => setPaused(p => !p)}
              className={`btn-secondary text-xs flex items-center gap-1.5 ${paused ? 'text-yellow-400 border-yellow-500/30' : ''}`}
            >
              {paused ? <Play size={12} /> : <Pause size={12} />}
              {paused ? 'Resume' : 'Pause'}
            </button>
            <button onClick={() => setLogs([])} className="btn-secondary text-xs flex items-center gap-1.5">
              <Trash2 size={12} /> Clear
            </button>
          </div>
        </div>

        <div className="font-mono bg-black/40 h-96 overflow-y-auto p-3 space-y-px">
          {/* Column headers */}
          {logs.length > 0 && (
            <div className="flex gap-2 px-2 py-1 text-[10px] text-gray-600 border-b border-white/10 mb-1 sticky top-0 bg-black/60">
              <span className="flex-shrink-0 w-[72px]">TIME</span>
              <span className="flex-shrink-0 w-[64px]">LEVEL</span>
              <span className="flex-shrink-0 w-[130px]">SOURCE</span>
              <span className="flex-shrink-0 w-[150px]">EVENT TYPE</span>
              <span className="flex-1">MESSAGE</span>
            </div>
          )}
          {logs.length === 0 ? (
            <div className="flex flex-col items-center justify-center h-full text-gray-600 gap-2">
              <Terminal size={32} className="opacity-40" />
              <p className="text-sm">Waiting for live events…</p>
              <p className="text-[11px] text-gray-700">
                {connected
                  ? 'WebSocket connected — events will appear here as they arrive'
                  : 'Start the backend (python run.py) and run the PowerShell forwarder'}
              </p>
            </div>
          ) : (
            logs.map((log, i) => (
              <div key={log.id ?? i} className="flex gap-2 hover:bg-white/5 px-2 py-1 rounded text-[11px] group border-b border-white/5 last:border-0">
                {/* Time */}
                <span className="text-gray-500 flex-shrink-0 w-[72px] font-mono">
                  {log.timestamp
                    ? new Date(log.timestamp).toLocaleTimeString()
                    : new Date().toLocaleTimeString()}
                </span>
                {/* Severity badge */}
                <span className={`flex-shrink-0 w-[64px] font-bold text-center ${sevColor(log.severity)}`}>
                  [{(log.severity || 'info').toUpperCase().slice(0,4)}]
                </span>
                {/* Source host */}
                <span className="text-cyan-400 flex-shrink-0 w-[130px] truncate font-mono">
                  {log.source || log.hostname || 'unknown'}
                </span>
                {/* Provider/event type — subtle */}
                <span className="text-gray-600 flex-shrink-0 w-[150px] truncate">
                  {log.event_type || log.source_type}
                  {log.event_id ? ` (${log.event_id})` : ''}
                </span>
                {/* Message — takes remaining space */}
                <span className="text-gray-300 flex-1 truncate" title={log.message}>
                  {log.message}
                </span>
              </div>
            ))
          )}
          <div ref={logEndRef} />
        </div>
      </div>

    </div>
  )
}
