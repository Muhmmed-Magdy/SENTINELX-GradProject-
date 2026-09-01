import { useEffect, useState } from 'react'
import { api } from '../services/api'
import { LogEntry } from '../types'
import { Search, Filter, Download, RefreshCw } from 'lucide-react'

export default function LogExplorer() {
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [search, setSearch] = useState('')
  const [sourceType, setSourceType] = useState('all')
  const [severity, setSeverity] = useState('all')
  const [uploadOnly, setUploadOnly] = useState(false)
  const [sources, setSources] = useState<any[]>([])

  useEffect(() => {
    loadLogs()
    loadSources()
  }, [sourceType, severity, uploadOnly])

  const loadLogs = async () => {
    setLoading(true)
    try {
      const params: any = { limit: 200 }
      if (sourceType !== 'all') params.source_type = sourceType
      if (severity !== 'all') params.severity = severity
      if (search) params.search = search
      if (uploadOnly) params.upload_only = 'true'
      const data = await api.logs.list(params)
      setLogs(data)
    } catch (error) {
      console.error('Failed to load logs:', error)
    } finally {
      setLoading(false)
    }
  }

  const loadSources = async () => {
    try {
      const data = await api.logs.getSources()
      setSources(data)
    } catch (error) {
      console.error('Failed to load sources:', error)
    }
  }

  const handleSearch = () => {
    loadLogs()
  }

  const exportLogs = () => {
    const csv = [
      'timestamp,source,source_type,event_type,severity,message,source_ip,username',
      ...logs.map(l => 
        `"${l.timestamp || ''}","${l.source}","${l.source_type}","${l.event_type}","${l.severity}","${(l.message || '').replace(/"/g, '""')}","${l.source_ip || ''}","${l.username || ''}"`
      )
    ].join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `soc_logs_${new Date().toISOString().slice(0,10)}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  const sevColor = (sev: string) => {
    switch(sev) {
      case 'critical': return 'text-red-400'
      case 'high': return 'text-orange-400'
      case 'medium': return 'text-yellow-400'
      case 'low': return 'text-blue-400'
      default: return 'text-green-400'
    }
  }

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Log Explorer</h1>
          <p className="text-sm text-gray-400 mt-1">Search and analyze all ingested logs</p>
        </div>
        <div className="flex gap-2">
          <button onClick={exportLogs} className="btn-secondary text-xs flex items-center gap-1.5">
            <Download size={14} /> Export CSV
          </button>
          <button onClick={loadLogs} className="btn-secondary text-xs flex items-center gap-1.5">
            <RefreshCw size={14} /> Refresh
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <div className="relative flex-1 min-w-64">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
          <input
            type="text"
            placeholder="Search logs (full text)..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && handleSearch()}
            className="input pl-9 w-full"
          />
        </div>
        <select value={sourceType} onChange={(e) => setSourceType(e.target.value)} className="input">
          <option value="all">All Sources</option>
          <option value="windows">Windows</option>
          <option value="linux">Linux</option>
          <option value="firewall">Firewall</option>
          <option value="ids">IDS</option>
          <option value="network">Network</option>
          <option value="uploaded">Uploaded</option>
        </select>
        <select value={severity} onChange={(e) => setSeverity(e.target.value)} className="input">
          <option value="all">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
        <button
          onClick={() => setUploadOnly(!uploadOnly)}
          className={`px-3 py-2 rounded-lg text-xs font-medium transition-all border ${
            uploadOnly
              ? 'bg-violet-600/20 text-violet-300 border-violet-500/30'
              : 'bg-gray-800 text-gray-400 border-white/5 hover:border-white/10'
          }`}
        >
          🟣 {uploadOnly ? 'Uploaded Only ✓' : 'Uploaded Only'}
        </button>
        <button onClick={handleSearch} className="btn-primary text-xs">Search</button>
      </div>

      {/* Sources Summary */}
      {sources.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {sources.slice(0, 10).map((s, i) => (
            <span key={i} className="px-2 py-1 bg-gray-800 rounded text-[10px] text-gray-400">
              {s.source} <span className="text-gray-600">({s.count})</span>
            </span>
          ))}
        </div>
      )}

      {/* Log Table */}
      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-white/5 text-gray-500">
                <th className="text-left p-3 font-medium">Time</th>
                <th className="text-left p-3 font-medium">Source</th>
                <th className="text-left p-3 font-medium">Type</th>
                <th className="text-left p-3 font-medium">Event</th>
                <th className="text-left p-3 font-medium">Severity</th>
                <th className="text-left p-3 font-medium">Message</th>
                <th className="text-left p-3 font-medium">IP</th>
                <th className="text-left p-3 font-medium">User</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr><td colSpan={8} className="text-center p-8 text-gray-500">Loading logs...</td></tr>
              ) : logs.length === 0 ? (
                <tr><td colSpan={8} className="text-center p-8 text-gray-500">No logs found. Upload logs or connect a log source.</td></tr>
              ) : (
                logs.map((log) => (
                  <tr key={log.id} className="border-b border-white/5 hover:bg-white/5 transition-colors">
                    <td className="p-3 text-gray-400 font-mono whitespace-nowrap">
                      {log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : '-'}
                    </td>
                    <td className="p-3 text-gray-300 font-mono">{log.source}</td>
                    <td className="p-3">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium border ${
                        log.source_type === 'linux'    ? 'bg-orange-500/10 text-orange-400 border-orange-500/20' :
                        log.source_type === 'firewall' ? 'bg-red-500/10 text-red-400 border-red-500/20' :
                        log.source_type === 'windows'  ? 'bg-blue-500/10 text-blue-400 border-blue-500/20' :
                        'bg-gray-800 text-gray-400 border-white/10'
                      }`}>
                        {log.source_type}
                      </span>
                    </td>
                    <td className="p-3">
                      <span className="px-1.5 py-0.5 bg-gray-800/80 border border-white/8 rounded text-[10px] text-gray-300 font-mono">
                        {log.event_type || '—'}
                      </span>
                    </td>
                    <td className={`p-3 font-medium ${sevColor(log.severity)}`}>
                      {log.severity?.toUpperCase()}
                    </td>
                    <td className="p-3 text-gray-300 max-w-xs truncate" title={log.message}>
                      {log.message}
                    </td>
                    <td className="p-3 text-gray-400 font-mono">{log.source_ip || '-'}</td>
                    <td className="p-3 text-gray-400">{log.username || '-'}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
