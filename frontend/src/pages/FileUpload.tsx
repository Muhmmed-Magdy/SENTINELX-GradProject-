import { useState, useEffect, useCallback } from 'react'
import { api } from '../services/api'
import { UploadResult, UploadedFile, LogEntry } from '../types'
import {
  Upload, File, CheckCircle, AlertTriangle, Eye, FileText,
  X, Shield, FileSearch, BarChart3, Activity, Download, Trash2
} from 'lucide-react'
import { PieChart, Pie, Cell, ResponsiveContainer, Tooltip } from 'recharts'

const COLORS = ['#8b5cf6', '#3b82f6', '#22c55e', '#eab308', '#f97316', '#ef4444']

const sevColor = (sev: string) => {
  switch (sev) {
    case 'critical': return 'text-red-400 bg-red-500/10'
    case 'high':     return 'text-orange-400 bg-orange-500/10'
    case 'medium':   return 'text-yellow-400 bg-yellow-500/10'
    case 'low':      return 'text-blue-400 bg-blue-500/10'
    default:         return 'text-green-400 bg-green-500/10'
  }
}

type UploadStats = {
  total_logs: number
  total_alerts: number
  total_files: number
  by_severity: Record<string, number>
  by_source: Record<string, number>
  files: UploadedFile[]
}

export default function FileUpload() {
  const [formats, setFormats]               = useState<any[]>([])
  const [selectedFormat, setSelectedFormat] = useState('auto')
  const [uploading, setUploading]           = useState(false)
  const [result, setResult]                 = useState<UploadResult | null>(null)
  const [uploadStats, setUploadStats]       = useState<UploadStats | null>(null)
  const [uploadedLogs, setUploadedLogs]     = useState<LogEntry[]>([])
  const [viewingUpload, setViewingUpload]   = useState<string | null>(null)
  const [viewingFileName, setViewingFileName] = useState('')
  const [dragOver, setDragOver]             = useState(false)
  const [error, setError]                   = useState<string | null>(null)
  const [deletingId, setDeletingId]         = useState<string | null>(null)
  const [confirmDelete, setConfirmDelete]   = useState<UploadedFile | null>(null)

  useEffect(() => {
    loadFormats()
    loadUploadStats()
  }, [])

  const loadFormats = async () => {
    try {
      const data = await api.upload.getFormats()
      setFormats(data.formats || [])
    } catch {
      setFormats([
        { id: 'auto',        name: 'Auto-Detect',   description: 'Automatically detect format', extensions: ['*'] },
        { id: 'windows_xml', name: 'Windows XML',    description: 'Windows Event Log XML',       extensions: ['.xml'] },
        { id: 'syslog',      name: 'Syslog',         description: 'Linux syslog',                extensions: ['.log'] },
        { id: 'firewall',    name: 'Firewall',        description: 'Firewall logs',               extensions: ['.log'] },
        { id: 'json',        name: 'JSON',            description: 'JSON formatted logs',         extensions: ['.json'] },
        { id: 'csv',         name: 'CSV',             description: 'CSV log files',               extensions: ['.csv'] },
        { id: 'plain',       name: 'Plain Text',      description: 'Plain text logs',             extensions: ['.txt'] },
      ])
    }
  }

  const loadUploadStats = async () => {
    try {
      const data = await api.upload.getStats()
      setUploadStats(data)
    } catch (err) {
      console.error('Failed to load upload stats:', err)
    }
  }

  const handleUpload = async (file: File) => {
    setUploading(true)
    setError(null)
    setResult(null)
    try {
      const data = await api.upload.file(file, selectedFormat)
      setResult(data)
      loadUploadStats()
    } catch (err: any) {
      setError(err.response?.data?.error || err.response?.data?.detail || 'Upload failed')
    } finally {
      setUploading(false)
    }
  }

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault()
    setDragOver(false)
    const file = e.dataTransfer.files[0]
    if (file) handleUpload(file)
  }, [selectedFormat])

  const handleFileInput = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) handleUpload(file)
    e.target.value = ''
  }

  const viewUploadedLogs = async (uploadSessionId: string, filename: string) => {
    setViewingUpload(uploadSessionId)
    setViewingFileName(filename)
    try {
      const data = await api.upload.getLogs(uploadSessionId, { limit: 500 })
      setUploadedLogs(data)
    } catch (err) {
      console.error('Failed to load logs:', err)
    }
  }

  const exportLogs = () => {
    if (!uploadedLogs.length) return
    const csv = [
      'timestamp,source,source_type,severity,message,source_ip,username',
      ...uploadedLogs.map(l =>
        `"${l.timestamp || ''}","${l.source}","${l.source_type}","${l.severity}","${(l.message || '').replace(/"/g, '""')}","${l.source_ip || ''}","${l.username || ''}"`
      ),
    ].join('\n')
    const blob = new Blob([csv], { type: 'text/csv' })
    const url  = URL.createObjectURL(blob)
    const a    = document.createElement('a')
    a.href     = url
    a.download = `logs_${viewingFileName || 'export'}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  const handleDelete = async () => {
    if (!confirmDelete) return
    const id = confirmDelete.id
    setDeletingId(id)
    setConfirmDelete(null)
    try {
      await api.upload.delete(id)
      // Close the log viewer if it belonged to this file
      if (viewingUpload === (confirmDelete.upload_session_id || id)) {
        setViewingUpload(null)
        setUploadedLogs([])
      }
      // Clear the latest-result banner if it matched
      if (result?.upload_session_id === confirmDelete.upload_session_id) {
        setResult(null)
      }
      await loadUploadStats()
    } catch {
      setError('Failed to delete the file. Please try again.')
    } finally {
      setDeletingId(null)
    }
  }

  const sourceChartData = uploadStats?.by_source
    ? Object.entries(uploadStats.by_source).map(([name, value]) => ({
        name:  name.charAt(0).toUpperCase() + name.slice(1),
        value: value as number,
      }))
    : []

  return (
    <div className="space-y-6 animate-fade-in">

      {/* ── Confirm Delete Modal ── */}
      {confirmDelete && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-soc-card border border-red-500/30 rounded-xl p-6 w-full max-w-md shadow-2xl">
            <div className="flex items-center gap-3 mb-4">
              <div className="p-2 bg-red-500/10 rounded-lg">
                <Trash2 size={20} className="text-red-400" />
              </div>
              <div>
                <h3 className="text-sm font-semibold text-white">Delete File</h3>
                <p className="text-[11px] text-gray-400 mt-0.5">This cannot be undone</p>
              </div>
            </div>
            <p className="text-sm text-gray-300 mb-1">
              Are you sure you want to delete:
            </p>
            <p className="text-sm font-semibold text-white bg-gray-800/60 rounded-lg px-3 py-2 mb-2 truncate">
              {confirmDelete.original_name || confirmDelete.filename}
            </p>
            <p className="text-[11px] text-gray-500 mb-5">
              This will permanently remove the file record, all&nbsp;
              <span className="text-white font-medium">{confirmDelete.total_logs}</span> log entries, and&nbsp;
              <span className="text-red-400 font-medium">{confirmDelete.alerts_generated ?? 0}</span> generated alerts.
            </p>
            <div className="flex gap-3">
              <button
                onClick={() => setConfirmDelete(null)}
                className="flex-1 btn-secondary text-sm"
              >
                Cancel
              </button>
              <button
                onClick={handleDelete}
                className="flex-1 bg-red-600 hover:bg-red-500 text-white text-sm font-medium px-4 py-2 rounded-lg transition-colors flex items-center justify-center gap-2"
              >
                <Trash2 size={14} /> Delete
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white">Log File Upload & Analysis</h1>
        <p className="text-sm text-gray-400 mt-1">
          Upload log files for threat detection and analysis
        </p>
      </div>

      {/* Overview stats — only shown when files exist */}
      {uploadStats && uploadStats.total_files > 0 && (
        <div className="card border border-violet-500/20">
          <div className="flex items-center gap-2 mb-4">
            <BarChart3 size={18} className="text-violet-400" />
            <h3 className="text-sm font-semibold text-violet-300">Uploaded Files Summary</h3>
          </div>

          <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3 mb-4">
            {[
              { label: 'Files',    value: uploadStats.total_files,               color: 'text-violet-400' },
              { label: 'Total Logs', value: uploadStats.total_logs,              color: 'text-white'      },
              { label: 'Alerts',   value: uploadStats.total_alerts,              color: 'text-red-400'    },
              { label: 'Critical', value: uploadStats.by_severity?.critical || 0, color: 'text-red-400'  },
              { label: 'High',     value: uploadStats.by_severity?.high     || 0, color: 'text-orange-400'},
              { label: 'Medium',   value: uploadStats.by_severity?.medium   || 0, color: 'text-yellow-400'},
            ].map(({ label, value, color }) => (
              <div key={label} className="bg-gray-800/50 rounded-lg p-3 text-center">
                <p className={`text-2xl font-bold ${color}`}>{value.toLocaleString()}</p>
                <p className="text-[10px] text-gray-500 mt-1">{label}</p>
              </div>
            ))}
          </div>

          {sourceChartData.length > 0 && (
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div>
                <p className="text-xs text-gray-500 mb-2">Log Sources Breakdown</p>
                <div className="flex flex-wrap gap-2">
                  {Object.entries(uploadStats.by_source || {}).map(([src, count]) => (
                    <span key={src} className="px-3 py-1.5 bg-gray-800/50 rounded-lg text-xs">
                      <span className="text-gray-300 font-medium capitalize">{src}</span>
                      <span className="text-gray-500 ml-1">({count as number})</span>
                    </span>
                  ))}
                </div>
              </div>
              <div className="h-32">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={sourceChartData} cx="50%" cy="50%" innerRadius={30} outerRadius={50} paddingAngle={3} dataKey="value">
                      {sourceChartData.map((_, i) => <Cell key={i} fill={COLORS[i % COLORS.length]} />)}
                    </Pie>
                    <Tooltip contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: '8px', fontSize: '11px' }} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
            </div>
          )}
        </div>
      )}

      {/* Format picker */}
      <div className="card">
        <h3 className="text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2">
          <FileText size={16} className="text-violet-400" />
          Log Format
        </h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
          {formats.map((fmt: any) => (
            <button
              key={fmt.id}
              onClick={() => setSelectedFormat(fmt.id)}
              className={`p-3 rounded-lg border text-left transition-all ${
                selectedFormat === fmt.id
                  ? 'border-violet-500 bg-violet-500/10 text-violet-300'
                  : 'border-white/5 bg-gray-800/50 text-gray-400 hover:border-white/10'
              }`}
            >
              <p className="text-xs font-medium">{fmt.name}</p>
              <p className="text-[10px] text-gray-500 mt-0.5">{fmt.description}</p>
            </button>
          ))}
        </div>
      </div>

      {/* Drop zone */}
      <div
        onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
        onDragLeave={() => setDragOver(false)}
        onDrop={handleDrop}
        className={`card border-2 border-dashed transition-all ${
          dragOver ? 'border-violet-500 bg-violet-500/5' : 'border-white/10 hover:border-white/20'
        }`}
      >
        <label className="flex flex-col items-center justify-center py-12 cursor-pointer">
          <input
            type="file"
            className="hidden"
            accept=".xml,.log,.txt,.json,.csv,.ndjson,.evtx"
            onChange={handleFileInput}
            disabled={uploading}
          />
          {uploading ? (
            <>
              <div className="w-12 h-12 border-4 border-violet-500 border-t-transparent rounded-full animate-spin mb-4" />
              <p className="text-sm text-gray-300">Uploading and analysing…</p>
            </>
          ) : (
            <>
              <Upload size={40} className="text-gray-500 mb-4" />
              <p className="text-sm text-gray-300">Drop your log file here or click to browse</p>
              <p className="text-xs text-gray-500 mt-1">Supports: .xml, .log, .txt, .json, .csv (max 50 MB)</p>
            </>
          )}
        </label>
      </div>

      {/* Error banner */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-4 flex items-center gap-3">
          <AlertTriangle size={18} className="text-red-400 flex-shrink-0" />
          <p className="text-sm text-red-300">{error}</p>
          <button onClick={() => setError(null)} className="ml-auto text-gray-500 hover:text-gray-300">
            <X size={16} />
          </button>
        </div>
      )}

      {/* Latest upload result */}
      {result && (
        <div className="card border border-green-500/20 animate-slide-in">
          <div className="flex items-center gap-3 mb-4">
            <CheckCircle size={20} className="text-green-400 flex-shrink-0" />
            <div>
              <h3 className="text-sm font-semibold text-green-300">Analysis Complete — {result.filename}</h3>
              <p className="text-xs text-gray-400">Format detected: {result.format_detected}</p>
            </div>
          </div>
          <div className="grid grid-cols-5 gap-3">
            {[
              { label: 'Log Entries', value: result.total_logs,                      color: 'text-white' },
              { label: 'Alerts',      value: result.alerts_generated,                color: 'text-red-400' },
              { label: 'Critical',    value: result.severity_breakdown?.critical || 0, color: 'text-red-400' },
              { label: 'High',        value: result.severity_breakdown?.high     || 0, color: 'text-orange-400' },
              { label: 'Medium',      value: result.severity_breakdown?.medium   || 0, color: 'text-yellow-400' },
            ].map(({ label, value, color }) => (
              <div key={label} className="bg-gray-800/50 rounded-lg p-3 text-center">
                <p className={`text-2xl font-bold ${color}`}>{value}</p>
                <p className="text-[10px] text-gray-500">{label}</p>
              </div>
            ))}
          </div>
          <div className="flex gap-2 mt-4">
            <button
              onClick={() => viewUploadedLogs(result.upload_session_id, result.filename)}
              className="btn-primary text-xs flex items-center gap-1.5"
            >
              <Eye size={12} /> View Logs ({result.total_logs})
            </button>
            <a href="/alerts" className="btn-secondary text-xs flex items-center gap-1.5">
              <Shield size={12} /> View Alerts ({result.alerts_generated})
            </a>
          </div>
        </div>
      )}

      {/* Inline log viewer */}
      {viewingUpload && (
        <div className="card border border-violet-500/30">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-gray-300 flex items-center gap-2 min-w-0">
              <FileSearch size={16} className="text-violet-400 flex-shrink-0" />
              <span className="truncate">Logs from: <span className="text-violet-300">{viewingFileName}</span></span>
              <span className="text-[10px] px-2 py-0.5 bg-violet-500/20 text-violet-300 rounded-full flex-shrink-0">
                {uploadedLogs.length} entries
              </span>
            </h3>
            <div className="flex gap-2 flex-shrink-0">
              <button onClick={exportLogs} className="btn-secondary text-xs flex items-center gap-1">
                <Download size={12} /> CSV
              </button>
              <button
                onClick={() => { setViewingUpload(null); setUploadedLogs([]) }}
                className="text-gray-500 hover:text-gray-300 p-1"
              >
                <X size={16} />
              </button>
            </div>
          </div>
          <div className="overflow-x-auto max-h-96 overflow-y-auto">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-soc-card z-10">
                <tr className="border-b border-white/5 text-gray-500 text-left">
                  <th className="p-2">Time</th>
                  <th className="p-2">Source</th>
                  <th className="p-2">Type</th>
                  <th className="p-2">Severity</th>
                  <th className="p-2">Message</th>
                  <th className="p-2">IP</th>
                  <th className="p-2">User</th>
                </tr>
              </thead>
              <tbody>
                {uploadedLogs.length === 0 ? (
                  <tr><td colSpan={7} className="text-center p-8 text-gray-500">No logs found</td></tr>
                ) : (
                  uploadedLogs.map((log) => (
                    <tr key={log.id} className="border-b border-white/5 hover:bg-white/5">
                      <td className="p-2 text-gray-400 font-mono whitespace-nowrap">
                        {log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : '-'}
                      </td>
                      <td className="p-2 text-gray-300 font-mono">{log.source}</td>
                      <td className="p-2">
                        <span className="px-1.5 py-0.5 bg-gray-800 rounded text-[10px] text-gray-400">{log.source_type}</span>
                      </td>
                      <td className="p-2">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${sevColor(log.severity)}`}>
                          {log.severity?.toUpperCase()}
                        </span>
                      </td>
                      <td className="p-2 text-gray-300 max-w-xs truncate" title={log.message}>{log.message}</td>
                      <td className="p-2 text-gray-400 font-mono">{log.source_ip || '-'}</td>
                      <td className="p-2 text-gray-400">{log.username || '-'}</td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Upload history */}
      <div className="card">
        <h3 className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">
          <Activity size={16} className="text-gray-400" />
          Upload History
          {uploadStats && (
            <span className="text-[10px] text-gray-500">({uploadStats.total_files} file{uploadStats.total_files !== 1 ? 's' : ''})</span>
          )}
        </h3>

        {!uploadStats || uploadStats.files.length === 0 ? (
          <div className="text-center py-10 text-gray-600">
            <Upload size={32} className="mx-auto mb-3 opacity-30" />
            <p className="text-xs">No files uploaded yet — upload a log file above to begin analysis</p>
          </div>
        ) : (
          <div className="space-y-2">
            {uploadStats.files.map((file) => (
              <div
                key={file.id}
                className="flex items-center justify-between p-3 bg-gray-800/30 rounded-lg border border-white/5 hover:border-white/10 transition-all gap-3"
              >
                {/* File info */}
                <div className="flex items-center gap-3 min-w-0">
                  <File size={16} className="text-violet-400 flex-shrink-0" />
                  <div className="min-w-0">
                    <p className="text-xs text-gray-200 font-medium truncate">
                      {file.original_name || file.filename}
                    </p>
                    <p className="text-[10px] text-gray-500 mt-0.5">
                      {file.log_format}
                      {' · '}<span className="text-white">{file.total_logs}</span> entries
                      {' · '}<span className="text-red-400">{file.alerts_generated ?? 0}</span> alerts
                      {file.file_size ? ` · ${(file.file_size / 1024).toFixed(1)} KB` : ''}
                      {file.created_at ? ` · ${new Date(file.created_at).toLocaleDateString()}` : ''}
                    </p>
                  </div>
                </div>

                {/* Actions */}
                <div className="flex items-center gap-2 flex-shrink-0">
                  <span className={`text-[10px] ${file.status === 'completed' ? 'text-green-400' : 'text-yellow-400'}`}>
                    {file.status}
                  </span>
                  <button
                    onClick={() => viewUploadedLogs(file.upload_session_id || file.id, file.original_name || file.filename || '')}
                    className="btn-secondary text-xs flex items-center gap-1"
                  >
                    <Eye size={12} /> View
                  </button>
                  <button
                    onClick={() => setConfirmDelete(file)}
                    disabled={deletingId === file.id}
                    className={`flex items-center gap-1 text-xs px-2.5 py-1.5 rounded-lg border transition-colors ${
                      deletingId === file.id
                        ? 'bg-gray-800 border-white/5 text-gray-600 cursor-not-allowed'
                        : 'bg-red-500/10 border-red-500/20 text-red-400 hover:bg-red-500/20 hover:border-red-500/40'
                    }`}
                  >
                    {deletingId === file.id ? (
                      <div className="w-3 h-3 border-2 border-gray-600 border-t-transparent rounded-full animate-spin" />
                    ) : (
                      <Trash2 size={12} />
                    )}
                    {deletingId === file.id ? 'Deleting…' : 'Delete'}
                  </button>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

    </div>
  )
}
