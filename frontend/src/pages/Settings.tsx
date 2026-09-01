import { useState, useEffect } from 'react'
import { api } from '../services/api'
import { DetectionRule } from '../types'
import {
  Key, Shield, Database, RefreshCw, CheckCircle, AlertTriangle,
  Trash2, Radio, X, Plus, Copy, Eye, EyeOff, Loader2
} from 'lucide-react'

const sevColor = (s: string) => {
  switch (s) {
    case 'critical': return 'text-red-400 bg-red-500/10 border-red-500/20'
    case 'high':     return 'text-orange-400 bg-orange-500/10 border-orange-500/20'
    case 'medium':   return 'text-yellow-400 bg-yellow-500/10 border-yellow-500/20'
    default:         return 'text-blue-400 bg-blue-500/10 border-blue-500/20'
  }
}

export default function Settings() {
  const [aiStatus, setAiStatus] = useState<any>(null)
  const [rules, setRules]       = useState<DetectionRule[]>([])
  const [loading, setLoading]   = useState(true)
  const [userRole, setUserRole] = useState<string>('')

  // Data management
  const [confirmClear, setConfirmClear] = useState(false)
  const [clearing, setClearing]         = useState(false)
  const [clearResult, setClearResult]   = useState<{ logs: number; alerts: number } | null>(null)
  const [clearError, setClearError]     = useState<string | null>(null)

  // Ingest keys
  const [ingestKeys, setIngestKeys]       = useState<any[]>([])
  const [newKeyName, setNewKeyName]       = useState('')
  const [creatingKey, setCreatingKey]     = useState(false)
  const [newKeyValue, setNewKeyValue]     = useState<string | null>(null)
  const [showNewKey, setShowNewKey]       = useState(true)
  const [revokingKeyId, setRevokingKeyId] = useState<string | null>(null)

  useEffect(() => { load() }, [])

  const load = async () => {
    setLoading(true)
    try {
      const [ai, r, me] = await Promise.all([
        api.ai.getStatus(),
        api.detectionRules.list(),
        api.auth.me(),
      ])
      setAiStatus(ai)
      setRules(r)
      setUserRole(me.role || '')
      if (me.role === 'admin') {
        const keys = await api.auth.listIngestKeys()
        setIngestKeys(keys)
      }
    } catch { /* silent */ }
    finally { setLoading(false) }
  }

  const handleClearLiveLogs = async () => {
    setClearing(true); setClearError(null); setClearResult(null); setConfirmClear(false)
    try {
      const res = await api.data.clearLiveLogs()
      setClearResult({ logs: res.logs_deleted, alerts: res.alerts_deleted })
    } catch (err: any) {
      if (err?.response?.status === 403) setClearError('Permission denied — Admin role required.')
      else setClearError(err?.response?.data?.error || 'Failed to clear logs.')
    } finally { setClearing(false) }
  }

  const handleCreateKey = async () => {
    if (!newKeyName.trim()) return
    setCreatingKey(true)
    try {
      const res = await api.auth.createIngestKey(newKeyName.trim())
      setNewKeyValue(res.key)
      setNewKeyName('')
      setIngestKeys(await api.auth.listIngestKeys())
    } catch { /* silent */ }
    finally { setCreatingKey(false) }
  }

  const handleRevokeKey = async (id: string) => {
    setRevokingKeyId(id)
    try {
      await api.auth.revokeIngestKey(id)
      setIngestKeys(await api.auth.listIngestKeys())
    } catch { /* silent */ }
    finally { setRevokingKeyId(null) }
  }

  const isAdmin = userRole === 'admin'

  const updateRule = async (rule: DetectionRule, data: Parameters<typeof api.detectionRules.update>[1]) => {
    try {
      await api.detectionRules.update(rule.name, data)
      setRules(await api.detectionRules.list())
    } catch { /* silent */ }
  }

  return (
    <div className="space-y-6 animate-fade-in max-w-4xl">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Settings</h1>
          <p className="text-sm text-gray-400 mt-1">Dashboard configuration and system status</p>
        </div>
        <button onClick={load} className="btn-secondary flex items-center gap-1.5">
          <RefreshCw size={12} /> Refresh
        </button>
      </div>

      {/* ── Ingest Keys (Admin only) ── */}
      {isAdmin && (
        <div className="card border border-violet-500/15">
          <h3 className="text-sm font-semibold text-gray-300 mb-1 flex items-center gap-2">
            <Key size={15} className="text-violet-400" /> Ingest Keys
          </h3>
          <p className="text-xs text-gray-500 mb-4">
            API keys used by log forwarder agents via the{' '}
            <code className="bg-gray-800 px-1 rounded font-mono text-[10px]">X-Ingest-Key</code> header.
            Keys are shown only once on creation.
          </p>

          {newKeyValue && (
            <div className="mb-4 p-3 bg-green-500/8 border border-green-500/20 rounded-lg">
              <p className="text-xs text-green-300 font-medium mb-2">
                ✅ New key created — copy it now, it cannot be retrieved again:
              </p>
              <div className="flex items-center gap-2">
                <code className="flex-1 text-[11px] font-mono bg-black/40 px-3 py-2 rounded text-green-200 break-all">
                  {showNewKey ? newKeyValue : '•'.repeat(Math.min(newKeyValue.length, 48))}
                </code>
                <button onClick={() => setShowNewKey(v => !v)} className="text-gray-500 hover:text-gray-300 p-1">
                  {showNewKey ? <EyeOff size={14} /> : <Eye size={14} />}
                </button>
                <button onClick={() => navigator.clipboard.writeText(newKeyValue)}
                  className="text-gray-500 hover:text-green-400 p-1" title="Copy">
                  <Copy size={14} />
                </button>
                <button onClick={() => setNewKeyValue(null)} className="text-gray-500 hover:text-gray-300 p-1">
                  <X size={14} />
                </button>
              </div>
              <p className="text-[10px] text-gray-500 mt-2">
                In forwarder: <code className="bg-gray-800 px-1 rounded">INGEST_KEY={newKeyValue.slice(0, 20)}…</code>
              </p>
            </div>
          )}

          <div className="flex gap-2 mb-4">
            <input type="text" placeholder="Key name (e.g. windows-forwarder-01)"
              value={newKeyName} onChange={e => setNewKeyName(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && handleCreateKey()}
              className="input flex-1 text-xs" />
            <button onClick={handleCreateKey} disabled={!newKeyName.trim() || creatingKey}
              className="btn-primary text-xs flex items-center gap-1.5 disabled:opacity-60">
              {creatingKey ? <Loader2 size={12} className="animate-spin" /> : <Plus size={12} />}
              Generate
            </button>
          </div>

          {ingestKeys.length === 0 ? (
            <p className="text-xs text-gray-600 text-center py-3">No ingest keys yet.</p>
          ) : (
            <div className="space-y-2">
              {ingestKeys.map((k: any) => (
                <div key={k.id} className={`flex items-center gap-3 p-3 rounded-lg border ${
                  k.revoked_at ? 'border-white/5 bg-gray-800/20 opacity-50' : 'border-white/10 bg-gray-800/30'
                }`}>
                  <div className="flex-1 min-w-0">
                    <p className="text-xs text-gray-200 font-medium truncate">{k.name}</p>
                    <p className="text-[10px] text-gray-500 mt-0.5">
                      Created {k.created_at ? new Date(k.created_at).toLocaleDateString() : '—'}
                      {k.last_used_at && ` · Last used ${new Date(k.last_used_at).toLocaleString()}`}
                      {k.revoked_at && <span className="text-red-400"> · Revoked</span>}
                    </p>
                  </div>
                  <span className={`text-[10px] px-2 py-0.5 rounded-full border ${
                    k.revoked_at ? 'border-red-500/20 text-red-400 bg-red-500/10' :
                    k.is_active  ? 'border-green-500/20 text-green-400 bg-green-500/10' :
                                   'border-gray-500/20 text-gray-400'
                  }`}>
                    {k.revoked_at ? 'Revoked' : k.is_active ? 'Active' : 'Inactive'}
                  </span>
                  {!k.revoked_at && (
                    <button onClick={() => handleRevokeKey(k.id)} disabled={revokingKeyId === k.id}
                      className="text-gray-500 hover:text-red-400 p-1 disabled:opacity-50" title="Revoke">
                      {revokingKeyId === k.id ? <Loader2 size={13} className="animate-spin" /> : <Trash2 size={13} />}
                    </button>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ── Data Management ── */}
      <div className="card border border-red-500/15">
        <h3 className="text-sm font-semibold text-gray-300 mb-1 flex items-center gap-2">
          <Database size={15} className="text-red-400" /> Data Management
          {!isAdmin && <span className="text-[10px] text-gray-600">(Admin only)</span>}
        </h3>
        <p className="text-xs text-gray-500 mb-4">
          Manage logs collected by the forwarder. Uploaded file logs are never affected.
        </p>

        {clearResult && (
          <div className="flex items-start gap-3 mb-4 p-3 bg-green-500/8 border border-green-500/20 rounded-lg">
            <CheckCircle size={16} className="text-green-400 shrink-0 mt-0.5" />
            <div className="flex-1">
              <p className="text-xs font-semibold text-green-300">Cleared successfully</p>
              <p className="text-[11px] text-gray-400 mt-0.5">
                Removed <span className="text-white font-medium">{clearResult.logs.toLocaleString()}</span> live
                log{clearResult.logs !== 1 ? 's' : ''} and{' '}
                <span className="text-white font-medium">{clearResult.alerts}</span> alert{clearResult.alerts !== 1 ? 's' : ''}.
              </p>
              <p className="text-[11px] text-green-400 mt-1 flex items-center gap-1">
                <Radio size={10} className="animate-pulse" /> Forwarder will resume on next cycle.
              </p>
            </div>
            <button onClick={() => setClearResult(null)} className="text-gray-600 hover:text-gray-400">
              <X size={14} />
            </button>
          </div>
        )}

        {clearError && (
          <div className="flex items-center gap-3 mb-4 p-3 bg-red-500/8 border border-red-500/20 rounded-lg">
            <AlertTriangle size={16} className="text-red-400 shrink-0" />
            <p className="text-xs text-red-300 flex-1">{clearError}</p>
            <button onClick={() => setClearError(null)} className="text-gray-600 hover:text-gray-400"><X size={14} /></button>
          </div>
        )}

        <div className="flex items-center justify-between p-4 bg-gray-800/30 rounded-xl border border-white/5">
          <div className="flex items-start gap-3">
            <div className="w-9 h-9 bg-red-500/10 rounded-lg flex items-center justify-center shrink-0">
              <Trash2 size={17} className="text-red-400" />
            </div>
            <div>
              <p className="text-sm font-semibold text-gray-200">Clear Live Ingested Logs</p>
              <p className="text-[11px] text-gray-500 mt-0.5 max-w-sm">
                Permanently deletes all forwarder logs and associated alerts. The forwarder resumes automatically.
              </p>
            </div>
          </div>

          {!isAdmin ? (
            <span className="text-xs text-gray-600 ml-4">Admin only</span>
          ) : !confirmClear ? (
            <button onClick={() => { setConfirmClear(true); setClearResult(null); setClearError(null) }}
              disabled={clearing}
              className="btn-danger flex items-center gap-1.5 ml-4 shrink-0">
              {clearing
                ? <><span className="w-3 h-3 border-2 border-white/40 border-t-white rounded-full animate-spin" /> Clearing…</>
                : <><Trash2 size={13} /> Clear All Logs</>}
            </button>
          ) : (
            <div className="flex items-center gap-2 ml-4 shrink-0">
              <span className="text-[11px] text-red-300 font-medium">Sure?</span>
              <button onClick={handleClearLiveLogs}
                className="bg-red-600 hover:bg-red-500 text-white text-xs font-semibold px-3 py-1.5 rounded-lg flex items-center gap-1.5">
                <Trash2 size={12} /> Yes, delete
              </button>
              <button onClick={() => setConfirmClear(false)} className="btn-secondary text-xs flex items-center gap-1.5">
                <X size={12} /> Cancel
              </button>
            </div>
          )}
        </div>
      </div>

      {/* ── AI Engine ── */}
      <div className="card">
        <h3 className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">
          <Key size={15} className="text-violet-400" /> AI Engine Status
        </h3>
        {loading ? <p className="text-xs text-gray-500">Loading…</p> : aiStatus ? (
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-xs text-gray-400">Status</span>
              <span className={`flex items-center gap-1.5 text-xs ${aiStatus.available ? 'text-green-400' : 'text-yellow-400'}`}>
                {aiStatus.available
                  ? <><CheckCircle size={12} /> Active — Live AI</>
                  : <><AlertTriangle size={12} /> Mock Mode (DB-aware)</>}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-xs text-gray-400">Model</span>
              <span className="text-xs text-gray-300 font-mono">{aiStatus.model}</span>
            </div>
            <p className="text-xs text-gray-500">{aiStatus.message}</p>
            {!aiStatus.available && (
              <div className="bg-yellow-500/5 border border-yellow-500/20 rounded-lg p-3">
                <p className="text-xs text-yellow-300 mb-2">
                  To enable live AI, add your key to <code className="bg-gray-800 px-1 rounded font-mono">backend/.env</code>:
                </p>
                <code className="text-[11px] text-gray-400 block font-mono bg-black/40 p-2 rounded">
                  OPENAI_API_KEY=sk-your-key-here{'\n'}OPENAI_MODEL=gpt-4o-mini
                </code>
              </div>
            )}
          </div>
        ) : null}
      </div>

      {/* ── Detection Rules ── */}
      <div className="card">
        <h3 className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">
          <Shield size={15} className="text-blue-400" /> Detection Rules
          <span className="text-[10px] text-gray-500">({rules.filter(rule => rule.enabled).length} active / {rules.length})</span>
        </h3>
        <div className="space-y-2">
          {rules.map(rule => (
            <div key={rule.name} className="p-3 bg-gray-800/30 rounded-lg border border-white/5 hover:border-white/10 transition-all">
              <div className="flex items-center gap-2 mb-1 flex-wrap">
                <span className={`text-[10px] font-semibold px-2 py-0.5 rounded border ${sevColor(rule.severity)}`}>
                  {rule.severity?.toUpperCase()}
                </span>
                <span className={`text-[10px] px-2 py-0.5 rounded border ${rule.enabled ? 'text-green-400 border-green-500/20 bg-green-500/10' : 'text-gray-500 border-white/10'}`}>
                  {rule.enabled ? 'Enabled' : 'Disabled'}
                </span>
                <span className="text-[10px] text-gray-500">{rule.category}</span>
                {isAdmin && <button onClick={() => updateRule(rule, { enabled: !rule.enabled })}
                  className="ml-auto text-[10px] text-blue-400 hover:text-blue-300">
                  {rule.enabled ? 'Disable' : 'Enable'}
                </button>}
                {rule.confidence !== undefined && (
                  <span className="text-[10px] text-gray-500">Confidence: {rule.confidence}%</span>
                )}
              </div>
              <p className="text-xs text-gray-200 font-mono font-medium">{rule.name}</p>
              <p className="text-[11px] text-gray-500 mt-0.5">{rule.description}</p>
              <div className="grid grid-cols-2 gap-2 mt-2 text-[10px] text-gray-500">
                <span>Trigger count: <b className="text-gray-300">{rule.trigger_count}</b></span>
                <span>Last triggered: <b className="text-gray-300">{rule.last_triggered ? new Date(rule.last_triggered).toLocaleString() : 'Never'}</b></span>
                <span>Threshold: <b className="text-gray-300">{rule.threshold ?? 'Event-based'}</b></span>
                <span>Window: <b className="text-gray-300">{rule.time_window_seconds ? `${rule.time_window_seconds}s` : 'Event-based'}</b></span>
                <span>Created: <b className="text-gray-300">{rule.created_at ? new Date(rule.created_at).toLocaleString() : '—'}</b></span>
                <span>Updated: <b className="text-gray-300">{rule.updated_at ? new Date(rule.updated_at).toLocaleString() : '—'}</b></span>
              </div>
              {isAdmin && rule.supported_configuration && (
                <div className="flex items-center gap-2 mt-2">
                  <label className="text-[10px] text-gray-500">Threshold</label>
                  <input type="number" min={1} max={100000} defaultValue={rule.threshold ?? undefined}
                    onBlur={event => updateRule(rule, { threshold: Number(event.target.value) })}
                    className="input w-20 py-1 text-[10px]" />
                  <label className="text-[10px] text-gray-500">Window (s)</label>
                  <input type="number" min={1} max={86400} defaultValue={rule.time_window_seconds ?? undefined}
                    onBlur={event => updateRule(rule, { time_window_seconds: Number(event.target.value) })}
                    className="input w-20 py-1 text-[10px]" />
                </div>
              )}
              {rule.kill_chain_phase && (
                <p className="text-[10px] text-gray-600 mt-0.5">
                  Phase: <span className="text-gray-400">{rule.kill_chain_phase}</span>
                </p>
              )}
              {rule.mitre_techniques && rule.mitre_techniques.length > 0 && (
                <div className="flex flex-wrap gap-1 mt-1.5">
                  {rule.mitre_techniques.map((t: string, j: number) => (
                    <span key={j} className="text-[9px] px-1.5 py-0.5 bg-violet-500/10 text-violet-400 rounded border border-violet-500/20">
                      {t}
                    </span>
                  ))}
                </div>
              )}
            </div>
          ))}
        </div>
      </div>

      {/* ── System Info ── */}
      <div className="card">
        <h3 className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">
          <Database size={15} className="text-green-400" /> System Information
        </h3>
        <div className="grid grid-cols-2 gap-3">
          {[
            { label: 'Backend',  value: 'Flask 3.1 + SQLite (WAL mode)' },
            { label: 'Frontend', value: 'React 18 + Vite 5 + Tailwind 3' },
            { label: 'Auth',     value: 'DB sessions · SHA-256 token hash' },
            { label: 'Ingest',   value: 'X-Ingest-Key · constant-time check' },
            { label: 'Detection',value: `${rules.length} rules — threshold-based` },
            { label: 'AI',       value: aiStatus?.available ? `Live · ${aiStatus.model}` : 'Mock (DB-aware)' },
          ].map(({ label, value }) => (
            <div key={label} className="bg-gray-800/30 rounded-lg p-3">
              <p className="text-[10px] text-gray-500">{label}</p>
              <p className="text-xs text-gray-300 font-mono mt-1">{value}</p>
            </div>
          ))}
        </div>
      </div>

    </div>
  )
}
