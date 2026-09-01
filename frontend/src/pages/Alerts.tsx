import { useEffect, useState, useCallback, useRef } from 'react'
import axios from 'axios'
import { api, getSocketUrl } from '../services/api'
import { Alert, AIAnalysis, InvestigationContext, AlertCorrelation } from '../types'
import {
  AlertTriangle, Shield, Search, X, Brain, ShieldAlert, User, Server,
  ArrowUpRight, Zap, Loader2, ExternalLink, Tag, Link2, RefreshCw,
  CheckCircle, XCircle, HelpCircle, AlertCircle
} from 'lucide-react'
import { io, Socket } from 'socket.io-client'

// ── Severity styling ──────────────────────────────────────────────────────────
const severityColors: Record<string, string> = {
  critical: 'border-red-500/30 bg-red-500/5',
  high:     'border-orange-500/30 bg-orange-500/5',
  medium:   'border-yellow-500/30 bg-yellow-500/5',
  low:      'border-blue-500/30 bg-blue-500/5',
  info:     'border-green-500/30 bg-green-500/5',
}

// ── FP classification config ──────────────────────────────────────────────────
const FP_OPTIONS = [
  { value: 'TRUE_POSITIVE',       label: 'True Positive',        icon: CheckCircle, color: 'text-red-400',    bg: 'bg-red-500/10 border-red-500/20' },
  { value: 'FALSE_POSITIVE',      label: 'False Positive',       icon: XCircle,     color: 'text-gray-400',  bg: 'bg-gray-500/10 border-gray-500/20' },
  { value: 'BENIGN',              label: 'Benign',               icon: Shield,      color: 'text-green-400', bg: 'bg-green-500/10 border-green-500/20' },
  { value: 'NEEDS_INVESTIGATION', label: 'Needs Investigation',  icon: HelpCircle,  color: 'text-yellow-400',bg: 'bg-yellow-500/10 border-yellow-500/20' },
] as const

function FpBadge({ classification }: { classification: string }) {
  const opt = FP_OPTIONS.find(o => o.value === classification)
  if (!opt) return null
  const Icon = opt.icon
  return (
    <span className={`inline-flex items-center gap-1 text-[10px] font-semibold px-2 py-0.5 rounded-full border ${opt.bg} ${opt.color}`}>
      <Icon size={10} />{opt.label}
    </span>
  )
}

// ── MITRE tactic extraction ───────────────────────────────────────────────────
function parseMitre(techniques: string[]): { id: string; name: string; tactic: string }[] {
  return (techniques || []).map(t => {
    const match = t.match(/^(T\d+(?:\.\d+)?)\s*[-–]\s*(.+?)(?:\s*:\s*(.+))?$/)
    if (match) {
      const hasSubtactic = match[3]
      return {
        id:     match[1],
        tactic: hasSubtactic ? match[2] : '',
        name:   hasSubtactic ? match[3] : match[2],
      }
    }
    return { id: '', tactic: '', name: t }
  })
}

export default function Alerts() {
  const [alerts, setAlerts]                     = useState<Alert[]>([])
  const [loading, setLoading]                   = useState(true)
  const [selectedAlert, setSelectedAlert]       = useState<Alert | null>(null)
  const [aiAnalysis, setAiAnalysis]             = useState<AIAnalysis | null>(null)
  const [investigationContext, setInvestigationContext] = useState<InvestigationContext | null>(null)
  const [correlations, setCorrelations]         = useState<AlertCorrelation[]>([])
  const [loadingDetail, setLoadingDetail]       = useState(false)
  const [detailError, setDetailError]           = useState<string | null>(null)
  const [loadingAI, setLoadingAI]               = useState(false)
  const [loadingContext, setLoadingContext]      = useState(false)
  const [loadingCorrelations, setLoadingCorrelations] = useState(false)
  const [filter, setFilter]                     = useState<string>('all')
  const [search, setSearch]                     = useState('')
  const [escalating, setEscalating]             = useState(false)
  const [escalatedIncident, setEscalatedIncident] = useState<{id: string; title: string; ai_generated: boolean} | null>(null)

  // FP classification
  const [showClassify, setShowClassify]         = useState(false)
  const [classifyValue, setClassifyValue]       = useState('')
  const [classifyReason, setClassifyReason]     = useState('')
  const [classifying, setClassifying]           = useState(false)
  const [classifyError, setClassifyError]       = useState<string | null>(null)

  // Real-time
  const socketRef = useRef<Socket | null>(null)
  const selectedAlertRef = useRef<Alert | null>(null)
  selectedAlertRef.current = selectedAlert

  // ── WebSocket setup ─────────────────────────────────────────────────────────
  useEffect(() => {
    const token = localStorage.getItem('token')
    if (!token) return

    const socket = io(getSocketUrl(), {
      auth: { token },
      transports: ['websocket', 'polling'],
      reconnectionAttempts: 5,
    })
    socketRef.current = socket

    socket.on('new_alert', (data: any) => {
      // Prepend new alert to list
      setAlerts(prev => {
        const exists = prev.find(a => a.id === data.id)
        if (exists) return prev
        const newAlert: Alert = {
          id: data.id,
          title: data.title,
          severity: data.severity,
          status: 'new',
          rule_name: data.rule_name,
          created_at: new Date().toISOString(),
        }
        return [newAlert, ...prev]
      })
    })

    socket.on('alert_update', (data: any) => {
      setAlerts(prev => prev.map(a => a.id === data.id ? { ...a, status: data.status } : a))
      if (selectedAlertRef.current?.id === data.id) {
        setSelectedAlert(prev => prev ? { ...prev, status: data.status } : prev)
      }
    })

    socket.on('alert_triage_complete', (data: any) => {
      setAlerts(prev => prev.map(a =>
        a.id === data.alert_id
          ? { ...a, threat_score: data.threat_score, ai_triage_status: 'completed' }
          : a
      ))
      if (selectedAlertRef.current?.id === data.alert_id && aiAnalysis === null) {
        // Refresh AI analysis if the triage just finished
        api.alerts.getAIAnalysis(data.alert_id).then(setAiAnalysis).catch(() => {})
      }
    })

    return () => { socket.disconnect() }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  // ── Initial load + polling fallback ────────────────────────────────────────
  useEffect(() => {
    loadAlerts()
    const interval = setInterval(loadAlerts, 30000) // reduced from 10s since WS handles real-time
    return () => clearInterval(interval)
  }, [filter]) // eslint-disable-line react-hooks/exhaustive-deps

  const loadAlerts = useCallback(async () => {
    try {
      const params: any = { limit: 100, hide_closed: 'true' }
      if (filter !== 'all') params.severity = filter
      const data = await api.alerts.list(params)
      setAlerts(data)
    } catch (error) {
      console.error('Failed to load alerts:', error)
    } finally {
      setLoading(false)
    }
  }, [filter])

  // ── Select alert ────────────────────────────────────────────────────────────
  const handleSelectAlert = async (alert: Alert) => {
    setSelectedAlert(alert)
    setAiAnalysis(null)
    setInvestigationContext(null)
    setCorrelations([])
    setDetailError(null)
    setEscalatedIncident(null)
    setEscalating(false)
    setShowClassify(false)
    setClassifyValue('')
    setClassifyReason('')
    setClassifyError(null)
    setLoadingAI(true)
    setLoadingContext(true)
    setLoadingCorrelations(true)
    setLoadingDetail(true)

    try {
      const [fullAlert, context, corrs] = await Promise.all([
        api.alerts.get(alert.id),
        api.alerts.getInvestigationContext(alert.id),
        api.alerts.getCorrelations(alert.id),
      ])
      setSelectedAlert(fullAlert)
      setInvestigationContext(context)
      setCorrelations(corrs.correlations || [])

      if (fullAlert.ai_analysis && Object.keys(fullAlert.ai_analysis).length > 0) {
        setAiAnalysis(fullAlert.ai_analysis)
      } else {
        const analysis = await api.alerts.getAIAnalysis(alert.id)
        setAiAnalysis(analysis)
      }
    } catch (error: unknown) {
      const status = axios.isAxiosError(error) ? error.response?.status : undefined
      setDetailError(
        status === 401 || status === 403 ? 'Access denied.' :
        status === 404 ? 'Alert not found.' :
        'Unable to load alert investigation.'
      )
    } finally {
      setLoadingDetail(false)
      setLoadingAI(false)
      setLoadingContext(false)
      setLoadingCorrelations(false)
    }
  }

  // ── Status update ───────────────────────────────────────────────────────────
  const handleStatusUpdate = async (alertId: string, status: Alert['status']) => {
    if (!selectedAlert) return
    const prompt = status === 'resolved'
      ? 'Resolve this alert?\nEnter a reason:'
      : `Change alert status to ${status.toUpperCase()}?\nEnter a reason:`
    const reason = window.prompt(prompt)
    if (reason === null || !reason.trim()) return
    if (!window.confirm(`Confirm status change to ${status.toUpperCase()}?`)) return

    try {
      await api.alerts.updateStatus(alertId, status, reason.trim())
      const closedStatuses = ['resolved', 'false_positive']
      if (closedStatuses.includes(status)) {
        setAlerts(prev => prev.filter(a => a.id !== alertId))
        if (selectedAlert?.id === alertId) {
          setSelectedAlert(null)
          setAiAnalysis(null)
          setInvestigationContext(null)
        }
      } else {
        setAlerts(prev => prev.map(a => a.id === alertId ? { ...a, status } : a))
        if (selectedAlert?.id === alertId)
          setSelectedAlert(prev => prev ? { ...prev, status } : prev)
      }
      window.dispatchEvent(new CustomEvent('soc:alert-updated'))
    } catch (error) {
      console.error('Failed to update status:', error)
    }
  }

  // ── FP Classification ───────────────────────────────────────────────────────
  const handleClassify = async () => {
    if (!selectedAlert || !classifyValue || !classifyReason.trim()) return
    setClassifying(true)
    setClassifyError(null)
    try {
      const result = await api.alerts.classify(selectedAlert.id, classifyValue, classifyReason.trim())
      setSelectedAlert(prev => prev ? {
        ...prev,
        fp_classification: result.classification,
        fp_classified_by: result.classified_by,
        fp_classified_at: result.classified_at,
        fp_reason: result.reason,
        status: result.status_changed ? result.new_status : prev.status,
      } : prev)
      if (result.status_changed) {
        setAlerts(prev => prev.filter(a => a.id !== selectedAlert.id))
        window.dispatchEvent(new CustomEvent('soc:alert-updated'))
      }
      setShowClassify(false)
      setClassifyValue('')
      setClassifyReason('')
    } catch (err: any) {
      setClassifyError(err?.response?.data?.error || 'Classification failed.')
    } finally {
      setClassifying(false)
    }
  }

  // ── Escalate ────────────────────────────────────────────────────────────────
  const handleEscalate = async () => {
    if (!selectedAlert || escalating) return
    setEscalating(true)
    setEscalatedIncident(null)
    try {
      const result = await api.alerts.escalate(selectedAlert.id)
      setEscalatedIncident({
        id: result.incident_id,
        title: result.title || 'Incident created',
        ai_generated: result.ai_generated,
      })
      setAlerts(prev => prev.map(a =>
        a.id === selectedAlert.id ? { ...a, status: 'escalated' } : a
      ))
      if (selectedAlert)
        setSelectedAlert(prev => prev ? { ...prev, status: 'escalated' } : prev)
      window.dispatchEvent(new CustomEvent('soc:alert-updated'))
    } catch (error: any) {
      if (error?.response?.status === 403)
        alert('You do not have permission to escalate alerts.')
      else
        console.error('Failed to escalate:', error)
    } finally {
      setEscalating(false)
    }
  }

  const filteredAlerts = alerts.filter(a =>
    !search ||
    a.title.toLowerCase().includes(search.toLowerCase()) ||
    a.source_ip?.includes(search) ||
    a.rule_name?.toLowerCase().includes(search.toLowerCase())
  )

  const mitreParsed = parseMitre(selectedAlert?.mitre_techniques || [])

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Security Alerts</h1>
          <p className="text-sm text-gray-400 mt-1">
            {filteredAlerts.length} alerts • AI-powered analysis
          </p>
        </div>
        <button onClick={loadAlerts} className="btn-secondary text-xs flex items-center gap-1.5">
          <RefreshCw size={12} /> Refresh
        </button>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-4 flex-wrap">
        <div className="flex gap-2">
          {['all', 'critical', 'high', 'medium', 'low'].map((sev) => (
            <button
              key={sev}
              onClick={() => setFilter(sev)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                filter === sev ? 'bg-violet-600 text-white' : 'bg-gray-800 text-gray-400 hover:bg-gray-700'
              }`}
            >
              {sev === 'all' ? 'All' : sev.charAt(0).toUpperCase() + sev.slice(1)}
            </button>
          ))}
        </div>
        <div className="relative flex-1 max-w-xs">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
          <input
            type="text"
            placeholder="Search alerts..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="input pl-9 w-full"
          />
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-5 gap-6">
        {/* Alert List */}
        <div className="lg:col-span-2 space-y-2 max-h-[80vh] overflow-y-auto pr-1">
          {loading ? (
            <div className="text-center py-8 text-gray-500 text-sm">Loading alerts...</div>
          ) : filteredAlerts.length === 0 ? (
            <div className="text-center py-8 text-gray-500 text-sm">No alerts found</div>
          ) : (
            filteredAlerts.map((alert) => (
              <div
                key={alert.id}
                onClick={() => handleSelectAlert(alert)}
                className={`p-3 rounded-lg border cursor-pointer transition-all hover:border-white/20 ${
                  severityColors[alert.severity] || ''
                } ${selectedAlert?.id === alert.id ? 'ring-1 ring-violet-500' : ''}`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1 flex-wrap">
                      <span className={`badge-${alert.severity} text-[10px]`}>
                        {alert.severity?.toUpperCase()}
                      </span>
                      <span className="text-[10px] text-gray-500">{alert.status}</span>
                      {alert.fp_classification && (
                        <FpBadge classification={alert.fp_classification} />
                      )}
                    </div>
                    <p className="text-xs text-gray-200 font-medium truncate">{alert.title}</p>
                    <div className="flex items-center gap-3 mt-1">
                      {alert.source_ip && (
                        <span className="text-[10px] text-gray-500 font-mono">{alert.source_ip}</span>
                      )}
                      {alert.threat_score !== undefined && alert.threat_score > 0 && (
                        <span className={`text-[10px] ${alert.threat_score > 70 ? 'text-red-400' : 'text-yellow-400'}`}>
                          Score: {alert.threat_score}
                        </span>
                      )}
                    </div>
                  </div>
                  <span className="text-[10px] text-gray-600 flex-shrink-0">
                    {alert.created_at ? new Date(alert.created_at).toLocaleTimeString() : ''}
                  </span>
                </div>
              </div>
            ))
          )}
        </div>

        {/* Alert Detail Panel */}
        <div className="lg:col-span-3">
          {loadingDetail ? (
            <div className="card flex items-center justify-center h-64 text-gray-400 text-sm gap-2">
              <Loader2 size={16} className="animate-spin" /> Loading alert investigation...
            </div>
          ) : detailError ? (
            <div className="card flex items-center justify-center h-64 text-center text-red-400 text-sm">{detailError}</div>
          ) : selectedAlert ? (
            <div className="card space-y-4 max-h-[80vh] overflow-y-auto">

              {/* Header */}
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-2 flex-wrap">
                    <span className={`badge-${selectedAlert.severity}`}>
                      {selectedAlert.severity?.toUpperCase()}
                    </span>
                    <span className="badge bg-gray-700 text-gray-300">{selectedAlert.status}</span>
                    {selectedAlert.confidence !== undefined && (
                      <span className="badge bg-blue-500/20 text-blue-400">
                        Confidence: {selectedAlert.confidence}%
                      </span>
                    )}
                    {selectedAlert.threat_score !== undefined && selectedAlert.threat_score > 0 && (
                      <span className={`badge ${selectedAlert.threat_score > 70 ? 'bg-red-500/20 text-red-400' : 'bg-yellow-500/20 text-yellow-400'}`}>
                        Threat: {selectedAlert.threat_score}/100
                      </span>
                    )}
                    {selectedAlert.fp_classification && (
                      <FpBadge classification={selectedAlert.fp_classification} />
                    )}
                  </div>
                  <p className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">Alert Summary</p>
                  <h2 className="text-lg font-bold text-white">{selectedAlert.title}</h2>
                  <p className="text-sm text-gray-400 mt-1">{selectedAlert.description}</p>
                  <p className="text-[10px] text-gray-500 mt-2 font-mono">ID: {selectedAlert.id}</p>
                  <p className="text-[10px] text-gray-500 mt-1">
                    Detected: {selectedAlert.detection?.detection_timestamp
                      ? new Date(selectedAlert.detection.detection_timestamp).toLocaleString()
                      : 'Unavailable'}
                  </p>
                </div>
                <button onClick={() => setSelectedAlert(null)} className="text-gray-500 hover:text-gray-300 ml-2">
                  <X size={18} />
                </button>
              </div>

              {/* FP Classification display */}
              {selectedAlert.fp_classification && (
                <div className="bg-gray-800/40 rounded-lg p-3 border border-white/5">
                  <p className="text-[10px] text-gray-500 uppercase mb-1">Analyst Classification</p>
                  <div className="flex items-center gap-2 flex-wrap">
                    <FpBadge classification={selectedAlert.fp_classification} />
                    {selectedAlert.fp_reason && (
                      <span className="text-xs text-gray-300">"{selectedAlert.fp_reason}"</span>
                    )}
                  </div>
                  {selectedAlert.fp_classified_by && (
                    <p className="text-[10px] text-gray-500 mt-1">
                      by {selectedAlert.fp_classified_by}
                      {selectedAlert.fp_classified_at && ` · ${new Date(selectedAlert.fp_classified_at).toLocaleString()}`}
                    </p>
                  )}
                </div>
              )}

              {/* Source Context */}
              <p className="text-xs text-gray-500 uppercase tracking-wider border-t border-white/5 pt-4">Source Context</p>
              <div className="grid grid-cols-2 gap-3">
                {selectedAlert.rule_name && (
                  <div className="bg-gray-800/50 rounded-lg p-3">
                    <p className="text-[10px] text-gray-500 uppercase">Detection Rule</p>
                    <p className="text-sm text-gray-200 font-mono mt-1">{selectedAlert.rule_name}</p>
                  </div>
                )}
                {selectedAlert.source_ip && (
                  <div className="bg-gray-800/50 rounded-lg p-3">
                    <p className="text-[10px] text-gray-500 uppercase">Source IP</p>
                    <p className="text-sm text-gray-200 font-mono mt-1">{selectedAlert.source_ip}</p>
                  </div>
                )}
                {selectedAlert.username && (
                  <div className="bg-gray-800/50 rounded-lg p-3">
                    <p className="text-[10px] text-gray-500 uppercase flex items-center gap-1"><User size={10} /> User</p>
                    <p className="text-sm text-gray-200 mt-1">{selectedAlert.username}</p>
                  </div>
                )}
                {selectedAlert.hostname && (
                  <div className="bg-gray-800/50 rounded-lg p-3">
                    <p className="text-[10px] text-gray-500 uppercase flex items-center gap-1"><Server size={10} /> Host</p>
                    <p className="text-sm text-gray-200 mt-1">{selectedAlert.hostname}</p>
                  </div>
                )}
                {selectedAlert.destination_ip && (
                  <div className="bg-gray-800/50 rounded-lg p-3">
                    <p className="text-[10px] text-gray-500 uppercase">Destination IP</p>
                    <p className="text-sm text-gray-200 font-mono mt-1">{selectedAlert.destination_ip}</p>
                  </div>
                )}
                {selectedAlert.kill_chain_phase && (
                  <div className="bg-gray-800/50 rounded-lg p-3">
                    <p className="text-[10px] text-gray-500 uppercase">Kill Chain Phase</p>
                    <p className="text-sm text-gray-200 mt-1">{selectedAlert.kill_chain_phase}</p>
                  </div>
                )}
              </div>

              {/* Rule-Based Detection */}
              {selectedAlert.detection && (
                <div className="border-t border-white/5 pt-4">
                  <p className="text-xs text-gray-500 uppercase tracking-wider mb-2">Rule-Based Detection</p>
                  <div className="grid grid-cols-2 gap-3 text-xs">
                    <span className="text-gray-500">Rule <b className="text-gray-200 font-mono">{selectedAlert.detection.rule || 'N/A'}</b></span>
                    <span className="text-gray-500">Category <b className="text-gray-200">{selectedAlert.detection.category || 'N/A'}</b></span>
                    <span className="text-gray-500">Threshold <b className="text-gray-200">{selectedAlert.detection.threshold ?? 'Event-based'}</b></span>
                    <span className="text-gray-500">Confidence <b className="text-gray-200">{selectedAlert.detection.confidence ?? 'N/A'}{selectedAlert.detection.confidence != null ? '%' : ''}</b></span>
                  </div>
                </div>
              )}

              {/* MITRE ATT&CK */}
              {mitreParsed.length > 0 && (
                <div className="border-t border-white/5 pt-4">
                  <p className="text-xs text-gray-500 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                    <Tag size={12} className="text-violet-400" /> MITRE ATT&CK — Rule Detection Only
                  </p>
                  <div className="flex flex-wrap gap-2">
                    {mitreParsed.map((tech, i) => (
                      <div key={i} className="flex flex-col px-2.5 py-1.5 bg-violet-500/10 rounded-lg border border-violet-500/20">
                        {tech.id && <span className="text-[10px] font-mono text-violet-300 font-bold">{tech.id}</span>}
                        {tech.tactic && <span className="text-[9px] text-violet-500">{tech.tactic}</span>}
                        <span className="text-[10px] text-violet-200">{tech.name}</span>
                      </div>
                    ))}
                  </div>
                  <p className="text-[10px] text-gray-600 mt-2">
                    Techniques shown are from the triggered detection rule. AI Assessment may suggest additional context.
                  </p>
                </div>
              )}

              {/* Observed Evidence */}
              {selectedAlert.evidence_trace && (
                <div className="border-t border-white/5 pt-4">
                  <p className="text-xs text-gray-500 mb-2 flex items-center gap-1.5 uppercase tracking-wider">
                    <Shield size={12} className="text-blue-400" /> Observed Evidence
                  </p>
                  <p className="text-[10px] text-gray-500 mb-2">
                    Rule <span className="text-blue-300 font-mono">{selectedAlert.evidence_trace.rule || 'N/A'}</span> → linked event(s)
                  </p>
                  <div className="space-y-2">
                    {selectedAlert.evidence_trace.events.length > 0 ? (
                      selectedAlert.evidence_trace.events.map(event => (
                        <details key={event.id || `${event.timestamp}-${event.event_id}`} className="bg-black/40 rounded-lg border border-white/5 p-3">
                          <summary className="cursor-pointer text-xs text-gray-300">
                            {event.event_id || 'Event'} · {event.source || 'Unknown'} · {event.timestamp ? new Date(event.timestamp).toLocaleString() : 'Time unavailable'}
                          </summary>
                          <p className="text-[11px] text-gray-400 mt-2 break-words">{event.message || 'No message.'}</p>
                          <p className="text-[10px] text-gray-600 mt-1">
                            {[event.source_ip, event.username, event.hostname].filter(Boolean).join(' · ')}
                          </p>
                        </details>
                      ))
                    ) : (
                      <p className="text-xs text-gray-600">No linked log events.</p>
                    )}
                  </div>
                  {Object.keys(selectedAlert.evidence_trace.detection_evidence || {}).length > 0 && (
                    <div className="bg-black/40 rounded-lg p-3 border border-white/5 font-mono text-[10px] text-gray-400 space-y-1 mt-2">
                      {Object.entries(selectedAlert.evidence_trace.detection_evidence).map(([k, v]) => (
                        <div key={k} className="flex gap-2">
                          <span className="text-gray-600 flex-shrink-0 w-32">{k}:</span>
                          <span className="text-gray-300 truncate">{String(v)}</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* AI Assessment */}
              <div className="border-t border-white/5 pt-4">
                <h3 className="text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2">
                  <Brain size={16} className="text-violet-400" /> AI ASSESSMENT
                </h3>
                <p className="text-[10px] text-violet-300 mb-3 bg-violet-500/5 border border-violet-500/15 rounded px-2 py-1">
                  AI-generated interpretation. Not confirmed evidence. Verify independently.
                </p>
                {loadingAI ? (
                  <div className="flex items-center gap-2 text-violet-400 text-sm py-4">
                    <div className="w-4 h-4 border-2 border-violet-400 border-t-transparent rounded-full animate-spin" />
                    AI analyzing...
                  </div>
                ) : aiAnalysis ? (
                  <div className="space-y-3">
                    <div className="bg-violet-500/5 border border-violet-500/20 rounded-lg p-3">
                      <p className="text-xs text-violet-300 font-medium mb-1">Summary</p>
                      <p className="text-sm text-gray-300">{aiAnalysis.summary}</p>
                    </div>
                    <div className="grid grid-cols-3 gap-2">
                      <div className="bg-gray-800/50 rounded-lg p-2 text-center">
                        <p className="text-[10px] text-gray-500">Attack Type</p>
                        <p className="text-xs text-gray-200 font-medium mt-1">{aiAnalysis.attack_type}</p>
                      </div>
                      <div className="bg-gray-800/50 rounded-lg p-2 text-center">
                        <p className="text-[10px] text-gray-500">Confidence</p>
                        <p className="text-xs text-gray-200 font-medium mt-1">{aiAnalysis.confidence}%</p>
                      </div>
                      <div className="bg-gray-800/50 rounded-lg p-2 text-center">
                        <p className="text-[10px] text-gray-500">FP Likelihood</p>
                        <p className="text-xs text-gray-200 font-medium mt-1 capitalize">{aiAnalysis.false_positive_likelihood || 'N/A'}</p>
                      </div>
                    </div>
                    {aiAnalysis.recommended_actions && aiAnalysis.recommended_actions.length > 0 && (
                      <div>
                        <p className="text-xs text-gray-500 mb-2">Recommended Actions</p>
                        <div className="space-y-1.5">
                          {aiAnalysis.recommended_actions.map((action, i) => (
                            <div key={i} className="flex items-start gap-2 text-xs text-gray-300 bg-gray-800/30 rounded p-2">
                              <Zap size={12} className="text-yellow-400 mt-0.5 flex-shrink-0" />
                              {action}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                    {aiAnalysis.reasoning && (
                      <div className="bg-gray-800/30 rounded-lg p-3">
                        <p className="text-[10px] text-gray-500 mb-1">AI Reasoning</p>
                        <p className="text-xs text-gray-400 italic">{aiAnalysis.reasoning}</p>
                      </div>
                    )}
                  </div>
                ) : (
                  <p className="text-xs text-gray-500">No AI analysis available.</p>
                )}
              </div>

              {/* Alert Correlations */}
              <div className="border-t border-white/5 pt-4">
                <h3 className="text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2">
                  <Link2 size={16} className="text-cyan-400" /> Related Alerts
                </h3>
                {loadingCorrelations ? (
                  <div className="flex items-center gap-2 text-cyan-400 text-sm py-2">
                    <Loader2 size={13} className="animate-spin" /> Correlating...
                  </div>
                ) : correlations.length > 0 ? (
                  <div className="space-y-2">
                    {correlations.map((corr) => (
                      <div
                        key={corr.alert_id}
                        className="bg-gray-800/40 rounded-lg p-3 border border-white/5 cursor-pointer hover:border-cyan-500/20 transition-all"
                        onClick={() => {
                          const a = alerts.find(x => x.id === corr.alert_id)
                          if (a) handleSelectAlert(a)
                          else handleSelectAlert({ id: corr.alert_id, title: corr.title, severity: corr.severity as any, status: corr.status as any })
                        }}
                      >
                        <div className="flex items-center gap-2 mb-1">
                          <span className={`badge-${corr.severity} text-[9px]`}>{corr.severity?.toUpperCase()}</span>
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-cyan-500/10 text-cyan-400 border border-cyan-500/20">
                            {corr.relationship_reason}
                          </span>
                        </div>
                        <p className="text-xs text-gray-200 truncate">{corr.title}</p>
                        <p className="text-[10px] text-gray-500 mt-0.5">
                          {[corr.rule_name, corr.source_ip, corr.created_at ? new Date(corr.created_at).toLocaleString() : ''].filter(Boolean).join(' · ')}
                        </p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-gray-500">No related alerts found for this source IP, user, host, or timeframe.</p>
                )}
              </div>

              {/* Investigation Context */}
              <div className="border-t border-white/5 pt-4">
                <h3 className="text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2">
                  <ShieldAlert size={16} className="text-blue-400" /> Investigation Context
                </h3>
                {loadingContext ? (
                  <div className="flex items-center gap-2 text-blue-400 text-sm py-2">
                    <Loader2 size={13} className="animate-spin" /> Correlating evidence...
                  </div>
                ) : investigationContext ? (
                  <div className="space-y-3">
                    <div className="bg-blue-500/5 border border-blue-500/20 rounded-lg p-3">
                      <p className="text-xs text-blue-300 font-medium mb-2">Recommended next steps</p>
                      <ul className="space-y-1.5">
                        {investigationContext.recommended_next_steps?.map((step: string, i: number) => (
                          <li key={i} className="flex items-start gap-2 text-xs text-gray-300">
                            <span className="text-blue-400 mt-0.5">•</span>
                            <span>{step}</span>
                          </li>
                        ))}
                      </ul>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      <div className="bg-gray-800/40 rounded-lg p-3">
                        <p className="text-[10px] text-gray-500 uppercase mb-2">Related Logs</p>
                        <div className="space-y-1.5 max-h-32 overflow-y-auto">
                          {investigationContext.related_logs?.length > 0
                            ? investigationContext.related_logs.slice(0, 4).map((log: any) => (
                                <div key={log.id} className="text-xs text-gray-400">
                                  <p className="text-gray-300 truncate">{log.message || 'No message'}</p>
                                  <p className="text-[10px] text-gray-500 mt-0.5">{log.source} · {log.severity}</p>
                                </div>
                              ))
                            : <p className="text-xs text-gray-500">No related logs.</p>
                          }
                        </div>
                      </div>
                      <div className="bg-gray-800/40 rounded-lg p-3">
                        <p className="text-[10px] text-gray-500 uppercase mb-2">Related Alerts (by context)</p>
                        <div className="space-y-1.5 max-h-32 overflow-y-auto">
                          {investigationContext.related_alerts?.length > 0
                            ? investigationContext.related_alerts.slice(0, 4).map((related: any) => (
                                <div key={related.id} className="text-xs text-gray-400">
                                  <p className="text-gray-300 truncate">{related.title}</p>
                                  <p className="text-[10px] text-gray-500 mt-0.5">{related.severity} · {related.status}</p>
                                </div>
                              ))
                            : <p className="text-xs text-gray-500">No nearby alerts.</p>
                          }
                        </div>
                      </div>
                    </div>
                  </div>
                ) : (
                  <p className="text-xs text-gray-500">No investigation context available.</p>
                )}
              </div>

              {/* Audit History */}
              <div className="border-t border-white/5 pt-4">
                <h3 className="text-sm font-semibold text-gray-300 mb-3 flex items-center gap-2">
                  <AlertCircle size={16} className="text-amber-400" /> Alert Audit History
                </h3>
                {selectedAlert.status_history && selectedAlert.status_history.length > 0 ? (
                  <div className="space-y-2">
                    {selectedAlert.status_history.map((entry, index) => (
                      <div key={`${entry.created_at}-${index}`} className="bg-gray-800/40 rounded-lg p-3 border border-white/5">
                        <p className="text-xs text-gray-200 font-medium">
                          {entry.previous_status.toUpperCase()} <span className="text-amber-400">→</span> {entry.new_status.toUpperCase()}
                        </p>
                        <p className="text-[10px] text-gray-500 mt-1">Analyst: <span className="text-gray-300">{entry.changed_by_email || entry.changed_by}</span></p>
                        <p className="text-[10px] text-gray-500">Reason: <span className="text-gray-300">{entry.reason}</span></p>
                        <p className="text-[10px] text-gray-600 mt-1">{new Date(entry.created_at).toLocaleString()}</p>
                      </div>
                    ))}
                  </div>
                ) : (
                  <p className="text-xs text-gray-500">No status transitions recorded.</p>
                )}
              </div>

              {/* Response Actions */}
              <div className="border-t border-white/5 pt-4">
                <p className="text-xs text-gray-500 mb-3 uppercase tracking-wider">Response Actions</p>

                {/* Escalated incident result */}
                {escalatedIncident && selectedAlert?.status === 'escalated' && (
                  <div className="mb-3 p-3 rounded-lg bg-violet-500/10 border border-violet-500/30">
                    <div className="flex items-center justify-between gap-2">
                      <div>
                        <p className="text-xs text-violet-300 font-medium">
                          {escalatedIncident.ai_generated ? '🤖 AI-generated incident created' : '📋 Incident created (template)'}
                        </p>
                        <p className="text-[11px] text-gray-400 mt-0.5 truncate">{escalatedIncident.title}</p>
                      </div>
                      <a href="/incidents" className="flex items-center gap-1 text-xs text-violet-400 hover:text-violet-300 shrink-0">
                        View <ExternalLink size={11} />
                      </a>
                    </div>
                  </div>
                )}

                <div className="flex flex-wrap gap-2 mb-3">
                  {selectedAlert.status === 'new' && (
                    <button onClick={() => handleStatusUpdate(selectedAlert.id, 'acknowledged')} className="btn-secondary text-xs">
                      ✓ Acknowledge
                    </button>
                  )}
                  {selectedAlert.status === 'acknowledged' && (
                    <button onClick={() => handleStatusUpdate(selectedAlert.id, 'investigating')} className="btn-secondary text-xs">
                      🔍 Start Investigation
                    </button>
                  )}
                  {selectedAlert.status === 'investigating' && (
                    <button onClick={() => handleStatusUpdate(selectedAlert.id, 'resolved')} className="btn-success text-xs">
                      ✓ Resolve
                    </button>
                  )}
                  <button
                    onClick={() => handleStatusUpdate(selectedAlert.id, 'false_positive')}
                    className="btn-base px-3 py-1.5 bg-gray-700 hover:bg-gray-600 text-gray-300 hover:text-white text-xs rounded-lg"
                  >
                    ✕ False Positive
                  </button>
                  <button
                    onClick={handleEscalate}
                    disabled={escalating || selectedAlert.status === 'escalated'}
                    className="btn-danger flex items-center gap-1.5 disabled:opacity-60 disabled:cursor-not-allowed text-xs"
                  >
                    {escalating
                      ? <><Loader2 size={12} className="animate-spin" /> Creating incident…</>
                      : selectedAlert.status === 'escalated' && escalatedIncident
                      ? <><ExternalLink size={12} /> Escalated</>
                      : '⬆ Escalate → Incident'
                    }
                  </button>

                  {/* Classify button */}
                  <button
                    onClick={() => { setShowClassify(!showClassify); setClassifyError(null) }}
                    className="btn-secondary text-xs flex items-center gap-1.5"
                  >
                    <Tag size={11} /> Classify
                  </button>
                </div>

                {/* FP Classification panel */}
                {showClassify && (
                  <div className="bg-gray-800/40 border border-white/10 rounded-lg p-3 space-y-3 animate-fade-in">
                    <p className="text-xs text-gray-300 font-medium">Analyst Classification</p>
                    <div className="grid grid-cols-2 gap-2">
                      {FP_OPTIONS.map(opt => {
                        const Icon = opt.icon
                        return (
                          <button
                            key={opt.value}
                            onClick={() => setClassifyValue(opt.value)}
                            className={`flex items-center gap-2 p-2.5 rounded-lg border text-xs transition-all ${
                              classifyValue === opt.value
                                ? `${opt.bg} ${opt.color} border-current`
                                : 'border-white/10 text-gray-400 hover:border-white/20'
                            }`}
                          >
                            <Icon size={13} />
                            {opt.label}
                          </button>
                        )
                      })}
                    </div>
                    <textarea
                      placeholder="Reason / justification (required)..."
                      value={classifyReason}
                      onChange={e => setClassifyReason(e.target.value)}
                      className="input w-full h-16 resize-none text-xs"
                    />
                    {classifyError && (
                      <p className="text-xs text-red-400">{classifyError}</p>
                    )}
                    <div className="flex gap-2">
                      <button
                        onClick={handleClassify}
                        disabled={!classifyValue || !classifyReason.trim() || classifying}
                        className="btn-primary text-xs flex items-center gap-1.5 disabled:opacity-50"
                      >
                        {classifying ? <Loader2 size={11} className="animate-spin" /> : <Tag size={11} />}
                        Save Classification
                      </button>
                      <button onClick={() => setShowClassify(false)} className="btn-secondary text-xs">Cancel</button>
                    </div>
                  </div>
                )}
              </div>

            </div>
          ) : (
            <div className="card flex items-center justify-center h-64 text-gray-500">
              <div className="text-center">
                <AlertTriangle size={32} className="mx-auto mb-3 text-gray-600" />
                <p className="text-sm">Select an alert to investigate</p>
                <p className="text-xs text-gray-600 mt-1">See evidence, AI assessment, correlations, and respond</p>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
