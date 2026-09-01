import { useEffect, useState, useRef } from 'react'
import { api, getSocketUrl } from '../services/api'
import { Incident } from '../types'
import {
  Shield, Plus, FileText, Loader2, ChevronDown, ChevronRight,
  Copy, Download, RefreshCw, User, Server, Globe, Tag, Edit3,
  CheckCircle, Clock, AlertCircle
} from 'lucide-react'
import { io, Socket } from 'socket.io-client'

// ── Status config ─────────────────────────────────────────────────────────────
const STATUS_FLOW = ['new', 'triaged', 'investigating', 'contained', 'resolved'] as const
const STATUS_OPTIONS = ['new', 'triaged', 'investigating', 'contained', 'resolved', 'open', 'remediated', 'closed'] as const

const statusColor = (s: string) => {
  const m: Record<string, string> = {
    new:          'bg-red-500/10 text-red-400 border-red-500/20',
    triaged:      'bg-orange-500/10 text-orange-400 border-orange-500/20',
    open:         'bg-red-500/10 text-red-400 border-red-500/20',
    investigating:'bg-yellow-500/10 text-yellow-400 border-yellow-500/20',
    contained:    'bg-blue-500/10 text-blue-400 border-blue-500/20',
    remediated:   'bg-green-500/10 text-green-400 border-green-500/20',
    resolved:     'bg-green-500/10 text-green-400 border-green-500/20',
    closed:       'bg-gray-500/10 text-gray-400 border-gray-500/20',
  }
  return m[s] || 'bg-gray-500/10 text-gray-400 border-gray-500/20'
}

const severityColor = (s: string) => ({
  critical: 'text-red-400',
  high:     'text-orange-400',
  medium:   'text-yellow-400',
  low:      'text-blue-400',
  info:     'text-green-400',
}[s] || 'text-gray-400')

export default function Incidents() {
  const [incidents, setIncidents]           = useState<Incident[]>([])
  const [loading, setLoading]               = useState(true)
  const [showCreate, setShowCreate]         = useState(false)
  const [newTitle, setNewTitle]             = useState('')
  const [newDesc, setNewDesc]               = useState('')
  const [newSeverity, setNewSeverity]       = useState('medium')
  const [newPriority, setNewPriority]       = useState('medium')
  const [newAssigned, setNewAssigned]       = useState('')
  const [expandedId, setExpandedId]         = useState<string | null>(null)
  const [incidentDetail, setIncidentDetail] = useState<any>(null)
  const [detailLoading, setDetailLoading]   = useState(false)
  const [report, setReport]                 = useState<string | null>(null)
  const [reportLoading, setReportLoading]   = useState(false)
  const [reportIncidentId, setReportIncidentId] = useState<string | null>(null)

  // Edit fields
  const [editNotes, setEditNotes]           = useState('')
  const [editResolution, setEditResolution] = useState('')
  const [editAssigned, setEditAssigned]     = useState('')
  const [savingEdit, setSavingEdit]         = useState(false)

  // WS
  const socketRef = useRef<Socket | null>(null)

  useEffect(() => {
    const token = localStorage.getItem('token')
    if (!token) return
    const socket = io(getSocketUrl(), { auth: { token }, transports: ['websocket', 'polling'] })
    socketRef.current = socket
    socket.on('incident_created', () => loadIncidents())
    socket.on('incident_updated', (data: any) => {
      setIncidents(prev => prev.map(i => i.id === data.id ? { ...i, status: data.status ?? i.status } : i))
    })
    return () => { socket.disconnect() }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => { loadIncidents() }, [])

  const loadIncidents = async () => {
    try {
      const data = await api.incidents.list()
      setIncidents(data)
    } catch { /* silent */ }
    finally { setLoading(false) }
  }

  const createIncident = async () => {
    if (!newTitle.trim()) return
    try {
      await api.incidents.create({
        title: newTitle, description: newDesc, severity: newSeverity,
        priority: newPriority, assigned_analyst: newAssigned,
      })
      setShowCreate(false)
      setNewTitle(''); setNewDesc(''); setNewAssigned('')
      loadIncidents()
    } catch (e: any) {
      if (e?.response?.status === 403) alert('Permission denied — Analyst role required.')
    }
  }

  const toggleExpand = async (id: string) => {
    if (expandedId === id) { setExpandedId(null); setIncidentDetail(null); return }
    setExpandedId(id)
    setDetailLoading(true)
    setEditNotes(''); setEditResolution(''); setEditAssigned('')
    try {
      const d = await api.incidents.get(id)
      setIncidentDetail(d)
      setEditNotes(d.notes || '')
      setEditResolution(d.resolution || '')
      setEditAssigned(d.assigned_analyst || d.assigned_to || '')
    } catch { /* silent */ }
    finally { setDetailLoading(false) }
  }

  const updateStatus = async (id: string, status: string) => {
    try {
      await api.incidents.update(id, { status })
      setIncidents(prev => prev.map(i => i.id === id ? { ...i, status } : i))
      if (incidentDetail?.id === id) setIncidentDetail((d: any) => ({ ...d, status }))
    } catch { /* silent */ }
  }

  const saveEdits = async (id: string) => {
    setSavingEdit(true)
    try {
      await api.incidents.update(id, {
        notes: editNotes,
        resolution: editResolution,
        assigned_analyst: editAssigned,
      })
      setIncidentDetail((d: any) => d ? {
        ...d, notes: editNotes, resolution: editResolution, assigned_analyst: editAssigned
      } : d)
      setIncidents(prev => prev.map(i => i.id === id ? {
        ...i, notes: editNotes, resolution: editResolution, assigned_analyst: editAssigned
      } : i))
    } catch { /* silent */ }
    finally { setSavingEdit(false) }
  }

  const generateReport = async (id: string) => {
    setReportLoading(true); setReport(null); setReportIncidentId(id)
    try {
      const data = await api.incidents.generateReport(id)
      setReport(data.markdown || '')
    } catch { setReport('Failed to generate report.') }
    finally { setReportLoading(false) }
  }

  const copyReport = () => { if (report) navigator.clipboard.writeText(report) }
  const downloadReport = () => {
    if (!report) return
    const blob = new Blob([report], { type: 'text/markdown' })
    const url  = URL.createObjectURL(blob)
    const a = document.createElement('a'); a.href = url
    a.download = `incident-report-${reportIncidentId?.slice(0, 8)}.md`
    a.click(); URL.revokeObjectURL(url)
  }

  return (
    <div className="space-y-6 animate-fade-in">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Incidents</h1>
          <p className="text-sm text-gray-400 mt-1">Track and manage security incidents</p>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={loadIncidents} className="btn-secondary text-xs flex items-center gap-1.5">
            <RefreshCw size={12} /> Refresh
          </button>
          <button onClick={() => setShowCreate(true)} className="btn-primary text-xs flex items-center gap-1.5">
            <Plus size={14} /> New Incident
          </button>
        </div>
      </div>

      {/* Status flow indicator */}
      <div className="flex items-center gap-1 text-[10px] text-gray-600 flex-wrap">
        {STATUS_FLOW.map((s, i) => (
          <span key={s} className="flex items-center gap-1">
            <span className={`px-2 py-0.5 rounded-full border ${statusColor(s)}`}>{s.toUpperCase()}</span>
            {i < STATUS_FLOW.length - 1 && <span className="text-gray-700">→</span>}
          </span>
        ))}
      </div>

      {/* Create form */}
      {showCreate && (
        <div className="card border border-violet-500/20 animate-slide-in">
          <h3 className="text-sm font-semibold text-gray-300 mb-3">Create New Incident</h3>
          <div className="space-y-3">
            <input type="text" placeholder="Incident title..." value={newTitle}
              onChange={e => setNewTitle(e.target.value)} className="input w-full" />
            <textarea placeholder="Description..." value={newDesc}
              onChange={e => setNewDesc(e.target.value)} className="input w-full h-20 resize-none" />
            <div className="grid grid-cols-3 gap-3">
              <div>
                <label className="text-[10px] text-gray-500 mb-1 block">Severity</label>
                <select value={newSeverity} onChange={e => setNewSeverity(e.target.value)} className="input w-full">
                  {['critical','high','medium','low'].map(s =>
                    <option key={s} value={s}>{s.charAt(0).toUpperCase()+s.slice(1)}</option>)}
                </select>
              </div>
              <div>
                <label className="text-[10px] text-gray-500 mb-1 block">Priority</label>
                <select value={newPriority} onChange={e => setNewPriority(e.target.value)} className="input w-full">
                  {['critical','high','medium','low'].map(s =>
                    <option key={s} value={s}>{s.charAt(0).toUpperCase()+s.slice(1)}</option>)}
                </select>
              </div>
              <div>
                <label className="text-[10px] text-gray-500 mb-1 block">Assign to</label>
                <input type="text" placeholder="analyst@example.com" value={newAssigned}
                  onChange={e => setNewAssigned(e.target.value)} className="input w-full" />
              </div>
            </div>
            <div className="flex gap-2 justify-end">
              <button onClick={() => setShowCreate(false)} className="btn-secondary text-xs">Cancel</button>
              <button onClick={createIncident} className="btn-primary text-xs">Create Incident</button>
            </div>
          </div>
        </div>
      )}

      {/* Report viewer */}
      {report !== null && (
        <div className="card border border-blue-500/20">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-semibold text-gray-300 flex items-center gap-2">
              <FileText size={14} className="text-blue-400" /> Generated Report
              {reportLoading && <Loader2 size={13} className="animate-spin text-blue-400" />}
            </h3>
            <div className="flex items-center gap-2">
              <button onClick={copyReport} className="btn-secondary text-xs flex items-center gap-1"><Copy size={11} /> Copy</button>
              <button onClick={downloadReport} className="btn-secondary text-xs flex items-center gap-1"><Download size={11} /> .md</button>
              <button onClick={() => setReport(null)} className="text-gray-500 hover:text-gray-300 text-xs">✕</button>
            </div>
          </div>
          <pre className="text-xs text-gray-300 whitespace-pre-wrap bg-black/30 rounded-lg p-4 max-h-96 overflow-y-auto font-mono">
            {report}
          </pre>
        </div>
      )}

      {/* Incidents list */}
      {loading ? (
        <div className="text-center py-12 text-gray-500">Loading incidents...</div>
      ) : incidents.length === 0 ? (
        <div className="card text-center py-12">
          <Shield size={40} className="mx-auto text-gray-600 mb-3" />
          <p className="text-sm text-gray-400">No incidents yet</p>
          <p className="text-xs text-gray-600 mt-1">Create manually or escalate an alert to auto-generate</p>
        </div>
      ) : (
        <div className="space-y-2">
          {incidents.map(incident => (
            <div key={incident.id} className="card hover:border-white/10 transition-all">
              {/* Header row */}
              <div className="flex items-start justify-between gap-3">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1.5 flex-wrap">
                    <span className={`badge-${incident.severity}`}>{incident.severity?.toUpperCase()}</span>
                    <span className={`badge border text-[10px] ${statusColor(incident.status)}`}>{incident.status}</span>
                    {incident.priority && incident.priority !== 'medium' && (
                      <span className="text-[10px] px-2 py-0.5 rounded border border-white/10 text-gray-400">
                        Priority: {incident.priority}
                      </span>
                    )}
                    {incident.ai_summary && (
                      <span className="badge bg-violet-500/10 text-violet-400 border border-violet-500/20 text-[10px]">AI</span>
                    )}
                    {incident.assigned_analyst && (
                      <span className="flex items-center gap-1 text-[10px] text-gray-500">
                        <User size={9} /> {incident.assigned_analyst}
                      </span>
                    )}
                    <span className="text-[10px] text-gray-600">
                      {incident.created_at ? new Date(incident.created_at).toLocaleString() : ''}
                    </span>
                  </div>
                  <h3 className="text-sm font-semibold text-gray-200">{incident.title}</h3>
                  {incident.description && (
                    <p className="text-xs text-gray-400 mt-1 line-clamp-2">{incident.description}</p>
                  )}
                  {incident.ai_summary && (
                    <div className="mt-2 p-2 bg-violet-500/5 border border-violet-500/20 rounded text-xs text-violet-300 line-clamp-2">
                      🤖 {incident.ai_summary}
                    </div>
                  )}
                </div>

                {/* Actions */}
                <div className="flex items-center gap-2 shrink-0">
                  <select
                    value={incident.status}
                    onChange={e => updateStatus(incident.id, e.target.value)}
                    onClick={e => e.stopPropagation()}
                    className="input text-xs py-1 px-2 w-32"
                  >
                    {STATUS_OPTIONS.map(s =>
                      <option key={s} value={s}>{s.charAt(0).toUpperCase()+s.slice(1)}</option>
                    )}
                  </select>
                  <button
                    onClick={() => generateReport(incident.id)}
                    disabled={reportLoading && reportIncidentId === incident.id}
                    className="btn-secondary text-xs flex items-center gap-1 disabled:opacity-60"
                    title="Generate AI report"
                  >
                    {reportLoading && reportIncidentId === incident.id
                      ? <Loader2 size={11} className="animate-spin" />
                      : <FileText size={11} />
                    }
                    Report
                  </button>
                  <button onClick={() => toggleExpand(incident.id)} className="text-gray-500 hover:text-gray-300 p-1">
                    {expandedId === incident.id ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
                  </button>
                </div>
              </div>

              {/* Expanded detail */}
              {expandedId === incident.id && (
                <div className="mt-4 border-t border-white/5 pt-4 space-y-4">
                  {detailLoading ? (
                    <div className="flex items-center gap-2 text-gray-500 text-xs">
                      <Loader2 size={12} className="animate-spin" /> Loading details...
                    </div>
                  ) : incidentDetail ? (
                    <>
                      {/* Affected assets */}
                      {((incidentDetail.affected_hosts?.length > 0) ||
                        (incidentDetail.affected_users?.length > 0) ||
                        (incidentDetail.source_ips?.length > 0)) && (
                        <div>
                          <p className="text-[10px] text-gray-500 uppercase mb-2">Affected Assets</p>
                          <div className="grid grid-cols-3 gap-3">
                            {incidentDetail.affected_hosts?.length > 0 && (
                              <div className="bg-gray-800/40 rounded-lg p-2">
                                <p className="text-[10px] text-gray-500 flex items-center gap-1 mb-1"><Server size={9} /> Hosts</p>
                                {incidentDetail.affected_hosts.map((h: string, i: number) => (
                                  <p key={i} className="text-[11px] text-gray-300 font-mono truncate">{h}</p>
                                ))}
                              </div>
                            )}
                            {incidentDetail.affected_users?.length > 0 && (
                              <div className="bg-gray-800/40 rounded-lg p-2">
                                <p className="text-[10px] text-gray-500 flex items-center gap-1 mb-1"><User size={9} /> Users</p>
                                {incidentDetail.affected_users.map((u: string, i: number) => (
                                  <p key={i} className="text-[11px] text-gray-300 truncate">{u}</p>
                                ))}
                              </div>
                            )}
                            {incidentDetail.source_ips?.length > 0 && (
                              <div className="bg-gray-800/40 rounded-lg p-2">
                                <p className="text-[10px] text-gray-500 flex items-center gap-1 mb-1"><Globe size={9} /> Source IPs</p>
                                {incidentDetail.source_ips.map((ip: string, i: number) => (
                                  <p key={i} className="text-[11px] text-gray-300 font-mono truncate">{ip}</p>
                                ))}
                              </div>
                            )}
                          </div>
                        </div>
                      )}

                      {/* MITRE techniques */}
                      {incidentDetail.mitre_techniques?.length > 0 && (
                        <div>
                          <p className="text-[10px] text-gray-500 uppercase mb-2 flex items-center gap-1">
                            <Tag size={9} /> MITRE ATT&CK (from linked alerts)
                          </p>
                          <div className="flex flex-wrap gap-1.5">
                            {incidentDetail.mitre_techniques.map((t: string, i: number) => (
                              <span key={i} className="text-[10px] px-2 py-0.5 rounded border border-violet-500/20 bg-violet-500/10 text-violet-300">
                                {t}
                              </span>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Linked alerts */}
                      {incidentDetail.alerts?.length > 0 && (
                        <div>
                          <p className="text-[10px] text-gray-500 uppercase mb-2">Linked Alerts</p>
                          <div className="space-y-1.5">
                            {incidentDetail.alerts.map((a: any) => (
                              <div key={a.id} className="flex items-center gap-2 text-xs bg-gray-800/30 rounded p-2">
                                <span className={`badge-${a.severity} text-[9px]`}>{a.severity?.toUpperCase()}</span>
                                <span className="text-gray-300 truncate flex-1">{a.title}</span>
                                <span className="text-gray-600 shrink-0 text-[10px]">{a.status}</span>
                                {a.rule_name && <span className="text-[10px] text-gray-500 font-mono shrink-0">{a.rule_name}</span>}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Edit: Assigned analyst, Notes, Resolution */}
                      <div>
                        <p className="text-[10px] text-gray-500 uppercase mb-2 flex items-center gap-1">
                          <Edit3 size={9} /> Investigation Notes & Resolution
                        </p>
                        <div className="space-y-2">
                          <div>
                            <label className="text-[10px] text-gray-500 mb-1 block">Assigned Analyst</label>
                            <input
                              type="text"
                              placeholder="analyst@example.com"
                              value={editAssigned}
                              onChange={e => setEditAssigned(e.target.value)}
                              className="input w-full text-xs"
                            />
                          </div>
                          <div>
                            <label className="text-[10px] text-gray-500 mb-1 block">Investigation Notes</label>
                            <textarea
                              placeholder="Document investigation findings, IOCs, steps taken..."
                              value={editNotes}
                              onChange={e => setEditNotes(e.target.value)}
                              className="input w-full h-24 resize-none text-xs"
                            />
                          </div>
                          <div>
                            <label className="text-[10px] text-gray-500 mb-1 block">Resolution</label>
                            <textarea
                              placeholder="Describe the resolution and remediation actions taken..."
                              value={editResolution}
                              onChange={e => setEditResolution(e.target.value)}
                              className="input w-full h-20 resize-none text-xs"
                            />
                          </div>
                          <button
                            onClick={() => saveEdits(incident.id)}
                            disabled={savingEdit}
                            className="btn-primary text-xs flex items-center gap-1.5 disabled:opacity-60"
                          >
                            {savingEdit ? <Loader2 size={11} className="animate-spin" /> : <CheckCircle size={11} />}
                            Save Notes
                          </button>
                        </div>
                      </div>

                      {/* Existing notes display */}
                      {incidentDetail.notes && !editNotes && (
                        <div className="bg-gray-800/30 rounded-lg p-3 border border-white/5">
                          <p className="text-[10px] text-gray-500 mb-1">Current Notes</p>
                          <p className="text-xs text-gray-300 whitespace-pre-wrap">{incidentDetail.notes}</p>
                        </div>
                      )}
                      {incidentDetail.resolution && !editResolution && (
                        <div className="bg-green-500/5 rounded-lg p-3 border border-green-500/10">
                          <p className="text-[10px] text-green-400 mb-1 flex items-center gap-1"><CheckCircle size={9} /> Resolution</p>
                          <p className="text-xs text-gray-300 whitespace-pre-wrap">{incidentDetail.resolution}</p>
                        </div>
                      )}

                      {/* Timeline */}
                      {incidentDetail.timeline?.length > 0 && (
                        <div>
                          <p className="text-[10px] text-gray-500 uppercase mb-2 flex items-center gap-1">
                            <Clock size={9} /> Timeline
                          </p>
                          <div className="space-y-1.5 border-l-2 border-white/10 pl-3">
                            {incidentDetail.timeline.map((t: any, i: number) => (
                              <div key={i} className="text-xs">
                                <span className="text-gray-500 text-[10px]">
                                  {t.timestamp ? new Date(t.timestamp).toLocaleString() : ''}
                                </span>
                                <p className="text-gray-300">{t.event}</p>
                                {t.actor && <p className="text-gray-600 text-[10px]">by {t.actor}</p>}
                                {t.ai_generated && (
                                  <span className="text-[9px] text-violet-400">🤖 AI-generated</span>
                                )}
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </>
                  ) : null}
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
