export interface Alert {
  id: string
  title: string
  description?: string
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  status: 'new' | 'acknowledged' | 'investigating' | 'resolved' | 'false_positive' | 'escalated'
  rule_name?: string
  confidence?: number
  source?: string
  source_ip?: string
  destination_ip?: string
  username?: string
  hostname?: string
  mitre_techniques?: string[]
  kill_chain_phase?: string
  ai_analysis?: AIAnalysis
  evidence?: Record<string, unknown>
  threat_score?: number
  timestamp?: string
  created_at?: string
  related_logs?: LogEntry[]
  detection?: AlertDetection
  evidence_trace?: AlertEvidenceTrace
  ai_assessment?: AIAnalysis
  status_history?: AlertStatusHistory[]
  // FP Classification
  fp_classification?: 'TRUE_POSITIVE' | 'FALSE_POSITIVE' | 'BENIGN' | 'NEEDS_INVESTIGATION' | ''
  fp_classified_by?: string
  fp_classified_at?: string
  fp_reason?: string
}

export interface AlertStatusHistory {
  previous_status: string
  new_status: string
  changed_by: string
  changed_by_email?: string
  reason: string
  created_at: string
}

export interface AlertDetection {
  rule?: string | null
  category?: string | null
  threshold?: number | null
  time_window_seconds?: number | null
  detection_timestamp?: string | null
  confidence?: number | null
  mitre_techniques: string[]
}

export interface AlertEvidenceEvent {
  id?: string
  event_id?: string
  timestamp?: string
  source?: string
  source_type?: string
  severity?: string
  message?: string
  source_ip?: string
  destination_ip?: string
  username?: string
  hostname?: string
}

export interface AlertEvidenceTrace {
  rule?: string | null
  events: AlertEvidenceEvent[]
  detection_evidence: Record<string, unknown>
}

export interface InvestigationContext {
  alert: Alert
  related_logs: LogEntry[]
  related_alerts: Alert[]
  recommended_next_steps: string[]
  evidence: Record<string, unknown>
}

export interface LogEntry {
  id: string
  timestamp?: string
  source: string
  source_type: string
  event_type: string
  event_id?: string
  severity: string
  message: string
  raw_log?: string
  source_ip?: string
  destination_ip?: string
  source_port?: number
  destination_port?: number
  username?: string
  hostname?: string
  process_name?: string
  tags?: string[]
}

export interface AIAnalysis {
  threat_score: number
  summary: string
  attack_type: string
  kill_chain_phase?: string
  recommended_actions: string[]
  reasoning?: string
  confidence?: number
  false_positive_likelihood?: string
}

export interface DashboardStats {
  alerts: {
    total: number
    by_severity: Record<string, number>
    by_status: Record<string, number>
  }
  logs: {
    total: number
    by_source: Record<string, number>
    live_count?: number
    uploaded_count?: number
  }
  recent_alerts: Alert[]
  recent_logs: LogEntry[]
  top_ips: { ip: string; count: number }[]
  top_hosts: { host: string; count: number }[]
}

export interface Incident {
  id: string
  title: string
  description?: string
  severity: string
  status: string
  alert_ids?: string[]
  alerts?: any[]
  ai_summary?: string
  timeline?: any[]
  assigned_to?: string
  assigned_analyst?: string
  affected_hosts?: string[]
  affected_users?: string[]
  source_ips?: string[]
  notes?: string
  resolution?: string
  priority?: string
  mitre_techniques?: string[]
  created_at?: string
  updated_at?: string
}

export interface AlertCorrelation {
  alert_id: string
  title: string
  severity: string
  status: string
  rule_name?: string
  source_ip?: string
  username?: string
  hostname?: string
  created_at: string
  relationship_reason: string
}

export interface SocMetrics {
  total_events: number
  total_alerts: number
  critical_alerts: number
  high_alerts: number
  medium_alerts: number
  low_alerts: number
  open_alerts: number
  resolved_alerts: number
  false_positive_alerts: number
  total_incidents: number
  open_incidents: number
  resolved_incidents: number
  false_positive_rate: number | null
  classified_alerts: number
  mttr_minutes: number | null
  analyst_workload: Record<string, number>
  top_detection_rules: { rule: string; count: number; last_triggered: string }[]
  top_mitre: { technique: string; count: number }[]
  by_severity: Record<string, number>
  by_status: Record<string, number>
}

export interface UploadedFile {
  id: string
  filename: string
  original_name?: string
  file_type?: string
  file_size?: number
  log_format?: string
  status: string
  total_logs: number
  parsed_logs?: number
  alerts_generated?: number
  analysis_results?: any
  upload_session_id?: string
  created_at?: string
}

export interface UploadResult {
  id: string
  filename: string
  format_detected: string
  total_logs: number
  alerts_generated: number
  severity_breakdown: Record<string, number>
  upload_session_id: string
  status: string
}

export interface ThreatAssessment {
  overall_score: number
  risk_level: string
  summary: string
  top_concerns: string[]
}

export interface DetectionRule {
  name: string
  description: string
  category: string
  severity: string
  confidence?: number
  enabled: boolean
  threshold?: number | null
  time_window_seconds?: number | null
  supported_configuration?: boolean
  mitre_techniques?: string[]
  kill_chain_phase?: string
  trigger_count: number
  last_triggered?: string | null
  created_at?: string
  updated_at?: string
}
