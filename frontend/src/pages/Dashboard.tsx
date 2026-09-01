import { useEffect, useState } from 'react'
import { api } from '../services/api'
import { DashboardStats, ThreatAssessment, SocMetrics } from '../types'
import {
  AlertTriangle, ShieldAlert, AlertCircle, Info, Activity,
  TrendingUp, Shield, Zap, Globe, Server, ArrowUpRight,
  Radio, Upload, RefreshCw, BarChart2, CheckCircle, XCircle, Layers
} from 'lucide-react'
import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer,
  PieChart, Pie, Cell
} from 'recharts'

const severityColors: Record<string, string> = {
  critical: '#ef4444',
  high:     '#f97316',
  medium:   '#eab308',
  low:      '#3b82f6',
  info:     '#22c55e',
}

const severityBg: Record<string, string> = {
  critical: 'bg-red-500/10 border-red-500/30',
  high:     'bg-orange-500/10 border-orange-500/30',
  medium:   'bg-yellow-500/10 border-yellow-500/30',
  low:      'bg-blue-500/10 border-blue-500/30',
  info:     'bg-green-500/10 border-green-500/30',
}

const COLORS = ['#8b5cf6', '#3b82f6', '#22c55e', '#eab308', '#f97316', '#ef4444']

type Source = 'live' | 'uploaded'

export default function Dashboard() {
  const [liveStats, setLiveStats]       = useState<DashboardStats | null>(null)
  const [uploadedStats, setUploadedStats] = useState<DashboardStats | null>(null)
  const [threat, setThreat]             = useState<ThreatAssessment | null>(null)
  const [metrics, setMetrics]           = useState<SocMetrics | null>(null)
  const [loading, setLoading]           = useState(true)
  const [source, setSource]             = useState<Source>('live')

  useEffect(() => {
    loadData()
    const interval = setInterval(loadData, 15000)
    // Refresh immediately when an alert is resolved/dismissed from the Alerts page
    window.addEventListener('soc:alert-updated', loadData)
    return () => {
      clearInterval(interval)
      window.removeEventListener('soc:alert-updated', loadData)
    }
  }, [])

  const loadData = async () => {
    try {
      const [liveData, uploadedData, threatData, metricsData] = await Promise.all([
        api.dashboard.getStats('live'),
        api.dashboard.getStats('uploaded'),
        api.ai.getThreatAssessment(),
        api.metrics.get(),
      ])
      setLiveStats(liveData)
      setUploadedStats(uploadedData)
      setThreat(threatData)
      setMetrics(metricsData)
    } catch (error) {
      console.error('Failed to load dashboard data:', error)
    } finally {
      setLoading(false)
    }
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-96">
        <div className="text-center">
          <Shield className="w-12 h-12 text-violet-500 mx-auto animate-pulse mb-4" />
          <p className="text-gray-400">Loading security data...</p>
        </div>
      </div>
    )
  }

  const stats = source === 'live' ? liveStats : uploadedStats

  const alertStats    = stats?.alerts?.by_severity || {}
  const criticalCount = alertStats.critical || 0
  const highCount     = alertStats.high     || 0
  const mediumCount   = alertStats.medium   || 0
  const lowCount      = alertStats.low      || 0
  const totalAlerts   = stats?.alerts?.total || 0
  const totalLogs     = stats?.logs?.total   || 0
  const sourceData    = stats?.logs?.by_source || {}

  const sourceChartData = Object.entries(sourceData).map(([name, value]) => ({
    name:  name.charAt(0).toUpperCase() + name.slice(1),
    value: value as number,
  }))

  const topIps      = stats?.top_ips      || []
  const recentAlerts = stats?.recent_alerts || []
  const recentLogs   = stats?.recent_logs   || []
  const threatScore  = threat?.overall_score || 0
  const topConcernList = threat?.top_concerns || []
  const alertPriorityCount = (criticalCount > 0 ? 1 : 0) + (highCount > 0 ? 1 : 0)

  const liveTotalLogs     = (liveStats?.logs as any)?.total          || 0
  const uploadedTotalLogs = (uploadedStats?.logs as any)?.total      || 0
  const liveTotalAlerts   = liveStats?.alerts?.total                  || 0
  const uploadedTotalAlerts = uploadedStats?.alerts?.total            || 0

  return (
    <div className="space-y-6 animate-fade-in">

      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white">Security Overview</h1>
          <p className="text-sm text-gray-400 mt-1">Real-time security monitoring and threat detection</p>
        </div>
        <div className="flex items-center gap-3">
          <button
            onClick={loadData}
            className="btn-secondary text-xs flex items-center gap-1.5"
          >
            <RefreshCw size={12} /> Refresh
          </button>
          <div className="flex items-center gap-1.5 text-xs text-gray-500">
            <Activity size={13} className="text-green-400 animate-pulse" />
            Auto-refresh 15s
          </div>
        </div>
      </div>

      {/* ── Source Toggle ── */}
      <div className="grid grid-cols-2 gap-3">
        {/* Live Logs tab */}
        <button
          onClick={() => setSource('live')}
          className={`relative flex items-center gap-4 p-4 rounded-xl border-2 text-left transition-all ${
            source === 'live'
              ? 'border-green-500 bg-green-500/10'
              : 'border-white/10 bg-soc-card hover:border-white/20'
          }`}
        >
          <div className={`p-3 rounded-xl ${source === 'live' ? 'bg-green-500/20' : 'bg-gray-800'}`}>
            <Radio size={22} className={source === 'live' ? 'text-green-400' : 'text-gray-500'} />
          </div>
          <div>
            <p className={`text-sm font-semibold ${source === 'live' ? 'text-green-300' : 'text-gray-300'}`}>
              Live Ingested Logs
            </p>
            <p className="text-[11px] text-gray-500 mt-0.5">
              From Windows Event Log forwarder
            </p>
            <div className="flex items-center gap-3 mt-1.5">
              <span className="text-xs font-bold text-white">{liveTotalLogs.toLocaleString()} logs</span>
              <span className="text-[10px] text-red-400">{liveTotalAlerts} alerts</span>
            </div>
          </div>
          {source === 'live' && (
            <span className="absolute top-3 right-3 flex items-center gap-1 text-[10px] text-green-400">
              <span className="w-1.5 h-1.5 rounded-full bg-green-400 animate-pulse inline-block" />
              Active
            </span>
          )}
        </button>

        {/* Uploaded Files tab */}
        <button
          onClick={() => setSource('uploaded')}
          className={`relative flex items-center gap-4 p-4 rounded-xl border-2 text-left transition-all ${
            source === 'uploaded'
              ? 'border-violet-500 bg-violet-500/10'
              : 'border-white/10 bg-soc-card hover:border-white/20'
          }`}
        >
          <div className={`p-3 rounded-xl ${source === 'uploaded' ? 'bg-violet-500/20' : 'bg-gray-800'}`}>
            <Upload size={22} className={source === 'uploaded' ? 'text-violet-400' : 'text-gray-500'} />
          </div>
          <div>
            <p className={`text-sm font-semibold ${source === 'uploaded' ? 'text-violet-300' : 'text-gray-300'}`}>
              Uploaded Log Files
            </p>
            <p className="text-[11px] text-gray-500 mt-0.5">
              From manually uploaded log files
            </p>
            <div className="flex items-center gap-3 mt-1.5">
              <span className="text-xs font-bold text-white">{uploadedTotalLogs.toLocaleString()} logs</span>
              <span className="text-[10px] text-red-400">{uploadedTotalAlerts} alerts</span>
            </div>
          </div>
          {source === 'uploaded' && (
            <span className="absolute top-3 right-3 text-[10px] text-violet-400 font-medium">
              Selected
            </span>
          )}
        </button>
      </div>

      {/* Source label bar */}
      <div className={`flex items-center gap-2 px-4 py-2 rounded-lg text-xs font-medium border ${
        source === 'live'
          ? 'bg-green-500/5 border-green-500/20 text-green-400'
          : 'bg-violet-500/5 border-violet-500/20 text-violet-400'
      }`}>
        {source === 'live'
          ? <><Radio size={13} /> Showing data from: Live Windows Event Log ingestion</>
          : <><Upload size={13} /> Showing data from: Uploaded log files</>
        }
      </div>

      {/* Alert Counters */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4">
        <StatCard icon={<ShieldAlert size={20} />} label="Critical"     value={criticalCount} color="text-red-400"     bgColor="bg-red-500/10"     borderColor="border-red-500/20"     pulse={criticalCount > 0} />
        <StatCard icon={<AlertTriangle size={20} />} label="High"       value={highCount}     color="text-orange-400"  bgColor="bg-orange-500/10"  borderColor="border-orange-500/20" />
        <StatCard icon={<AlertCircle size={20} />}   label="Medium"     value={mediumCount}   color="text-yellow-400"  bgColor="bg-yellow-500/10"  borderColor="border-yellow-500/20" />
        <StatCard icon={<Info size={20} />}          label="Low"        value={lowCount}      color="text-blue-400"    bgColor="bg-blue-500/10"    borderColor="border-blue-500/20" />
        <StatCard icon={<Zap size={20} />}           label="Total Alerts" value={totalAlerts} color="text-violet-400"  bgColor="bg-violet-500/10"  borderColor="border-violet-500/20" />
        <StatCard icon={<Server size={20} />}        label="Total Logs" value={totalLogs}     color="text-emerald-400" bgColor="bg-emerald-500/10" borderColor="border-emerald-500/20" />
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

        {/* Executive Summary */}
        <div className="card lg:col-span-3">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between gap-3">
            <div>
              <h3 className="text-sm font-semibold text-gray-300">Executive Summary</h3>
              <p className="text-sm text-gray-400 mt-1">{threat?.summary || 'Collecting posture data...'}</p>
            </div>
            <div className="flex flex-wrap gap-2">
              <div className="rounded-full border border-red-500/20 bg-red-500/10 px-3 py-1 text-xs text-red-300">{criticalCount} critical</div>
              <div className="rounded-full border border-orange-500/20 bg-orange-500/10 px-3 py-1 text-xs text-orange-300">{highCount} high</div>
              <div className="rounded-full border border-blue-500/20 bg-blue-500/10 px-3 py-1 text-xs text-blue-300">{alertPriorityCount} priority buckets</div>
            </div>
          </div>
          {topConcernList.length > 0 && (
            <div className="mt-4 grid gap-2 md:grid-cols-2">
              {topConcernList.map((concern, index) => (
                <div key={index} className="rounded-lg border border-white/10 bg-black/20 px-3 py-2 text-sm text-gray-300">
                  {concern}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* AI Threat Score */}
        <div className="card">
          <h3 className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">
            <Shield size={16} className="text-violet-400" />
            AI Threat Assessment
          </h3>
          <div className="flex items-center justify-center py-4">
            <div className="relative w-32 h-32">
              <svg className="w-full h-full transform -rotate-90" viewBox="0 0 100 100">
                <circle cx="50" cy="50" r="40" fill="none" stroke="#1f2937" strokeWidth="8" />
                <circle
                  cx="50" cy="50" r="40" fill="none"
                  stroke={threatScore > 80 ? '#ef4444' : threatScore > 60 ? '#f97316' : threatScore > 40 ? '#eab308' : '#22c55e'}
                  strokeWidth="8"
                  strokeDasharray={`${threatScore * 2.51} 251`}
                  strokeLinecap="round"
                  className="transition-all duration-1000"
                />
              </svg>
              <div className="absolute inset-0 flex flex-col items-center justify-center">
                <span className="text-3xl font-bold text-white">{threatScore}</span>
                <span className="text-[10px] text-gray-400 uppercase">{threat?.risk_level || 'N/A'}</span>
              </div>
            </div>
          </div>
          <p className="text-xs text-gray-400 text-center mt-2">{threat?.summary || 'Analyzing...'}</p>
          {threat?.top_concerns && threat.top_concerns.length > 0 && (
            <div className="mt-3 space-y-1">
              {threat.top_concerns.map((concern, i) => (
                <div key={i} className="flex items-center gap-2 text-xs text-gray-400">
                  <div className="w-1.5 h-1.5 rounded-full bg-violet-500" />
                  {concern}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Log Sources Pie */}
        <div className="card">
          <h3 className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">
            <Globe size={16} className="text-blue-400" />
            Log Sources
          </h3>
          {sourceChartData.length > 0 ? (
            <>
              <div className="h-48">
                <ResponsiveContainer width="100%" height="100%">
                  <PieChart>
                    <Pie data={sourceChartData} cx="50%" cy="50%" innerRadius={50} outerRadius={75} paddingAngle={3} dataKey="value">
                      {sourceChartData.map((_, index) => (
                        <Cell key={index} fill={COLORS[index % COLORS.length]} />
                      ))}
                    </Pie>
                    <Tooltip contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: '8px', fontSize: '12px' }} itemStyle={{ color: '#e5e7eb' }} />
                  </PieChart>
                </ResponsiveContainer>
              </div>
              <div className="flex flex-wrap gap-2 mt-2">
                {sourceChartData.map((item, i) => (
                  <div key={i} className="flex items-center gap-1.5 text-xs text-gray-400">
                    <div className="w-2 h-2 rounded-full" style={{ backgroundColor: COLORS[i % COLORS.length] }} />
                    {item.name}: {item.value}
                  </div>
                ))}
              </div>
            </>
          ) : (
            <div className="flex items-center justify-center h-48 text-gray-600 text-xs text-center">
              <div>
                <Globe size={28} className="mx-auto mb-2 opacity-30" />
                No log sources yet
              </div>
            </div>
          )}
        </div>

        {/* Top Attacking IPs */}
        <div className="card">
          <h3 className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">
            <TrendingUp size={16} className="text-red-400" />
            Top Attacking IPs
          </h3>
          <div className="space-y-2">
            {topIps.length > 0 ? topIps.slice(0, 6).map((item, i) => (
              <div key={i} className="flex items-center justify-between">
                <span className="text-xs font-mono text-gray-300">{item.ip}</span>
                <div className="flex items-center gap-2">
                  <div className="w-20 h-1.5 bg-gray-800 rounded-full overflow-hidden">
                    <div
                      className="h-full bg-gradient-to-r from-red-500 to-orange-500 rounded-full"
                      style={{ width: `${Math.min(100, (item.count / (topIps[0]?.count || 1)) * 100)}%` }}
                    />
                  </div>
                  <span className="text-xs text-gray-500 w-6 text-right">{item.count}</span>
                </div>
              </div>
            )) : (
              <p className="text-xs text-gray-500 text-center py-8">No attack data yet</p>
            )}
          </div>
        </div>
      </div>

      {/* Alert Feed & Log Stream */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

        {/* Recent Alerts */}
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-gray-300 flex items-center gap-2">
              <AlertTriangle size={16} className="text-orange-400" />
              Recent Alerts
              <span className={`text-[10px] px-2 py-0.5 rounded-full border ${
                source === 'live'
                  ? 'bg-green-500/10 text-green-400 border-green-500/20'
                  : 'bg-violet-500/10 text-violet-400 border-violet-500/20'
              }`}>
                {source === 'live' ? 'Live' : 'Uploaded'}
              </span>
            </h3>
            <a href="/alerts" className="text-xs text-violet-400 hover:text-violet-300 flex items-center gap-1">
              View All <ArrowUpRight size={12} />
            </a>
          </div>
          <div className="space-y-2 max-h-80 overflow-y-auto">
            {recentAlerts.length > 0 ? recentAlerts.map((alert) => (
              <div
                key={alert.id}
                className={`p-3 rounded-lg border transition-all hover:border-white/20 ${severityBg[alert.severity] || ''}`}
              >
                <div className="flex items-start justify-between gap-2">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="text-[10px] font-bold px-1.5 py-0.5 rounded"
                        style={{ color: severityColors[alert.severity], background: severityColors[alert.severity] + '22' }}>
                        {alert.severity?.toUpperCase()}
                      </span>
                      <span className="text-[10px] text-gray-500">{alert.rule_name}</span>
                    </div>
                    <p className="text-xs text-gray-200 truncate">{alert.title}</p>
                    {alert.source_ip && (
                      <p className="text-[10px] text-gray-500 font-mono mt-1">{alert.source_ip}</p>
                    )}
                  </div>
                  <span className="text-[10px] text-gray-500 flex-shrink-0">
                    {alert.created_at ? new Date(alert.created_at).toLocaleTimeString() : ''}
                  </span>
                </div>
              </div>
            )) : (
              <div className="text-center py-10 text-gray-600">
                <AlertTriangle size={28} className="mx-auto mb-2 opacity-30" />
                <p className="text-xs">No alerts for {source === 'live' ? 'live ingested' : 'uploaded'} data yet</p>
              </div>
            )}
          </div>
        </div>

        {/* Recent Logs */}
        <div className="card">
          <div className="flex items-center justify-between mb-4">
            <h3 className="text-sm font-semibold text-gray-300 flex items-center gap-2">
              <Activity size={16} className="text-green-400" />
              Recent Log Entries
              <span className={`text-[10px] px-2 py-0.5 rounded-full border ${
                source === 'live'
                  ? 'bg-green-500/10 text-green-400 border-green-500/20'
                  : 'bg-violet-500/10 text-violet-400 border-violet-500/20'
              }`}>
                {source === 'live' ? 'Live' : 'Uploaded'}
              </span>
            </h3>
            {source === 'live'
              ? <a href="/live" className="text-xs text-green-400 hover:text-green-300 flex items-center gap-1">Live View <ArrowUpRight size={12} /></a>
              : <a href="/upload" className="text-xs text-violet-400 hover:text-violet-300 flex items-center gap-1">Upload <ArrowUpRight size={12} /></a>
            }
          </div>
          <div className="terminal h-80 overflow-y-auto space-y-0.5">
            {recentLogs.length > 0 ? recentLogs.map((log, i) => (
              <div key={log.id || i} className="flex gap-2 hover:bg-white/5 px-1 py-0.5 rounded text-[11px]">
                <span className="text-gray-600 flex-shrink-0 w-16 font-mono">
                  {log.timestamp ? new Date(log.timestamp).toLocaleTimeString() : ''}
                </span>
                <span className={`flex-shrink-0 font-medium ${
                  log.severity === 'critical' ? 'text-red-400' :
                  log.severity === 'high'     ? 'text-orange-400' :
                  log.severity === 'medium'   ? 'text-yellow-400' :
                  'text-green-400'
                }`}>
                  [{log.source_type?.toUpperCase() || 'LOG'}]
                </span>
                <span className="text-gray-300 truncate">{log.message}</span>
              </div>
            )) : (
              <div className="flex flex-col items-center justify-center h-full text-gray-600 gap-2">
                <Activity size={28} className="opacity-30" />
                <p className="text-xs">No {source === 'live' ? 'live' : 'uploaded'} log data yet</p>
                {source === 'live'
                  ? <p className="text-[10px] text-gray-700">Run the PowerShell forwarder to start collecting</p>
                  : <p className="text-[10px] text-gray-700">Go to File Upload to analyse a log file</p>
                }
              </div>
            )}
          </div>
        </div>
      </div>

      {/* SOC Metrics */}
      {metrics && (
        <div className="space-y-4">
          <h3 className="text-sm font-semibold text-gray-300 flex items-center gap-2">
            <BarChart2 size={16} className="text-cyan-400" /> SOC Metrics
          </h3>
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-5 gap-3">
            <MetricCard label="Total Events"       value={metrics.total_events}        color="text-emerald-400" />
            <MetricCard label="Total Alerts"       value={metrics.total_alerts}        color="text-violet-400" />
            <MetricCard label="Open Alerts"        value={metrics.open_alerts}         color="text-red-400" pulse={metrics.open_alerts > 0} />
            <MetricCard label="Resolved Alerts"    value={metrics.resolved_alerts}     color="text-green-400" />
            <MetricCard label="Critical Alerts"    value={metrics.critical_alerts}     color="text-red-400" />
            <MetricCard label="High Alerts"        value={metrics.high_alerts}         color="text-orange-400" />
            <MetricCard label="Open Incidents"     value={metrics.open_incidents}      color="text-yellow-400" />
            <MetricCard label="Resolved Incidents" value={metrics.resolved_incidents}  color="text-green-400" />
            <MetricCard
              label="FP Rate"
              value={metrics.false_positive_rate !== null ? `${metrics.false_positive_rate}%` : 'N/A'}
              color="text-gray-400"
              raw
            />
            <MetricCard
              label="MTTR"
              value={metrics.mttr_minutes !== null ? `${metrics.mttr_minutes}m` : 'N/A'}
              color="text-blue-400"
              raw
            />
          </div>

          {/* Analyst workload */}
          {metrics.analyst_workload && (
            <div className="card">
              <h4 className="text-xs font-semibold text-gray-400 mb-3 flex items-center gap-1.5">
                <Layers size={13} className="text-cyan-400" /> Alert Workload by Status
              </h4>
              <div className="flex gap-4 flex-wrap">
                {Object.entries(metrics.analyst_workload).map(([status, count]) => (
                  <div key={status} className="flex flex-col items-center">
                    <span className="text-xl font-bold text-white">{count}</span>
                    <span className="text-[10px] text-gray-500 capitalize">{status}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Top detection rules + top MITRE */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {metrics.top_detection_rules.length > 0 && (
              <div className="card">
                <h4 className="text-xs font-semibold text-gray-400 mb-3 flex items-center gap-1.5">
                  <Shield size={13} className="text-blue-400" /> Top Detection Rules
                </h4>
                <div className="space-y-2">
                  {metrics.top_detection_rules.slice(0, 6).map((r, i) => (
                    <div key={i} className="flex items-center gap-2">
                      <span className="text-xs text-gray-300 font-mono flex-1 truncate">{r.rule}</span>
                      <div className="flex items-center gap-2">
                        <div className="w-16 h-1.5 bg-gray-800 rounded-full overflow-hidden">
                          <div
                            className="h-full bg-blue-500 rounded-full"
                            style={{ width: `${Math.min(100, (r.count / (metrics.top_detection_rules[0]?.count || 1)) * 100)}%` }}
                          />
                        </div>
                        <span className="text-xs text-gray-500 w-6 text-right">{r.count}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {metrics.top_mitre.length > 0 && (
              <div className="card">
                <h4 className="text-xs font-semibold text-gray-400 mb-3 flex items-center gap-1.5">
                  <Zap size={13} className="text-violet-400" /> Top MITRE Techniques (Active Alerts)
                </h4>
                <div className="flex flex-wrap gap-2">
                  {metrics.top_mitre.map((m, i) => {
                    const techId = m.technique.match(/T\d+(?:\.\d+)?/)?.[0] || m.technique
                    return (
                      <div key={i} className="flex items-center gap-1.5 px-2.5 py-1.5 bg-violet-500/10 rounded-lg border border-violet-500/20">
                        <span className="text-[10px] font-mono text-violet-300">{techId}</span>
                        <span className="text-[9px] text-violet-500">×{m.count}</span>
                      </div>
                    )
                  })}
                </div>
              </div>
            )}
          </div>

          {/* Alert status breakdown */}
          {metrics.by_status && Object.keys(metrics.by_status).length > 0 && (
            <div className="card">
              <h4 className="text-xs font-semibold text-gray-400 mb-3 flex items-center gap-1.5">
                <CheckCircle size={13} className="text-green-400" /> Alert Status Breakdown
              </h4>
              <div className="flex flex-wrap gap-3">
                {Object.entries(metrics.by_status).map(([status, count]) => count > 0 ? (
                  <div key={status} className="flex items-center gap-2 px-3 py-1.5 bg-gray-800/40 rounded-lg border border-white/5">
                    <span className="text-xs font-bold text-white">{count}</span>
                    <span className="text-[10px] text-gray-500 capitalize">{status.replace('_', ' ')}</span>
                  </div>
                ) : null)}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Top Hosts */}
      {(stats?.top_hosts || []).length > 0 && (
        <div className="card">
          <h3 className="text-sm font-semibold text-gray-300 mb-4 flex items-center gap-2">
            <Server size={16} className="text-blue-400" />
            Top Active Hosts
          </h3>
          <div className="h-48">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={(stats?.top_hosts || []).slice(0, 10)} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" />
                <XAxis type="number" tick={{ fill: '#6b7280', fontSize: 11 }} />
                <YAxis dataKey="host" type="category" tick={{ fill: '#9ca3af', fontSize: 11 }} width={100} />
                <Tooltip contentStyle={{ background: '#1f2937', border: '1px solid #374151', borderRadius: '8px', fontSize: '12px' }} itemStyle={{ color: '#e5e7eb' }} />
                <Bar dataKey="count" fill={source === 'live' ? '#22c55e' : '#8b5cf6'} radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

    </div>
  )
}

// Stat Card Component
function StatCard({ icon, label, value, color, bgColor, borderColor, pulse = false }: {
  icon: React.ReactNode
  label: string
  value: number
  color: string
  bgColor: string
  borderColor: string
  pulse?: boolean
}) {
  return (
    <div className={`card ${borderColor} border ${pulse ? 'animate-pulse-red' : ''}`}>
      <div className={`p-2 rounded-lg ${bgColor} w-fit`}>
        <span className={color}>{icon}</span>
      </div>
      <div className="mt-3">
        <p className="text-2xl font-bold text-white">{value.toLocaleString()}</p>
        <p className="text-xs text-gray-500 mt-0.5">{label}</p>
      </div>
    </div>
  )
}

// Metric Card Component
function MetricCard({ label, value, color, pulse = false, raw = false }: {
  label: string
  value: number | string
  color: string
  pulse?: boolean
  raw?: boolean
}) {
  return (
    <div className={`card border ${pulse ? 'animate-pulse-red border-red-500/20' : 'border-white/5'}`}>
      <p className={`text-xl font-bold ${color}`}>
        {raw ? value : typeof value === 'number' ? value.toLocaleString() : value}
      </p>
      <p className="text-[11px] text-gray-500 mt-0.5">{label}</p>
    </div>
  )
}
