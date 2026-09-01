import axios from 'axios'
import { Alert, InvestigationContext } from '../types'

// Use the same host in development, or set VITE_API_URL for a separately hosted frontend.
export const API_BASE = import.meta.env.VITE_API_URL || '/api'

export const getSocketUrl = () => {
  if (import.meta.env.VITE_SOCKET_URL) return import.meta.env.VITE_SOCKET_URL
  if (API_BASE.startsWith('http')) return new URL(API_BASE).origin
  return window.location.origin
}

const apiClient = axios.create({
  baseURL: API_BASE,
  headers: { 'Content-Type': 'application/json' },
})

// Add auth token to requests
apiClient.interceptors.request.use((config) => {
  const token = localStorage.getItem('token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

apiClient.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('token')
      localStorage.removeItem('user_email')
      localStorage.removeItem('user_role')
      localStorage.removeItem('user_name')
    }
    return Promise.reject(error)
  }
)

export const api = {
  // Dashboard
  dashboard: {
    getStats: (dataSource?: string) => apiClient.get('/dashboard/stats', { params: dataSource ? { data_source: dataSource } : {} }).then(r => r.data),
  },
  
  // Alerts — add escalate and report endpoints
  alerts: {
    list: (params?: any) => apiClient.get('/alerts', { params }).then(r => r.data),
    get: (id: string) => apiClient.get<Alert>(`/alerts/${id}`).then(r => r.data),
    getStats: () => apiClient.get('/alerts/stats').then(r => r.data),
    getAIAnalysis: (id: string) => apiClient.get(`/alerts/${id}/ai-analysis`).then(r => r.data),
    getInvestigationContext: (id: string) => apiClient.get<InvestigationContext>(`/alerts/${id}/investigation-context`).then(r => r.data),
    updateStatus: (id: string, status: string, reason: string) =>
      apiClient.patch(`/alerts/${id}/status`, { status, reason }).then(r => r.data),
    classify: (id: string, classification: string, reason: string) =>
      apiClient.post(`/alerts/${id}/classify`, { classification, reason }).then(r => r.data),
    getCorrelations: (id: string) =>
      apiClient.get(`/alerts/${id}/correlations`).then(r => r.data),
    escalate: (id: string) => apiClient.post(`/alerts/${id}/escalate`).then(r => r.data),
    respond: (id: string, action: string) => 
      apiClient.post(`/alerts/${id}/respond`, null, { params: { action } }).then(r => r.data),
  },
  
  // Logs
  logs: {
    list: (params?: any) => apiClient.get('/logs', { params }).then(r => r.data),
    getStats: () => apiClient.get('/logs/stats').then(r => r.data),
    getSources: () => apiClient.get('/logs/sources').then(r => r.data),
    getRules: () => apiClient.get('/logs/rules').then(r => r.data),
    ingest: (logs: any[]) => apiClient.post('/logs/ingest', { logs }).then(r => r.data),
  },
  
  // Upload
  upload: {
    file: (file: File, format: string = 'auto') => {
      const formData = new FormData()
      formData.append('file', file)
      formData.append('log_format', format)
      return apiClient.post('/upload/file', formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      }).then(r => r.data)
    },
    history: () => apiClient.get('/upload/history').then(r => r.data),
    getLogs: (uploadId: string, params?: any) => 
      apiClient.get(`/upload/${uploadId}/logs`, { params }).then(r => r.data),
    getFormats: () => apiClient.get('/upload/formats').then(r => r.data),
    getStats: () => apiClient.get('/upload/stats').then(r => r.data),
    delete: (uploadId: string) => apiClient.delete(`/upload/${uploadId}`).then(r => r.data),
  },
  
  // AI
  ai: {
    chat: (message: string, options?: { hours?: number; data_source?: string; severity?: string; source_type?: string }) => 
      apiClient.post('/ai/chat', { message, ...options }).then(r => r.data),
    analyzeAlert: (alertId?: string, alertData?: any) => 
      apiClient.post('/ai/analyze-alert', { alert_id: alertId, alert_data: alertData }).then(r => r.data),
    getThreatAssessment: () => apiClient.get('/ai/threat-assessment').then(r => r.data),
    getStatus: () => apiClient.get('/ai/status').then(r => r.data),
    summarizeLogs: (options: any) => apiClient.post('/ai/summarize-logs', options).then(r => r.data),
  },
  
  // Incidents — add report endpoint
  incidents: {
    list: () => apiClient.get('/incidents').then(r => r.data),
    get: (id: string) => apiClient.get(`/incidents/${id}`).then(r => r.data),
    create: (data: any) => apiClient.post('/incidents', data).then(r => r.data),
    update: (id: string, data: any) => 
      apiClient.patch(`/incidents/${id}`, typeof data === 'string' ? { status: data } : data).then(r => r.data),
    generateReport: (id: string) => apiClient.post(`/incidents/${id}/report`).then(r => r.data),
  },

  // SOC Metrics
  metrics: {
    get: () => apiClient.get('/soc/metrics').then(r => r.data),
  },
  
  // Auth
  auth: {
    login: (email: string, password: string) => 
      apiClient.post('/auth/login', { email, password }).then(r => r.data),
    logout: () => apiClient.post('/auth/logout').then(r => r.data),
    me: () => apiClient.get('/auth/me').then(r => r.data),
    listUsers: () => apiClient.get('/auth/users').then(r => r.data),
    createUser: (data: any) => apiClient.post('/auth/users', data).then(r => r.data),
    updateUser: (id: string, data: any) => apiClient.patch(`/auth/users/${id}`, data).then(r => r.data),
    listIngestKeys: () => apiClient.get('/auth/ingest-keys').then(r => r.data),
    createIngestKey: (name: string) => apiClient.post('/auth/ingest-keys', { name }).then(r => r.data),
    revokeIngestKey: (id: string) => apiClient.delete(`/auth/ingest-keys/${id}`).then(r => r.data),
  },

  detectionRules: {
    list: () => apiClient.get('/detection-rules').then(r => r.data),
    update: (name: string, data: { enabled?: boolean; threshold?: number; time_window_seconds?: number }) =>
      apiClient.patch(`/detection-rules/${name}`, data).then(r => r.data),
  },

  // Data management
  data: {
    clearLiveLogs: () => apiClient.delete('/data/live-logs').then(r => r.data),
  },
}

export default api
