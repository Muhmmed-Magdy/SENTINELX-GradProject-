import { create } from 'zustand'
import { Alert, LogEntry, DashboardStats } from '../types'
import { api } from '../services/api'

interface AppState {
  // Dashboard
  stats: DashboardStats | null
  loadingStats: boolean
  
  // Alerts
  alerts: Alert[]
  selectedAlert: Alert | null
  loadingAlerts: boolean
  
  // Logs
  logs: LogEntry[]
  liveLogs: LogEntry[]
  loadingLogs: boolean
  
  // Actions
  fetchStats: () => Promise<void>
  fetchAlerts: (params?: any) => Promise<void>
  fetchLogs: (params?: any) => Promise<void>
  setSelectedAlert: (alert: Alert | null) => void
  addLiveLog: (log: LogEntry) => void
  addAlert: (alert: Alert) => void
}

export const useStore = create<AppState>((set, get) => ({
  stats: null,
  loadingStats: false,
  alerts: [],
  selectedAlert: null,
  loadingAlerts: false,
  logs: [],
  liveLogs: [],
  loadingLogs: false,
  
  fetchStats: async () => {
    set({ loadingStats: true })
    try {
      const stats = await api.dashboard.getStats()
      set({ stats, loadingStats: false })
    } catch (error) {
      console.error('Failed to fetch stats:', error)
      set({ loadingStats: false })
    }
  },
  
  fetchAlerts: async (params) => {
    set({ loadingAlerts: true })
    try {
      const alerts = await api.alerts.list(params)
      set({ alerts, loadingAlerts: false })
    } catch (error) {
      console.error('Failed to fetch alerts:', error)
      set({ loadingAlerts: false })
    }
  },
  
  fetchLogs: async (params) => {
    set({ loadingLogs: true })
    try {
      const logs = await api.logs.list(params)
      set({ logs, loadingLogs: false })
    } catch (error) {
      console.error('Failed to fetch logs:', error)
      set({ loadingLogs: false })
    }
  },
  
  setSelectedAlert: (alert) => set({ selectedAlert: alert }),
  
  addLiveLog: (log) => set((state) => ({
    liveLogs: [log, ...state.liveLogs].slice(0, 200)
  })),
  
  addAlert: (alert) => set((state) => ({
    alerts: [alert, ...state.alerts].slice(0, 200)
  })),
}))
