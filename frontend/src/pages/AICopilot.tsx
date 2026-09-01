import { useState, useRef, useEffect } from 'react'
import { api } from '../services/api'
import { Bot, Send, User, Brain, Sparkles, AlertTriangle, Shield,
         Clock, Database, ChevronDown } from 'lucide-react'

interface Message {
  role: 'user' | 'assistant'
  content: string
  timestamp: Date
  meta?: {
    alerts_considered?: number
    logs_considered?: number
    ai_mode?: string
    model?: string
    time_range_hours?: number
    truncated?: boolean
  }
}

const TIME_OPTIONS = [
  { label: 'Last 1 hour',  value: 1 },
  { label: 'Last 6 hours', value: 6 },
  { label: 'Last 24 hours',value: 24 },
  { label: 'Last 7 days',  value: 168 },
]

const SOURCE_OPTIONS = [
  { label: 'All sources',  value: 'all' },
  { label: 'Live ingested',value: 'live' },
  { label: 'Uploaded files',value: 'uploaded' },
]

export default function AICopilot() {
  const [messages, setMessages] = useState<Message[]>([{
    role: 'assistant',
    content: "Hello! I'm your AI SOC Analyst. I have access to your live database — ask me about current alerts, threats, hosts, or request an incident report.",
    timestamp: new Date(),
  }])
  const [input, setInput] = useState('')
  const [loading, setLoading] = useState(false)
  const [aiStatus, setAiStatus] = useState<any>(null)
  const [hours, setHours] = useState(24)
  const [dataSource, setDataSource] = useState('all')
  const [showOptions, setShowOptions] = useState(false)
  const messagesEndRef = useRef<HTMLDivElement>(null)

  useEffect(() => { api.ai.getStatus().then(setAiStatus).catch(() => {}) }, [])
  useEffect(() => { messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' }) }, [messages])

  const sendMessage = async (text?: string) => {
    const msg = (text || input).trim()
    if (!msg || loading) return
    setInput('')
    setMessages(prev => [...prev, { role: 'user', content: msg, timestamp: new Date() }])
    setLoading(true)
    try {
      const data = await api.ai.chat(msg, { hours, data_source: dataSource })
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: data.response,
        timestamp: new Date(),
        meta: data.context_meta,
      }])
    } catch {
      setMessages(prev => [...prev, {
        role: 'assistant',
        content: "Failed to reach the AI engine. Check the backend is running.",
        timestamp: new Date(),
      }])
    } finally {
      setLoading(false)
    }
  }

  const quickQuestions = [
    "What are the top threats right now?",
    "Are there any critical alerts?",
    "Which hosts need immediate attention?",
    "Show likely false positives",
    "Summarize the last 24 hours",
    "Generate an incident report",
  ]

  return (
    <div className="space-y-4 animate-fade-in h-[calc(100vh-8rem)]">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Brain className="text-violet-400" /> AI Copilot
          </h1>
          <p className="text-sm text-gray-400 mt-1">Context-aware analysis using your live SOC data</p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          {/* Time range picker */}
          <div className="relative">
            <button
              onClick={() => setShowOptions(v => !v)}
              className="flex items-center gap-1.5 px-3 py-1.5 bg-gray-800 border border-white/10 rounded-lg text-xs text-gray-300 hover:border-white/20"
            >
              <Clock size={12} />
              {TIME_OPTIONS.find(o => o.value === hours)?.label}
              <ChevronDown size={12} />
            </button>
            {showOptions && (
              <div className="absolute right-0 top-9 z-20 bg-gray-900 border border-white/10 rounded-lg shadow-xl min-w-36 overflow-hidden">
                {TIME_OPTIONS.map(o => (
                  <button key={o.value} onClick={() => { setHours(o.value); setShowOptions(false) }}
                    className={`w-full text-left px-3 py-2 text-xs hover:bg-white/5 ${hours === o.value ? 'text-violet-400' : 'text-gray-300'}`}>
                    {o.label}
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Source picker */}
          <select value={dataSource} onChange={e => setDataSource(e.target.value)}
            className="px-2 py-1.5 bg-gray-800 border border-white/10 rounded-lg text-xs text-gray-300">
            {SOURCE_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
          </select>

          {/* AI status badge */}
          {aiStatus && (
            <div className={`flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs border ${
              aiStatus.available && aiStatus.health !== 'error'
                ? 'bg-green-500/10 text-green-400 border-green-500/20'
                : 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20'
            }`}>
              <Sparkles size={12} />
              {aiStatus.available ? `AI · ${aiStatus.model}` : 'Mock mode'}
            </div>
          )}
        </div>
      </div>

      {/* Warning banners */}
      {aiStatus?.health === 'error' && (
        <div className="bg-yellow-500/5 border border-yellow-500/20 rounded-lg p-3 flex items-center gap-3">
          <AlertTriangle size={14} className="text-yellow-400 shrink-0" />
          <p className="text-xs text-yellow-300">{aiStatus.message}</p>
        </div>
      )}
      {!aiStatus?.available && (
        <div className="bg-blue-500/5 border border-blue-500/20 rounded-lg p-3 flex items-center gap-3">
          <Database size={14} className="text-blue-400 shrink-0" />
          <p className="text-xs text-blue-300">
            Running in mock mode — responses use real DB statistics.
            Add <code className="bg-gray-800 px-1 rounded">OPENAI_API_KEY</code> for full AI narrative.
          </p>
        </div>
      )}

      <div className="flex gap-4 h-[calc(100%-9rem)]">
        {/* Chat area */}
        <div className="flex-1 flex flex-col card overflow-hidden">
          <div className="flex-1 overflow-y-auto space-y-4 p-4">
            {messages.map((msg, i) => (
              <div key={i} className={`flex gap-3 ${msg.role === 'user' ? 'justify-end' : ''}`}>
                {msg.role === 'assistant' && (
                  <div className="w-8 h-8 bg-violet-500/20 rounded-lg flex items-center justify-center shrink-0">
                    <Bot size={15} className="text-violet-400" />
                  </div>
                )}
                <div className={`max-w-[75%] ${
                  msg.role === 'user'
                    ? 'bg-violet-600/20 border border-violet-500/30 rounded-2xl rounded-br-sm px-4 py-2.5'
                    : 'bg-gray-800/50 border border-white/5 rounded-2xl rounded-bl-sm px-4 py-2.5'
                }`}>
                  <p className="text-sm text-gray-200 whitespace-pre-wrap">{msg.content}</p>
                  <div className="flex items-center gap-3 mt-1.5 flex-wrap">
                    <span className="text-[10px] text-gray-600">{msg.timestamp.toLocaleTimeString()}</span>
                    {msg.meta && (
                      <span className="text-[10px] text-gray-600">
                        {msg.meta.alerts_considered} alerts · {msg.meta.logs_considered?.toLocaleString()} logs ·
                        {msg.meta.time_range_hours}h · {msg.meta.ai_mode === 'live' ? '🤖 AI' : '📊 mock'}
                        {msg.meta.truncated ? ' · truncated' : ''}
                      </span>
                    )}
                  </div>
                </div>
                {msg.role === 'user' && (
                  <div className="w-8 h-8 bg-blue-500/20 rounded-lg flex items-center justify-center shrink-0">
                    <User size={15} className="text-blue-400" />
                  </div>
                )}
              </div>
            ))}
            {loading && (
              <div className="flex gap-3">
                <div className="w-8 h-8 bg-violet-500/20 rounded-lg flex items-center justify-center">
                  <Bot size={15} className="text-violet-400" />
                </div>
                <div className="bg-gray-800/50 border border-white/5 rounded-2xl rounded-bl-sm px-4 py-3">
                  <div className="flex gap-1">
                    {[0, 150, 300].map(d => (
                      <div key={d} className="w-2 h-2 bg-violet-400 rounded-full animate-bounce"
                           style={{ animationDelay: `${d}ms` }} />
                    ))}
                  </div>
                </div>
              </div>
            )}
            <div ref={messagesEndRef} />
          </div>

          <div className="p-4 border-t border-white/5">
            <div className="flex gap-2">
              <input type="text" value={input}
                onChange={e => setInput(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && !e.shiftKey && sendMessage()}
                placeholder="Ask about alerts, threats, hosts..."
                className="input flex-1" disabled={loading} />
              <button onClick={() => sendMessage()} disabled={!input.trim() || loading}
                className="btn-primary flex items-center gap-1.5">
                <Send size={14} />
              </button>
            </div>
          </div>
        </div>

        {/* Sidebar */}
        <div className="w-56 space-y-3 hidden lg:block shrink-0">
          <p className="text-xs font-semibold text-gray-500 uppercase">Quick Questions</p>
          <div className="space-y-1.5">
            {quickQuestions.map((q, i) => (
              <button key={i} onClick={() => sendMessage(q)}
                disabled={loading}
                className="w-full text-left p-2.5 bg-gray-800/30 border border-white/5 rounded-lg text-xs text-gray-400 hover:text-gray-200 hover:border-white/10 transition-all disabled:opacity-50">
                {q}
              </button>
            ))}
          </div>
          <div className="card mt-4">
            <p className="text-xs font-semibold text-gray-500 uppercase mb-2">Context</p>
            <div className="space-y-1.5 text-[10px] text-gray-400">
              <div className="flex items-center gap-2"><Shield size={10} className="text-green-400" /> Live DB statistics</div>
              <div className="flex items-center gap-2"><AlertTriangle size={10} className="text-orange-400" /> Active alerts</div>
              <div className="flex items-center gap-2"><Brain size={10} className="text-violet-400" /> MITRE mapping</div>
              <div className="flex items-center gap-2"><Database size={10} className="text-blue-400" /> Recent logs</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
