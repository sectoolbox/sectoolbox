import React, { useState, useCallback, useEffect, useRef } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import {
  ArrowLeft,
  Upload,
  Activity,
  Shield,
  FileText,
  Download,
  Copy,
  Target,
  Flag,
  Terminal,
  Users,
  BarChart3,
  Search,
  Filter,
  X,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Clock
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Card } from '../components/ui/card'
import { LineChart, Line, AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import {
  EVTXAnalysisResult,
  EVTXEvent,
  getEventDescription
} from '../lib/evtxAnalysis'

const EVTXAnalysis: React.FC = () => {
  const navigate = useNavigate()
  const location = useLocation()
  const workerRef = useRef<Worker | null>(null)

  // State
  const [files, setFiles] = useState<File[]>([])
  const [result, setResult] = useState<EVTXAnalysisResult | null>(null)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [activeTab, setActiveTab] = useState<'overview' | 'events' | 'timeline' | 'threats' | 'mitre' | 'flags' | 'commands' | 'sessions'>('overview')
  const [progress, setProgress] = useState(0)
  const [progressStatus, setProgressStatus] = useState('')
  const [filteredEvents, setFilteredEvents] = useState<EVTXEvent[]>([])
  const [searchTerm, setSearchTerm] = useState('')
  const [levelFilter, setLevelFilter] = useState<string>('All')
  const [selectedEvent, setSelectedEvent] = useState<EVTXEvent | null>(null)

  // Initialize Web Worker
  useEffect(() => {
    workerRef.current = new Worker(new URL('../workers/evtxWorker.ts', import.meta.url), {
      type: 'module'
    })

    workerRef.current.onmessage = (event) => {
      const { type, payload } = event.data

      if (type === 'progress') {
        setProgress(payload.progress)
        setProgressStatus(payload.status)
      } else if (type === 'complete') {
        setResult(payload)
        setFilteredEvents(payload.events)
        setProgress(100)
        setTimeout(() => {
          setIsAnalyzing(false)
          setProgress(0)
          setProgressStatus('')
        }, 1000)
      } else if (type === 'error') {
        alert('Analysis failed: ' + payload.message)
        setIsAnalyzing(false)
        setProgress(0)
        setProgressStatus('')
      }
    }

    return () => {
      workerRef.current?.terminate()
    }
  }, [])

  // Handle file from Digital Forensics page
  useEffect(() => {
    if (location.state?.evtxFile) {
      const file = location.state.evtxFile
      setFiles([file])
      analyzeFiles([file])
    }
  }, [location.state])

  // Handle file selection
  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFiles = Array.from(e.target.files || [])
    if (selectedFiles.length > 0) {
      setFiles(selectedFiles)
      analyzeFiles(selectedFiles)
    }
  }

  // Analyze files using Web Worker
  const analyzeFiles = useCallback(async (filesToAnalyze?: File[]) => {
    const targetFiles = filesToAnalyze || files
    if (!targetFiles || targetFiles.length === 0 || !workerRef.current) return

    setIsAnalyzing(true)
    setProgress(0)
    setProgressStatus('Preparing analysis...')

    try {
      const fileBuffers = await Promise.all(
        targetFiles.map(async (f) => ({
          name: f.name,
          buffer: await f.arrayBuffer()
        }))
      )

      workerRef.current.postMessage({
        type: targetFiles.length === 1 ? 'parse-single' : 'parse-multiple',
        payload: { fileBuffers }
      })
    } catch (error) {
      console.error('Failed to read files:', error)
      alert('Failed to read EVTX file(s)')
      setIsAnalyzing(false)
    }
  }, [files])

  // Apply filters
  useEffect(() => {
    if (!result) return

    let filtered = result.events

    if (searchTerm) {
      const term = searchTerm.toLowerCase()
      filtered = filtered.filter(e =>
        e.message.toLowerCase().includes(term) ||
        e.source.toLowerCase().includes(term) ||
        e.eventId.toString().includes(term) ||
        (e.userName && e.userName.toLowerCase().includes(term))
      )
    }

    if (levelFilter !== 'All') {
      filtered = filtered.filter(e => e.level === levelFilter)
    }

    setFilteredEvents(filtered)
  }, [result, searchTerm, levelFilter])

  // Copy to clipboard
  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  // Level color helper
  const getLevelColor = (level: string) => {
    switch (level) {
      case 'Critical': return 'border-red-500 bg-red-500/10 text-red-400'
      case 'Error': return 'border-orange-500 bg-orange-500/10 text-orange-400'
      case 'Warning': return 'border-yellow-500 bg-yellow-500/10 text-yellow-400'
      case 'Information': return 'border-blue-500 bg-blue-500/10 text-blue-400'
      default: return 'border-gray-500 bg-gray-500/10 text-gray-400'
    }
  }

  // Level icon helper
  const getLevelIcon = (level: string) => {
    switch (level) {
      case 'Critical':
      case 'Error':
        return <XCircle className="w-3 h-3" />
      case 'Warning':
        return <AlertTriangle className="w-3 h-3" />
      case 'Information':
        return <CheckCircle className="w-3 h-3" />
      default:
        return <Clock className="w-3 h-3" />
    }
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-4">
          <Button
            variant="ghost"
            size="sm"
            onClick={() => navigate(-1)}
            className="flex items-center space-x-2"
          >
            <ArrowLeft className="w-4 h-4" />
            <span>Back</span>
          </Button>
          <div>
            <h1 className="text-2xl font-bold">EVTX Analysis</h1>
            <p className="text-sm text-muted-foreground">Windows Event Log Forensics</p>
          </div>
        </div>
      </div>

      {/* File Upload */}
      {files.length === 0 && !result ? (
        <Card className="p-6">
          <h2 className="text-lg font-semibold mb-4">Upload EVTX Files</h2>
          <div className="border-2 border-dashed border-border rounded-lg p-8 text-center hover:border-accent transition-colors">
            <Upload className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
            <p className="text-lg font-medium mb-2">Select Windows Event Log files</p>
            <p className="text-sm text-muted-foreground mb-4">
              Supports .evtx files • Upload multiple files for cross-log correlation
            </p>
            <input
              type="file"
              accept=".evtx"
              onChange={handleFileSelect}
              multiple
              className="hidden"
              id="evtx-upload"
            />
            <label htmlFor="evtx-upload">
              <Button variant="outline" asChild>
                <span>Browse Files</span>
              </Button>
            </label>
          </div>
        </Card>
      ) : (
        <Card className="p-4">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center space-x-3">
              <FileText className="w-5 h-5 text-accent" />
              <div>
                <p className="font-medium">
                  {files.length} file{files.length > 1 ? 's' : ''} loaded
                </p>
                <p className="text-xs text-muted-foreground">
                  {files.map(f => f.name).join(', ')}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              {result && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => analyzeFiles()}
                  disabled={isAnalyzing}
                >
                  Re-analyze
                </Button>
              )}
              <Button
                variant="ghost"
                size="sm"
                onClick={() => {
                  setFiles([])
                  setResult(null)
                }}
              >
                Remove File{files.length > 1 ? 's' : ''}
              </Button>
            </div>
          </div>

          {isAnalyzing && progress > 0 && (
            <div className="space-y-2">
              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">{progressStatus}</span>
                <span className="text-accent font-medium">{progress}%</span>
              </div>
              <div className="w-full bg-muted rounded-full h-2 overflow-hidden">
                <div
                  className="bg-accent h-full transition-all duration-300 ease-out"
                  style={{ width: `${progress}%` }}
                />
              </div>
            </div>
          )}
        </Card>
      )}

      {/* Analysis Results */}
      {result && (
        <>
          {/* Statistics Overview */}
          <Card className="p-6">
            <h3 className="text-lg font-semibold mb-4">Analysis Summary</h3>
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
              <div className="bg-background border border-border rounded-lg p-4 text-center">
                <div className="text-3xl font-bold text-accent">{result.statistics.totalEvents}</div>
                <div className="text-xs text-muted-foreground mt-1">Total Events</div>
              </div>
              <div className="bg-background border border-border rounded-lg p-4 text-center">
                <div className="text-3xl font-bold text-red-400">{result.statistics.criticalCount}</div>
                <div className="text-xs text-muted-foreground mt-1">Critical</div>
              </div>
              <div className="bg-background border border-border rounded-lg p-4 text-center">
                <div className="text-3xl font-bold text-orange-400">{result.statistics.errorCount}</div>
                <div className="text-xs text-muted-foreground mt-1">Errors</div>
              </div>
              <div className="bg-background border border-border rounded-lg p-4 text-center">
                <div className="text-3xl font-bold text-yellow-400">{result.statistics.warningCount}</div>
                <div className="text-xs text-muted-foreground mt-1">Warnings</div>
              </div>
              <div className="bg-background border border-border rounded-lg p-4 text-center">
                <div className="text-3xl font-bold text-blue-400">{result.statistics.infoCount}</div>
                <div className="text-xs text-muted-foreground mt-1">Info</div>
              </div>
            </div>

            {/* Quick Insights */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4">
              <div className="bg-background border border-border rounded-lg p-4">
                <div className="flex items-center space-x-2 text-sm text-muted-foreground mb-2">
                  <Shield className="w-4 h-4" />
                  <span>Threat Level</span>
                </div>
                <div className="text-2xl font-bold text-red-400">
                  {result.threats.filter(t => t.severity === 'Critical' || t.severity === 'High').length}
                </div>
                <div className="text-xs text-muted-foreground mt-1">
                  {result.threats.length > 0 ? result.threats.slice(0, 2).map(t => t.type).join(', ') : 'No threats detected'}
                </div>
              </div>

              <div className="bg-background border border-border rounded-lg p-4">
                <div className="flex items-center space-x-2 text-sm text-muted-foreground mb-2">
                  <Users className="w-4 h-4" />
                  <span>User Activity</span>
                </div>
                <div className="text-2xl font-bold text-orange-400">
                  {result.statistics.uniqueUsers}
                </div>
                <div className="text-xs text-muted-foreground mt-1">
                  Failed logons: {result.events.filter(e => e.eventId === 4625).length}
                </div>
              </div>

              <div className="bg-background border border-border rounded-lg p-4">
                <div className="flex items-center space-x-2 text-sm text-muted-foreground mb-2">
                  <Terminal className="w-4 h-4" />
                  <span>System Impact</span>
                </div>
                <div className="text-2xl font-bold text-purple-400">
                  {result.suspiciousCommands.length}
                </div>
                <div className="text-xs text-muted-foreground mt-1">
                  {result.suspiciousCommands.length > 0 ? 'Suspicious commands detected' : 'No suspicious activity'}
                </div>
              </div>
            </div>
          </Card>

          {/* Tabs */}
          <Card>
            <div className="flex flex-wrap border-b border-border">
              {[
                { id: 'overview', label: 'Overview', icon: Target },
                { id: 'events', label: 'Events', icon: FileText, count: filteredEvents.length },
                { id: 'timeline', label: 'Timeline', icon: BarChart3 },
                { id: 'threats', label: 'Threats', icon: Shield, count: result.threats.length },
                { id: 'mitre', label: 'MITRE', icon: Target, count: result.mitreAttacks.length },
                { id: 'flags', label: 'Flags', icon: Flag, count: result.flags.length },
                { id: 'commands', label: 'Commands', icon: Terminal, count: result.suspiciousCommands.length },
                { id: 'sessions', label: 'Sessions', icon: Users, count: result.userSessions.length }
              ].map(tab => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={`flex items-center space-x-2 px-4 py-3 text-sm font-medium transition-colors border-b-2 ${
                    activeTab === tab.id
                      ? 'border-accent text-accent'
                      : 'border-transparent text-muted-foreground hover:text-foreground hover:border-border'
                  }`}
                >
                  <tab.icon className="w-4 h-4" />
                  <span>{tab.label}</span>
                  {'count' in tab && tab.count !== undefined && (
                    <span className="px-2 py-0.5 bg-accent/20 text-accent rounded text-xs">
                      {tab.count}
                    </span>
                  )}
                </button>
              ))}
            </div>

            <div className="p-6">
              {/* Overview Tab */}
              {activeTab === 'overview' && (
                <div className="space-y-4">
                  <h4 className="font-medium text-lg">Investigation Summary</h4>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="bg-background border border-border rounded-lg p-4">
                      <h5 className="font-medium mb-2">Top Threats</h5>
                      <div className="space-y-2">
                        {result.threats.slice(0, 5).map((t, i) => (
                          <div key={i} className="flex justify-between text-sm">
                            <span className={`font-medium ${
                              t.severity === 'Critical' ? 'text-red-400' :
                              t.severity === 'High' ? 'text-orange-400' :
                              'text-yellow-400'
                            }`}>{t.type}</span>
                            <span className="text-muted-foreground">{t.confidence}%</span>
                          </div>
                        ))}
                        {result.threats.length === 0 && (
                          <p className="text-sm text-muted-foreground">No threats detected</p>
                        )}
                      </div>
                    </div>

                    <div className="bg-background border border-border rounded-lg p-4">
                      <h5 className="font-medium mb-2">Top Event Types</h5>
                      <div className="space-y-2">
                        {result.statistics.topEventIds.slice(0, 5).map((item, i) => (
                          <div key={i} className="text-sm">
                            <div className="flex justify-between">
                              <span className="font-mono text-accent">{item.eventId}</span>
                              <span className="text-muted-foreground">{item.count}</span>
                            </div>
                            <div className="text-xs text-muted-foreground">{item.description}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Events Tab */}
              {activeTab === 'events' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h4 className="font-medium">All Events ({filteredEvents.length})</h4>
                    <div className="flex items-center gap-2">
                      <div className="relative">
                        <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                        <input
                          type="text"
                          placeholder="Search events..."
                          value={searchTerm}
                          onChange={(e) => setSearchTerm(e.target.value)}
                          className="pl-10 pr-3 py-2 bg-background border border-border rounded text-sm w-64"
                        />
                        {searchTerm && (
                          <button
                            onClick={() => setSearchTerm('')}
                            className="absolute right-3 top-1/2 transform -translate-y-1/2"
                          >
                            <X className="w-4 h-4" />
                          </button>
                        )}
                      </div>
                      <select
                        value={levelFilter}
                        onChange={(e) => setLevelFilter(e.target.value)}
                        className="px-3 py-2 bg-background border border-border rounded text-sm"
                      >
                        <option>All</option>
                        <option>Critical</option>
                        <option>Error</option>
                        <option>Warning</option>
                        <option>Information</option>
                      </select>
                    </div>
                  </div>

                  <div className="border border-border rounded-lg overflow-hidden">
                    <div className="max-h-[500px] overflow-auto">
                      <table className="w-full text-sm">
                        <thead className="bg-muted/50 sticky top-0">
                          <tr className="text-xs text-muted-foreground">
                            <th className="text-left p-3 w-12">#</th>
                            <th className="text-left p-3">Event ID</th>
                            <th className="text-left p-3">Level</th>
                            <th className="text-left p-3">Time</th>
                            <th className="text-left p-3">Source</th>
                            <th className="text-left p-3">Message</th>
                          </tr>
                        </thead>
                        <tbody>
                          {filteredEvents.map((event, index) => (
                            <tr
                              key={index}
                              className="border-t border-border hover:bg-muted/20 cursor-pointer"
                              onClick={() => setSelectedEvent(event)}
                            >
                              <td className="p-3 text-accent font-medium">{event.number}</td>
                              <td className="p-3">
                                <span className="font-mono text-xs bg-accent/10 px-2 py-1 rounded">
                                  {event.eventId}
                                </span>
                              </td>
                              <td className="p-3">
                                <span className={`flex items-center space-x-1 text-xs px-2 py-1 rounded border ${getLevelColor(event.level)}`}>
                                  {getLevelIcon(event.level)}
                                  <span>{event.level}</span>
                                </span>
                              </td>
                              <td className="p-3 text-xs text-muted-foreground">
                                {new Date(event.timestamp).toLocaleString()}
                              </td>
                              <td className="p-3 text-xs font-mono">{event.source}</td>
                              <td className="p-3 text-xs">
                                <div className="max-w-md truncate">{event.message}</div>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              )}

              {/* Timeline Tab */}
              {activeTab === 'timeline' && (
                <div className="space-y-4">
                  <h4 className="font-medium">Event Timeline</h4>
                  <div className="h-96">
                    <ResponsiveContainer width="100%" height="100%">
                      <AreaChart data={result.timeline}>
                        <XAxis
                          dataKey="timestamp"
                          tick={{ fontSize: 12 }}
                          tickFormatter={(value) => new Date(value).toLocaleTimeString()}
                        />
                        <YAxis tick={{ fontSize: 12 }} />
                        <Tooltip
                          contentStyle={{
                            backgroundColor: 'hsl(var(--card))',
                            border: '1px solid hsl(var(--border))',
                            borderRadius: '8px'
                          }}
                        />
                        <Area type="monotone" dataKey="critical" stackId="1" stroke="#ef4444" fill="#ef4444" fillOpacity={0.8} />
                        <Area type="monotone" dataKey="error" stackId="1" stroke="#f97316" fill="#f97316" fillOpacity={0.8} />
                        <Area type="monotone" dataKey="warning" stackId="1" stroke="#eab308" fill="#eab308" fillOpacity={0.8} />
                        <Area type="monotone" dataKey="info" stackId="1" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.8} />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                </div>
              )}

              {/* Threats Tab */}
              {activeTab === 'threats' && (
                <div className="space-y-4">
                  <h4 className="font-medium">Detected Threats</h4>
                  {result.threats.length === 0 ? (
                    <div className="text-center py-12 text-muted-foreground">
                      <Shield className="w-16 h-16 mx-auto mb-4 opacity-50" />
                      <p>No threats detected</p>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {result.threats.map((threat, index) => (
                        <div
                          key={index}
                          className={`border rounded-lg p-4 ${
                            threat.severity === 'Critical' ? 'border-red-400/50 bg-red-400/5' :
                            threat.severity === 'High' ? 'border-orange-400/50 bg-orange-400/5' :
                            'border-border'
                          }`}
                        >
                          <div className="flex items-start justify-between mb-2">
                            <h5 className="font-medium">{threat.type}</h5>
                            <span className={`px-2 py-1 rounded text-xs ${
                              threat.severity === 'Critical' ? 'bg-red-400/20 text-red-400' :
                              threat.severity === 'High' ? 'bg-orange-400/20 text-orange-400' :
                              threat.severity === 'Medium' ? 'bg-yellow-400/20 text-yellow-400' :
                              'bg-blue-400/20 text-blue-400'
                            }`}>
                              {threat.severity}
                            </span>
                          </div>
                          <p className="text-sm text-muted-foreground mb-2">{threat.description}</p>
                          <p className="text-xs text-muted-foreground mb-2">{threat.details}</p>
                          <div className="flex items-center justify-between text-xs">
                            <span className="text-muted-foreground">
                              Confidence: {threat.confidence}%
                            </span>
                            <span className="text-muted-foreground">
                              {new Date(threat.timestamp).toLocaleString()}
                            </span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* MITRE ATT&CK Tab */}
              {activeTab === 'mitre' && (
                <div className="space-y-4">
                  <h4 className="font-medium">MITRE ATT&CK Techniques</h4>
                  {result.mitreAttacks.length === 0 ? (
                    <div className="text-center py-12 text-muted-foreground">
                      <Target className="w-16 h-16 mx-auto mb-4 opacity-50" />
                      <p>No MITRE ATT&CK techniques detected</p>
                    </div>
                  ) : (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                      {result.mitreAttacks.map((attack, index) => (
                        <div key={index} className="border border-border rounded-lg p-4">
                          <div className="flex items-start justify-between mb-2">
                            <div>
                              <span className="font-mono text-sm text-accent">{attack.id}</span>
                              <h5 className="font-medium">{attack.technique}</h5>
                            </div>
                            <span className={`px-2 py-1 rounded text-xs ${
                              attack.severity === 'Critical' ? 'bg-red-400/20 text-red-400' :
                              attack.severity === 'High' ? 'bg-orange-400/20 text-orange-400' :
                              'bg-yellow-400/20 text-yellow-400'
                            }`}>
                              {attack.severity}
                            </span>
                          </div>
                          <p className="text-xs text-muted-foreground mb-2">{attack.tactic}</p>
                          <p className="text-sm text-muted-foreground">{attack.description}</p>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Flags Tab */}
              {activeTab === 'flags' && (
                <div className="space-y-4">
                  <h4 className="font-medium">Detected Flags & Suspicious Strings</h4>
                  {result.flags.length === 0 ? (
                    <div className="text-center py-12 text-muted-foreground">
                      <Flag className="w-16 h-16 mx-auto mb-4 opacity-50" />
                      <p>No flags detected</p>
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {result.flags.map((flag, index) => (
                        <div key={index} className="border border-border rounded-lg p-3 flex items-start justify-between">
                          <div className="flex-1">
                            <div className="flex items-center space-x-2 mb-1">
                              <span className="px-2 py-0.5 bg-accent/20 text-accent rounded text-xs">
                                {flag.type}
                              </span>
                              <span className="text-xs text-muted-foreground">
                                {flag.confidence}% confidence
                              </span>
                            </div>
                            <div className="font-mono text-sm bg-muted p-2 rounded">{flag.value}</div>
                            <div className="text-xs text-muted-foreground mt-1 truncate">{flag.context}</div>
                          </div>
                          <Button variant="ghost" size="sm" onClick={() => copyToClipboard(flag.value)}>
                            <Copy className="w-4 h-4" />
                          </Button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Commands Tab */}
              {activeTab === 'commands' && (
                <div className="space-y-4">
                  <h4 className="font-medium">Suspicious Commands</h4>
                  {result.suspiciousCommands.length === 0 ? (
                    <div className="text-center py-12 text-muted-foreground">
                      <Terminal className="w-16 h-16 mx-auto mb-4 opacity-50" />
                      <p>No suspicious commands detected</p>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {result.suspiciousCommands.map((cmd, index) => (
                        <div key={index} className="border border-border rounded-lg p-4">
                          <div className="flex items-start justify-between mb-2">
                            <h5 className="font-medium">{cmd.reason}</h5>
                            <span className={`px-2 py-1 rounded text-xs ${
                              cmd.severity === 'Critical' ? 'bg-red-400/20 text-red-400' :
                              cmd.severity === 'High' ? 'bg-orange-400/20 text-orange-400' :
                              'bg-yellow-400/20 text-yellow-400'
                            }`}>
                              {cmd.severity}
                            </span>
                          </div>
                          <div className="bg-muted p-2 rounded font-mono text-sm mb-2">{cmd.command}</div>
                          <div className="flex flex-wrap gap-1">
                            {cmd.indicators.map((ind, i) => (
                              <span key={i} className="px-2 py-0.5 bg-accent/10 text-accent rounded text-xs">
                                {ind}
                              </span>
                            ))}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Sessions Tab */}
              {activeTab === 'sessions' && (
                <div className="space-y-4">
                  <h4 className="font-medium">User Sessions</h4>
                  {result.userSessions.length === 0 ? (
                    <div className="text-center py-12 text-muted-foreground">
                      <Users className="w-16 h-16 mx-auto mb-4 opacity-50" />
                      <p>No user sessions found</p>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {result.userSessions.map((session, index) => (
                        <div
                          key={index}
                          className={`border rounded-lg p-4 ${
                            session.suspicious ? 'border-red-400/50 bg-red-400/5' : 'border-border'
                          }`}
                        >
                          <div className="flex items-start justify-between mb-3">
                            <div>
                              <div className="flex items-center space-x-2 mb-1">
                                <span className="font-medium">{session.userName}</span>
                                {session.suspicious && (
                                  <span className="px-2 py-1 bg-red-400/20 text-red-400 rounded text-xs">
                                    Suspicious
                                  </span>
                                )}
                              </div>
                              <div className="text-sm text-muted-foreground">
                                {session.computer} • {session.logonType}
                              </div>
                            </div>
                          </div>
                          <div className="grid grid-cols-2 gap-2 text-sm">
                            <div>
                              <span className="text-muted-foreground">Logon:</span>{' '}
                              {new Date(session.logonTime).toLocaleString()}
                            </div>
                            <div>
                              <span className="text-muted-foreground">Duration:</span>{' '}
                              {session.duration ? `${Math.round(session.duration / 1000 / 60)} min` : 'Active'}
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          </Card>
        </>
      )}

      {/* Event Details Modal */}
      {selectedEvent && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50 p-4" onClick={() => setSelectedEvent(null)}>
          <Card className="max-w-4xl w-full max-h-[90vh] overflow-auto" onClick={(e) => e.stopPropagation()}>
            <div className="p-6">
              <div className="flex items-start justify-between mb-4">
                <div>
                  <h3 className="text-lg font-semibold mb-1">Event Details</h3>
                  <p className="text-sm text-muted-foreground">
                    Event ID: {selectedEvent.eventId} • {getEventDescription(selectedEvent.eventId)}
                  </p>
                </div>
                <button
                  onClick={() => setSelectedEvent(null)}
                  className="text-muted-foreground hover:text-foreground"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              <div className="space-y-4">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <span className="text-sm text-muted-foreground">Level:</span>
                    <span className={`ml-2 px-2 py-1 rounded text-xs ${getLevelColor(selectedEvent.level)}`}>
                      {selectedEvent.level}
                    </span>
                  </div>
                  <div>
                    <span className="text-sm text-muted-foreground">Timestamp:</span>
                    <span className="ml-2 text-sm">{new Date(selectedEvent.timestamp).toLocaleString()}</span>
                  </div>
                  <div>
                    <span className="text-sm text-muted-foreground">Source:</span>
                    <span className="ml-2 text-sm font-mono">{selectedEvent.source}</span>
                  </div>
                  <div>
                    <span className="text-sm text-muted-foreground">Computer:</span>
                    <span className="ml-2 text-sm font-mono">{selectedEvent.computer}</span>
                  </div>
                  {selectedEvent.userName && (
                    <div>
                      <span className="text-sm text-muted-foreground">User:</span>
                      <span className="ml-2 text-sm font-mono">{selectedEvent.userName}</span>
                    </div>
                  )}
                  {selectedEvent.task && (
                    <div>
                      <span className="text-sm text-muted-foreground">Task:</span>
                      <span className="ml-2 text-sm">{selectedEvent.task}</span>
                    </div>
                  )}
                  {selectedEvent.taskCategory && (
                    <div>
                      <span className="text-sm text-muted-foreground">Task Category:</span>
                      <span className="ml-2 text-sm">{selectedEvent.taskCategory}</span>
                    </div>
                  )}
                  {selectedEvent.keywords && selectedEvent.keywords.length > 0 && (
                    <div className="col-span-2">
                      <span className="text-sm text-muted-foreground">Keywords:</span>
                      <div className="flex flex-wrap gap-1 mt-1">
                        {selectedEvent.keywords.map((kw, i) => (
                          <span key={i} className="px-2 py-0.5 bg-accent/10 text-accent rounded text-xs">
                            {kw}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>

                <div>
                  <span className="text-sm text-muted-foreground">Message:</span>
                  <div className="mt-1 p-3 bg-muted rounded text-sm">{selectedEvent.message}</div>
                </div>

                {selectedEvent.eventData && Object.keys(selectedEvent.eventData).length > 0 && (
                  <div>
                    <span className="text-sm text-muted-foreground">Event Data:</span>
                    <div className="mt-1 p-3 bg-muted rounded text-sm font-mono">
                      <pre>{JSON.stringify(selectedEvent.eventData, null, 2)}</pre>
                    </div>
                  </div>
                )}

                {selectedEvent.userData && Object.keys(selectedEvent.userData).length > 0 && (
                  <div>
                    <span className="text-sm text-muted-foreground">User Data:</span>
                    <div className="mt-1 p-3 bg-muted rounded text-sm font-mono">
                      <pre>{JSON.stringify(selectedEvent.userData, null, 2)}</pre>
                    </div>
                  </div>
                )}
              </div>

              <div className="flex justify-end mt-4">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => copyToClipboard(JSON.stringify(selectedEvent, null, 2))}
                >
                  <Copy className="w-4 h-4 mr-2" />
                  Copy JSON
                </Button>
              </div>
            </div>
          </Card>
        </div>
      )}
    </div>
  )
}

export default EVTXAnalysis
