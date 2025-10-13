import React, { useState, useCallback, useEffect } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import {
  ArrowLeft,
  Upload,
  Activity,
  AlertTriangle,
  Shield,
  FileText,
  Calendar,
  User,
  Server,
  Search,
  Filter,
  Download,
  Copy,
  TrendingUp,
  AlertCircle,
  CheckCircle,
  XCircle,
  Clock,
  Target,
  Flag,
  Terminal,
  Users,
  BarChart3,
  Eye,
  X
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Card } from '../components/ui/card'
import { LineChart, Line, AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend, Brush, ReferenceDot } from 'recharts'
import {
  analyzeEVTX,
  analyzeMultipleEVTX,
  filterEvents,
  getEventDescription,
  type EVTXAnalysisResult,
  type EVTXEvent
} from '../lib/evtxAnalysis'

const EVTXAnalysis: React.FC = () => {
  const navigate = useNavigate()
  const location = useLocation()
  const [files, setFiles] = useState<File[]>([])
  const [result, setResult] = useState<EVTXAnalysisResult | null>(null)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [activeTab, setActiveTab] = useState<'statistics' | 'timeline' | 'mitre' | 'events' | 'threats' | 'flags' | 'commands' | 'sessions' | 'artifacts' | 'correlation'>('statistics')
  const [searchTerm, setSearchTerm] = useState('')
  const [levelFilter, setLevelFilter] = useState<string>('All')
  const [sourceFilter, setSourceFilter] = useState<string>('All')
  const [eventIdFilter, setEventIdFilter] = useState<string>('')
  const [filteredEvents, setFilteredEvents] = useState<EVTXEvent[]>([])
  const [quickFilter, setQuickFilter] = useState<string | null>(null)
  const [selectedEvent, setSelectedEvent] = useState<EVTXEvent | null>(null)
  const [timelineZoom, setTimelineZoom] = useState<{startIndex?: number, endIndex?: number} | null>(null)

  // Handle file from Digital Forensics page
  useEffect(() => {
    if (location.state?.evtxFile) {
      const uploadedFile = location.state.evtxFile as File
      setFiles([uploadedFile])
      analyzeFiles([uploadedFile])
    }
  }, [location.state])

  // Apply filters when result or filters change
  useEffect(() => {
    if (result) {
      const filters: any = {
        searchTerm: searchTerm || undefined,
        level: levelFilter !== 'All' ? levelFilter : undefined,
        source: sourceFilter !== 'All' ? sourceFilter : undefined,
        eventId: eventIdFilter ? parseInt(eventIdFilter) : undefined
      }

      // Quick filters
      if (quickFilter === 'failed-logons') {
        filters.eventId = 4625
      } else if (quickFilter === 'successful-logons') {
        filters.eventId = 4624
      } else if (quickFilter === 'powershell') {
        filters.eventId = 4104
      } else if (quickFilter === 'log-cleared') {
        filters.eventId = 1102
      } else if (quickFilter === 'privilege-use') {
        filters.eventId = 4672
      } else if (quickFilter === 'critical') {
        filters.level = 'Critical'
      }

      const filtered = filterEvents(result.events, filters)
      setFilteredEvents(filtered)
    }
  }, [result, searchTerm, levelFilter, sourceFilter, eventIdFilter, quickFilter])

  const analyzeFiles = useCallback(async (filesToAnalyze?: File[]) => {
    const targetFiles = filesToAnalyze || files
    if (!targetFiles || targetFiles.length === 0) return

    setIsAnalyzing(true)
    try {
      if (targetFiles.length === 1) {
        // Single file analysis
        const buffer = await targetFiles[0].arrayBuffer()
        const analysis = analyzeEVTX(buffer, targetFiles[0].name)
        setResult(analysis)
        setFilteredEvents(analysis.events)
      } else {
        // Multi-file analysis
        const fileBuffers = await Promise.all(
          targetFiles.map(async (f) => ({
            name: f.name,
            buffer: await f.arrayBuffer()
          }))
        )
        const analysis = await analyzeMultipleEVTX(fileBuffers)
        setResult(analysis)
        setFilteredEvents(analysis.events)
      }
    } catch (error) {
      console.error('EVTX analysis failed:', error)
      alert('Failed to analyze EVTX file(s): ' + (error instanceof Error ? error.message : 'Unknown error'))
    } finally {
      setIsAnalyzing(false)
    }
  }, [files])

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFiles = e.target.files
    if (selectedFiles && selectedFiles.length > 0) {
      setFiles(Array.from(selectedFiles))
      setResult(null)
    }
  }

  const removeFile = (index: number) => {
    const newFiles = files.filter((_, i) => i !== index)
    setFiles(newFiles)
    if (newFiles.length === 0) {
      setResult(null)
    }
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  const downloadEvents = () => {
    if (!filteredEvents.length) return
    const csv = [
      ['Number', 'Event ID', 'Level', 'Timestamp', 'Source', 'Computer', 'Message'].join(','),
      ...filteredEvents.map(e =>
        [e.number, e.eventId, e.level, e.timestamp, e.source, e.computer, `"${e.message.replace(/"/g, '""')}"`].join(',')
      )
    ].join('\n')

    const blob = new Blob([csv], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `evtx_events_${Date.now()}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  const applyQuickFilter = (filter: string) => {
    setQuickFilter(quickFilter === filter ? null : filter)
  }

  const clearFilters = () => {
    setSearchTerm('')
    setLevelFilter('All')
    setSourceFilter('All')
    setEventIdFilter('')
    setQuickFilter(null)
  }

  const getLevelColor = (level: string) => {
    switch (level) {
      case 'Critical': return 'text-red-400 bg-red-400/10 border-red-400/30'
      case 'Error': return 'text-orange-400 bg-orange-400/10 border-orange-400/30'
      case 'Warning': return 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30'
      case 'Information': return 'text-blue-400 bg-blue-400/10 border-blue-400/30'
      default: return 'text-gray-400 bg-gray-400/10 border-gray-400/30'
    }
  }

  const getLevelIcon = (level: string) => {
    switch (level) {
      case 'Critical': return <XCircle className="w-4 h-4" />
      case 'Error': return <AlertCircle className="w-4 h-4" />
      case 'Warning': return <AlertTriangle className="w-4 h-4" />
      case 'Information': return <CheckCircle className="w-4 h-4" />
      default: return <Activity className="w-4 h-4" />
    }
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center space-x-3">
            <Button
              variant="outline"
              size="sm"
              onClick={() => navigate('/forensics')}
              className="mb-2"
            >
              <ArrowLeft className="w-4 h-4 mr-2" />
              Back to Forensics
            </Button>
          </div>
          <h1 className="text-2xl font-bold flex items-center space-x-2">
            <Shield className="w-6 h-6 text-accent" />
            <span>EVTX Analysis</span>
          </h1>
          <p className="text-muted-foreground mt-1">
            Windows Event Log forensics and threat detection
          </p>
        </div>
      </div>

      {/* File Upload */}
      {files.length === 0 && !result ? (
        <Card className="p-6">
          <h2 className="text-lg font-semibold mb-4">Upload EVTX Files</h2>
          <div className="border-2 border-dashed border-border rounded-lg p-8 text-center hover:border-accent transition-colors">
            <Upload className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
            <p className="text-lg font-medium mb-2">
              Select Windows Event Log files
            </p>
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
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <FileText className="w-5 h-5 text-accent" />
              <div>
                <p className="font-medium">
                  {files.length === 1 ? files[0].name : `${files.length} EVTX files selected`}
                </p>
                <p className="text-sm text-muted-foreground">
                  {files.length === 1
                    ? `${(files[0].size / 1024 / 1024).toFixed(2)} MB`
                    : `Total: ${(files.reduce((sum, f) => sum + f.size, 0) / 1024 / 1024).toFixed(2)} MB`
                  }
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              {!result && (
                <Button onClick={() => analyzeFiles()} disabled={isAnalyzing}>
                  {isAnalyzing ? (
                    <>
                      <Activity className="w-4 h-4 mr-2 animate-spin" />
                      Analyzing...
                    </>
                  ) : (
                    <>
                      <Activity className="w-4 h-4 mr-2" />
                      Analyze
                    </>
                  )}
                </Button>
              )}
              <Button
                variant="destructive"
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
        </Card>
      )}

      {/* Results */}
      {result && (
        <>
          {/* Statistics Dashboard */}
          <Card className="p-6">
            <h3 className="text-lg font-semibold mb-4">Statistics Overview</h3>
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
              <div className="bg-background border border-border rounded-lg p-4 text-center">
                <div className="text-3xl font-bold text-accent">{result.statistics.totalEvents}</div>
                <div className="text-sm text-muted-foreground">Total Events</div>
              </div>
              <div className="bg-red-400/10 border border-red-400/30 rounded-lg p-4 text-center">
                <div className="text-3xl font-bold text-red-400">{result.statistics.criticalCount}</div>
                <div className="text-sm text-red-400">Critical</div>
              </div>
              <div className="bg-orange-400/10 border border-orange-400/30 rounded-lg p-4 text-center">
                <div className="text-3xl font-bold text-orange-400">{result.statistics.errorCount}</div>
                <div className="text-sm text-orange-400">Errors</div>
              </div>
              <div className="bg-yellow-400/10 border border-yellow-400/30 rounded-lg p-4 text-center">
                <div className="text-3xl font-bold text-yellow-400">{result.statistics.warningCount}</div>
                <div className="text-sm text-yellow-400">Warnings</div>
              </div>
              <div className="bg-blue-400/10 border border-blue-400/30 rounded-lg p-4 text-center">
                <div className="text-3xl font-bold text-blue-400">{result.statistics.infoCount}</div>
                <div className="text-sm text-blue-400">Info</div>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4">
              <div className="bg-background border border-border rounded-lg p-4">
                <div className="flex items-center space-x-2 text-sm text-muted-foreground mb-2">
                  <Calendar className="w-4 h-4" />
                  <span>Time Range</span>
                </div>
                <div className="text-xs font-mono">
                  {new Date(result.statistics.timeRange.start).toLocaleString()}
                  <br />
                  to {new Date(result.statistics.timeRange.end).toLocaleString()}
                </div>
              </div>
              <div className="bg-background border border-border rounded-lg p-4">
                <div className="flex items-center space-x-2 text-sm text-muted-foreground mb-2">
                  <User className="w-4 h-4" />
                  <span>Unique Users</span>
                </div>
                <div className="text-2xl font-bold">{result.statistics.uniqueUsers}</div>
              </div>
              <div className="bg-background border border-border rounded-lg p-4">
                <div className="flex items-center space-x-2 text-sm text-muted-foreground mb-2">
                  <Server className="w-4 h-4" />
                  <span>Unique Computers</span>
                </div>
                <div className="text-2xl font-bold">{result.statistics.uniqueComputers}</div>
              </div>
            </div>
          </Card>

          {/* Tabs */}
          <Card>
            <div className="flex flex-wrap border-b border-border">
              {[
                { id: 'statistics', label: 'Stats', icon: TrendingUp },
                { id: 'timeline', label: 'Timeline', icon: BarChart3 },
                { id: 'mitre', label: 'MITRE', icon: Target, count: result.mitreAttacks.length },
                { id: 'events', label: 'Events', icon: FileText, count: filteredEvents.length },
                { id: 'threats', label: 'Threats', icon: Shield, count: result.threats.length },
                { id: 'flags', label: 'Flags', icon: Flag, count: result.flags.length },
                { id: 'commands', label: 'Commands', icon: Terminal, count: result.suspiciousCommands.length },
                { id: 'sessions', label: 'Sessions', icon: Users, count: result.userSessions.length },
                { id: 'correlation', label: 'Correlation', icon: Activity, count: result.correlatedEvents?.length || 0 },
                { id: 'artifacts', label: 'Artifacts', icon: Target, count: result.artifacts.length }
              ].map(tab => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={`px-4 py-3 text-sm font-medium transition-colors flex items-center justify-center space-x-2 ${
                    activeTab === tab.id
                      ? 'text-accent border-b-2 border-accent'
                      : 'text-muted-foreground hover:text-foreground'
                  }`}
                >
                  <tab.icon className="w-4 h-4" />
                  <span>{tab.label}</span>
                  {tab.count !== undefined && (
                    <span className="bg-accent/20 text-accent px-2 py-0.5 rounded text-xs">
                      {tab.count}
                    </span>
                  )}
                </button>
              ))}
            </div>

            <div className="p-6">
              {/* Statistics Tab */}
              {activeTab === 'statistics' && (
                <div className="space-y-6">
                  <div>
                    <h4 className="font-medium mb-3 flex items-center">
                      <TrendingUp className="w-4 h-4 mr-2 text-accent" />
                      Top Event IDs
                    </h4>
                    <div className="space-y-2">
                      {result.statistics.topEventIds.map((item, index) => (
                        <div
                          key={index}
                          className="flex items-center justify-between p-3 bg-background border border-border rounded-lg hover:border-accent/50 transition-colors cursor-pointer"
                          onClick={() => {
                            setEventIdFilter(item.eventId.toString())
                            setActiveTab('events')
                          }}
                        >
                          <div className="flex-1">
                            <div className="font-medium text-sm">
                              Event {item.eventId} - {item.description}
                            </div>
                            <div className="text-xs text-muted-foreground mt-1">
                              {item.count} occurrences
                            </div>
                          </div>
                          <div className="text-accent font-mono text-sm ml-4">
                            {((item.count / result.statistics.totalEvents) * 100).toFixed(1)}%
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  <div>
                    <h4 className="font-medium mb-3">Top Sources</h4>
                    <div className="space-y-2">
                      {result.statistics.topSources.map((item, index) => (
                        <div
                          key={index}
                          className="flex items-center justify-between p-3 bg-background border border-border rounded-lg"
                        >
                          <span className="font-mono text-sm">{item.source}</span>
                          <span className="text-accent font-medium">{item.count} events</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* Timeline Tab */}
              {activeTab === 'timeline' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h4 className="font-medium flex items-center">
                      <BarChart3 className="w-4 h-4 mr-2 text-accent" />
                      Event Timeline (Grouped by Hour)
                    </h4>
                    {timelineZoom && (
                      <Button variant="outline" size="sm" onClick={() => setTimelineZoom(null)}>
                        Reset Zoom
                      </Button>
                    )}
                  </div>
                  <div className="bg-background border border-border rounded-lg p-4">
                    <ResponsiveContainer width="100%" height={400}>
                      <AreaChart data={result.timeline}>
                        <XAxis
                          dataKey="timestamp"
                          tickFormatter={(value) => new Date(value).toLocaleDateString()}
                          tick={{ fill: '#888' }}
                        />
                        <YAxis tick={{ fill: '#888' }} />
                        <Tooltip
                          contentStyle={{ backgroundColor: '#1a1a1a', border: '1px solid #333' }}
                          labelFormatter={(value) => new Date(value).toLocaleString()}
                        />
                        <Legend />
                        <Area type="monotone" dataKey="critical" stackId="1" stroke="#ef4444" fill="#ef4444" name="Critical" />
                        <Area type="monotone" dataKey="error" stackId="1" stroke="#f97316" fill="#f97316" name="Error" />
                        <Area type="monotone" dataKey="warning" stackId="1" stroke="#eab308" fill="#eab308" name="Warning" />
                        <Area type="monotone" dataKey="info" stackId="1" stroke="#3b82f6" fill="#3b82f6" name="Info" />
                        <Brush
                          dataKey="timestamp"
                          height={30}
                          stroke="#00ff88"
                          fill="#00ff8820"
                          tickFormatter={(value) => new Date(value).toLocaleDateString()}
                          onChange={(data: any) => setTimelineZoom(data)}
                        />
                      </AreaChart>
                    </ResponsiveContainer>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div className="bg-background border border-border rounded-lg p-4">
                      <h5 className="font-medium mb-2">Peak Activity</h5>
                      <p className="text-sm text-muted-foreground">
                        {result.timeline.length > 0
                          ? `${result.timeline.reduce((max, point) => point.count > max.count ? point : max, result.timeline[0]).count} events at ${new Date(result.timeline.reduce((max, point) => point.count > max.count ? point : max, result.timeline[0]).timestamp).toLocaleString()}`
                          : 'No data'}
                      </p>
                    </div>
                    <div className="bg-background border border-border rounded-lg p-4">
                      <h5 className="font-medium mb-2">Activity Duration</h5>
                      <p className="text-sm text-muted-foreground">
                        {result.timeline.length > 0
                          ? `${Math.round((new Date(result.timeline[result.timeline.length - 1].timestamp).getTime() - new Date(result.timeline[0].timestamp).getTime()) / (1000 * 60 * 60))} hours`
                          : 'No data'}
                      </p>
                    </div>
                    <div className="bg-background border border-border rounded-lg p-4">
                      <h5 className="font-medium mb-2">Total Data Points</h5>
                      <p className="text-sm text-muted-foreground">
                        {result.timeline.length} hourly buckets
                      </p>
                    </div>
                  </div>
                  <div className="text-xs text-muted-foreground text-center">
                    💡 Tip: Drag the brush below the chart to zoom into specific time ranges
                  </div>
                </div>
              )}

              {/* MITRE ATT&CK Tab */}
              {activeTab === 'mitre' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between mb-4">
                    <h4 className="font-medium flex items-center">
                      <Target className="w-4 h-4 mr-2 text-accent" />
                      MITRE ATT&CK Techniques Detected
                    </h4>
                  </div>
                  {result.mitreAttacks.length === 0 ? (
                    <div className="text-center py-12">
                      <CheckCircle className="w-16 h-16 mx-auto mb-4 text-green-400" />
                      <h3 className="text-lg font-medium text-green-400">No ATT&CK Techniques Detected</h3>
                      <p className="text-sm text-muted-foreground mt-2">
                        No known attack techniques identified in event logs
                      </p>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {result.mitreAttacks.map((attack, index) => (
                        <div
                          key={index}
                          className={`border rounded-lg p-4 ${
                            attack.severity === 'Critical' ? 'border-red-400/50 bg-red-400/5' :
                            attack.severity === 'High' ? 'border-orange-400/50 bg-orange-400/5' :
                            attack.severity === 'Medium' ? 'border-yellow-400/50 bg-yellow-400/5' :
                            'border-blue-400/50 bg-blue-400/5'
                          }`}
                        >
                          <div className="flex items-start justify-between mb-3">
                            <div className="flex-1">
                              <div className="flex items-center space-x-3 mb-2">
                                <span className={`px-3 py-1 rounded text-sm font-mono ${
                                  attack.severity === 'Critical' ? 'bg-red-400/20 text-red-400' :
                                  attack.severity === 'High' ? 'bg-orange-400/20 text-orange-400' :
                                  attack.severity === 'Medium' ? 'bg-yellow-400/20 text-yellow-400' :
                                  'bg-blue-400/20 text-blue-400'
                                }`}>
                                  {attack.id}
                                </span>
                                <h5 className="font-medium">{attack.technique}</h5>
                              </div>
                              <div className="text-sm text-accent mb-2">{attack.tactic}</div>
                              <p className="text-sm text-muted-foreground">{attack.description}</p>
                            </div>
                            <div className="flex flex-col items-end space-y-2">
                              <span className={`px-3 py-1 rounded text-xs font-medium ${
                                attack.severity === 'Critical' ? 'bg-red-400/20 text-red-400' :
                                attack.severity === 'High' ? 'bg-orange-400/20 text-orange-400' :
                                attack.severity === 'Medium' ? 'bg-yellow-400/20 text-yellow-400' :
                                'bg-blue-400/20 text-blue-400'
                              }`}>
                                {attack.severity}
                              </span>
                              <span className="text-xs text-muted-foreground">{attack.confidence}% confidence</span>
                            </div>
                          </div>
                          <div className="flex items-center space-x-4 text-xs text-muted-foreground mt-3 pt-3 border-t border-border">
                            <span>Event IDs: {attack.eventIds.join(', ')}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Events Tab */}
              {activeTab === 'events' && (
                <div className="space-y-4">
                  {/* Quick Filters */}
                  <div className="flex flex-wrap gap-2">
                    <span className="text-sm text-muted-foreground flex items-center">
                      <Filter className="w-4 h-4 mr-2" />
                      Quick Filters:
                    </span>
                    {[
                      { id: 'failed-logons', label: 'Failed Logons', color: 'red' },
                      { id: 'successful-logons', label: 'Successful Logons', color: 'green' },
                      { id: 'powershell', label: 'PowerShell', color: 'purple' },
                      { id: 'log-cleared', label: 'Log Cleared', color: 'red' },
                      { id: 'privilege-use', label: 'Privilege Use', color: 'yellow' },
                      { id: 'critical', label: 'Critical Only', color: 'red' }
                    ].map(filter => (
                      <Button
                        key={filter.id}
                        variant="outline"
                        size="sm"
                        onClick={() => applyQuickFilter(filter.id)}
                        className={quickFilter === filter.id ? 'bg-accent/20 border-accent' : ''}
                      >
                        {filter.label}
                      </Button>
                    ))}
                    <Button variant="outline" size="sm" onClick={clearFilters}>
                      Clear All
                    </Button>
                  </div>

                  {/* Filters */}
                  <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
                    <div className="relative">
                      <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                      <input
                        type="text"
                        placeholder="Search events..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        className="w-full pl-10 pr-3 py-2 bg-background border border-border rounded text-sm"
                      />
                    </div>
                    <select
                      value={levelFilter}
                      onChange={(e) => setLevelFilter(e.target.value)}
                      className="px-3 py-2 bg-background border border-border rounded text-sm"
                    >
                      <option>All Levels</option>
                      <option>Critical</option>
                      <option>Error</option>
                      <option>Warning</option>
                      <option>Information</option>
                    </select>
                    <select
                      value={sourceFilter}
                      onChange={(e) => setSourceFilter(e.target.value)}
                      className="px-3 py-2 bg-background border border-border rounded text-sm"
                    >
                      <option>All Sources</option>
                      {Array.from(new Set(result.events.map(e => e.source))).map(source => (
                        <option key={source}>{source}</option>
                      ))}
                    </select>
                    <input
                      type="text"
                      placeholder="Event ID..."
                      value={eventIdFilter}
                      onChange={(e) => setEventIdFilter(e.target.value)}
                      className="px-3 py-2 bg-background border border-border rounded text-sm"
                    />
                  </div>

                  <div className="flex items-center justify-between">
                    <span className="text-sm text-muted-foreground">
                      Showing {filteredEvents.length} of {result.events.length} events
                    </span>
                    <Button variant="outline" size="sm" onClick={downloadEvents}>
                      <Download className="w-4 h-4 mr-2" />
                      Export CSV
                    </Button>
                  </div>

                  {/* Events Table */}
                  <div className="border border-border rounded-lg overflow-hidden">
                    <div className="max-h-[500px] overflow-auto">
                      <table className="w-full text-sm min-w-[900px]">
                        <thead className="bg-muted/50 sticky top-0">
                          <tr className="text-xs text-muted-foreground">
                            <th className="text-left p-3 w-12">#</th>
                            <th className="text-left p-3 w-20">Event ID</th>
                            <th className="text-left p-3 w-24">Level</th>
                            <th className="text-left p-3 w-32">Time</th>
                            <th className="text-left p-3 w-24">Source</th>
                            <th className="text-left p-3">Message</th>
                          </tr>
                        </thead>
                        <tbody>
                          {filteredEvents.slice(0, 100).map((event, index) => (
                            <tr key={index} className="border-t border-border hover:bg-muted/20 cursor-pointer" onClick={() => setSelectedEvent(event)}>
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
                      {filteredEvents.length > 100 && (
                        <div className="p-4 text-center text-sm text-muted-foreground border-t border-border">
                          Showing first 100 events. Use filters to narrow results.
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              )}

              {/* Threats Tab */}
              {activeTab === 'threats' && (
                <div className="space-y-4">
                  {result.threats.length === 0 ? (
                    <div className="text-center py-12">
                      <CheckCircle className="w-16 h-16 mx-auto mb-4 text-green-400" />
                      <h3 className="text-lg font-medium text-green-400">No Threats Detected</h3>
                      <p className="text-sm text-muted-foreground mt-2">
                        Event log appears normal based on current analysis
                      </p>
                    </div>
                  ) : (
                    result.threats.map((threat, index) => (
                      <div
                        key={index}
                        className={`border rounded-lg p-4 ${
                          threat.severity === 'Critical' ? 'border-red-400/50 bg-red-400/5' :
                          threat.severity === 'High' ? 'border-orange-400/50 bg-orange-400/5' :
                          threat.severity === 'Medium' ? 'border-yellow-400/50 bg-yellow-400/5' :
                          'border-blue-400/50 bg-blue-400/5'
                        }`}
                      >
                        <div className="flex items-start justify-between mb-3">
                          <div className="flex items-center space-x-3">
                            <div className={`p-2 rounded-lg ${
                              threat.severity === 'Critical' ? 'bg-red-400/20 text-red-400' :
                              threat.severity === 'High' ? 'bg-orange-400/20 text-orange-400' :
                              threat.severity === 'Medium' ? 'bg-yellow-400/20 text-yellow-400' :
                              'bg-blue-400/20 text-blue-400'
                            }`}>
                              {threat.severity === 'Critical' ? <XCircle className="w-5 h-5" /> :
                               threat.severity === 'High' ? <AlertCircle className="w-5 h-5" /> :
                               <AlertTriangle className="w-5 h-5" />}
                            </div>
                            <div>
                              <h4 className="font-medium">{threat.type}</h4>
                              <p className="text-sm text-muted-foreground mt-1">
                                {threat.description}
                              </p>
                            </div>
                          </div>
                          <div className={`px-3 py-1 rounded text-xs font-medium ${
                            threat.severity === 'Critical' ? 'bg-red-400/20 text-red-400' :
                            threat.severity === 'High' ? 'bg-orange-400/20 text-orange-400' :
                            threat.severity === 'Medium' ? 'bg-yellow-400/20 text-yellow-400' :
                            'bg-blue-400/20 text-blue-400'
                          }`}>
                            {threat.severity}
                          </div>
                        </div>
                        <div className="bg-background/50 rounded p-3 text-sm">
                          <p className="text-muted-foreground">{threat.details}</p>
                          <div className="flex items-center justify-between mt-2 text-xs">
                            <span className="text-muted-foreground">
                              Event IDs: {threat.eventIds.join(', ')}
                            </span>
                            <span className="text-accent">
                              Confidence: {threat.confidence}%
                            </span>
                          </div>
                        </div>
                      </div>
                    ))
                  )}
                </div>
              )}

              {/* Flags Tab */}
              {activeTab === 'flags' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between mb-4">
                    <h4 className="font-medium flex items-center">
                      <Flag className="w-4 h-4 mr-2 text-accent" />
                      CTF Flags & Suspicious Strings
                    </h4>
                  </div>
                  {result.flags.length === 0 ? (
                    <div className="text-center py-12 text-muted-foreground">
                      <Flag className="w-16 h-16 mx-auto mb-4 opacity-50" />
                      <p>No flags or suspicious strings detected</p>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {result.flags.map((flag, index) => (
                        <div
                          key={index}
                          className="border border-border rounded-lg p-4 hover:border-accent/50 transition-colors"
                        >
                          <div className="flex items-start justify-between mb-3">
                            <div className="flex-1 min-w-0">
                              <div className="flex items-center space-x-2 mb-2">
                                <span className={`px-2 py-1 rounded text-xs ${
                                  flag.type === 'CTF Flag' ? 'bg-green-400/20 text-green-400' :
                                  flag.type === 'Base64' ? 'bg-blue-400/20 text-blue-400' :
                                  flag.type === 'Hex' ? 'bg-purple-400/20 text-purple-400' :
                                  'bg-yellow-400/20 text-yellow-400'
                                }`}>
                                  {flag.type}
                                </span>
                                <span className="text-xs text-muted-foreground">{flag.confidence}% confidence</span>
                              </div>
                              <div className="font-mono text-sm mb-2 break-all bg-muted/20 p-2 rounded">
                                {flag.value}
                              </div>
                              <div className="text-xs text-muted-foreground mb-2">
                                Context: {flag.context}
                              </div>
                              <div className="text-xs text-muted-foreground">
                                Event {flag.eventId} • {new Date(flag.timestamp).toLocaleString()}
                              </div>
                            </div>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => copyToClipboard(flag.value)}
                            >
                              <Copy className="w-4 h-4" />
                            </Button>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Suspicious Commands Tab */}
              {activeTab === 'commands' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between mb-4">
                    <h4 className="font-medium flex items-center">
                      <Terminal className="w-4 h-4 mr-2 text-accent" />
                      Suspicious Command Lines
                    </h4>
                  </div>

                  {/* User/Computer Filters */}
                  {result.suspiciousCommands.length > 0 && (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
                      <div>
                        <label className="text-sm text-muted-foreground mb-2 block">Filter by User</label>
                        <select
                          className="w-full px-3 py-2 bg-background border border-border rounded text-sm"
                          onChange={(e) => {
                            const user = e.target.value
                            if (user === 'all') {
                              setFilteredEvents(result.events)
                            } else {
                              setFilteredEvents(result.events.filter(ev => ev.userName === user))
                            }
                          }}
                        >
                          <option value="all">All Users ({result.statistics.uniqueUsers})</option>
                          {Array.from(new Set(result.suspiciousCommands.map(c => c.user).filter(Boolean))).map(user => (
                            <option key={user} value={user}>{user}</option>
                          ))}
                        </select>
                      </div>
                      <div>
                        <label className="text-sm text-muted-foreground mb-2 block">Filter by Computer</label>
                        <select
                          className="w-full px-3 py-2 bg-background border border-border rounded text-sm"
                          onChange={(e) => {
                            const computer = e.target.value
                            if (computer === 'all') {
                              setFilteredEvents(result.events)
                            } else {
                              setFilteredEvents(result.events.filter(ev => ev.computer === computer))
                            }
                          }}
                        >
                          <option value="all">All Computers ({result.statistics.uniqueComputers})</option>
                          {Array.from(new Set(result.events.map(e => e.computer))).slice(0, 20).map(computer => (
                            <option key={computer} value={computer}>{computer}</option>
                          ))}
                        </select>
                      </div>
                    </div>
                  )}

                  {result.suspiciousCommands.length === 0 ? (
                    <div className="text-center py-12">
                      <CheckCircle className="w-16 h-16 mx-auto mb-4 text-green-400" />
                      <h3 className="text-lg font-medium text-green-400">No Suspicious Commands Detected</h3>
                      <p className="text-sm text-muted-foreground mt-2">
                        No known malicious command patterns found
                      </p>
                    </div>
                  ) : (
                    <>
                      <div className="text-sm text-muted-foreground mb-2">
                        Showing {result.suspiciousCommands.length} suspicious command(s) • {result.statistics.uniqueUsers} unique user(s) • {result.statistics.uniqueComputers} unique computer(s)
                      </div>
                      <div className="space-y-3">
                        {result.suspiciousCommands.map((cmd, index) => (
                        <div
                          key={index}
                          className={`border rounded-lg p-4 ${
                            cmd.severity === 'Critical' ? 'border-red-400/50 bg-red-400/5' :
                            cmd.severity === 'High' ? 'border-orange-400/50 bg-orange-400/5' :
                            cmd.severity === 'Medium' ? 'border-yellow-400/50 bg-yellow-400/5' :
                            'border-blue-400/50 bg-blue-400/5'
                          }`}
                        >
                          <div className="flex items-start justify-between mb-3">
                            <div className="flex-1">
                              <div className="flex items-center space-x-2 mb-2">
                                <span className={`px-2 py-1 rounded text-xs font-medium ${
                                  cmd.severity === 'Critical' ? 'bg-red-400/20 text-red-400' :
                                  cmd.severity === 'High' ? 'bg-orange-400/20 text-orange-400' :
                                  cmd.severity === 'Medium' ? 'bg-yellow-400/20 text-yellow-400' :
                                  'bg-blue-400/20 text-blue-400'
                                }`}>
                                  {cmd.severity}
                                </span>
                                <span className="text-sm font-medium">{cmd.reason}</span>
                              </div>
                              <div className="font-mono text-sm mb-3 bg-muted/20 p-3 rounded overflow-x-auto">
                                {cmd.command}
                              </div>
                              <div className="flex flex-wrap gap-2 mb-2">
                                {cmd.indicators.map((indicator, idx) => (
                                  <span key={idx} className="px-2 py-1 bg-accent/10 text-accent rounded text-xs">
                                    {indicator}
                                  </span>
                                ))}
                              </div>
                              <div className="text-xs text-muted-foreground">
                                Event {cmd.eventId} • {new Date(cmd.timestamp).toLocaleString()}
                                {cmd.user && ` • User: ${cmd.user}`}
                              </div>
                            </div>
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => copyToClipboard(cmd.command)}
                            >
                              <Copy className="w-4 h-4" />
                            </Button>
                          </div>
                        </div>
                      ))}
                      </div>
                    </>
                  )}
                </div>
              )}

              {/* User Sessions Tab */}
              {activeTab === 'sessions' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between mb-4">
                    <h4 className="font-medium flex items-center">
                      <Users className="w-4 h-4 mr-2 text-accent" />
                      User Sessions Reconstruction
                    </h4>
                  </div>
                  {result.userSessions.length === 0 ? (
                    <div className="text-center py-12 text-muted-foreground">
                      <Users className="w-16 h-16 mx-auto mb-4 opacity-50" />
                      <p>No user sessions found</p>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {result.userSessions.slice(0, 20).map((session, index) => (
                        <div
                          key={index}
                          className={`border rounded-lg p-4 ${
                            session.suspicious ? 'border-red-400/50 bg-red-400/5' : 'border-border'
                          }`}
                        >
                          <div className="flex items-start justify-between mb-3">
                            <div className="flex-1">
                              <div className="flex items-center space-x-3 mb-2">
                                <User className="w-5 h-5 text-accent" />
                                <span className="font-medium">{session.userName}</span>
                                {session.suspicious && (
                                  <span className="px-2 py-1 bg-red-400/20 text-red-400 rounded text-xs">
                                    Suspicious
                                  </span>
                                )}
                              </div>
                              <div className="grid grid-cols-2 gap-2 text-sm text-muted-foreground mb-3">
                                <div>
                                  <span className="font-medium">Computer:</span> {session.computer}
                                </div>
                                <div>
                                  <span className="font-medium">Logon Type:</span> {session.logonType}
                                </div>
                                <div>
                                  <span className="font-medium">Logon:</span> {new Date(session.logonTime).toLocaleString()}
                                </div>
                                <div>
                                  <span className="font-medium">Duration:</span>{' '}
                                  {session.duration
                                    ? `${Math.round(session.duration / 1000 / 60)} minutes`
                                    : 'Active'}
                                </div>
                              </div>
                              <div className="text-xs text-muted-foreground">
                                {session.actions.length} events during session
                              </div>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Event Correlation Tab */}
              {activeTab === 'correlation' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between mb-4">
                    <h4 className="font-medium flex items-center">
                      <Activity className="w-4 h-4 mr-2 text-accent" />
                      Event Correlation & Attack Chains
                    </h4>
                  </div>
                  {!result.correlatedEvents || result.correlatedEvents.length === 0 ? (
                    <div className="text-center py-12 text-muted-foreground">
                      <Activity className="w-16 h-16 mx-auto mb-4 opacity-50" />
                      <p>No correlated events found</p>
                      <p className="text-xs mt-2">Multi-file analysis may reveal more correlations</p>
                    </div>
                  ) : (
                    <div className="space-y-4">
                      {result.correlatedEvents.map((correlation, index) => (
                        <div
                          key={index}
                          className="border border-border rounded-lg p-4 hover:border-accent/50 transition-colors"
                        >
                          <div className="flex items-start justify-between mb-4">
                            <div className="flex-1">
                              <div className="flex items-center space-x-3 mb-2">
                                <span className={`px-3 py-1 rounded text-sm font-medium ${
                                  correlation.correlationType === 'Logon Chain' ? 'bg-blue-400/20 text-blue-400' :
                                  correlation.correlationType === 'Privilege Escalation' ? 'bg-red-400/20 text-red-400' :
                                  correlation.correlationType === 'Process Execution' ? 'bg-green-400/20 text-green-400' :
                                  'bg-yellow-400/20 text-yellow-400'
                                }`}>
                                  {correlation.correlationType}
                                </span>
                                <span className="text-sm text-muted-foreground">
                                  {correlation.confidence}% confidence
                                </span>
                              </div>
                              <div className="space-y-2">
                                <div className="flex items-start space-x-3">
                                  <div className="w-8 h-8 rounded-full bg-accent/20 flex items-center justify-center flex-shrink-0">
                                    <span className="text-accent font-mono text-xs">1</span>
                                  </div>
                                  <div className="flex-1">
                                    <div className="font-medium text-sm">
                                      Event {correlation.event.eventId} - {getEventDescription(correlation.event.eventId)}
                                    </div>
                                    <div className="text-xs text-muted-foreground mt-1">
                                      {new Date(correlation.event.timestamp).toLocaleString()} • {correlation.event.computer}
                                    </div>
                                    <div className="text-xs text-muted-foreground truncate mt-1">
                                      {correlation.event.message}
                                    </div>
                                  </div>
                                </div>
                                {correlation.relatedEvents.map((related, idx) => (
                                  <div key={idx}>
                                    <div className="flex items-center ml-4">
                                      <div className="w-px h-6 bg-border"></div>
                                    </div>
                                    <div className="flex items-start space-x-3">
                                      <div className="w-8 h-8 rounded-full bg-accent/20 flex items-center justify-center flex-shrink-0">
                                        <span className="text-accent font-mono text-xs">{idx + 2}</span>
                                      </div>
                                      <div className="flex-1">
                                        <div className="font-medium text-sm">
                                          Event {related.eventId} - {getEventDescription(related.eventId)}
                                        </div>
                                        <div className="text-xs text-muted-foreground mt-1">
                                          {new Date(related.timestamp).toLocaleString()} • {related.computer}
                                        </div>
                                        <div className="text-xs text-muted-foreground truncate mt-1">
                                          {related.message}
                                        </div>
                                      </div>
                                    </div>
                                  </div>
                                ))}
                              </div>
                            </div>
                          </div>
                          <div className="text-xs text-muted-foreground pt-3 border-t border-border">
                            Attack chain detected across {correlation.relatedEvents.length + 1} events •
                            Time span: {Math.round((new Date(correlation.relatedEvents[correlation.relatedEvents.length - 1].timestamp).getTime() - new Date(correlation.event.timestamp).getTime()) / 1000)}s
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Artifacts Tab */}
              {activeTab === 'artifacts' && (
                <div className="space-y-4">
                  {result.artifacts.length === 0 ? (
                    <div className="text-center py-12 text-muted-foreground">
                      <FileText className="w-16 h-16 mx-auto mb-4 opacity-50" />
                      <p>No artifacts extracted</p>
                    </div>
                  ) : (
                    <div className="space-y-4">
                      {['IP', 'Username', 'FilePath', 'CommandLine'].map(type => {
                        const items = result.artifacts.filter(a => a.type === type)
                        if (items.length === 0) return null

                        return (
                          <div key={type}>
                            <h4 className="font-medium mb-2">{type}s ({items.length})</h4>
                            <div className="space-y-2">
                              {items.slice(0, 20).map((artifact, index) => (
                                <div
                                  key={index}
                                  className="flex items-center justify-between p-3 bg-background border border-border rounded-lg hover:border-accent/50 transition-colors"
                                >
                                  <div className="flex-1 min-w-0">
                                    <div className="font-mono text-sm truncate">{artifact.value}</div>
                                    <div className="text-xs text-muted-foreground mt-1">
                                      Event {artifact.eventId} • {new Date(artifact.timestamp).toLocaleString()}
                                    </div>
                                  </div>
                                  <Button
                                    variant="ghost"
                                    size="sm"
                                    onClick={() => copyToClipboard(artifact.value)}
                                  >
                                    <Copy className="w-4 h-4" />
                                  </Button>
                                </div>
                              ))}
                            </div>
                          </div>
                        )
                      })}
                    </div>
                  )}
                </div>
              )}
            </div>
          </Card>
        </>
      )}

      {/* Event Details Modal - Enhanced with ALL information */}
      {selectedEvent && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4" onClick={() => setSelectedEvent(null)}>
          <div className="bg-card border border-border rounded-lg max-w-5xl w-full max-h-[90vh] overflow-hidden" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between p-4 border-b border-border bg-muted/20">
              <h3 className="text-lg font-semibold flex items-center">
                <Eye className="w-5 h-5 mr-2 text-accent" />
                Event {selectedEvent.eventId} - {getEventDescription(selectedEvent.eventId)}
              </h3>
              <div className="flex items-center space-x-2">
                <Button variant="ghost" size="sm" onClick={() => copyToClipboard(JSON.stringify(selectedEvent, null, 2))}>
                  <Copy className="w-4 h-4 mr-1" />
                  Copy All
                </Button>
                <Button variant="ghost" size="sm" onClick={() => setSelectedEvent(null)}>
                  <X className="w-5 h-5" />
                </Button>
              </div>
            </div>
            <div className="p-6 overflow-y-auto max-h-[calc(90vh-80px)]">
              <div className="space-y-6">
                {/* Primary Information */}
                <div>
                  <h4 className="font-medium mb-3 text-accent">Primary Information</h4>
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                    <div className="bg-background border border-border rounded p-3">
                      <span className="text-xs text-muted-foreground block mb-1">Event ID</span>
                      <div className="font-mono text-lg font-bold text-accent">{selectedEvent.eventId}</div>
                    </div>
                    <div className="bg-background border border-border rounded p-3">
                      <span className="text-xs text-muted-foreground block mb-1">Event Number</span>
                      <div className="font-mono text-lg">{selectedEvent.number}</div>
                    </div>
                    <div className="bg-background border border-border rounded p-3">
                      <span className="text-xs text-muted-foreground block mb-1">Record ID</span>
                      <div className="font-mono text-lg">{selectedEvent.recordId}</div>
                    </div>
                  </div>
                </div>

                {/* Event Details */}
                <div>
                  <h4 className="font-medium mb-3 text-accent">Event Details</h4>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="bg-background border border-border rounded p-3">
                      <span className="text-xs text-muted-foreground block mb-1">Level / Severity</span>
                      <div className="flex items-center space-x-2 mt-1">
                        {getLevelIcon(selectedEvent.level)}
                        <span className="font-medium">{selectedEvent.level}</span>
                      </div>
                    </div>
                    <div className="bg-background border border-border rounded p-3">
                      <span className="text-xs text-muted-foreground block mb-1">Timestamp</span>
                      <div className="font-mono text-sm">{new Date(selectedEvent.timestamp).toLocaleString()}</div>
                      <div className="text-xs text-muted-foreground mt-1">{new Date(selectedEvent.timestamp).toISOString()}</div>
                    </div>
                    <div className="bg-background border border-border rounded p-3">
                      <span className="text-xs text-muted-foreground block mb-1">Source / Channel</span>
                      <div className="font-medium">{selectedEvent.source}</div>
                      <div className="text-xs text-muted-foreground mt-1">{selectedEvent.channel}</div>
                    </div>
                    <div className="bg-background border border-border rounded p-3">
                      <span className="text-xs text-muted-foreground block mb-1">Provider</span>
                      <div className="font-medium text-sm">{selectedEvent.provider}</div>
                    </div>
                  </div>
                </div>

                {/* System Information */}
                <div>
                  <h4 className="font-medium mb-3 text-accent">System Information</h4>
                  <div className="grid grid-cols-2 gap-4">
                    <div className="bg-background border border-border rounded p-3">
                      <span className="text-xs text-muted-foreground block mb-1">Computer</span>
                      <div className="font-medium">{selectedEvent.computer}</div>
                    </div>
                    {selectedEvent.userName && (
                      <div className="bg-background border border-border rounded p-3">
                        <span className="text-xs text-muted-foreground block mb-1">User Name</span>
                        <div className="font-medium">{selectedEvent.userName}</div>
                      </div>
                    )}
                    {selectedEvent.userId && (
                      <div className="bg-background border border-border rounded p-3">
                        <span className="text-xs text-muted-foreground block mb-1">User ID / SID</span>
                        <div className="font-mono text-xs">{selectedEvent.userId}</div>
                      </div>
                    )}
                  </div>
                </div>

                {/* Keywords */}
                {selectedEvent.keywords && selectedEvent.keywords.length > 0 && (
                  <div>
                    <h4 className="font-medium mb-3 text-accent">Keywords</h4>
                    <div className="flex flex-wrap gap-2">
                      {selectedEvent.keywords.map((keyword, idx) => (
                        <span key={idx} className="px-3 py-1 bg-accent/10 text-accent border border-accent/30 rounded text-sm">
                          {keyword}
                        </span>
                      ))}
                    </div>
                  </div>
                )}

                {/* Message */}
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <h4 className="font-medium text-accent">Event Message</h4>
                    <Button variant="ghost" size="sm" onClick={() => copyToClipboard(selectedEvent.message)}>
                      <Copy className="w-4 h-4 mr-1" />
                      Copy Message
                    </Button>
                  </div>
                  <div className="bg-background border border-border rounded p-4 font-mono text-sm break-words whitespace-pre-wrap">
                    {selectedEvent.message}
                  </div>
                </div>

                {/* Raw Data */}
                {selectedEvent.raw && (
                  <div>
                    <div className="flex items-center justify-between mb-2">
                      <h4 className="font-medium text-accent">Raw Event Data (JSON)</h4>
                      <Button variant="ghost" size="sm" onClick={() => copyToClipboard(JSON.stringify(selectedEvent.raw, null, 2))}>
                        <Copy className="w-4 h-4 mr-1" />
                        Copy Raw
                      </Button>
                    </div>
                    <div className="bg-background border border-border rounded p-4 font-mono text-xs break-words whitespace-pre-wrap max-h-60 overflow-y-auto">
                      {JSON.stringify(selectedEvent.raw, null, 2)}
                    </div>
                  </div>
                )}

                {/* Complete Event Object */}
                <div>
                  <div className="flex items-center justify-between mb-2">
                    <h4 className="font-medium text-accent">Complete Event Object</h4>
                    <Button variant="ghost" size="sm" onClick={() => copyToClipboard(JSON.stringify(selectedEvent, null, 2))}>
                      <Copy className="w-4 h-4 mr-1" />
                      Copy JSON
                    </Button>
                  </div>
                  <div className="bg-muted/20 border border-border rounded p-4 font-mono text-xs break-words whitespace-pre-wrap max-h-60 overflow-y-auto">
                    {JSON.stringify(selectedEvent, null, 2)}
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default EVTXAnalysis
