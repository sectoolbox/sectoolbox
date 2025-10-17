import React, { useState, useCallback, useEffect } from 'react'
import { useLocation } from 'react-router-dom'
import {
  Upload,
  Activity,
  AlertTriangle,
  Database,
  FileText,
  Search,
  Filter,
  Download,
  Copy,
  Target,
  Users,
  Server,
  Network,
  Terminal,
  Lock,
  Eye,
  X,
  MemoryStick,
  Shield,
  Key,
  GitBranch,
  Clock,
  FileWarning,
  Zap,
  TrendingUp
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Card } from '../components/ui/card'
import {
  AdvancedMemoryAnalyzer,
  type ThreatHuntingResult,
  type ProcessInfo
} from '../lib/memoryForensics'

const MemoryForensics: React.FC = () => {
  const location = useLocation()
  const [file, setFile] = useState<File | null>(null)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [activeTab, setActiveTab] = useState<
    'overview' | 'attack-chain' | 'processes' | 'network' | 'credentials' |
    'lateral-movement' | 'privilege-escalation' | 'services' | 'files' | 'registry' |
    'injections' | 'iocs' | 'timeline' | 'hex'
  >('overview')
  const [searchTerm, setSearchTerm] = useState('')
  const [processFilter, setProcessFilter] = useState<'All' | 'Suspicious' | 'Normal'>('All')

  // Analysis results
  const [results, setResults] = useState<ThreatHuntingResult | null>(null)
  const [selectedProcess, setSelectedProcess] = useState<ProcessInfo | null>(null)
  const [hexView, setHexView] = useState<string>('')
  const [progress, setProgress] = useState(0)
  const [progressStatus, setProgressStatus] = useState('')
  const [isLoadingHex, setIsLoadingHex] = useState(false)

  // Handle file from Digital Forensics page
  useEffect(() => {
    if (location.state?.memoryFile) {
      const uploadedFile = location.state.memoryFile as File
      setFile(uploadedFile)
      analyzeMemory(uploadedFile)
    }
  }, [location.state])

  // Generate full hex view when hex tab is activated
  const generateFullHexView = useCallback(async () => {
    if (!file || hexView || isLoadingHex) return

    setIsLoadingHex(true)
    try {
      // For large files, limit to first 10MB for performance
      const maxSize = Math.min(file.size, 10 * 1024 * 1024)
      const chunk = file.slice(0, maxSize)
      const buffer = await chunk.arrayBuffer()
      const bytes = new Uint8Array(buffer)

      let hexString = ''
      for (let i = 0; i < bytes.length; i += 16) {
        const hexPart = Array.from(bytes.slice(i, i + 16))
          .map(b => b.toString(16).padStart(2, '0'))
          .join(' ')
        const asciiPart = Array.from(bytes.slice(i, i + 16))
          .map(b => (b >= 32 && b < 127) ? String.fromCharCode(b) : '.')
          .join('')
        hexString += `${i.toString(16).padStart(8, '0')}: ${hexPart.padEnd(48, ' ')} | ${asciiPart}\n`
      }

      if (file.size > maxSize) {
        hexString += `\n... (showing first ${(maxSize / 1024 / 1024).toFixed(2)} MB of ${(file.size / 1024 / 1024).toFixed(2)} MB file)\n`
      }

      setHexView(hexString)
    } catch (error) {
      console.error('Error generating hex view:', error)
      setHexView('Error generating hex view')
    } finally {
      setIsLoadingHex(false)
    }
  }, [file, hexView, isLoadingHex])

  useEffect(() => {
    if (activeTab === 'hex' && file && !hexView && !isLoadingHex) {
      generateFullHexView()
    }
  }, [activeTab, file, hexView, isLoadingHex, generateFullHexView])

  const analyzeMemory = useCallback(async (fileToAnalyze?: File) => {
    const targetFile = fileToAnalyze || file
    if (!targetFile) return

    setIsAnalyzing(true)
    setProgress(0)
    setProgressStatus('Starting analysis...')

    try {
      // Use streaming analysis for large files (>100MB), regular analysis for smaller files
      const progressCallback = (prog: number, status: string) => {
        setProgress(prog)
        setProgressStatus(status)
      }

      let analysisResults: ThreatHuntingResult
      if (targetFile.size > 100 * 1024 * 1024) {
        // Use streaming for files larger than 100MB
        analysisResults = await AdvancedMemoryAnalyzer.analyzeStream(targetFile, progressCallback)
      } else {
        // Load entire file for smaller files
        const fullBuffer = await targetFile.arrayBuffer()
        analysisResults = await AdvancedMemoryAnalyzer.analyze(fullBuffer, progressCallback)
      }

      setResults(analysisResults)
      setProgressStatus('Analysis complete')
      setProgress(100)

    } catch (error) {
      console.error('Memory analysis failed:', error)
      alert('Failed to analyze memory dump: ' + (error instanceof Error ? error.message : 'Unknown error'))
    } finally {
      setIsAnalyzing(false)
      // Reset progress after a delay
      setTimeout(() => {
        setProgress(0)
        setProgressStatus('')
      }, 2000)
    }
  }, [file])

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0]
    if (selectedFile) {
      setFile(selectedFile)
    }
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  const downloadResults = () => {
    if (!results) return

    const blob = new Blob([JSON.stringify(results, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `memory_forensics_${Date.now()}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'Critical': return 'text-red-400 bg-red-400/10 border-red-400/30'
      case 'High': return 'text-orange-400 bg-orange-400/10 border-orange-400/30'
      case 'Medium': return 'text-yellow-400 bg-yellow-400/10 border-yellow-400/30'
      case 'Low': return 'text-blue-400 bg-blue-400/10 border-blue-400/30'
      case 'Info': return 'text-gray-400 bg-gray-400/10 border-gray-400/30'
      default: return 'text-gray-400 bg-gray-400/10 border-gray-400/30'
    }
  }

  const getStageIcon = (stage: string) => {
    switch (stage) {
      case 'Initial Access': return Target
      case 'Execution': return Zap
      case 'Persistence': return Lock
      case 'Privilege Escalation': return TrendingUp
      case 'Defense Evasion': return Shield
      case 'Credential Access': return Key
      case 'Discovery': return Search
      case 'Lateral Movement': return GitBranch
      case 'Collection': return Database
      case 'Command and Control': return Network
      case 'Exfiltration': return Upload
      default: return AlertTriangle
    }
  }

  const filteredProcesses = results?.processes.filter(p => {
    if (processFilter === 'Suspicious' && !p.suspicious) return false
    if (processFilter === 'Normal' && p.suspicious) return false
    if (searchTerm) {
      return (
        p.name.toLowerCase().includes(searchTerm.toLowerCase()) ||
        p.commandLine.toLowerCase().includes(searchTerm.toLowerCase()) ||
        p.pid.toString().includes(searchTerm)
      )
    }
    return true
  }) || []

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center space-x-2">
            <Database className="w-6 h-6 text-accent" />
            <span>Memory Analysis & Threat Hunting</span>
          </h1>
          <p className="text-muted-foreground mt-1">
            Advanced memory dump analysis for incident response and attack chain reconstruction
          </p>
        </div>
      </div>

      {/* File Upload */}
      {!file ? (
        <Card className="p-6">
          <h2 className="text-lg font-semibold mb-4">Upload Memory Dump</h2>
          <div className="border-2 border-dashed border-border rounded-lg p-8 text-center hover:border-accent transition-colors">
            <Upload className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
            <p className="text-lg font-medium mb-2">
              Select a memory dump file
            </p>
            <p className="text-sm text-muted-foreground mb-4">
              Supports .dmp, .mem, .raw, .vmem, .bin, .dump files (up to 1.5GB)
            </p>
            <input
              type="file"
              accept=".dmp,.mem,.raw,.vmem,.bin,.dump"
              onChange={handleFileSelect}
              className="hidden"
              id="memory-upload"
            />
            <label htmlFor="memory-upload">
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
              <MemoryStick className="w-5 h-5 text-accent" />
              <div>
                <p className="font-medium">{file.name}</p>
                <p className="text-sm text-muted-foreground">
                  {(file.size / 1024 / 1024).toFixed(2)} MB
                  {file.size > 100 * 1024 * 1024 && (
                    <span className="ml-2 text-accent">(Large file - streaming enabled)</span>
                  )}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              {!results && (
                <Button onClick={() => analyzeMemory()} disabled={isAnalyzing}>
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
                  setFile(null)
                  setResults(null)
                  setHexView('')
                }}
              >
                Remove File
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

      {/* Results */}
      {results && (
        <>
          {/* Statistics Dashboard */}
          <Card className="p-6">
            <div className="flex justify-between items-center mb-4">
              <h3 className="text-lg font-semibold">Investigation Overview</h3>
              <Button variant="outline" size="sm" onClick={downloadResults}>
                <Download className="w-4 h-4 mr-2" />
                Export Analysis
              </Button>
            </div>

            <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-4">
              <div className="bg-background border border-border rounded-lg p-4 text-center">
                <div className="text-3xl font-bold text-accent">{results.processes.length}</div>
                <div className="text-sm text-muted-foreground">Processes</div>
              </div>
              <div className="bg-background border border-red-400/30 rounded-lg p-4 text-center">
                <div className="text-3xl font-bold text-red-400">
                  {results.processes.filter(p => p.suspicious).length}
                </div>
                <div className="text-sm text-red-400">Suspicious</div>
              </div>
              <div className="bg-background border border-border rounded-lg p-4 text-center">
                <div className="text-3xl font-bold text-blue-400">{results.networks.length}</div>
                <div className="text-sm text-blue-400">Connections</div>
              </div>
              <div className="bg-background border border-border rounded-lg p-4 text-center">
                <div className="text-3xl font-bold text-orange-400">{results.credentials.length}</div>
                <div className="text-sm text-orange-400">Credentials</div>
              </div>
              <div className="bg-background border border-border rounded-lg p-4 text-center">
                <div className="text-3xl font-bold text-purple-400">{results.lateralMovement.length}</div>
                <div className="text-sm text-purple-400">Lateral Moves</div>
              </div>
              <div className="bg-background border border-border rounded-lg p-4 text-center">
                <div className="text-3xl font-bold text-green-400">{results.iocs.length}</div>
                <div className="text-sm text-green-400">IOCs</div>
              </div>
            </div>

            {/* Quick Insights */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-4">
              <div className="bg-background border border-border rounded-lg p-4">
                <div className="flex items-center space-x-2 text-sm text-muted-foreground mb-2">
                  <Users className="w-4 h-4" />
                  <span>Compromised Accounts</span>
                </div>
                <div className="text-2xl font-bold text-red-400">
                  {results.attackChain.compromisedAccounts.length}
                </div>
                <div className="text-xs text-muted-foreground mt-1">
                  {results.attackChain.compromisedAccounts.slice(0, 3).join(', ') || 'None detected'}
                </div>
              </div>

              <div className="bg-background border border-border rounded-lg p-4">
                <div className="flex items-center space-x-2 text-sm text-muted-foreground mb-2">
                  <Shield className="w-4 h-4" />
                  <span>Attack Stages</span>
                </div>
                <div className="text-2xl font-bold text-orange-400">
                  {results.attackChain.stages.length}
                </div>
                <div className="text-xs text-muted-foreground mt-1">
                  {results.attackChain.stages.map(s => s.stage).slice(0, 2).join(', ') || 'None detected'}
                </div>
              </div>

              <div className="bg-background border border-border rounded-lg p-4">
                <div className="flex items-center space-x-2 text-sm text-muted-foreground mb-2">
                  <Terminal className="w-4 h-4" />
                  <span>Attack Tools Used</span>
                </div>
                <div className="text-2xl font-bold text-purple-400">
                  {results.attackChain.toolsUsed.length}
                </div>
                <div className="text-xs text-muted-foreground mt-1">
                  {results.attackChain.toolsUsed.slice(0, 3).join(', ') || 'None detected'}
                </div>
              </div>
            </div>
          </Card>

          {/* Tabs */}
          <Card>
            <div className="flex flex-wrap border-b border-border">
              {[
                { id: 'overview', label: 'Overview', icon: Target },
                { id: 'attack-chain', label: 'Attack Chain', icon: GitBranch, count: results.attackChain.stages.length },
                { id: 'processes', label: 'Processes', icon: Activity, count: results.processes.length },
                { id: 'network', label: 'Network', icon: Network, count: results.networks.length },
                { id: 'credentials', label: 'Credentials', icon: Key, count: results.credentials.length },
                { id: 'lateral-movement', label: 'Lateral Movement', icon: GitBranch, count: results.lateralMovement.length },
                { id: 'privilege-escalation', label: 'Priv Esc', icon: TrendingUp, count: results.privilegeEscalation.length },
                { id: 'services', label: 'Services', icon: Server, count: results.services.length },
                { id: 'files', label: 'Files', icon: FileWarning, count: results.suspiciousFiles.length },
                { id: 'registry', label: 'Registry', icon: Lock, count: results.registryActivity.length },
                { id: 'injections', label: 'Injections', icon: Zap, count: results.injections.length },
                { id: 'iocs', label: 'IOCs', icon: AlertTriangle, count: results.iocs.length },
                { id: 'timeline', label: 'Timeline', icon: Clock, count: results.attackChain.timeline.length },
                { id: 'hex', label: 'Hex View', icon: FileText }
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
              {/* Overview Tab */}
              {activeTab === 'overview' && (
                <div className="space-y-4">
                  <h4 className="font-medium text-lg">Investigation Summary</h4>

                  <div className="bg-background border border-border rounded-lg p-4">
                    <h5 className="font-medium mb-3 flex items-center">
                      <Shield className="w-4 h-4 mr-2 text-accent" />
                      Key Findings
                    </h5>
                    <ul className="space-y-2">
                      <li className="flex items-start space-x-2">
                        <span className="text-accent">•</span>
                        <span>
                          <strong className="text-red-400">{results.processes.filter(p => p.suspicious).length}</strong> suspicious processes detected
                        </span>
                      </li>
                      <li className="flex items-start space-x-2">
                        <span className="text-accent">•</span>
                        <span>
                          <strong className="text-orange-400">{results.credentials.length}</strong> accounts compromised via credential dumping
                        </span>
                      </li>
                      <li className="flex items-start space-x-2">
                        <span className="text-accent">•</span>
                        <span>
                          <strong className="text-purple-400">{results.lateralMovement.length}</strong> lateral movement techniques identified
                        </span>
                      </li>
                      <li className="flex items-start space-x-2">
                        <span className="text-accent">•</span>
                        <span>
                          <strong className="text-blue-400">{results.networks.filter(n => n.isExternal).length}</strong> external network connections
                        </span>
                      </li>
                    </ul>
                  </div>

                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <div className="bg-background border border-border rounded-lg p-4">
                      <h5 className="font-medium mb-2">Most Suspicious Processes</h5>
                      <div className="space-y-2">
                        {results.processes
                          .filter(p => p.suspicious)
                          .slice(0, 5)
                          .map((p, i) => (
                            <div key={i} className="flex justify-between text-sm">
                              <span className="font-mono text-red-400">{p.name}</span>
                              <span className="text-muted-foreground">PID: {p.pid}</span>
                            </div>
                          ))}
                        {results.processes.filter(p => p.suspicious).length === 0 && (
                          <p className="text-sm text-muted-foreground">No suspicious processes detected</p>
                        )}
                      </div>
                    </div>

                    <div className="bg-background border border-border rounded-lg p-4">
                      <h5 className="font-medium mb-2">External Connections</h5>
                      <div className="space-y-2">
                        {results.networks
                          .filter(n => n.isExternal)
                          .slice(0, 5)
                          .map((n, i) => (
                            <div key={i} className="text-sm font-mono">
                              <div className="text-accent">{n.remoteAddr}:{n.remotePort}</div>
                              <div className="text-xs text-muted-foreground">{n.processName}</div>
                            </div>
                          ))}
                        {results.networks.filter(n => n.isExternal).length === 0 && (
                          <p className="text-sm text-muted-foreground">No external connections detected</p>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Attack Chain Tab */}
              {activeTab === 'attack-chain' && (
                <div className="space-y-4">
                  <h4 className="font-medium text-lg flex items-center">
                    <GitBranch className="w-5 h-5 mr-2 text-accent" />
                    Attack Chain Reconstruction
                  </h4>

                  {results.attackChain.stages.length === 0 ? (
                    <div className="text-center py-12 text-muted-foreground">
                      <Target className="w-16 h-16 mx-auto mb-4 opacity-50" />
                      <p>No clear attack chain detected</p>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {results.attackChain.stages.map((stage, index) => {
                        const StageIcon = getStageIcon(stage.stage)
                        return (
                          <div
                            key={index}
                            className="border border-border rounded-lg p-4 bg-background hover:border-accent/50 transition-colors"
                          >
                            <div className="flex items-start justify-between mb-3">
                              <div className="flex items-center space-x-3">
                                <div className="bg-accent/20 p-2 rounded">
                                  <StageIcon className="w-5 h-5 text-accent" />
                                </div>
                                <div>
                                  <h5 className="font-medium">{stage.stage}</h5>
                                  {stage.mitreId && (
                                    <span className="text-xs text-muted-foreground">
                                      MITRE ATT&CK: {stage.mitreId}
                                    </span>
                                  )}
                                </div>
                              </div>
                              <span className="text-xs bg-accent/20 text-accent px-2 py-1 rounded">
                                Stage {index + 1}
                              </span>
                            </div>
                            <p className="text-sm text-muted-foreground mb-3">
                              {stage.description}
                            </p>
                            <div className="bg-muted/30 rounded p-3">
                              <p className="text-xs font-medium mb-2">Evidence:</p>
                              <ul className="space-y-1">
                                {stage.evidence.map((ev, i) => (
                                  <li key={i} className="text-xs font-mono text-muted-foreground">
                                    • {ev}
                                  </li>
                                ))}
                              </ul>
                            </div>
                          </div>
                        )
                      })}
                    </div>
                  )}

                  {/* Summary Cards */}
                  <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-6">
                    <div className="bg-red-400/10 border border-red-400/30 rounded-lg p-4">
                      <h5 className="font-medium text-red-400 mb-2">Compromised Accounts</h5>
                      <div className="space-y-1">
                        {results.attackChain.compromisedAccounts.length > 0 ? (
                          results.attackChain.compromisedAccounts.map((acc, i) => (
                            <div key={i} className="text-sm font-mono">{acc}</div>
                          ))
                        ) : (
                          <div className="text-sm text-muted-foreground">None detected</div>
                        )}
                      </div>
                    </div>

                    <div className="bg-orange-400/10 border border-orange-400/30 rounded-lg p-4">
                      <h5 className="font-medium text-orange-400 mb-2">Tools Used</h5>
                      <div className="space-y-1">
                        {results.attackChain.toolsUsed.length > 0 ? (
                          results.attackChain.toolsUsed.map((tool, i) => (
                            <div key={i} className="text-sm font-mono">{tool}</div>
                          ))
                        ) : (
                          <div className="text-sm text-muted-foreground">None detected</div>
                        )}
                      </div>
                    </div>

                    <div className="bg-purple-400/10 border border-purple-400/30 rounded-lg p-4">
                      <h5 className="font-medium text-purple-400 mb-2">Techniques</h5>
                      <div className="space-y-1">
                        {results.attackChain.techniques.length > 0 ? (
                          results.attackChain.techniques.slice(0, 5).map((tech, i) => (
                            <div key={i} className="text-sm font-mono">{tech}</div>
                          ))
                        ) : (
                          <div className="text-sm text-muted-foreground">None detected</div>
                        )}
                      </div>
                    </div>
                  </div>
                </div>
              )}

              {/* Processes Tab */}
              {activeTab === 'processes' && (
                <div className="space-y-4">
                  <div className="flex flex-wrap gap-4 items-center">
                    <div className="flex-1 min-w-[200px] relative">
                      <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                      <input
                        type="text"
                        placeholder="Search processes..."
                        value={searchTerm}
                        onChange={(e) => setSearchTerm(e.target.value)}
                        className="w-full pl-10 pr-3 py-2 bg-background border border-border rounded text-sm"
                      />
                    </div>
                    <div className="flex gap-2">
                      {(['All', 'Suspicious', 'Normal'] as const).map(filter => (
                        <Button
                          key={filter}
                          variant={processFilter === filter ? 'default' : 'outline'}
                          size="sm"
                          onClick={() => setProcessFilter(filter)}
                        >
                          <Filter className="w-3 h-3 mr-1" />
                          {filter}
                        </Button>
                      ))}
                    </div>
                  </div>

                  <div className="space-y-2 max-h-[600px] overflow-y-auto">
                    {filteredProcesses.map((process, index) => (
                      <div
                        key={index}
                        className={`flex justify-between items-center py-3 px-4 rounded border cursor-pointer transition-colors ${
                          process.suspicious
                            ? 'border-red-400/30 bg-red-400/5 hover:bg-red-400/10'
                            : 'border-border hover:bg-muted/30'
                        }`}
                        onClick={() => setSelectedProcess(process)}
                      >
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <div className="font-mono text-sm font-semibold">{process.name}</div>
                            {process.suspicious && (
                              <span className="px-2 py-0.5 text-xs bg-red-500/20 text-red-400 rounded">
                                SUSPICIOUS
                              </span>
                            )}
                          </div>
                          <div className="text-xs text-muted-foreground">
                            PID: {process.pid} | PPID: {process.ppid} | User: {process.user}
                          </div>
                          {process.commandLine && (
                            <div className="text-xs text-muted-foreground truncate max-w-2xl mt-1">
                              {process.commandLine}
                            </div>
                          )}
                          {process.suspicionReasons.length > 0 && (
                            <div className="flex flex-wrap gap-1 mt-2">
                              {process.suspicionReasons.map((reason, i) => (
                                <span
                                  key={i}
                                  className="text-xs px-2 py-0.5 bg-orange-500/20 text-orange-400 rounded"
                                >
                                  {reason}
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                        <div className="text-right ml-4">
                          <div className="text-xs font-mono">
                            <div>Threads: {process.threads}</div>
                            <div>Handles: {process.handles}</div>
                          </div>
                        </div>
                      </div>
                    ))}
                    {filteredProcesses.length === 0 && (
                      <div className="text-center py-12 text-muted-foreground">
                        <Activity className="w-16 h-16 mx-auto mb-4 opacity-50" />
                        <p>No processes found matching the current filter</p>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Network Tab */}
              {activeTab === 'network' && (
                <div className="space-y-4">
                  <h4 className="font-medium">Network Connections</h4>
                  <div className="space-y-2 max-h-[600px] overflow-y-auto">
                    {results.networks.length > 0 ? (
                      results.networks.map((conn, index) => (
                        <div
                          key={index}
                          className={`flex justify-between items-center py-3 px-4 rounded border ${
                            conn.isSuspicious
                              ? 'border-red-400/30 bg-red-400/5'
                              : 'border-border hover:bg-muted/30'
                          }`}
                        >
                          <div className="flex-1">
                            <div className="font-mono text-sm">
                              {conn.localAddr}:{conn.localPort} → {conn.remoteAddr}:{conn.remotePort}
                            </div>
                            <div className="text-xs text-muted-foreground">
                              {conn.protocol} | {conn.processName} (PID: {conn.pid})
                              {conn.isExternal && (
                                <span className="ml-2 text-orange-400">• External Connection</span>
                              )}
                            </div>
                          </div>
                          <div className={`px-2 py-1 rounded text-xs ${
                            conn.state === 'ESTABLISHED' ? 'bg-green-500/20 text-green-400' :
                            conn.state === 'LISTENING' ? 'bg-blue-500/20 text-blue-400' :
                            'bg-gray-500/20 text-gray-400'
                          }`}>
                            {conn.state}
                          </div>
                        </div>
                      ))
                    ) : (
                      <div className="text-center py-12 text-muted-foreground">
                        <Network className="w-16 h-16 mx-auto mb-4 opacity-50" />
                        <p>No network connections detected</p>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Credentials Tab */}
              {activeTab === 'credentials' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h4 className="font-medium flex items-center">
                      <Key className="w-5 h-5 mr-2 text-accent" />
                      Credential Dumping Activity
                    </h4>
                    <span className="text-sm text-red-400">
                      {results.credentials.length} accounts compromised
                    </span>
                  </div>

                  {results.credentials.length === 0 ? (
                    <div className="text-center py-12 text-muted-foreground">
                      <Key className="w-16 h-16 mx-auto mb-4 opacity-50" />
                      <p>No credential dumping detected</p>
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {results.credentials.map((cred, index) => (
                        <div
                          key={index}
                          className="border border-red-400/30 bg-red-400/5 rounded-lg p-4"
                        >
                          <div className="flex items-center justify-between mb-2">
                            <div className="font-mono font-medium text-red-400">
                              {cred.domain}\\{cred.username}
                            </div>
                            <span className="text-xs bg-red-500/20 text-red-400 px-2 py-1 rounded">
                              {cred.method}
                            </span>
                          </div>
                          {cred.ntlmHash && (
                            <div className="text-xs font-mono text-muted-foreground mb-2">
                              NTLM: {cred.ntlmHash}
                            </div>
                          )}
                          <div className="text-xs text-muted-foreground">
                            Source: {cred.sourceProcess || 'Unknown'}
                            {cred.timestamp && ` | ${cred.timestamp.toLocaleString()}`}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Lateral Movement Tab */}
              {activeTab === 'lateral-movement' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h4 className="font-medium flex items-center">
                      <GitBranch className="w-5 h-5 mr-2 text-accent" />
                      Lateral Movement Techniques
                    </h4>
                  </div>

                  {results.lateralMovement.length === 0 ? (
                    <div className="text-center py-12 text-muted-foreground">
                      <GitBranch className="w-16 h-16 mx-auto mb-4 opacity-50" />
                      <p>No lateral movement detected</p>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {results.lateralMovement.map((lm, index) => (
                        <div
                          key={index}
                          className="border border-purple-400/30 bg-purple-400/5 rounded-lg p-4"
                        >
                          <div className="flex items-center justify-between mb-3">
                            <div>
                              <h5 className="font-medium text-purple-400">{lm.technique}</h5>
                              <p className="text-sm text-muted-foreground">
                                User: {lm.username}
                              </p>
                            </div>
                            <div className="text-right">
                              <span className="text-xs bg-purple-500/20 text-purple-400 px-2 py-1 rounded">
                                Confidence: {lm.confidence}%
                              </span>
                            </div>
                          </div>
                          <div className="bg-muted/30 rounded p-3">
                            <p className="text-xs font-medium mb-2">Evidence:</p>
                            <ul className="space-y-1">
                              {lm.evidence.map((ev, i) => (
                                <li key={i} className="text-xs text-muted-foreground">
                                  • {ev}
                                </li>
                              ))}
                            </ul>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Privilege Escalation Tab */}
              {activeTab === 'privilege-escalation' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h4 className="font-medium flex items-center">
                      <TrendingUp className="w-5 h-5 mr-2 text-accent" />
                      Privilege Escalation
                    </h4>
                  </div>

                  {results.privilegeEscalation.length === 0 ? (
                    <div className="text-center py-12 text-muted-foreground">
                      <TrendingUp className="w-16 h-16 mx-auto mb-4 opacity-50" />
                      <p>No privilege escalation detected</p>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {results.privilegeEscalation.map((pe, index) => (
                        <div
                          key={index}
                          className="border border-orange-400/30 bg-orange-400/5 rounded-lg p-4"
                        >
                          <div className="flex items-center justify-between mb-3">
                            <div>
                              <h5 className="font-medium text-orange-400">{pe.type}</h5>
                              <p className="text-sm text-muted-foreground">
                                {pe.fromUser} → {pe.toUser}
                              </p>
                            </div>
                            <span className="text-xs bg-orange-500/20 text-orange-400 px-2 py-1 rounded">
                              {pe.method}
                            </span>
                          </div>
                          {pe.toolPath && (
                            <div className="bg-muted/30 rounded p-3 mb-2">
                              <p className="text-xs font-medium mb-1">Tool Path:</p>
                              <p className="text-xs font-mono text-accent">{pe.toolPath}</p>
                            </div>
                          )}
                          <div className="bg-muted/30 rounded p-3">
                            <p className="text-xs font-medium mb-2">Evidence:</p>
                            <ul className="space-y-1">
                              {pe.evidence.map((ev, i) => (
                                <li key={i} className="text-xs text-muted-foreground">
                                  • {ev}
                                </li>
                              ))}
                            </ul>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* Services Tab */}
              {activeTab === 'services' && (
                <div className="space-y-4">
                  <h4 className="font-medium">Windows Services</h4>
                  <div className="space-y-2 max-h-[600px] overflow-y-auto">
                    {results.services.length > 0 ? (
                      results.services.map((service, index) => (
                        <div
                          key={index}
                          className={`border rounded-lg p-4 ${
                            service.isSuspicious
                              ? 'border-red-400/30 bg-red-400/5'
                              : 'border-border bg-background'
                          }`}
                        >
                          <div className="flex items-center justify-between mb-2">
                            <div>
                              <h5 className="font-medium">{service.displayName}</h5>
                              <p className="text-sm text-muted-foreground">{service.name}</p>
                            </div>
                            <div className="flex items-center gap-2">
                              <span className={`text-xs px-2 py-1 rounded ${
                                service.state === 'Running'
                                  ? 'bg-green-500/20 text-green-400'
                                  : service.state === 'Stopped'
                                  ? 'bg-gray-500/20 text-gray-400'
                                  : 'bg-yellow-500/20 text-yellow-400'
                              }`}>
                                {service.state}
                              </span>
                              {service.isSuspicious && (
                                <span className="text-xs px-2 py-1 bg-red-500/20 text-red-400 rounded">
                                  SUSPICIOUS
                                </span>
                              )}
                            </div>
                          </div>
                          <div className="text-xs text-muted-foreground">
                            <div className="font-mono">{service.path}</div>
                            <div className="mt-1">
                              Start Type: {service.startType}
                              {service.user && ` | User: ${service.user}`}
                              {service.pid && ` | PID: ${service.pid}`}
                            </div>
                          </div>
                        </div>
                      ))
                    ) : (
                      <div className="text-center py-12 text-muted-foreground">
                        <Server className="w-16 h-16 mx-auto mb-4 opacity-50" />
                        <p>No services detected</p>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Files Tab */}
              {activeTab === 'files' && (
                <div className="space-y-4">
                  <h4 className="font-medium">Suspicious Files</h4>
                  <div className="space-y-2 max-h-[600px] overflow-y-auto">
                    {results.suspiciousFiles.length > 0 ? (
                      results.suspiciousFiles.map((file, index) => (
                        <div
                          key={index}
                          className="border border-border rounded-lg p-4 bg-background"
                        >
                          <div className="flex items-center justify-between mb-2">
                            <div className="font-mono text-sm font-medium">{file.name}</div>
                            <div className="flex gap-2">
                              <span className={`text-xs px-2 py-1 rounded ${
                                file.category === 'Malware' ? 'bg-red-500/20 text-red-400' :
                                file.category === 'Tool' ? 'bg-orange-500/20 text-orange-400' :
                                file.category === 'Script' ? 'bg-yellow-500/20 text-yellow-400' :
                                'bg-blue-500/20 text-blue-400'
                              }`}>
                                {file.category}
                              </span>
                              <span className="text-xs px-2 py-1 bg-muted text-muted-foreground rounded">
                                {file.type}
                              </span>
                            </div>
                          </div>
                          <div className="text-xs font-mono text-muted-foreground truncate">
                            {file.path}
                          </div>
                          <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                            {file.isHidden && (
                              <span className="text-orange-400">Hidden File</span>
                            )}
                            {file.isPacked && (
                              <span className="text-red-400">Packed/Obfuscated</span>
                            )}
                            <span>Entropy: {file.entropy.toFixed(2)}</span>
                          </div>
                        </div>
                      ))
                    ) : (
                      <div className="text-center py-12 text-muted-foreground">
                        <FileWarning className="w-16 h-16 mx-auto mb-4 opacity-50" />
                        <p>No suspicious files detected</p>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Registry Tab */}
              {activeTab === 'registry' && (
                <div className="space-y-4">
                  <h4 className="font-medium">Registry Activity</h4>
                  <div className="space-y-2 max-h-[600px] overflow-y-auto">
                    {results.registryActivity.length > 0 ? (
                      results.registryActivity.map((reg, index) => (
                        <div
                          key={index}
                          className={`border rounded-lg p-4 ${
                            reg.isPersistence
                              ? 'border-red-400/30 bg-red-400/5'
                              : 'border-border bg-background'
                          }`}
                        >
                          <div className="flex items-center justify-between mb-2">
                            <span className={`text-xs px-2 py-1 rounded ${
                              reg.operation === 'Write' ? 'bg-orange-500/20 text-orange-400' :
                              reg.operation === 'Delete' ? 'bg-red-500/20 text-red-400' :
                              'bg-blue-500/20 text-blue-400'
                            }`}>
                              {reg.operation}
                            </span>
                            {reg.isPersistence && (
                              <span className="text-xs px-2 py-1 bg-red-500/20 text-red-400 rounded">
                                PERSISTENCE
                              </span>
                            )}
                          </div>
                          <div className="text-xs font-mono text-muted-foreground">
                            {reg.key}
                          </div>
                          {reg.process && (
                            <div className="text-xs text-muted-foreground mt-1">
                              Process: {reg.process}
                            </div>
                          )}
                        </div>
                      ))
                    ) : (
                      <div className="text-center py-12 text-muted-foreground">
                        <Lock className="w-16 h-16 mx-auto mb-4 opacity-50" />
                        <p>No registry activity detected</p>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* Injections Tab */}
              {activeTab === 'injections' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h4 className="font-medium flex items-center">
                      <Zap className="w-5 h-5 mr-2 text-accent" />
                      Process Injection
                    </h4>
                  </div>

                  {results.injections.length === 0 ? (
                    <div className="text-center py-12 text-muted-foreground">
                      <Zap className="w-16 h-16 mx-auto mb-4 opacity-50" />
                      <p>No process injection detected</p>
                    </div>
                  ) : (
                    <div className="space-y-3">
                      {results.injections.map((inj, index) => (
                        <div
                          key={index}
                          className="border border-red-400/30 bg-red-400/5 rounded-lg p-4"
                        >
                          <div className="flex items-center justify-between mb-3">
                            <div>
                              <h5 className="font-medium text-red-400">{inj.technique}</h5>
                              <p className="text-sm text-muted-foreground">
                                {inj.injectorProcess} (PID: {inj.injectorPid}) → {inj.targetProcess} (PID: {inj.targetPid})
                              </p>
                            </div>
                            <span className="text-xs bg-red-500/20 text-red-400 px-2 py-1 rounded">
                              Confidence: {inj.confidence}%
                            </span>
                          </div>
                          <div className="bg-muted/30 rounded p-3">
                            <p className="text-xs font-medium mb-2">Evidence:</p>
                            <ul className="space-y-1">
                              {inj.evidence.map((ev, i) => (
                                <li key={i} className="text-xs text-muted-foreground">
                                  • {ev}
                                </li>
                              ))}
                            </ul>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}

              {/* IOCs Tab */}
              {activeTab === 'iocs' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h4 className="font-medium">Indicators of Compromise (IOCs)</h4>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => copyToClipboard(results.iocs.join('\n'))}
                    >
                      <Copy className="w-4 h-4 mr-2" />
                      Copy All
                    </Button>
                  </div>
                  {results.iocs.length > 0 ? (
                    <div className="bg-background border border-border rounded-lg p-4 max-h-[600px] overflow-y-auto">
                      <div className="font-mono text-xs space-y-1">
                        {results.iocs.map((ioc, index) => (
                          <div
                            key={index}
                            className="py-1 hover:bg-muted/30 px-2 rounded cursor-pointer"
                            onClick={() => copyToClipboard(ioc)}
                          >
                            {ioc}
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : (
                    <div className="text-center py-12 text-muted-foreground">
                      <AlertTriangle className="w-16 h-16 mx-auto mb-4 opacity-50" />
                      <p>No IOCs detected</p>
                    </div>
                  )}
                </div>
              )}

              {/* Timeline Tab */}
              {activeTab === 'timeline' && (
                <div className="space-y-4">
                  <h4 className="font-medium flex items-center">
                    <Clock className="w-5 h-5 mr-2 text-accent" />
                    Attack Timeline
                  </h4>
                  {results.attackChain.timeline.length > 0 ? (
                    <div className="space-y-2 max-h-[600px] overflow-y-auto">
                      {results.attackChain.timeline.map((event, index) => (
                        <div
                          key={index}
                          className={`border-l-4 pl-4 py-2 ${
                            event.severity === 'Critical' ? 'border-red-400' :
                            event.severity === 'High' ? 'border-orange-400' :
                            event.severity === 'Medium' ? 'border-yellow-400' :
                            'border-blue-400'
                          }`}
                        >
                          <div className="flex items-center justify-between mb-1">
                            <span className="text-xs text-muted-foreground">
                              {event.timestamp.toLocaleString()}
                            </span>
                            <span className={`text-xs px-2 py-0.5 rounded ${getSeverityColor(event.severity)}`}>
                              {event.severity}
                            </span>
                          </div>
                          <div className="font-medium text-sm">{event.type}</div>
                          <div className="text-xs text-muted-foreground mt-1">
                            {event.description}
                          </div>
                          {event.process && (
                            <div className="text-xs font-mono text-accent mt-1">
                              {event.process}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-center py-12 text-muted-foreground">
                      <Clock className="w-16 h-16 mx-auto mb-4 opacity-50" />
                      <p>No timeline events detected</p>
                    </div>
                  )}
                </div>
              )}

              {/* Hex View Tab */}
              {activeTab === 'hex' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h4 className="font-medium">
                      Hex View {file && `(${file.size > 10 * 1024 * 1024 ? 'First 10 MB' : 'Full File'})`}
                    </h4>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => copyToClipboard(hexView)}
                      disabled={!hexView || isLoadingHex}
                    >
                      <Copy className="w-4 h-4 mr-2" />
                      Copy
                    </Button>
                  </div>
                  {isLoadingHex ? (
                    <div className="text-center py-12">
                      <Activity className="w-12 h-12 mx-auto mb-4 animate-spin text-accent" />
                      <p className="text-muted-foreground">Generating hex view...</p>
                    </div>
                  ) : (
                    <div className="bg-background border border-border rounded-lg p-4 overflow-x-auto max-h-[600px] overflow-y-auto">
                      <pre className="font-mono text-xs text-muted-foreground whitespace-pre">
                        {hexView || 'Click this tab to generate hex view'}
                      </pre>
                    </div>
                  )}
                </div>
              )}
            </div>
          </Card>
        </>
      )}

      {/* Process Details Modal */}
      {selectedProcess && (
        <div className="fixed inset-0 bg-black/80 flex items-center justify-center z-50 p-4" onClick={() => setSelectedProcess(null)}>
          <div className="bg-card border border-border rounded-lg max-w-3xl w-full max-h-[80vh] overflow-hidden" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between p-4 border-b border-border bg-muted/20">
              <h3 className="text-lg font-semibold flex items-center">
                <Eye className="w-5 h-5 mr-2 text-accent" />
                Process Details: {selectedProcess.name}
              </h3>
              <div className="flex items-center space-x-2">
                <Button variant="ghost" size="sm" onClick={() => copyToClipboard(JSON.stringify(selectedProcess, null, 2))}>
                  <Copy className="w-4 h-4 mr-1" />
                  Copy
                </Button>
                <Button variant="ghost" size="sm" onClick={() => setSelectedProcess(null)}>
                  <X className="w-5 h-5" />
                </Button>
              </div>
            </div>
            <div className="p-6 overflow-y-auto max-h-[calc(80vh-80px)]">
              <div className="space-y-4">
                {selectedProcess.suspicious && (
                  <div className="bg-red-400/10 border border-red-400/30 rounded-lg p-4">
                    <h5 className="font-medium text-red-400 mb-2 flex items-center">
                      <AlertTriangle className="w-4 h-4 mr-2" />
                      Suspicious Indicators
                    </h5>
                    <ul className="space-y-1">
                      {selectedProcess.suspicionReasons.map((reason, i) => (
                        <li key={i} className="text-sm text-muted-foreground">• {reason}</li>
                      ))}
                    </ul>
                  </div>
                )}

                <div className="grid grid-cols-2 gap-4">
                  <div className="bg-background border border-border rounded p-3">
                    <span className="text-xs text-muted-foreground block mb-1">Process ID</span>
                    <div className="font-mono text-lg">{selectedProcess.pid}</div>
                  </div>
                  <div className="bg-background border border-border rounded p-3">
                    <span className="text-xs text-muted-foreground block mb-1">Parent PID</span>
                    <div className="font-mono text-lg">{selectedProcess.ppid}</div>
                  </div>
                  <div className="bg-background border border-border rounded p-3">
                    <span className="text-xs text-muted-foreground block mb-1">Threads</span>
                    <div className="font-mono text-lg">{selectedProcess.threads}</div>
                  </div>
                  <div className="bg-background border border-border rounded p-3">
                    <span className="text-xs text-muted-foreground block mb-1">Handles</span>
                    <div className="font-mono text-lg">{selectedProcess.handles}</div>
                  </div>
                </div>

                <div className="bg-background border border-border rounded p-3">
                  <span className="text-xs text-muted-foreground block mb-1">File Path</span>
                  <div className="font-mono text-sm break-all">{selectedProcess.path}</div>
                </div>

                <div className="bg-background border border-border rounded p-3">
                  <span className="text-xs text-muted-foreground block mb-1">Image Base</span>
                  <div className="font-mono text-sm">{selectedProcess.imageBase}</div>
                </div>

                {selectedProcess.commandLine && (
                  <div className="bg-background border border-border rounded p-3">
                    <span className="text-xs text-muted-foreground block mb-1">Command Line</span>
                    <div className="font-mono text-sm break-all">{selectedProcess.commandLine}</div>
                  </div>
                )}

                <div className="bg-background border border-border rounded p-3">
                  <span className="text-xs text-muted-foreground block mb-1">User</span>
                  <div className="font-mono text-sm">{selectedProcess.user}</div>
                </div>

                <div className="bg-background border border-border rounded p-3">
                  <span className="text-xs text-muted-foreground block mb-1">Session ID</span>
                  <div className="font-mono text-sm">{selectedProcess.sessionId}</div>
                </div>

                <div className="bg-background border border-border rounded p-3">
                  <span className="text-xs text-muted-foreground block mb-1">Create Time</span>
                  <div className="font-mono text-sm">{selectedProcess.createTime.toLocaleString()}</div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

export default MemoryForensics
