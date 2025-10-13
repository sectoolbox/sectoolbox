import React, { useState, useCallback, useEffect } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import {
  ArrowLeft,
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
  const navigate = useNavigate()
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

  // Handle file from Digital Forensics page
  useEffect(() => {
    if (location.state?.memoryFile) {
      const uploadedFile = location.state.memoryFile as File
      setFile(uploadedFile)
      analyzeMemory(uploadedFile)
    }
  }, [location.state])

  const analyzeMemory = useCallback(async (fileToAnalyze?: File) => {
    const targetFile = fileToAnalyze || file
    if (!targetFile) return

    setIsAnalyzing(true)
    setProgress(0)
    setProgressStatus('Starting analysis...')

    try {
      // Generate simple hex preview for first 512 bytes
      const firstChunk = targetFile.slice(0, 512)
      const buffer = await firstChunk.arrayBuffer()
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
      setHexView(hexString)

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
            <Database className="w-6 h-6 text-accent" />
            <span>Memory Forensics & Threat Hunting</span>
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
            <div className="flex border-b border-border overflow-x-auto">
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
                  className={`flex-shrink-0 px-4 py-3 text-sm font-medium transition-colors flex items-center justify-center space-x-2 ${
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

              {/* Hex View Tab */}
              {activeTab === 'hex' && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h4 className="font-medium">Hex View (First 512 bytes)</h4>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => copyToClipboard(hexView)}
                    >
                      <Copy className="w-4 h-4 mr-2" />
                      Copy
                    </Button>
                  </div>
                  <div className="bg-background border border-border rounded-lg p-4 overflow-x-auto">
                    <pre className="font-mono text-xs text-muted-foreground whitespace-pre">
                      {hexView}
                    </pre>
                  </div>
                </div>
              )}

              {/* Placeholder for other tabs - Will show coming soon message */}
              {activeTab !== 'overview' && activeTab !== 'hex' && (
                <div className="text-center py-12">
                  <AlertTriangle className="w-16 h-16 mx-auto mb-4 opacity-50 text-muted-foreground" />
                  <h4 className="text-lg font-medium mb-2">Tab Content Available</h4>
                  <p className="text-muted-foreground">
                    {activeTab.split('-').map(w => w.charAt(0).toUpperCase() + w.slice(1)).join(' ')} analysis results
                  </p>
                  <div className="mt-4 text-sm text-muted-foreground">
                    Check the Overview tab for key findings
                  </div>
                </div>
              )}
            </div>
          </Card>
        </>
      )}
    </div>
  )
}

export default MemoryForensics
