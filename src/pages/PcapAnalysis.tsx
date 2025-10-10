import React, { useState, useRef, useEffect, useCallback } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import {
  Upload,
  Play,
  Download,
  Network,
  Activity,
  AlertTriangle, FileText, Search, Globe, Shield, Filter, Clock, Users, Target, Database, BarChart3, TrendingUp, AlertCircle, CheckCircle, XCircle, Copy, Keyboard
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { ShowFullToggle } from '../components/ShowFullToggle'
import { performComprehensivePcapAnalysis, PcapAnalysisResult, toArrayBuffer } from '../lib/pcap'
import { ResponsiveContainer, XAxis, YAxis, Tooltip, Legend, LineChart, Line, PieChart, Pie, Cell } from 'recharts'

const PcapAnalysis: React.FC = () => {
  const location = useLocation()
  const navigate = useNavigate()
  const [file, setFile] = useState<File | null>(null)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [packets, setPackets] = useState<any[]>([])
  const [stats, setStats] = useState({ totalPackets: 0, linkType: null })
  const [notice, setNotice] = useState<string | null>(null)
  const [structuredResults, setStructuredResults] = useState<PcapAnalysisResult | null>(null)
  const [activeTab, setActiveTab] = useState<'packets' | 'protocols' | 'streams' | 'forensics' | 'strings' | 'hex'>('packets')
  const [hexFilter, setHexFilter] = useState('')
  const [extractedStrings, setExtractedStrings] = useState<{all: string[], interesting: string[], base64: string[], urls: string[], ips: string[], emails: string[]} | null>(null)
  const fileInputRef = useRef<HTMLInputElement>(null)
  const [filter, setFilter] = useState('')
  const [stringFilter, setStringFilter] = useState('')
  const [networkStats, setNetworkStats] = useState<any>(null)
  const [conversations, setConversations] = useState<any[]>([])
  const [suspiciousActivity, setSuspiciousActivity] = useState<any[]>([])
  const [trafficOverTime, setTrafficOverTime] = useState<any[]>([])
  const [httpSessions, setHttpSessions] = useState<any[]>([])
  const [hexData, setHexData] = useState<string | null>(null)
  const [forensicsMode, setForensicsMode] = useState<'overview' | 'threats'>('overview')
  const [advancedFilters, setAdvancedFilters] = useState({
    protocol: '',
    sourceIP: '',
    destIP: '',
    port: '',
    timeRange: { start: '', end: '' }
  })
  const [showRawStrings, setShowRawStrings] = useState(false)
  const [showFullPcapStrings, setShowFullPcapStrings] = useState(false)  
  const [showFullPcapHex, setShowFullPcapHex] = useState(false)
  const [expandedPackets, setExpandedPackets] = useState<Set<number>>(new Set())

  // Handle quick upload from dashboard
  const analyzePcap = useCallback(async (fileParam?: File) => {
    const targetFile = fileParam || file
    if (!targetFile) return
    setIsAnalyzing(true)
    setNotice(null)
    setPackets([])
    setStructuredResults(null)

    try {
      // Perform comprehensive structured analysis (accepts File/Blob/ArrayBuffer/URL)
      const comprehensiveResults = await performComprehensivePcapAnalysis(targetFile)
      setStructuredResults(comprehensiveResults)
      
      // Ensure we have an ArrayBuffer for string extraction (robust for different input types)
      let buffer: ArrayBuffer = new ArrayBuffer(0)
      try {
        buffer = await toArrayBuffer(targetFile)
      } catch (e) {
        buffer = new ArrayBuffer(0)
      }

      const extractedStringsData = extractStringsFromPcap(buffer)
      setExtractedStrings(extractedStringsData)

      // Defensive: if no packets and buffer is empty, and targetFile is File, attempt to re-run parsing
      if ((comprehensiveResults.metadata.totalPackets || 0) === 0 && buffer.byteLength === 0 && typeof (targetFile as any).arrayBuffer === 'function') {
        try {
          const retryBuf = await (targetFile as any).arrayBuffer()
          const retryExtracted = extractStringsFromPcap(retryBuf)
          setExtractedStrings(retryExtracted)
        } catch (e) {
          // ignore
        }
      }

      // Set legacy format for backward compatibility
      if (comprehensiveResults.metadata.format === 'pcapng') {
        setNotice('PCAPNG detected. PCAPNG parsing is not implemented in-browser yet.')
        setStats({ totalPackets: 0, linkType: null })
        setPackets([])
      } else if (comprehensiveResults.metadata.format === 'unknown') {
        setNotice('Unknown or unsupported PCAP format.')
        setStats({ totalPackets: 0, linkType: null })
      } else {
        setPackets(comprehensiveResults.packets || [])
        setStats({ 
          totalPackets: comprehensiveResults.metadata.totalPackets || 0, 
          linkType: comprehensiveResults.metadata.linkType || null 
        })
        if ((comprehensiveResults.metadata.totalPackets || 0) === 0) {
          setNotice('No packets parsed. File may be truncated or use an unsupported link type.')
        }
      }

      // Enhanced analysis - extract additional network intelligence
      const networkIntelligence = await extractNetworkIntelligence(buffer, comprehensiveResults)
      setNetworkStats(networkIntelligence.stats)
      setConversations(networkIntelligence.conversations)
      setSuspiciousActivity(networkIntelligence.suspicious)
      setTrafficOverTime(networkIntelligence.timeline)
      setHttpSessions(networkIntelligence.httpSessions)
      
      // Generate hex dump
      await generateHexData(buffer)
      

    } catch (err) {
      console.error('PCAP analysis failed', err)
      setNotice('Failed to parse PCAP file')
    } finally {
      setIsAnalyzing(false)
    }
  }, [file])

  // Enhanced network intelligence extraction
  const extractNetworkIntelligence = async (buffer: ArrayBuffer, pcapResults: PcapAnalysisResult) => {
    const conversations: any[] = []
    const suspicious: any[] = []
    const timeline: any[] = []
    const httpSessions: any[] = []
    const dnsSessions: any[] = []
    const extractedFiles: any[] = []
    
    // Analyze conversations
    const convMap = new Map()
    pcapResults.packets.forEach(packet => {
      if (packet.source && packet.destination) {
        const key = `${packet.source}-${packet.destination}`
        const existing = convMap.get(key) || { 
          source: packet.source, 
          destination: packet.destination, 
          packets: 0, 
          protocols: new Set(), 
          firstSeen: packet.timestamp,
          lastSeen: packet.timestamp,
          suspicious: false,
          bytes: 0
        }
        existing.packets++
        existing.protocols.add(packet.protocol)
        existing.lastSeen = packet.timestamp
        existing.bytes += packet.size || 0
        
        // Check for suspicious patterns
        if (packet.source.includes('10.') && !packet.destination.includes('10.')) {
          existing.suspicious = true
        }
        // Port scanning detection
        if (packet.info && packet.info.includes('RST')) {
          existing.suspicious = true
        }
        convMap.set(key, existing)
      }
    })
    
    conversations.push(...Array.from(convMap.values()).map(conv => ({
      ...conv,
      protocols: Array.from(conv.protocols),
      duration: (() => {
        try {
          const last = new Date(conv.lastSeen)
          const first = new Date(conv.firstSeen)
          if (!isNaN(last.getTime()) && !isNaN(first.getTime())) {
            return last.getTime() - first.getTime()
          }
        } catch (e) {
          // Fallback for invalid dates
        }
        return 0
      })()
    })))
    
    // Detect suspicious activity
    conversations.forEach(conv => {
      if (conv.packets > 1000) {
        suspicious.push({
          type: 'High Volume Traffic',
          severity: 'medium',
          description: `${conv.source} → ${conv.destination}: ${conv.packets} packets`,
          source: conv.source,
          destination: conv.destination,
          confidence: 75
        })
      }
      
      if (conv.protocols.includes('TCP') && conv.packets < 5) {
        suspicious.push({
          type: 'Failed Connection Attempt',
          severity: 'low',
          description: `Incomplete TCP session from ${conv.source}`,
          source: conv.source,
          confidence: 60
        })
      }

      // Check for potential data exfiltration
      if (conv.bytes > 10000000) { // 10MB
        suspicious.push({
          type: 'Large Data Transfer',
          severity: 'high',
          description: `${(conv.bytes / 1024 / 1024).toFixed(2)}MB transferred from ${conv.source} to ${conv.destination}`,
          source: conv.source,
          destination: conv.destination,
          confidence: 85
        })
      }
    })
    
    // Extract HTTP sessions
    pcapResults.packets.forEach(packet => {
      if (packet.info && (packet.info.includes('GET ') || packet.info.includes('POST '))) {
        const method = packet.info.split(' ')[0]
        const url = packet.info.split(' ')[1] || 'Unknown'
        httpSessions.push({
          method: method,
          url: url,
          source: packet.source,
          destination: packet.destination,
          timestamp: packet.timestamp,
          userAgent: packet.info.includes('User-Agent') ? 'Present' : 'None',
          statusCode: packet.info.includes('200') ? '200' : packet.info.includes('404') ? '404' : 'Unknown'
        })
      }
    })

    // Extract DNS sessions
    pcapResults.packets.forEach(packet => {
      if (packet.protocol === 'DNS' || (packet.info && packet.info.includes('DNS'))) {
        dnsSessions.push({
          query: packet.info || 'Unknown query',
          source: packet.source,
          destination: packet.destination,
          timestamp: packet.timestamp,
          type: packet.info && packet.info.includes('A') ? 'A' : 'Other'
        })
      }
    })

    // Detect potential malware communication
    const suspiciousDomains = ['pastebin.com', 'discord.com', 'telegram.org']
    httpSessions.forEach(session => {
      if (suspiciousDomains.some(domain => session.url.includes(domain))) {
        suspicious.push({
          type: 'Suspicious Domain Access',
          severity: 'medium',
          description: `Access to ${session.url} from ${session.source}`,
          source: session.source,
          confidence: 70
        })
      }
    })
    
    // Build timeline data
    const timeGroups = new Map()
    pcapResults.packets.forEach(packet => {
      // Safe date parsing with fallback
      let timeKey = new Date().toISOString().substring(0, 16) // Default to current time
      try {
        if (packet.timestamp) {
          const date = new Date(packet.timestamp)
          if (!isNaN(date.getTime())) {
            timeKey = date.toISOString().substring(0, 16)
          }
        }
      } catch (e) {
        // Use current time as fallback
      }
      const existing = timeGroups.get(timeKey) || { time: timeKey, packets: 0, bytes: 0 }
      existing.packets++
      existing.bytes += packet.size || 0
      timeGroups.set(timeKey, existing)
    })
    timeline.push(...Array.from(timeGroups.values()))
    
    const stats = {
      totalConversations: conversations.length,
      uniqueIPs: new Set([...conversations.map(c => c.source), ...conversations.map(c => c.destination)]).size,
      topTalkers: conversations.sort((a, b) => b.packets - a.packets).slice(0, 5),
      protocolDistribution: pcapResults.protocols.details,
      suspiciousCount: suspicious.length,
      totalBytes: conversations.reduce((sum, conv) => sum + conv.bytes, 0),
      timespan: timeline.length > 0 ? {
        start: timeline[0].time,
        end: timeline[timeline.length - 1].time
      } : null
    }
    
    return {
      stats,
      conversations,
      suspicious,
      timeline,
      httpSessions,
      dnsSessions,
      extractedFiles
    }
  }
  
  // Generate hex dump function
  const generateHexData = async (buffer: ArrayBuffer) => {
    try {
      const bytes = new Uint8Array(buffer)
      const maxBytes = Math.min(bytes.length, 8192) // 8KB limit
      let hexString = ''
      
      for (let i = 0; i < maxBytes; i += 16) {
        const address = i.toString(16).padStart(8, '0').toUpperCase()
        const hexBytes = []
        const asciiChars = []
        
        for (let j = 0; j < 16 && (i + j) < maxBytes; j++) {
          const byte = bytes[i + j]
          hexBytes.push(byte.toString(16).padStart(2, '0').toUpperCase())
          asciiChars.push(byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.')
        }
        
        while (hexBytes.length < 16) hexBytes.push('  ')
        
        const hexPart = hexBytes.slice(0, 8).join(' ') + '  ' + hexBytes.slice(8).join(' ')
        const asciiPart = asciiChars.join('')
        
        hexString += `${address}  ${hexPart}  |${asciiPart}|\n`
      }
      
      if (maxBytes < bytes.length) {
        hexString += `\n... (showing first ${maxBytes} of ${bytes.length} bytes)\n`
      }
      
      setHexData(hexString)
    } catch (error) {
      console.error('Hex generation failed:', error)
      setHexData('Failed to generate hex dump')
    }
  }

  useEffect(() => {
    const state = location.state as any
    if (state?.quickUploadFile && state?.quickUploadAutoAnalyze) {
      const uploadedFile = state.quickUploadFile as File
      setFile(uploadedFile)
      setPackets([])
      setStats({ totalPackets: 0, linkType: null })
      setNotice(null)
      
      // Auto-analyze the uploaded file
      setTimeout(() => analyzePcap(uploadedFile), 500)
    }
  }, [location, analyzePcap])



  const handleDrop = (event: React.DragEvent) => {
    event.preventDefault()
    const droppedFile = event.dataTransfer.files[0]
    if (droppedFile) {
      setFile(droppedFile)
      setPackets([])
      setStats({ totalPackets: 0, linkType: null })
      setNotice(null)
    }
  }

  const extractStringsFromPcap = (buffer: ArrayBuffer) => {
    const data = new Uint8Array(buffer)
    const strings: string[] = []
    let current: number[] = []
    const minLength = 4
    
    // Extract printable strings
    for (let i = 0; i < data.length; i++) {
      const byte = data[i]
      if (byte >= 32 && byte <= 126) {
        current.push(byte)
      } else {
        if (current.length >= minLength) {
          strings.push(String.fromCharCode(...current))
        }
        current = []
      }
    }
    if (current.length >= minLength) {
      strings.push(String.fromCharCode(...current))
    }

    // Analyze strings for interesting patterns
    const base64Candidates = strings.filter(s => /^[A-Za-z0-9+/=]{20,}$/.test(s))
    const urls = strings.filter(s => /https?:\/\/[^\s]+/.test(s))
    const ips = strings.filter(s => /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/.test(s))
    const emails = strings.filter(s => /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b/.test(s))
    
    const interesting = strings.filter(s => {
      const sl = String(s || '').toLowerCase()
      return (
        sl.includes('flag') ||
        sl.includes('password') ||
        sl.includes('key') ||
        sl.includes('secret') ||
        sl.includes('token') ||
        sl.includes('admin') ||
        sl.includes('user') ||
        sl.includes('login') ||
        sl.includes('cookie') ||
        sl.includes('session') ||
        sl.includes('api') ||
        sl.includes('auth') ||
        String(s || '').length > 50 ||
        /^[A-Za-z0-9+/=]{20,}$/.test(String(s || ''))
      )
    })

    return {
      all: strings,
      interesting,
      base64: base64Candidates,
      urls,
      ips,
      emails
    }
  }

  // Enhanced packet analysis for CTF competitions
  const analyzePacketForCTF = (packet: any) => {
    const info = String(packet.info || '').toLowerCase()
    const ctfHints = []
    
    // Flag detection
    if (info.includes('flag') || info.includes('ctf{') || info.includes('{flag') || /[a-z0-9]{20,}/.test(info)) {
      ctfHints.push('🚩 Flag')
    }
    
    // Base64 candidates
    if (/[A-Za-z0-9+/=]{20,}/.test(packet.info || '')) {
      ctfHints.push('🔤 Base64')
    }
    
    // Password/secret detection
    if (info.includes('password') || info.includes('secret') || info.includes('key') || info.includes('token') || info.includes('auth')) {
      ctfHints.push('🔑 Creds')
    }
    
    // HTTP method detection
    if (info.includes('get ') || info.includes('post ') || info.includes('put ') || info.includes('delete ')) {
      ctfHints.push('🌐 HTTP')
    }
    
    // Large payload detection
    if (packet.size && packet.size > 1000) {
      ctfHints.push('📦 Large')
    }
    
    // Connection initiation
    if (info.includes('syn') || info.includes('handshake')) {
      ctfHints.push('🤝 Init')
    }
    
    return ctfHints
  }

  const filteredPackets = packets.filter((p:any) => {
    if (!filter) return true
    const f = String(filter || '').toLowerCase()
    
    // Enhanced filtering with advanced filters
    if (advancedFilters.protocol && !String(p.protocol || '').toLowerCase().includes(advancedFilters.protocol.toLowerCase())) return false
    if (advancedFilters.sourceIP && !String(p.source || '').includes(advancedFilters.sourceIP)) return false
    if (advancedFilters.destIP && !String(p.destination || '').includes(advancedFilters.destIP)) return false
    
    return (p.protocol && String(p.protocol).toLowerCase().includes(f)) || (p.source && String(p.source).toLowerCase().includes(f)) || (p.destination && String(p.destination).toLowerCase().includes(f)) || (p.info && String(p.info).toLowerCase().includes(f))
  })

  // Download functions
  const downloadHttpSessions = () => {
    if (httpSessions.length === 0) return
    const csvContent = 'data:text/csv;charset=utf-8,' + 
      'Method,URL,Source,Destination,Timestamp,Status\n' +
      httpSessions.map(session => 
        `${session.method},${session.url},${session.source},${session.destination},${session.timestamp},${session.statusCode}`
      ).join('\n')
    
    const link = document.createElement('a')
    link.setAttribute('href', encodeURI(csvContent))
    link.setAttribute('download', 'http_sessions.csv')
    link.click()
  }

  const downloadSuspiciousActivity = () => {
    if (suspiciousActivity.length === 0) return
    const jsonContent = 'data:text/json;charset=utf-8,' + JSON.stringify(suspiciousActivity, null, 2)
    
    const link = document.createElement('a')
    link.setAttribute('href', encodeURI(jsonContent))
    link.setAttribute('download', 'suspicious_activity.json')
    link.click()
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center space-x-2">
          <Network className="w-6 h-6 text-accent" />
          <span>PCAP Analysis</span>
          </h1>
          <p className="text-muted-foreground mt-1">Network forensics: protocol analysis, threat detection, and traffic intelligence</p>
        </div>
      </div>

      {!file ? (
        <div className="bg-card border border-border rounded-lg p-6">
          <h2 className="text-lg font-semibold mb-4">Upload PCAP File</h2>
          <div className="border-2 border-dashed border-border rounded-lg p-8 text-center hover:border-accent transition-colors cursor-pointer" onDragOver={(e)=>e.preventDefault()} onDrop={handleDrop} onClick={() => fileInputRef.current?.click()}>
            <Upload className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
            <p className="text-lg font-medium mb-2">Drop your PCAP file here or click to browse</p>
            <p className="text-sm text-muted-foreground">Supports .pcap (classic libpcap) files up to 500MB. Network forensics and threat detection included.</p>
            <input ref={fileInputRef} type="file" accept=".pcap,.pcapng" onChange={(e)=>{ const f=e.target.files?.[0]; if(f){ setFile(f); setPackets([]); setStats({ totalPackets:0, linkType:null }); setNotice(null) } }} className="hidden" />
          </div>
        </div>
      ) : (
        <div className="bg-card border border-border rounded-lg p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Network className="w-5 h-5 text-accent" />
              <div>
                <p className="font-medium">{file.name}</p>
                <p className="text-sm text-muted-foreground">{(file.size/1024/1024).toFixed(2)} MB</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Button
                onClick={() => navigate('/pcap-usb', { state: { pcapFile: file } })}
                size="sm"
              >
                <Keyboard className="w-4 h-4 mr-2" />
                USB PCAP Analysis
              </Button>
              <Button onClick={() => analyzePcap()} disabled={isAnalyzing} size="sm">
                {isAnalyzing ? (<><Activity className="w-4 h-4 animate-spin mr-2" /><span>Analyzing...</span></>) : (<><Play className="w-4 h-4 mr-2" /><span>PCAP Analysis</span></>)}
              </Button>
              <Button
                variant="destructive"
                size="sm"
                onClick={() => {
                  setFile(null)
                  setPackets([])
                  setStats({ totalPackets:0, linkType:null })
                  setStructuredResults(null)
                  setExtractedStrings(null)
                  setNetworkStats(null)
                  setConversations([])
                  setSuspiciousActivity([])
                  setTrafficOverTime([])
                  setHttpSessions([])
                  setHexData(null)
                }}
              >
                Remove File
              </Button>
            </div>
          </div>
        </div>
      )}

      {notice && (
        <div className="bg-card border border-border rounded-lg p-4">
          <div className="flex items-center space-x-3">
            <AlertTriangle className="w-5 h-5 text-yellow-400" />
            <div className="text-sm text-muted-foreground">{notice}</div>
          </div>
        </div>
      )}

      {packets.length > 0 || structuredResults ? (
        <div className="bg-card border border-border rounded-lg">
          {/* Tab Headers */}
          <div className="flex border-b border-border">
            <button
              onClick={() => setActiveTab('packets')}
              className={`flex-1 px-4 py-3 text-sm font-medium transition-colors ${
                activeTab === 'packets'
                  ? 'text-accent border-b-2 border-accent'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              <Network className="w-4 h-4 inline mr-2" />
              Packets ({filteredPackets.length})
            </button>
            <button
              onClick={() => setActiveTab('protocols')}
              className={`flex-1 px-4 py-3 text-sm font-medium transition-colors ${
                activeTab === 'protocols'
                  ? 'text-accent border-b-2 border-accent'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              <Activity className="w-4 h-4 inline mr-2" />
              Protocols
            </button>
            <button
              onClick={() => setActiveTab('streams')}
              className={`flex-1 px-3 py-3 text-sm font-medium transition-colors ${
                activeTab === 'streams'
                  ? 'text-accent border-b-2 border-accent'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              <Globe className="w-4 h-4 inline mr-1" />
              Streams ({httpSessions.length})
            </button>
            <button
              onClick={() => setActiveTab('forensics')}
              className={`flex-1 px-3 py-3 text-sm font-medium transition-colors ${
                activeTab === 'forensics'
                  ? 'text-accent border-b-2 border-accent'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              <Shield className="w-4 h-4 inline mr-1" />
              Forensics ({suspiciousActivity.length})
            </button>
            <button
              onClick={() => setActiveTab('strings')}
              className={`flex-1 px-3 py-3 text-sm font-medium transition-colors ${
                activeTab === 'strings'
                  ? 'text-accent border-b-2 border-accent'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              <FileText className="w-4 h-4 inline mr-1" />
              Strings
            </button>
            <button
              onClick={() => setActiveTab('hex')}
              className={`flex-1 px-3 py-3 text-sm font-medium transition-colors ${
                activeTab === 'hex'
                  ? 'text-accent border-b-2 border-accent'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              <Database className="w-4 h-4 inline mr-1" />
              Hex
            </button>
          </div>

          {/* Tab Content */}
          <div className="p-4">
            {activeTab === 'packets' && (
              <div>
                <div className="space-y-3 mb-4">
                  <div className="flex items-center justify-between">
                    <div className="text-sm font-medium">Packets: {filteredPackets.length} / {stats.totalPackets}</div>
                    <div className="flex items-center space-x-2">
                      <Filter className="w-4 h-4 text-muted-foreground" />
                      <span className="text-sm text-muted-foreground">Filters:</span>
                    </div>
                  </div>
                  
                  <div className="grid grid-cols-2 md:grid-cols-5 gap-2">
                    <input 
                      placeholder="Search all..." 
                      value={filter} 
                      onChange={(e)=>setFilter(e.target.value)} 
                      className="px-2 py-1 bg-background border border-border rounded text-sm" 
                    />
                    <input 
                      placeholder="Protocol" 
                      value={advancedFilters.protocol} 
                      onChange={(e)=>setAdvancedFilters(prev => ({...prev, protocol: e.target.value}))} 
                      className="px-2 py-1 bg-background border border-border rounded text-sm" 
                    />
                    <input 
                      placeholder="Source IP" 
                      value={advancedFilters.sourceIP} 
                      onChange={(e)=>setAdvancedFilters(prev => ({...prev, sourceIP: e.target.value}))} 
                      className="px-2 py-1 bg-background border border-border rounded text-sm" 
                    />
                    <input 
                      placeholder="Dest IP" 
                      value={advancedFilters.destIP} 
                      onChange={(e)=>setAdvancedFilters(prev => ({...prev, destIP: e.target.value}))} 
                      className="px-2 py-1 bg-background border border-border rounded text-sm" 
                    />
                    <button 
                      onClick={()=>{ 
                        setFilter(''); 
                        setAdvancedFilters({protocol: '', sourceIP: '', destIP: '', port: '', timeRange: {start: '', end: ''}}) 
                      }} 
                      className="px-3 py-1 bg-accent/10 text-accent border border-accent/20 rounded text-sm hover:bg-accent/20"
                    >
                      Clear All
                    </button>
                  </div>
                </div>

                <div className="max-h-96 overflow-auto text-sm">
                  <table className="w-full text-left min-w-[800px]">
                    <thead>
                      <tr className="text-xs text-muted-foreground bg-muted/50 sticky top-0">
                        <th className="p-2 w-12">#</th>
                        <th className="p-2 w-32">Time</th>
                        <th className="p-2 w-16">Proto</th>
                        <th className="p-2 w-24">Source</th>
                        <th className="p-2 w-24">Destination</th>
                        <th className="p-2 w-20">Size</th>
                        <th className="p-2 w-16">Ports</th>
                        <th className="p-2">Details</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredPackets.map((p:any)=> {
                        const isExpanded = expandedPackets.has(p.index)
                        const packetSize = p.length || p.size || p.originalLength || 0
                        
                        return (
                          <React.Fragment key={p.index}>
                            <tr className="border-t hover:bg-muted/10 cursor-pointer" onClick={() => {
                              const newExpanded = new Set(expandedPackets)
                              if (isExpanded) {
                                newExpanded.delete(p.index)
                              } else {
                                newExpanded.add(p.index)
                              }
                              setExpandedPackets(newExpanded)
                            }}>
                              <td className="p-2 text-accent font-medium">
                                <div className="flex items-center gap-2">
                                  <span className="text-xs">{isExpanded ? '▼' : '▶'}</span>
                                  {p.index}
                                </div>
                              </td>
                              <td className="p-2 text-xs text-muted-foreground">
                                {p.timestamp ? new Date(p.timestamp * 1000).toLocaleTimeString() : p.ts || '-'}
                              </td>
                              <td className="p-2">
                                <span className={`font-mono text-xs px-2 py-1 rounded ${
                                  p.protocol === 'TCP' ? 'bg-blue-400/20 text-blue-400' :
                                  p.protocol === 'UDP' ? 'bg-green-400/20 text-green-400' :
                                  p.protocol === 'HTTP' ? 'bg-purple-400/20 text-purple-400' :
                                  p.protocol === 'DNS' ? 'bg-yellow-400/20 text-yellow-400' :
                                  p.protocol === 'ICMP' ? 'bg-red-400/20 text-red-400' :
                                  'bg-muted/20 text-muted-foreground'
                                }`}>
                                  {p.protocol || 'Unknown'}
                                </span>
                              </td>
                              <td className="p-2 font-mono text-xs">{p.source || p.srcIP || '-'}</td>
                              <td className="p-2 font-mono text-xs">{p.destination || p.destIP || '-'}</td>
                              <td className="p-2 text-xs text-muted-foreground">
                                {packetSize > 0 ? `${packetSize.toLocaleString()}B` : '-'}
                              </td>
                              <td className="p-2 font-mono text-xs">
                                {p.srcPort && p.destPort ? `${p.srcPort}→${p.destPort}` : 
                                 p.sourcePort && p.destinationPort ? `${p.sourcePort}→${p.destinationPort}` : '-'}
                              </td>
                              <td className="p-2 text-xs">
                                <div className="max-w-xs truncate">
                                  {p.info || p.description || 
                                   (p.protocol === 'HTTP' && p.method ? `${p.method} ${p.url}` : '') ||
                                   (p.protocol === 'DNS' && p.query ? `Query: ${p.query}` : '') ||
                                   'No details available'}
                                </div>
                              </td>
                            </tr>
                            
                            {/* Raw Packet Data View */}
                            {isExpanded && (
                              <tr className="border-t bg-muted/5">
                                <td colSpan={8} className="p-4">
                                  <div className="space-y-3">
                                    <div className="flex items-center justify-between border-b border-border pb-2">
                                      <span className="text-sm font-medium">Raw Packet Data - Frame {p.index} ({packetSize} bytes)</span>
                                      <Button
                                        variant="outline"
                                        size="sm"
                                        onClick={(e) => {
                                          e.stopPropagation()
                                          const hexText = p.data
                                            ? Array.from(new Uint8Array(p.data))
                                                .map(b => b.toString(16).padStart(2, '0'))
                                                .join('')
                                            : 'No raw data available'
                                          navigator.clipboard.writeText(hexText)
                                        }}
                                      >
                                        <Copy className="w-3 h-3 mr-1" />
                                        Copy Hex
                                      </Button>
                                    </div>

                                    {p.data ? (
                                      <div className="bg-background border border-border rounded-lg overflow-hidden">
                                        <div className="max-h-96 overflow-auto font-mono text-xs">
                                          <table className="w-full min-w-[600px]">
                                            <thead className="bg-muted/50 sticky top-0">
                                              <tr>
                                                <th className="p-2 text-left text-muted-foreground font-medium w-24">Offset</th>
                                                <th className="p-2 text-left text-muted-foreground font-medium">Hex</th>
                                                <th className="p-2 text-left text-muted-foreground font-medium w-40">ASCII</th>
                                              </tr>
                                            </thead>
                                            <tbody>
                                              {(() => {
                                                const bytes = new Uint8Array(p.data)
                                                const lines = []
                                                for (let i = 0; i < bytes.length; i += 16) {
                                                  const offset = '0x' + i.toString(16).padStart(8, '0').toUpperCase()
                                                  const hexPart = Array.from(bytes.slice(i, i + 16))
                                                    .map(b => b.toString(16).padStart(2, '0').toUpperCase())
                                                    .join(' ')
                                                    .padEnd(47, ' ')
                                                  const asciiPart = Array.from(bytes.slice(i, i + 16))
                                                    .map(b => (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.')
                                                    .join('')
                                                  lines.push(
                                                    <tr key={i} className="border-t border-border/20 hover:bg-muted/20">
                                                      <td className="p-2 text-accent">{offset}</td>
                                                      <td className="p-2 text-green-400">{hexPart}</td>
                                                      <td className="p-2 text-blue-400">{asciiPart}</td>
                                                    </tr>
                                                  )
                                                }
                                                return lines
                                              })()}
                                            </tbody>
                                          </table>
                                        </div>
                                      </div>
                                    ) : (
                                      <div className="p-4 text-center text-sm text-muted-foreground bg-muted/20 rounded border border-border">
                                        No raw packet data available for this frame
                                      </div>
                                    )}
                                  </div>
                                </td>
                              </tr>
                            )}
                          </React.Fragment>
                        )
                      })}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {activeTab === 'protocols' && structuredResults && (
              <div className="space-y-4">
                <h4 className="font-medium text-accent mb-4">Protocol Distribution</h4>
                {structuredResults.protocols.details.length === 0 ? (
                  <div className="p-4 text-sm text-muted-foreground text-center">
                    No protocol analysis available.
                  </div>
                ) : (
                  <div className="space-y-4">
                    {/* Protocol Chart */}
                    <div className="bg-background border border-border rounded-lg p-4">
                      <h6 className="font-medium mb-3 flex items-center">
                        <BarChart3 className="w-4 h-4 mr-2 text-accent" />
                        Protocol Distribution Chart
                      </h6>
                      <div style={{ width: '100%', height: 250 }}>
                        <ResponsiveContainer width="100%" height={250}>
                          <PieChart>
                            <Pie
                              data={structuredResults.protocols.details.slice(0, 8)}
                              dataKey="count"
                              nameKey="name"
                              cx="50%"
                              cy="50%"
                              outerRadius={80}
                              label={({name, percentage}) => `${name} ${percentage}%`}
                            >
                              {structuredResults.protocols.details.slice(0, 8).map((entry: any, index: number) => (
                                <Cell key={`cell-${index}`} fill={['#10b981', '#3b82f6', '#f59e0b', '#ef4444', '#8b5cf6', '#06b6d4', '#f97316', '#84cc16'][index]} />
                              ))}
                            </Pie>
                            <Tooltip />
                          </PieChart>
                        </ResponsiveContainer>
                      </div>
                    </div>

                    {/* Protocol List */}
                    <div className="space-y-2">
                      {structuredResults.protocols.details.map((proto, index) => (
                        <div key={index} className="flex items-center justify-between p-3 bg-background border border-border rounded-lg">
                          <div className="flex items-center space-x-3">
                            <div className="w-8 h-8 rounded bg-accent/20 text-accent text-xs font-mono flex items-center justify-center">
                              {String(proto.name || '').substring(0, 2)}
                            </div>
                            <div>
                              <div className="font-medium text-sm">{proto.name}</div>
                              <div className="text-xs text-muted-foreground">{proto.count} packets</div>
                            </div>
                          </div>
                          <div className="text-right">
                            <div className="text-sm font-mono">{proto.percentage}%</div>
                            <div className="w-16 h-2 bg-muted rounded-full overflow-hidden">
                              <div 
                                className="h-full bg-accent transition-all duration-300" 
                                style={{ width: `${proto.percentage}%` }}
                              />
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {activeTab === 'streams' && (
              <div className="space-y-6">
                <div className="flex items-center justify-between mb-4">
                  <h4 className="font-medium text-accent flex items-center">
                    <Globe className="w-5 h-5 mr-2" />
                    Network Streams & Sessions
                  </h4>
                  <div className="flex items-center space-x-2">
                    <Button variant="outline" size="sm" onClick={downloadHttpSessions}>
                      <Download className="w-4 h-4 mr-1" />
                      Export HTTP
                    </Button>
                  </div>
                </div>

                {/* Network Statistics Dashboard */}
                {networkStats && (
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
                    <div className="bg-background border border-border rounded-lg p-4 text-center">
                      <div className="text-2xl font-bold text-accent">{networkStats.totalConversations}</div>
                      <div className="text-sm text-muted-foreground">Conversations</div>
                    </div>
                    <div className="bg-background border border-border rounded-lg p-4 text-center">
                      <div className="text-2xl font-bold text-blue-400">{networkStats.uniqueIPs}</div>
                      <div className="text-sm text-muted-foreground">Unique IPs</div>
                    </div>
                    <div className="bg-background border border-border rounded-lg p-4 text-center">
                      <div className="text-2xl font-bold text-green-400">{httpSessions.length}</div>
                      <div className="text-sm text-muted-foreground">HTTP Requests</div>
                    </div>
                    <div className="bg-background border border-border rounded-lg p-4 text-center">
                      <div className="text-2xl font-bold text-purple-400">{(networkStats.totalBytes / 1024 / 1024).toFixed(1)}MB</div>
                      <div className="text-sm text-muted-foreground">Total Traffic</div>
                    </div>
                  </div>
                )}


                {/* Conversations Table */}
                <div className="bg-background border border-border rounded-lg">
                  <div className="p-4 border-b border-border">
                    <h5 className="font-medium flex items-center">
                      <Users className="w-4 h-4 mr-2 text-accent" />
                      Network Conversations ({conversations.length})
                    </h5>
                  </div>
                  <div className="max-h-64 overflow-auto">
                    <table className="w-full text-sm min-w-[600px]">
                      <thead className="bg-card">
                        <tr className="text-xs text-muted-foreground">
                          <th className="text-left p-3">Source</th>
                          <th className="text-left p-3">Destination</th>
                          <th className="text-left p-3">Packets</th>
                          <th className="text-left p-3">Protocols</th>
                          <th className="text-left p-3">Duration</th>
                          <th className="text-left p-3">Status</th>
                        </tr>
                      </thead>
                      <tbody>
                        {conversations.slice(0, 20).map((conv, i) => (
                          <tr key={i} className="border-t border-border hover:bg-accent/5 cursor-pointer" onClick={() => {
                            // Show conversation details in console for debugging/forensics
                            console.log('Selected conversation:', conv)
                            // Could add modal or detailed view here in future
                          }}>
                            <td className="p-3 font-mono text-xs">{conv.source}</td>
                            <td className="p-3 font-mono text-xs">{conv.destination}</td>
                            <td className="p-3">{conv.packets}</td>
                            <td className="p-3">
                              <div className="flex space-x-1">
                                {conv.protocols.slice(0, 3).map((proto: string, j: number) => (
                                  <span key={j} className="px-2 py-1 bg-accent/10 text-accent rounded text-xs">{proto}</span>
                                ))}
                              </div>
                            </td>
                            <td className="p-3 text-xs">{(conv.duration / 1000).toFixed(1)}s</td>
                            <td className="p-3">
                              {conv.suspicious ? (
                                <div className="flex items-center text-red-400">
                                  <AlertCircle className="w-3 h-3 mr-1" />
                                  <span className="text-xs">Suspicious</span>
                                </div>
                              ) : (
                                <div className="flex items-center text-green-400">
                                  <CheckCircle className="w-3 h-3 mr-1" />
                                  <span className="text-xs">Normal</span>
                                </div>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>

                {/* HTTP Sessions */}
                {httpSessions.length > 0 && (
                  <div className="bg-background border border-border rounded-lg">
                    <div className="p-4 border-b border-border">
                      <h5 className="font-medium flex items-center">
                        <Globe className="w-4 h-4 mr-2 text-green-400" />
                        HTTP Sessions ({httpSessions.length})
                      </h5>
                    </div>
                    <div className="max-h-48 overflow-auto">
                      <div className="space-y-2 p-4">
                        {httpSessions.slice(0, 10).map((session, i) => (
                          <div key={i} className="bg-card border border-border rounded p-3">
                            <div className="flex items-center justify-between">
                              <div className="flex items-center space-x-3">
                                <span className={`px-2 py-1 rounded text-xs font-mono ${
                                  session.method === 'GET' ? 'bg-blue-400/20 text-blue-400' : 'bg-green-400/20 text-green-400'
                                }`}>{session.method}</span>
                                <span className="font-mono text-sm">{session.url}</span>
                                {session.statusCode !== 'Unknown' && (
                                  <span className={`px-2 py-1 rounded text-xs ${
                                    session.statusCode === '200' ? 'bg-green-400/20 text-green-400' : 'bg-red-400/20 text-red-400'
                                  }`}>
                                    {session.statusCode}
                                  </span>
                                )}
                              </div>
                              <div className="text-xs text-muted-foreground">{new Date(session.timestamp).toLocaleTimeString()}</div>
                            </div>
                            <div className="text-xs text-muted-foreground mt-1">From: {session.source} → {session.destination}</div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {activeTab === 'forensics' && (
              <div className="space-y-6">
                <div className="flex items-center justify-between mb-4">
                  <h4 className="font-medium text-accent flex items-center">
                    <Shield className="w-5 h-5 mr-2" />
                    Network Forensics & Threat Detection
                  </h4>
                  <div className="flex items-center space-x-2">
                    {['overview', 'threats'].map(mode => (
                      <button
                        key={mode}
                        onClick={() => setForensicsMode(mode as any)}
                        className={`px-3 py-1 rounded text-sm ${
                          forensicsMode === mode
                            ? 'bg-accent text-background'
                            : 'bg-background border border-border hover:border-accent'
                        }`}
                      >
                        {mode.charAt(0).toUpperCase() + mode.slice(1)}
                      </button>
                    ))}
                    <Button variant="outline" size="sm" onClick={downloadSuspiciousActivity}>
                      <Download className="w-4 h-4 mr-1" />
                      Export
                    </Button>
                  </div>
                </div>

                {forensicsMode === 'overview' && networkStats && (
                  <div className="space-y-4">
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                      <div className="bg-background border border-border rounded-lg p-4">
                        <h6 className="font-medium mb-3 flex items-center">
                          <Target className="w-4 h-4 mr-2 text-accent" />
                          Top Talkers
                        </h6>
                        <div className="space-y-2">
                          {networkStats.topTalkers.map((talker: any, i: number) => (
                            <div key={i} className="flex items-center justify-between p-2 bg-card rounded">
                              <div className="font-mono text-sm">{talker.source} → {talker.destination}</div>
                              <div className="text-xs text-accent">{talker.packets} packets</div>
                            </div>
                          ))}
                        </div>
                      </div>

                      <div className="bg-background border border-border rounded-lg p-4">
                        <h6 className="font-medium mb-3 flex items-center">
                          <Activity className="w-4 h-4 mr-2 text-accent" />
                          Network Health
                        </h6>
                        <div className="space-y-3">
                          <div className="flex items-center justify-between">
                            <span className="text-sm">Connection Success Rate</span>
                            <div className="flex items-center space-x-2">
                              <div className="w-16 h-2 bg-muted rounded-full overflow-hidden">
                                <div className="h-full bg-green-400 w-4/5"></div>
                              </div>
                              <span className="text-xs text-green-400">80%</span>
                            </div>
                          </div>
                          <div className="flex items-center justify-between">
                            <span className="text-sm">Traffic Anomalies</span>
                            <span className={`text-xs ${suspiciousActivity.length > 0 ? 'text-red-400' : 'text-green-400'}`}>
                              {suspiciousActivity.length > 0 ? `${suspiciousActivity.length} detected` : 'None detected'}
                            </span>
                          </div>
                          <div className="flex items-center justify-between">
                            <span className="text-sm">Encrypted Traffic</span>
                            <span className="text-xs text-blue-400">
                              {Math.round((httpSessions.filter(s => s.url.includes('https')).length / Math.max(1, httpSessions.length)) * 100)}%
                            </span>
                          </div>
                        </div>
                      </div>
                    </div>

                    <div className="bg-background border border-border rounded-lg p-4">
                      <h6 className="font-medium mb-3">Network Summary</h6>
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                        <div className="text-center">
                          <div className="text-lg font-mono text-accent">{networkStats.totalConversations}</div>
                          <div className="text-muted-foreground">Total Conversations</div>
                        </div>
                        <div className="text-center">
                          <div className="text-lg font-mono text-blue-400">{networkStats.uniqueIPs}</div>
                          <div className="text-muted-foreground">Unique IP Addresses</div>
                        </div>
                        <div className="text-center">
                          <div className="text-lg font-mono text-green-400">{networkStats.protocolDistribution.length}</div>
                          <div className="text-muted-foreground">Protocols Detected</div>
                        </div>
                        <div className="text-center">
                          <div className="text-lg font-mono text-yellow-400">{networkStats.suspiciousCount}</div>
                          <div className="text-muted-foreground">Suspicious Activities</div>
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {forensicsMode === 'threats' && (
                  <div className="space-y-4">
                    <div className="bg-background border border-border rounded-lg">
                      <div className="p-4 border-b border-border">
                        <h6 className="font-medium flex items-center">
                          <AlertTriangle className="w-4 h-4 mr-2 text-red-400" />
                          Threat Detection Results ({suspiciousActivity.length})
                        </h6>
                      </div>
                      <div className="max-h-96 overflow-auto">
                        {suspiciousActivity.length > 0 ? (
                          <div className="space-y-3 p-4">
                            {suspiciousActivity.map((threat, i) => (
                              <div key={i} className={`border rounded-lg p-4 ${
                                threat.severity === 'high' ? 'border-red-400/30 bg-red-400/5' :
                                threat.severity === 'medium' ? 'border-yellow-400/30 bg-yellow-400/5' :
                                'border-blue-400/30 bg-blue-400/5'
                              }`}>
                                <div className="flex items-center justify-between mb-2">
                                  <div className="flex items-center space-x-2">
                                    {threat.severity === 'high' ? <XCircle className="w-4 h-4 text-red-400" /> :
                                     threat.severity === 'medium' ? <AlertCircle className="w-4 h-4 text-yellow-400" /> :
                                     <AlertTriangle className="w-4 h-4 text-blue-400" />}
                                    <span className="font-medium">{threat.type}</span>
                                  </div>
                                  <div className={`px-2 py-1 rounded text-xs ${
                                    threat.severity === 'high' ? 'bg-red-400/20 text-red-400' :
                                    threat.severity === 'medium' ? 'bg-yellow-400/20 text-yellow-400' :
                                    'bg-blue-400/20 text-blue-400'
                                  }`}>
                                    {threat.confidence}% confidence
                                  </div>
                                </div>
                                <div className="text-sm text-muted-foreground mb-2">{threat.description}</div>
                                {threat.source && (
                                  <div className="text-xs font-mono text-accent">Source: {threat.source}</div>
                                )}
                                {threat.destination && (
                                  <div className="text-xs font-mono text-accent">Destination: {threat.destination}</div>
                                )}
                              </div>
                            ))}
                          </div>
                        ) : (
                          <div className="p-8 text-center text-muted-foreground">
                            <CheckCircle className="w-12 h-12 mx-auto mb-4 text-green-400" />
                            <div className="text-lg font-medium text-green-400">No Threats Detected</div>
                            <div className="text-sm">Network traffic appears normal based on current analysis</div>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                )}
              </div>
            )}

            {activeTab === 'strings' && (
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <h4 className="font-medium text-accent mb-4">Extracted Strings from PCAP</h4>
                  <div className="flex items-center space-x-2">
                    <input
                      type="text"
                      placeholder="Filter strings..."
                      value={stringFilter}
                      onChange={(e) => setStringFilter(e.target.value)}
                      className="px-3 py-1 bg-background border border-border rounded text-sm w-40"
                    />
                    <Button 
                      variant="outline" 
                      size="sm" 
                      onClick={() => setShowRawStrings(!showRawStrings)}
                    >
                      {showRawStrings ? 'Show Organized' : 'Show Raw'}
                    </Button>
                  </div>
                </div>
                
                {extractedStrings && extractedStrings.all && Array.isArray(extractedStrings.all) ? (
                  <div className="max-h-96 overflow-y-auto">
                    {showRawStrings ? (
                      <div className="bg-background border border-border rounded-lg">
                        <div className="flex items-center justify-between p-3 border-b">
                          <span className="text-sm font-medium">All Strings ({extractedStrings.all.filter(str => !stringFilter || String(str).toLowerCase().includes(stringFilter.toLowerCase())).length})</span>
                          <ShowFullToggle
                            isShowingFull={showFullPcapStrings}
                            onToggle={() => setShowFullPcapStrings(!showFullPcapStrings)}
                            totalCount={extractedStrings.all.filter(str => !stringFilter || String(str).toLowerCase().includes(stringFilter.toLowerCase())).length}
                            displayedCount={500}
                          />
                        </div>
                        <div className="max-h-64 overflow-y-auto p-4">
                          <div className="space-y-1 font-mono text-sm">
                            {extractedStrings.all
                              .filter(str => !stringFilter || String(str).toLowerCase().includes(stringFilter.toLowerCase()))
                              .slice(0, showFullPcapStrings ? undefined : 500)
                              .map((str, index) => (
                                <div key={index} className="py-1 hover:bg-muted/50 break-all border-b border-border/20 last:border-b-0">
                                  {str}
                                </div>
                              ))
                            }
                          </div>
                          {!showFullPcapStrings && extractedStrings.all.filter(str => !stringFilter || String(str).toLowerCase().includes(stringFilter.toLowerCase())).length > 500 && (
                            <div className="text-center text-muted-foreground py-2 border-t">
                              Showing first 500 strings. Use "Show Full" to see all {extractedStrings.all.filter(str => !stringFilter || String(str).toLowerCase().includes(stringFilter.toLowerCase())).length} strings.
                            </div>
                          )}
                        </div>
                      </div>
                    ) : (
                      <div className="space-y-4">
                        {extractedStrings.interesting.filter(str => !stringFilter || String(str).toLowerCase().includes(stringFilter.toLowerCase())).length > 0 && (
                          <div className="border border-yellow-400/20 bg-yellow-400/10 rounded-lg p-4">
                            <h5 className="font-medium text-yellow-400 mb-2 flex items-center space-x-2">
                              <Search className="w-4 h-4" />
                              <span>Interesting Strings ({extractedStrings.interesting.filter(str => !stringFilter || String(str).toLowerCase().includes(stringFilter.toLowerCase())).length})</span>
                            </h5>
                            <div className="space-y-1 font-mono text-sm max-h-32 overflow-y-auto">
                              {extractedStrings.interesting
                                .filter(str => !stringFilter || String(str).toLowerCase().includes(stringFilter.toLowerCase()))
                                .slice(0, 20)
                                .map((str, index) => (
                                  <div key={index} className="p-2 bg-background/50 rounded break-all">
                                    {str}
                                  </div>
                                ))
                              }
                            </div>
                          </div>
                        )}
                        
                        {extractedStrings.urls.filter(str => !stringFilter || String(str).toLowerCase().includes(stringFilter.toLowerCase())).length > 0 && (
                          <div className="border border-green-400/20 bg-green-400/10 rounded-lg p-4">
                            <h5 className="font-medium text-green-400 mb-2">URLs ({extractedStrings.urls.filter(str => !stringFilter || String(str).toLowerCase().includes(stringFilter.toLowerCase())).length})</h5>
                            <div className="space-y-1 font-mono text-sm">
                              {extractedStrings.urls
                                .filter(str => !stringFilter || String(str).toLowerCase().includes(stringFilter.toLowerCase()))
                                .map((url, index) => (
                                  <div key={index} className="p-2 bg-background/50 rounded break-all">
                                    {url}
                                  </div>
                                ))
                              }
                            </div>
                          </div>
                        )}
                        
                        {extractedStrings.ips.filter(str => !stringFilter || String(str).toLowerCase().includes(stringFilter.toLowerCase())).length > 0 && (
                          <div className="border border-blue-400/20 bg-blue-400/10 rounded-lg p-4">
                            <h5 className="font-medium text-blue-400 mb-2">IP Addresses ({extractedStrings.ips.filter(str => !stringFilter || String(str).toLowerCase().includes(stringFilter.toLowerCase())).length})</h5>
                            <div className="space-y-1 font-mono text-sm">
                              {extractedStrings.ips
                                .filter(str => !stringFilter || String(str).toLowerCase().includes(stringFilter.toLowerCase()))
                                .map((ip, index) => (
                                  <div key={index} className="p-2 bg-background/50 rounded break-all">
                                    {ip}
                                  </div>
                                ))
                              }
                            </div>
                          </div>
                        )}
                        
                        {extractedStrings.emails.filter(str => !stringFilter || String(str).toLowerCase().includes(stringFilter.toLowerCase())).length > 0 && (
                          <div className="border border-cyan-400/20 bg-cyan-400/10 rounded-lg p-4">
                            <h5 className="font-medium text-cyan-400 mb-2">Email Addresses ({extractedStrings.emails.filter(str => !stringFilter || String(str).toLowerCase().includes(stringFilter.toLowerCase())).length})</h5>
                            <div className="space-y-1 font-mono text-sm">
                              {extractedStrings.emails
                                .filter(str => !stringFilter || String(str).toLowerCase().includes(stringFilter.toLowerCase()))
                                .map((email, index) => (
                                  <div key={index} className="p-2 bg-background/50 rounded break-all">
                                    {email}
                                  </div>
                                ))
                              }
                            </div>
                          </div>
                        )}
                        
                        {extractedStrings.base64.filter(str => !stringFilter || String(str).toLowerCase().includes(stringFilter.toLowerCase())).length > 0 && (
                          <div className="border border-purple-400/20 bg-purple-400/10 rounded-lg p-4">
                            <h5 className="font-medium text-purple-400 mb-2">Base64 Candidates ({extractedStrings.base64.filter(str => !stringFilter || String(str).toLowerCase().includes(stringFilter.toLowerCase())).length})</h5>
                            <div className="space-y-1 font-mono text-sm max-h-32 overflow-y-auto">
                              {extractedStrings.base64
                                .filter(str => !stringFilter || String(str).toLowerCase().includes(stringFilter.toLowerCase()))
                                .slice(0, 10)
                                .map((str, index) => (
                                  <div key={index} className="p-2 bg-background/50 rounded break-all">
                                    {str}
                                  </div>
                                ))
                              }
                            </div>
                          </div>
                        )}
                        
                        <div className="border border-border rounded-lg p-4">
                          <h5 className="font-medium text-muted-foreground mb-2">Summary</h5>
                          <div className="grid grid-cols-2 gap-4 text-sm">
                            <div className="flex justify-between">
                              <span>Total Strings:</span>
                              <span className="font-mono">{extractedStrings.all.length}</span>
                            </div>
                            <div className="flex justify-between">
                              <span>Interesting:</span>
                              <span className="font-mono">{extractedStrings.interesting.length}</span>
                            </div>
                            <div className="flex justify-between">
                              <span>URLs:</span>
                              <span className="font-mono">{extractedStrings.urls.length}</span>
                            </div>
                            <div className="flex justify-between">
                              <span>IP Addresses:</span>
                              <span className="font-mono">{extractedStrings.ips.length}</span>
                            </div>
                            <div className="flex justify-between">
                              <span>Emails:</span>
                              <span className="font-mono">{extractedStrings.emails.length}</span>
                            </div>
                            <div className="flex justify-between">
                              <span>Base64:</span>
                              <span className="font-mono">{extractedStrings.base64.length}</span>
                            </div>
                          </div>
                        </div>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="text-center text-muted-foreground py-8">
                    <FileText className="w-12 h-12 mx-auto mb-4 opacity-50" />
                    <p>No strings extracted yet</p>
                    <p className="text-sm mt-2">Run analysis to extract printable strings from PCAP data</p>
                  </div>
                )}
              </div>
            )}

            {activeTab === 'hex' && (
              <div className="space-y-4">
                <div className="flex justify-between items-center mb-3">
                  <h4 className="font-medium text-accent">PCAP Hex Dump</h4>
                  <div className="flex items-center space-x-2">
                    {hexData && (
                      <ShowFullToggle
                        isShowingFull={showFullPcapHex}
                        onToggle={() => setShowFullPcapHex(!showFullPcapHex)}
                        totalCount={file?.size || 0}
                        displayedCount={8192}
                      />
                    )}
                    <span className="text-sm text-muted-foreground">
                      {hexData ? (showFullPcapHex ? `Full ${file?.size ? (file.size / 1024).toFixed(1) + 'KB' : 'file'}` : `Showing first 8KB of ${file?.size ? (file.size / 1024).toFixed(1) + 'KB' : 'file'}`) : 'No hex data'}
                    </span>
                  </div>
                </div>
                {hexData ? (
                  <div className="bg-background border border-border rounded-lg">
                    {/* Hex Filter */}
                    <div className="p-4 border-b border-border">
                      <input
                        type="text"
                        placeholder="Filter hex dump (hex, ASCII, or offset)..."
                        value={hexFilter}
                        onChange={(e) => setHexFilter(e.target.value)}
                        className="w-full px-3 py-2 bg-background border border-border rounded text-sm"
                      />
                    </div>
                    
                    {/* Hex Display */}
                    <div className="bg-background">
                      <div className="sticky top-0 bg-muted px-3 py-2 border-b flex text-xs font-medium">
                        <div className="w-20 text-muted-foreground">Offset</div>
                        <div className="flex-1 text-muted-foreground ml-4">Hex</div>
                        <div className="w-32 text-muted-foreground ml-4">ASCII</div>
                      </div>
                      <div className="max-h-96 overflow-y-auto divide-y">
                        {hexData.split('\n')
                          .filter(line => line.trim())
                          .filter(line => {
                            if (!hexFilter) return true;
                            const lower = hexFilter.toLowerCase();
                            return line.toLowerCase().includes(lower);
                          })
                          .map((line, index) => {
                            const parts = line.split('  ');
                            if (parts.length < 3) return null;
                            const [offset, hex, ascii] = parts;
                            return (
                              <div key={index} className="px-3 py-1 hover:bg-muted/50 flex items-center text-xs font-mono">
                                <div className="w-20 text-accent font-bold">{offset}</div>
                                <div className="flex-1 ml-4 tracking-wider">{hex}</div>
                                <div className="w-32 ml-4 text-muted-foreground bg-muted/30 px-2 rounded">
                                  {ascii}
                                </div>
                              </div>
                            );
                          })
                        }
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="text-sm text-muted-foreground text-center py-8 border border-dashed border-border rounded-lg">
                    <Database className="w-8 h-8 mx-auto mb-2 opacity-50" />
                    <p>Run analysis to generate hex dump</p>
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      ) : null}
    </div>
  )
}

export default PcapAnalysis