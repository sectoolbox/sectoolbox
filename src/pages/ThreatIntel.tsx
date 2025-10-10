import React, { useState, useCallback, useEffect, useRef } from 'react'
import {
  Shield,
  Search,
  RefreshCw,
  AlertCircle,
  Copy,
  Download,
  Database,
  Eye,
  Lock,
  Globe,
  Activity,
  Upload
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card } from '../components/ui/card'

type TabType = 'virustotal' | 'hibp' | 'urlhaus' | 'phishstats' | 'cloudflare' | 'abuseipdb' | 'greynoise' | 'alienvault'

// Check which APIs have keys configured
const checkApiKeys = async () => {
  try {
    const response = await fetch('/api/threat-intel?service=check-keys')
    if (response.ok) {
      return await response.json()
    }
  } catch (err) {
    console.error('Failed to check API keys:', err)
  }
  return { virustotal: true, hibp: true, abuseipdb: false, alienvault: false }
}

export default function ThreatIntel() {
  const [activeTab, setActiveTab] = useState<TabType>('virustotal')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)
  const [results, setResults] = useState<any>(null)
  const [input, setInput] = useState('')
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [apiKeys, setApiKeys] = useState({ virustotal: true, hibp: true, abuseipdb: false, alienvault: false })
  const fileInputRef = useRef<HTMLInputElement>(null)

  useEffect(() => {
    checkApiKeys().then(keys => setApiKeys(keys))
  }, [])

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
  }

  const exportData = (data: any, filename: string) => {
    const json = JSON.stringify(data, null, 2)
    const blob = new Blob([json], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    a.click()
    URL.revokeObjectURL(url)
  }

  const performLookup = useCallback(async (tab: TabType, query: string) => {
    // Cloudflare doesn't need a query
    if (tab !== 'cloudflare' && !query.trim() && !selectedFile) {
      setError('Please enter a query or upload a file')
      return
    }

    setLoading(true)
    setError(null)
    setResults(null)

    try {
      let url = ''

      switch (tab) {
        case 'virustotal':
          url = `/api/threat-intel?service=virustotal&type=domain&query=${encodeURIComponent(query)}`
          break
        case 'hibp':
          url = `/api/threat-intel?service=hibp&type=breach&query=${encodeURIComponent(query)}`
          break
        case 'urlhaus':
          url = `/api/threat-intel?service=urlhaus&type=url&query=${encodeURIComponent(query)}`
          break
        case 'phishstats':
          url = `/api/threat-intel?service=phishstats&type=domain&query=${encodeURIComponent(query)}`
          break
        case 'cloudflare':
          url = `/api/threat-intel?service=cloudflare`
          break
        case 'abuseipdb':
          url = `/api/threat-intel?service=abuseipdb&query=${encodeURIComponent(query)}`
          break
        case 'greynoise':
          url = `/api/threat-intel?service=greynoise&query=${encodeURIComponent(query)}`
          break
        case 'alienvault':
          url = `/api/threat-intel?service=alienvault&type=IPv4&query=${encodeURIComponent(query)}`
          break
      }

      const response = await fetch(url)
      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error || 'API request failed')
      }

      setResults(data)
    } catch (err: any) {
      setError(err.message || 'Lookup failed')
      setResults(null)
    } finally {
      setLoading(false)
    }
  }, [selectedFile])

  const uploadFile = useCallback(async (file: File) => {
    setLoading(true)
    setError(null)
    setResults(null)

    try {
      const formData = new FormData()
      formData.append('file', file)

      const response = await fetch('/api/threat-intel?service=virustotal-upload', {
        method: 'POST',
        body: formData
      })

      const data = await response.json()

      if (!response.ok) {
        throw new Error(data.error || 'Upload failed')
      }

      setResults(data)
    } catch (err: any) {
      setError(err.message || 'File upload failed')
      setResults(null)
    } finally {
      setLoading(false)
    }
  }, [])

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (file) {
      setSelectedFile(file)
      uploadFile(file)
    }
  }

  return (
    <div className="container mx-auto p-4 space-y-6">
      {/* Header */}
      <div className="text-center space-y-2">
        <div className="flex items-center justify-center gap-3">
          <Shield className="w-10 h-10 text-accent" />
          <h1 className="text-4xl font-bold bg-gradient-to-r from-accent to-red-400 bg-clip-text text-transparent">
            Threat Intelligence
          </h1>
        </div>
        <p className="text-muted-foreground max-w-2xl mx-auto">
          Real threat intelligence APIs for security research and CTF competitions
        </p>
      </div>

      {/* Main Tabs */}
      <div className="bg-card border border-border rounded-lg">
        <div className="flex flex-wrap items-center gap-2 border-b border-border p-2">
          <button
            onClick={() => setActiveTab('virustotal')}
            className={`flex items-center space-x-2 px-4 py-2 rounded-t-lg transition-colors ${
              activeTab === 'virustotal'
                ? 'text-accent border-b-2 border-accent bg-accent/5'
                : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'
            }`}
          >
            <Shield className="w-4 h-4" />
            <span>VirusTotal</span>
          </button>
          <button
            onClick={() => setActiveTab('hibp')}
            className={`flex items-center space-x-2 px-4 py-2 rounded-t-lg transition-colors ${
              activeTab === 'hibp'
                ? 'text-accent border-b-2 border-accent bg-accent/5'
                : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'
            }`}
          >
            <Lock className="w-4 h-4" />
            <span>HIBP</span>
          </button>
          <button
            onClick={() => setActiveTab('urlhaus')}
            className={`flex items-center space-x-2 px-4 py-2 rounded-t-lg transition-colors ${
              activeTab === 'urlhaus'
                ? 'text-accent border-b-2 border-accent bg-accent/5'
                : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'
            }`}
          >
            <Database className="w-4 h-4" />
            <span>URLhaus</span>
          </button>
          <button
            onClick={() => setActiveTab('phishstats')}
            className={`flex items-center space-x-2 px-4 py-2 rounded-t-lg transition-colors ${
              activeTab === 'phishstats'
                ? 'text-accent border-b-2 border-accent bg-accent/5'
                : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'
            }`}
          >
            <Eye className="w-4 h-4" />
            <span>PhishStats</span>
          </button>
          <button
            onClick={() => setActiveTab('cloudflare')}
            className={`flex items-center space-x-2 px-4 py-2 rounded-t-lg transition-colors ${
              activeTab === 'cloudflare'
                ? 'text-accent border-b-2 border-accent bg-accent/5'
                : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'
            }`}
          >
            <Globe className="w-4 h-4" />
            <span>Cloudflare</span>
          </button>
          <button
            onClick={() => setActiveTab('abuseipdb')}
            disabled={!apiKeys.abuseipdb}
            className={`flex items-center space-x-2 px-4 py-2 rounded-t-lg transition-colors ${
              activeTab === 'abuseipdb'
                ? 'text-accent border-b-2 border-accent bg-accent/5'
                : !apiKeys.abuseipdb
                ? 'text-muted-foreground/50 cursor-not-allowed'
                : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'
            }`}
            title={!apiKeys.abuseipdb ? 'API key required - not configured' : ''}
          >
            <AlertCircle className="w-4 h-4" />
            <span>AbuseIPDB</span>
            {!apiKeys.abuseipdb && <Lock className="w-3 h-3" />}
          </button>
          <button
            onClick={() => setActiveTab('greynoise')}
            className={`flex items-center space-x-2 px-4 py-2 rounded-t-lg transition-colors ${
              activeTab === 'greynoise'
                ? 'text-accent border-b-2 border-accent bg-accent/5'
                : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'
            }`}
          >
            <Activity className="w-4 h-4" />
            <span>GreyNoise</span>
          </button>
          <button
            onClick={() => setActiveTab('alienvault')}
            className={`flex items-center space-x-2 px-4 py-2 rounded-t-lg transition-colors ${
              activeTab === 'alienvault'
                ? 'text-accent border-b-2 border-accent bg-accent/5'
                : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'
            }`}
            title={!apiKeys.alienvault ? 'Works without API key (limited rate)' : ''}
          >
            <Shield className="w-4 h-4" />
            <span>AlienVault</span>
          </button>
        </div>

        <div className="p-6 space-y-4">
          <Card className="p-6">
            <div className="space-y-4">
              <div className="flex items-center gap-2 mb-4">
                {activeTab === 'virustotal' && <Shield className="w-5 h-5 text-accent" />}
                {activeTab === 'hibp' && <Lock className="w-5 h-5 text-accent" />}
                {activeTab === 'urlhaus' && <Database className="w-5 h-5 text-accent" />}
                {activeTab === 'phishstats' && <Eye className="w-5 h-5 text-accent" />}
                {activeTab === 'cloudflare' && <Globe className="w-5 h-5 text-accent" />}
                {activeTab === 'abuseipdb' && <AlertCircle className="w-5 h-5 text-accent" />}
                {activeTab === 'greynoise' && <Activity className="w-5 h-5 text-accent" />}
                {activeTab === 'alienvault' && <Shield className="w-5 h-5 text-accent" />}
                <h2 className="text-2xl font-bold">
                  {activeTab === 'virustotal' && 'VirusTotal'}
                  {activeTab === 'hibp' && 'Have I Been Pwned'}
                  {activeTab === 'urlhaus' && 'URLhaus Malware Database'}
                  {activeTab === 'phishstats' && 'PhishStats'}
                  {activeTab === 'cloudflare' && 'Cloudflare Trace'}
                  {activeTab === 'abuseipdb' && 'AbuseIPDB'}
                  {activeTab === 'greynoise' && 'GreyNoise'}
                  {activeTab === 'alienvault' && 'AlienVault OTX'}
                </h2>
              </div>

              {activeTab !== 'cloudflare' && (
                <>
                  <div className="flex gap-2">
                    <Input
                      placeholder={
                        activeTab === 'virustotal' ? 'Enter domain, IP, or file hash' :
                        activeTab === 'hibp' ? 'Enter email address' :
                        activeTab === 'urlhaus' ? 'Enter URL or domain' :
                        activeTab === 'phishstats' ? 'Enter domain or URL' :
                        activeTab === 'abuseipdb' ? 'Enter IP address' :
                        activeTab === 'greynoise' ? 'Enter IP address' :
                        activeTab === 'alienvault' ? 'Enter IP, domain, or hash' :
                        'Enter query'
                      }
                      value={input}
                      onChange={(e) => setInput(e.target.value)}
                      onKeyDown={(e) => e.key === 'Enter' && performLookup(activeTab, input)}
                      className="flex-1"
                    />
                    <Button onClick={() => performLookup(activeTab, input)} disabled={loading}>
                      {loading ? (
                        <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                      ) : (
                        <Search className="w-4 h-4 mr-2" />
                      )}
                      Search
                    </Button>
                  </div>

                  {activeTab === 'virustotal' && (
                    <div className="flex items-center gap-2">
                      <div className="text-sm text-muted-foreground">or</div>
                      <input
                        ref={fileInputRef}
                        type="file"
                        onChange={handleFileSelect}
                        className="hidden"
                        accept="*/*"
                      />
                      <Button
                        variant="outline"
                        onClick={() => fileInputRef.current?.click()}
                        disabled={loading}
                        className="w-full"
                      >
                        <Upload className="w-4 h-4 mr-2" />
                        {selectedFile ? `Upload: ${selectedFile.name}` : 'Upload File to Scan'}
                      </Button>
                    </div>
                  )}
                </>
              )}

              {activeTab === 'cloudflare' && (
                <div className="flex gap-2">
                  <Button onClick={() => performLookup(activeTab, '')} disabled={loading} className="w-full">
                    {loading ? (
                      <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                    ) : (
                      <Search className="w-4 h-4 mr-2" />
                    )}
                    Get My Info
                  </Button>
                </div>
              )}

              <div className="text-xs text-muted-foreground">
                {activeTab === 'virustotal' && 'Scan files, URLs, domains, and IPs for malware'}
                {activeTab === 'hibp' && 'Check if email addresses have been in data breaches'}
                {activeTab === 'urlhaus' && 'Check URLs against malware database'}
                {activeTab === 'phishstats' && 'Search phishing URL database'}
                {activeTab === 'cloudflare' && 'Get your IP info via Cloudflare'}
                {activeTab === 'abuseipdb' && 'Check IP reputation and abuse reports'}
                {activeTab === 'greynoise' && 'Identify internet scanners vs targeted attacks'}
                {activeTab === 'alienvault' && 'Threat intelligence from AlienVault OTX'}
              </div>

              {error && (
                <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3 flex items-center gap-2">
                  <AlertCircle className="w-4 h-4 text-red-500" />
                  <span className="text-sm text-red-500">{error}</span>
                </div>
              )}

              {results && (
                <div className="space-y-4 mt-6">
                  <div className="flex items-center justify-between">
                    <div className="text-sm text-muted-foreground">
                      Results from {activeTab}
                    </div>
                    <Button variant="outline" size="sm" onClick={() => exportData(results, `${activeTab}-results.json`)}>
                      <Download className="w-4 h-4 mr-2" />
                      Export
                    </Button>
                  </div>

                  <Card className="p-4">
                    <pre className="text-xs overflow-auto max-h-96 whitespace-pre-wrap break-words">
                      {JSON.stringify(results, null, 2)}
                    </pre>
                  </Card>
                </div>
              )}
            </div>
          </Card>
        </div>
      </div>
    </div>
  )
}
