import { useState, useCallback, useEffect } from 'react'
import {
  Shield,
  Search,
  RefreshCw,
  AlertCircle,
  Download,
  Eye,
  Lock,
  Globe,
  Activity
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card } from '../components/ui/card'

type TabType = 'virustotal' | 'hibp' | 'phishstats' | 'cloudflare' | 'abuseipdb' | 'greynoise' | 'alienvault'

// Check which APIs have keys configured
const checkApiKeys = async () => {
  try {
    const response = await fetch('/api/threat-intel?service=check-keys')
    if (response.ok) {
      return await response.json()
    }
  } catch (err) {
    // Failed to check API keys
  }
  return { virustotal: true, hibp: true, abuseipdb: false, alienvault: false }
}

export default function ThreatIntel() {
  const [activeTab, setActiveTab] = useState<TabType>('virustotal')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Per-tab results storage
  const [tabResults, setTabResults] = useState<Record<TabType, any>>({
    virustotal: null,
    hibp: null,
    phishstats: null,
    cloudflare: null,
    abuseipdb: null,
    greynoise: null,
    alienvault: null
  })

  const [input, setInput] = useState('')
  const [apiKeys, setApiKeys] = useState({ virustotal: true, hibp: true, abuseipdb: false, alienvault: false })

  // Get results for the current tab
  const results = tabResults[activeTab]

  useEffect(() => {
    checkApiKeys().then(keys => setApiKeys(keys))
  }, [])

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
    if (tab !== 'cloudflare' && !query.trim()) {
      setError('Please enter a query')
      return
    }

    setLoading(true)
    setError(null)

    try {
      let url = ''

      switch (tab) {
        case 'virustotal':
          url = `/api/threat-intel?service=virustotal&type=domain&query=${encodeURIComponent(query)}`
          break
        case 'hibp':
          url = `/api/threat-intel?service=hibp&type=breach&query=${encodeURIComponent(query)}`
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

      // Store results for this specific tab
      setTabResults(prev => ({ ...prev, [tab]: data }))
    } catch (err: any) {
      setError(err.message || 'Lookup failed')
      setTabResults(prev => ({ ...prev, [tab]: null }))
    } finally {
      setLoading(false)
    }
  }, [])

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
                {activeTab === 'phishstats' && <Eye className="w-5 h-5 text-accent" />}
                {activeTab === 'cloudflare' && <Globe className="w-5 h-5 text-accent" />}
                {activeTab === 'abuseipdb' && <AlertCircle className="w-5 h-5 text-accent" />}
                {activeTab === 'greynoise' && <Activity className="w-5 h-5 text-accent" />}
                {activeTab === 'alienvault' && <Shield className="w-5 h-5 text-accent" />}
                <h2 className="text-2xl font-bold">
                  {activeTab === 'virustotal' && 'VirusTotal'}
                  {activeTab === 'hibp' && 'Have I Been Pwned'}
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
                        activeTab === 'phishstats' ? 'Enter domain or URL' :
                        activeTab === 'abuseipdb' ? 'Enter IP address' :
                        activeTab === 'greynoise' ? 'Enter IP address' :
                        activeTab === 'alienvault' ? 'Enter IP address' :
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

                  {/* HIBP Results Display */}
                  {activeTab === 'hibp' && results.found && results.data && (
                    <div className="space-y-3">
                      {Array.isArray(results.data) ? results.data.map((breach: any, idx: number) => (
                        <Card key={idx} className="p-4">
                          <div className="space-y-3">
                            <div className="flex items-start justify-between">
                              <div>
                                <h3 className="text-lg font-bold text-accent">{breach.Name || breach.Title}</h3>
                                {breach.Domain && (
                                  <div className="text-sm text-muted-foreground">{breach.Domain}</div>
                                )}
                              </div>
                              {breach.IsVerified !== undefined && !breach.IsVerified && (
                                <span className="px-2 py-1 rounded text-xs bg-amber-500/20 text-amber-400 font-semibold">
                                  Unverified
                                </span>
                              )}
                            </div>

                            <div className="text-sm">
                              {breach.Description && (
                                <div className="mb-3" dangerouslySetInnerHTML={{ __html: breach.Description }} />
                              )}
                            </div>

                            <div className="grid grid-cols-2 md:grid-cols-3 gap-3 text-sm">
                              {breach.BreachDate && (
                                <div>
                                  <span className="font-semibold">Breach Date:</span> {breach.BreachDate}
                                </div>
                              )}
                              {breach.AddedDate && (
                                <div>
                                  <span className="font-semibold">Added:</span> {new Date(breach.AddedDate).toLocaleDateString()}
                                </div>
                              )}
                              {breach.ModifiedDate && (
                                <div>
                                  <span className="font-semibold">Modified:</span> {new Date(breach.ModifiedDate).toLocaleDateString()}
                                </div>
                              )}
                              {breach.PwnCount !== undefined && (
                                <div>
                                  <span className="font-semibold">Accounts:</span> {breach.PwnCount.toLocaleString()}
                                </div>
                              )}
                              {breach.Source && breach.Source !== breach.Title && (
                                <div className="col-span-2">
                                  <span className="font-semibold">Source:</span> {breach.Source}
                                </div>
                              )}
                            </div>

                            {breach.DataClasses && breach.DataClasses.length > 0 && (
                              <div>
                                <div className="font-semibold text-sm mb-2">Compromised Data:</div>
                                <div className="flex flex-wrap gap-1">
                                  {breach.DataClasses.map((dc: string, dcIdx: number) => (
                                    <span
                                      key={dcIdx}
                                      className="px-2 py-1 rounded text-xs bg-red-500/20 text-red-400 font-semibold"
                                    >
                                      {dc}
                                    </span>
                                  ))}
                                </div>
                              </div>
                            )}

                            <div className="flex items-center gap-4 text-xs text-muted-foreground">
                              {breach.IsFabricated && <span>Fabricated</span>}
                              {breach.IsSensitive && <span>Sensitive</span>}
                              {breach.IsRetired && <span>Retired</span>}
                              {breach.IsSpamList && <span>Spam List</span>}
                            </div>

                            {breach.LogoPath && (
                              <div className="flex items-center gap-2 mt-2 border-t border-border/50 pt-3">
                                <span className="text-xs text-muted-foreground">Breach Logo:</span>
                                <img
                                  src={breach.LogoPath.startsWith('http') ? breach.LogoPath : `https://haveibeenpwned.com${breach.LogoPath}`}
                                  alt={breach.Name}
                                  className="h-12 max-w-[200px] object-contain bg-white/10 rounded px-3 py-2"
                                  loading="lazy"
                                  onError={(e) => {
                                    const target = e.currentTarget as HTMLImageElement
                                    target.style.display = 'none'
                                    const parent = target.parentElement
                                    if (parent) {
                                      const fallback = document.createElement('span')
                                      fallback.className = 'text-xs text-muted-foreground italic'
                                      fallback.textContent = '(logo unavailable)'
                                      parent.appendChild(fallback)
                                    }
                                  }}
                                />
                              </div>
                            )}
                          </div>
                        </Card>
                      )) : results.type === 'paste' && results.data ? (
                        // Pastes display
                        <Card className="p-4">
                          <h3 className="font-bold mb-3">Pastes Found</h3>
                          <div className="space-y-2">
                            {results.data.map((paste: any, idx: number) => (
                              <div key={idx} className="border-b border-border/50 pb-2">
                                <div className="grid grid-cols-2 gap-2 text-sm">
                                  {paste.Source && <div><span className="font-semibold">Source:</span> {paste.Source}</div>}
                                  {paste.Id && <div><span className="font-semibold">ID:</span> {paste.Id}</div>}
                                  {paste.Title && <div className="col-span-2"><span className="font-semibold">Title:</span> {paste.Title}</div>}
                                  {paste.Date && <div><span className="font-semibold">Date:</span> {new Date(paste.Date).toLocaleString()}</div>}
                                  {paste.EmailCount !== undefined && <div><span className="font-semibold">Emails:</span> {paste.EmailCount}</div>}
                                </div>
                              </div>
                            ))}
                          </div>
                        </Card>
                      ) : null}
                    </div>
                  )}

                  {/* No results for HIBP */}
                  {activeTab === 'hibp' && results.found === false && (
                    <Card className="p-4">
                      <div className="text-center text-muted-foreground py-4">
                        <AlertCircle className="w-12 h-12 mx-auto mb-2 opacity-50" />
                        <p>{results.message || 'No breaches found'}</p>
                        <p className="text-xs mt-2">This email address has not been found in any known data breaches.</p>
                      </div>
                    </Card>
                  )}

                  {/* Default JSON display for other services */}
                  {activeTab !== 'hibp' && (
                    <Card className="p-4">
                      <pre className="text-xs overflow-auto max-h-96 whitespace-pre-wrap break-words">
                        {JSON.stringify(results, null, 2)}
                      </pre>
                    </Card>
                  )}
                </div>
              )}
            </div>
          </Card>
        </div>
      </div>
    </div>
  )
}
