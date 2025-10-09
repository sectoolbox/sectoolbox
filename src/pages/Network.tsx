import React, { useState, useCallback } from 'react'
import {
  Network as NetworkIcon,
  Globe,
  Server,
  Search,
  Copy,
  Download,
  RefreshCw,
  CheckCircle,
  XCircle,
  Info,
  Layers,
  MapPin,
  Shield,
  ExternalLink,
  AlertCircle
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card } from '../components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs'

type TabType = 'ip' | 'subnet' | 'dns' | 'whois' | 'geo' | 'headers'

interface SubnetInfo {
  network: string
  broadcast: string
  firstHost: string
  lastHost: string
  totalHosts: number
  usableHosts: number
  wildcardMask: string
  binarySubnet: string
  ipClass: string
  privateAddress: boolean
  subnetMask: string
}

interface IPInfo {
  ip: string
  version: number
  isPrivate: boolean
  isLoopback: boolean
  isMulticast: boolean
  isBroadcast: boolean
  binary: string
  decimal: string
  hex: string
  reverseDNS?: string
}

interface DNSRecord {
  name: string
  type: number
  TTL: number
  data: string
}

interface WhoisInfo {
  ip?: string
  domain?: string
  country?: string
  org?: string
  isp?: string
  asn?: string
  [key: string]: any
}

interface GeoInfo {
  ip: string
  city?: string
  region?: string
  country?: string
  country_code?: string
  continent?: string
  latitude?: number
  longitude?: number
  timezone?: string
  isp?: string
  org?: string
  as?: string
  asn?: string
}

interface HeaderInfo {
  url: string
  status: number
  statusText: string
  headers: { [key: string]: string }
  redirects?: string[]
  timings?: {
    total: number
  }
}

export default function Network() {
  const [activeTab, setActiveTab] = useState<TabType>('ip')
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // IP Analysis
  const [ipInput, setIpInput] = useState('')
  const [ipInfo, setIpInfo] = useState<IPInfo | null>(null)

  // Subnet Calculator
  const [subnetInput, setSubnetInput] = useState('')
  const [subnetInfo, setSubnetInfo] = useState<SubnetInfo | null>(null)

  // DNS Lookup
  const [dnsInput, setDnsInput] = useState('')
  const [dnsRecords, setDnsRecords] = useState<DNSRecord[]>([])
  const [dnsType, setDnsType] = useState<'A' | 'AAAA' | 'MX' | 'TXT' | 'NS' | 'CNAME'>('A')

  // WHOIS Lookup
  const [whoisInput, setWhoisInput] = useState('')
  const [whoisInfo, setWhoisInfo] = useState<WhoisInfo | null>(null)

  // Geolocation
  const [geoInput, setGeoInput] = useState('')
  const [geoInfo, setGeoInfo] = useState<GeoInfo | null>(null)

  // Headers
  const [headerInput, setHeaderInput] = useState('')
  const [headerInfo, setHeaderInfo] = useState<HeaderInfo | null>(null)

  // IP Address Analysis (Pure JavaScript - No API needed)
  const analyzeIP = useCallback((ip: string) => {
    const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/
    const match = ip.match(ipv4Regex)

    if (!match) {
      setError('Invalid IPv4 address format')
      setIpInfo(null)
      return
    }

    const octets = match.slice(1, 5).map(Number)

    if (octets.some(o => o > 255)) {
      setError('Invalid IPv4 address - octets must be 0-255')
      setIpInfo(null)
      return
    }

    const binary = octets.map(o => o.toString(2).padStart(8, '0')).join('.')
    const decimal = octets.reduce((acc, o, i) => acc + o * Math.pow(256, 3 - i), 0).toString()
    const hex = '0x' + octets.map(o => o.toString(16).padStart(2, '0')).join('')

    const isPrivate = (
      octets[0] === 10 ||
      (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
      (octets[0] === 192 && octets[1] === 168)
    )

    const isLoopback = octets[0] === 127
    const isMulticast = octets[0] >= 224 && octets[0] <= 239
    const isBroadcast = octets.every(o => o === 255)

    setIpInfo({
      ip,
      version: 4,
      isPrivate,
      isLoopback,
      isMulticast,
      isBroadcast,
      binary,
      decimal,
      hex
    })
    setError(null)
  }, [])

  // Subnet Calculator (Pure JavaScript - No API needed)
  const calculateSubnet = useCallback((cidr: string) => {
    const parts = cidr.split('/')
    if (parts.length !== 2) {
      setError('Invalid CIDR format. Use IP/prefix (e.g., 192.168.1.0/24)')
      return
    }

    const ip = parts[0]
    const prefix = parseInt(parts[1])

    if (prefix < 0 || prefix > 32) {
      setError('Invalid prefix length. Must be 0-32')
      return
    }

    const ipParts = ip.split('.').map(Number)
    if (ipParts.length !== 4 || ipParts.some(p => p > 255)) {
      setError('Invalid IP address in CIDR notation')
      return
    }

    // Calculate subnet mask
    const mask = []
    for (let i = 0; i < 4; i++) {
      const bits = Math.min(8, Math.max(0, prefix - i * 8))
      mask.push(256 - Math.pow(2, 8 - bits))
    }

    // Calculate network address
    const network = ipParts.map((p, i) => p & mask[i])

    // Calculate broadcast address
    const wildcard = mask.map(m => 255 - m)
    const broadcast = network.map((n, i) => n | wildcard[i])

    // Calculate first and last host
    const firstHost = [...network]
    firstHost[3] += 1
    const lastHost = [...broadcast]
    lastHost[3] -= 1

    const totalHosts = Math.pow(2, 32 - prefix)
    const usableHosts = totalHosts - 2

    // Determine IP class
    let ipClass = 'Unknown'
    if (ipParts[0] < 128) ipClass = 'A'
    else if (ipParts[0] < 192) ipClass = 'B'
    else if (ipParts[0] < 224) ipClass = 'C'
    else if (ipParts[0] < 240) ipClass = 'D (Multicast)'
    else ipClass = 'E (Reserved)'

    const privateAddress = (
      ipParts[0] === 10 ||
      (ipParts[0] === 172 && ipParts[1] >= 16 && ipParts[1] <= 31) ||
      (ipParts[0] === 192 && ipParts[1] === 168)
    )

    setSubnetInfo({
      network: network.join('.'),
      broadcast: broadcast.join('.'),
      firstHost: firstHost.join('.'),
      lastHost: lastHost.join('.'),
      totalHosts,
      usableHosts,
      wildcardMask: wildcard.join('.'),
      subnetMask: mask.join('.'),
      binarySubnet: mask.map(m => m.toString(2).padStart(8, '0')).join('.'),
      ipClass,
      privateAddress
    })
    setError(null)
  }, [])

  // DNS Lookup (Real DNS-over-HTTPS)
  const performDNSLookup = useCallback(async (domain: string, type: string) => {
    setLoading(true)
    setError(null)

    try {
      const typeMap: { [key: string]: number } = {
        'A': 1,
        'AAAA': 28,
        'MX': 15,
        'TXT': 16,
        'NS': 2,
        'CNAME': 5
      }

      const response = await fetch(
        `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${typeMap[type]}`,
        {
          headers: {
            'Accept': 'application/dns-json'
          }
        }
      )

      if (!response.ok) {
        throw new Error(`DNS lookup failed: ${response.statusText}`)
      }

      const data = await response.json()

      if (data.Answer && data.Answer.length > 0) {
        setDnsRecords(data.Answer)
      } else {
        setDnsRecords([])
        setError('No DNS records found')
      }
    } catch (err: any) {
      setError(err.message || 'DNS lookup failed')
      setDnsRecords([])
    } finally {
      setLoading(false)
    }
  }, [])

  // WHOIS Lookup (Real API)
  const performWhoisLookup = useCallback(async (target: string) => {
    setLoading(true)
    setError(null)

    try {
      const response = await fetch(`http://ip-api.com/json/${target}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,query`)

      if (!response.ok) {
        throw new Error(`WHOIS lookup failed: ${response.statusText}`)
      }

      const data = await response.json()

      if (data.status === 'fail') {
        throw new Error(data.message || 'WHOIS lookup failed')
      }

      setWhoisInfo(data)
    } catch (err: any) {
      setError(err.message || 'WHOIS lookup failed')
      setWhoisInfo(null)
    } finally {
      setLoading(false)
    }
  }, [])

  // IP Geolocation (Real API)
  const performGeolocation = useCallback(async (ip: string) => {
    setLoading(true)
    setError(null)

    try {
      const response = await fetch(`http://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,query`)

      if (!response.ok) {
        throw new Error(`Geolocation lookup failed: ${response.statusText}`)
      }

      const data = await response.json()

      if (data.status === 'fail') {
        throw new Error(data.message || 'Geolocation lookup failed')
      }

      setGeoInfo({
        ip: data.query,
        city: data.city,
        region: data.regionName,
        country: data.country,
        country_code: data.countryCode,
        latitude: data.lat,
        longitude: data.lon,
        timezone: data.timezone,
        isp: data.isp,
        org: data.org,
        as: data.as,
        asn: data.asname
      })
    } catch (err: any) {
      setError(err.message || 'Geolocation lookup failed')
      setGeoInfo(null)
    } finally {
      setLoading(false)
    }
  }, [])

  // HTTP Headers Inspection (Real CORS-permissive requests)
  const inspectHeaders = useCallback(async (url: string) => {
    setLoading(true)
    setError(null)

    try {
      if (!url.startsWith('http://') && !url.startsWith('https://')) {
        url = 'https://' + url
      }

      const startTime = Date.now()
      const response = await fetch(url, {
        method: 'HEAD',
        mode: 'cors'
      })
      const endTime = Date.now()

      const headers: { [key: string]: string } = {}
      response.headers.forEach((value, key) => {
        headers[key] = value
      })

      setHeaderInfo({
        url: response.url,
        status: response.status,
        statusText: response.statusText,
        headers,
        timings: {
          total: endTime - startTime
        }
      })
    } catch (err: any) {
      setError('Unable to fetch headers. The target may not allow CORS requests or may be unreachable.')
      setHeaderInfo(null)
    } finally {
      setLoading(false)
    }
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

  const getDNSTypeName = (type: number): string => {
    const types: { [key: number]: string } = {
      1: 'A',
      2: 'NS',
      5: 'CNAME',
      15: 'MX',
      16: 'TXT',
      28: 'AAAA'
    }
    return types[type] || `TYPE${type}`
  }

  return (
    <div className="container mx-auto p-4 space-y-6">
      {/* Header */}
      <div className="text-center space-y-2">
        <div className="flex items-center justify-center gap-3">
          <NetworkIcon className="w-10 h-10 text-accent" />
          <h1 className="text-4xl font-bold bg-gradient-to-r from-accent to-blue-400 bg-clip-text text-transparent">
            Network Analysis Tools
          </h1>
        </div>
        <p className="text-muted-foreground max-w-2xl mx-auto">
          Real networking tools for CTF competitions and security research
        </p>
      </div>

      {/* Main Tabs */}
      <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as TabType)} className="space-y-6">
        <TabsList className="grid grid-cols-3 lg:grid-cols-6 gap-2">
          <TabsTrigger value="ip" className="flex items-center gap-2">
            <Globe className="w-4 h-4" />
            IP Analysis
          </TabsTrigger>
          <TabsTrigger value="subnet" className="flex items-center gap-2">
            <Layers className="w-4 h-4" />
            Subnet Calc
          </TabsTrigger>
          <TabsTrigger value="dns" className="flex items-center gap-2">
            <Server className="w-4 h-4" />
            DNS Lookup
          </TabsTrigger>
          <TabsTrigger value="whois" className="flex items-center gap-2">
            <Search className="w-4 h-4" />
            WHOIS
          </TabsTrigger>
          <TabsTrigger value="geo" className="flex items-center gap-2">
            <MapPin className="w-4 h-4" />
            Geolocation
          </TabsTrigger>
          <TabsTrigger value="headers" className="flex items-center gap-2">
            <Shield className="w-4 h-4" />
            Headers
          </TabsTrigger>
        </TabsList>

        {/* IP Analysis Tab */}
        <TabsContent value="ip" className="space-y-4">
          <Card className="p-6">
            <div className="space-y-4">
              <div className="flex items-center gap-2 mb-4">
                <Globe className="w-5 h-5 text-accent" />
                <h2 className="text-2xl font-bold">IP Address Analysis</h2>
              </div>

              <div className="flex gap-2">
                <Input
                  placeholder="Enter IP address (e.g., 192.168.1.1)"
                  value={ipInput}
                  onChange={(e) => setIpInput(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && analyzeIP(ipInput)}
                  className="flex-1"
                />
                <Button onClick={() => analyzeIP(ipInput)}>
                  <Search className="w-4 h-4 mr-2" />
                  Analyze
                </Button>
              </div>

              {error && (
                <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3 flex items-center gap-2">
                  <AlertCircle className="w-4 h-4 text-red-500" />
                  <span className="text-sm text-red-500">{error}</span>
                </div>
              )}

              {ipInfo && (
                <div className="space-y-4 mt-6">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <Card className="p-4 space-y-2">
                      <h3 className="font-semibold flex items-center gap-2">
                        <Info className="w-4 h-4 text-accent" />
                        Basic Information
                      </h3>
                      <div className="space-y-1 text-sm">
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">IP Address:</span>
                          <span className="font-mono">{ipInfo.ip}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Version:</span>
                          <span>IPv{ipInfo.version}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Private:</span>
                          <span className="flex items-center gap-1">
                            {ipInfo.isPrivate ? <CheckCircle className="w-3 h-3 text-green-500" /> : <XCircle className="w-3 h-3 text-red-500" />}
                            {ipInfo.isPrivate ? 'Yes' : 'No'}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Loopback:</span>
                          <span className="flex items-center gap-1">
                            {ipInfo.isLoopback ? <CheckCircle className="w-3 h-3 text-green-500" /> : <XCircle className="w-3 h-3 text-red-500" />}
                            {ipInfo.isLoopback ? 'Yes' : 'No'}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Multicast:</span>
                          <span className="flex items-center gap-1">
                            {ipInfo.isMulticast ? <CheckCircle className="w-3 h-3 text-green-500" /> : <XCircle className="w-3 h-3 text-red-500" />}
                            {ipInfo.isMulticast ? 'Yes' : 'No'}
                          </span>
                        </div>
                      </div>
                    </Card>

                    <Card className="p-4 space-y-2">
                      <h3 className="font-semibold flex items-center gap-2">
                        <Info className="w-4 h-4 text-accent" />
                        Representations
                      </h3>
                      <div className="space-y-1 text-sm">
                        <div className="flex justify-between items-center">
                          <span className="text-muted-foreground">Binary:</span>
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-xs">{ipInfo.binary}</span>
                            <Button size="sm" variant="ghost" onClick={() => copyToClipboard(ipInfo.binary)}>
                              <Copy className="w-3 h-3" />
                            </Button>
                          </div>
                        </div>
                        <div className="flex justify-between items-center">
                          <span className="text-muted-foreground">Decimal:</span>
                          <div className="flex items-center gap-2">
                            <span className="font-mono">{ipInfo.decimal}</span>
                            <Button size="sm" variant="ghost" onClick={() => copyToClipboard(ipInfo.decimal)}>
                              <Copy className="w-3 h-3" />
                            </Button>
                          </div>
                        </div>
                        <div className="flex justify-between items-center">
                          <span className="text-muted-foreground">Hexadecimal:</span>
                          <div className="flex items-center gap-2">
                            <span className="font-mono">{ipInfo.hex}</span>
                            <Button size="sm" variant="ghost" onClick={() => copyToClipboard(ipInfo.hex)}>
                              <Copy className="w-3 h-3" />
                            </Button>
                          </div>
                        </div>
                      </div>
                    </Card>
                  </div>

                  <Button variant="outline" onClick={() => exportData(ipInfo, 'ip-analysis.json')}>
                    <Download className="w-4 h-4 mr-2" />
                    Export Results
                  </Button>
                </div>
              )}
            </div>
          </Card>
        </TabsContent>

        {/* Subnet Calculator Tab */}
        <TabsContent value="subnet" className="space-y-4">
          <Card className="p-6">
            <div className="space-y-4">
              <div className="flex items-center gap-2 mb-4">
                <Layers className="w-5 h-5 text-accent" />
                <h2 className="text-2xl font-bold">Subnet Calculator</h2>
              </div>

              <div className="flex gap-2">
                <Input
                  placeholder="Enter CIDR notation (e.g., 192.168.1.0/24)"
                  value={subnetInput}
                  onChange={(e) => setSubnetInput(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && calculateSubnet(subnetInput)}
                  className="flex-1"
                />
                <Button onClick={() => calculateSubnet(subnetInput)}>
                  <Search className="w-4 h-4 mr-2" />
                  Calculate
                </Button>
              </div>

              {error && (
                <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3 flex items-center gap-2">
                  <AlertCircle className="w-4 h-4 text-red-500" />
                  <span className="text-sm text-red-500">{error}</span>
                </div>
              )}

              {subnetInfo && (
                <div className="space-y-4 mt-6">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <Card className="p-4 space-y-2">
                      <h3 className="font-semibold flex items-center gap-2">
                        <NetworkIcon className="w-4 h-4 text-accent" />
                        Network Information
                      </h3>
                      <div className="space-y-1 text-sm">
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Network Address:</span>
                          <span className="font-mono">{subnetInfo.network}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Subnet Mask:</span>
                          <span className="font-mono">{subnetInfo.subnetMask}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Broadcast Address:</span>
                          <span className="font-mono">{subnetInfo.broadcast}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">First Host:</span>
                          <span className="font-mono">{subnetInfo.firstHost}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Last Host:</span>
                          <span className="font-mono">{subnetInfo.lastHost}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Wildcard Mask:</span>
                          <span className="font-mono">{subnetInfo.wildcardMask}</span>
                        </div>
                      </div>
                    </Card>

                    <Card className="p-4 space-y-2">
                      <h3 className="font-semibold flex items-center gap-2">
                        <Info className="w-4 h-4 text-accent" />
                        Host Information
                      </h3>
                      <div className="space-y-1 text-sm">
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Total Hosts:</span>
                          <span className="font-mono">{subnetInfo.totalHosts.toLocaleString()}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Usable Hosts:</span>
                          <span className="font-mono">{subnetInfo.usableHosts.toLocaleString()}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">IP Class:</span>
                          <span>{subnetInfo.ipClass}</span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Private Network:</span>
                          <span className="flex items-center gap-1">
                            {subnetInfo.privateAddress ? <CheckCircle className="w-3 h-3 text-green-500" /> : <XCircle className="w-3 h-3 text-red-500" />}
                            {subnetInfo.privateAddress ? 'Yes' : 'No'}
                          </span>
                        </div>
                        <div className="flex flex-col gap-1">
                          <span className="text-muted-foreground">Binary Subnet Mask:</span>
                          <span className="font-mono text-xs break-all">{subnetInfo.binarySubnet}</span>
                        </div>
                      </div>
                    </Card>
                  </div>

                  <Button variant="outline" onClick={() => exportData(subnetInfo, 'subnet-calc.json')}>
                    <Download className="w-4 h-4 mr-2" />
                    Export Results
                  </Button>
                </div>
              )}
            </div>
          </Card>
        </TabsContent>

        {/* DNS Lookup Tab */}
        <TabsContent value="dns" className="space-y-4">
          <Card className="p-6">
            <div className="space-y-4">
              <div className="flex items-center gap-2 mb-4">
                <Server className="w-5 h-5 text-accent" />
                <h2 className="text-2xl font-bold">DNS Lookup (Real DNS-over-HTTPS)</h2>
              </div>

              <div className="flex gap-2">
                <Input
                  placeholder="Enter domain name (e.g., example.com)"
                  value={dnsInput}
                  onChange={(e) => setDnsInput(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && performDNSLookup(dnsInput, dnsType)}
                  className="flex-1"
                />
                <select
                  value={dnsType}
                  onChange={(e) => setDnsType(e.target.value as any)}
                  className="px-3 py-2 bg-background border border-border rounded-md"
                >
                  <option value="A">A</option>
                  <option value="AAAA">AAAA</option>
                  <option value="MX">MX</option>
                  <option value="TXT">TXT</option>
                  <option value="NS">NS</option>
                  <option value="CNAME">CNAME</option>
                </select>
                <Button onClick={() => performDNSLookup(dnsInput, dnsType)} disabled={loading}>
                  {loading ? (
                    <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                  ) : (
                    <Search className="w-4 h-4 mr-2" />
                  )}
                  Lookup
                </Button>
              </div>

              <div className="text-xs text-muted-foreground">
                Using Cloudflare DNS-over-HTTPS for real DNS queries
              </div>

              {error && (
                <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3 flex items-center gap-2">
                  <AlertCircle className="w-4 h-4 text-red-500" />
                  <span className="text-sm text-red-500">{error}</span>
                </div>
              )}

              {dnsRecords.length > 0 && (
                <div className="space-y-4 mt-6">
                  <div className="flex items-center justify-between">
                    <div className="text-sm text-muted-foreground">
                      Found {dnsRecords.length} DNS record(s)
                    </div>
                    <Button variant="outline" size="sm" onClick={() => exportData(dnsRecords, 'dns-records.json')}>
                      <Download className="w-4 h-4 mr-2" />
                      Export
                    </Button>
                  </div>

                  <div className="space-y-2">
                    {dnsRecords.map((record, idx) => (
                      <Card key={idx} className="p-3">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-4 flex-1">
                            <span className="font-mono text-sm font-semibold text-accent min-w-[60px]">
                              {getDNSTypeName(record.type)}
                            </span>
                            <div className="flex-1">
                              <div className="font-mono text-sm">{record.data}</div>
                              <div className="text-xs text-muted-foreground">{record.name}</div>
                            </div>
                          </div>
                          <div className="flex items-center gap-2">
                            <span className="text-xs text-muted-foreground">
                              TTL: {record.TTL}s
                            </span>
                            <Button size="sm" variant="ghost" onClick={() => copyToClipboard(record.data)}>
                              <Copy className="w-3 h-3" />
                            </Button>
                          </div>
                        </div>
                      </Card>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </Card>
        </TabsContent>

        {/* WHOIS Tab */}
        <TabsContent value="whois" className="space-y-4">
          <Card className="p-6">
            <div className="space-y-4">
              <div className="flex items-center gap-2 mb-4">
                <Search className="w-5 h-5 text-accent" />
                <h2 className="text-2xl font-bold">WHOIS / IP Information</h2>
              </div>

              <div className="flex gap-2">
                <Input
                  placeholder="Enter IP or domain (e.g., 8.8.8.8 or google.com)"
                  value={whoisInput}
                  onChange={(e) => setWhoisInput(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && performWhoisLookup(whoisInput)}
                  className="flex-1"
                />
                <Button onClick={() => performWhoisLookup(whoisInput)} disabled={loading}>
                  {loading ? (
                    <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                  ) : (
                    <Search className="w-4 h-4 mr-2" />
                  )}
                  Lookup
                </Button>
              </div>

              <div className="text-xs text-muted-foreground">
                Using ip-api.com for real WHOIS data
              </div>

              {error && (
                <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3 flex items-center gap-2">
                  <AlertCircle className="w-4 h-4 text-red-500" />
                  <span className="text-sm text-red-500">{error}</span>
                </div>
              )}

              {whoisInfo && (
                <div className="space-y-4 mt-6">
                  <Card className="p-4 space-y-2">
                    <h3 className="font-semibold flex items-center gap-2">
                      <Info className="w-4 h-4 text-accent" />
                      WHOIS Information
                    </h3>
                    <div className="space-y-1 text-sm">
                      {whoisInfo.query && (
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">IP/Domain:</span>
                          <span className="font-mono">{whoisInfo.query}</span>
                        </div>
                      )}
                      {whoisInfo.country && (
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Country:</span>
                          <span>{whoisInfo.country} ({whoisInfo.countryCode})</span>
                        </div>
                      )}
                      {whoisInfo.regionName && (
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Region:</span>
                          <span>{whoisInfo.regionName}</span>
                        </div>
                      )}
                      {whoisInfo.city && (
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">City:</span>
                          <span>{whoisInfo.city}</span>
                        </div>
                      )}
                      {whoisInfo.isp && (
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">ISP:</span>
                          <span>{whoisInfo.isp}</span>
                        </div>
                      )}
                      {whoisInfo.org && (
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Organization:</span>
                          <span>{whoisInfo.org}</span>
                        </div>
                      )}
                      {whoisInfo.as && (
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">AS Number:</span>
                          <span className="font-mono">{whoisInfo.as}</span>
                        </div>
                      )}
                      {whoisInfo.asname && (
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">AS Name:</span>
                          <span>{whoisInfo.asname}</span>
                        </div>
                      )}
                    </div>
                  </Card>

                  <Button variant="outline" onClick={() => exportData(whoisInfo, 'whois-info.json')}>
                    <Download className="w-4 h-4 mr-2" />
                    Export Results
                  </Button>
                </div>
              )}
            </div>
          </Card>
        </TabsContent>

        {/* Geolocation Tab */}
        <TabsContent value="geo" className="space-y-4">
          <Card className="p-6">
            <div className="space-y-4">
              <div className="flex items-center gap-2 mb-4">
                <MapPin className="w-5 h-5 text-accent" />
                <h2 className="text-2xl font-bold">IP Geolocation</h2>
              </div>

              <div className="flex gap-2">
                <Input
                  placeholder="Enter IP address (e.g., 8.8.8.8)"
                  value={geoInput}
                  onChange={(e) => setGeoInput(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && performGeolocation(geoInput)}
                  className="flex-1"
                />
                <Button onClick={() => performGeolocation(geoInput)} disabled={loading}>
                  {loading ? (
                    <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                  ) : (
                    <Search className="w-4 h-4 mr-2" />
                  )}
                  Locate
                </Button>
              </div>

              <div className="text-xs text-muted-foreground">
                Using ip-api.com for real geolocation data
              </div>

              {error && (
                <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3 flex items-center gap-2">
                  <AlertCircle className="w-4 h-4 text-red-500" />
                  <span className="text-sm text-red-500">{error}</span>
                </div>
              )}

              {geoInfo && (
                <div className="space-y-4 mt-6">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <Card className="p-4 space-y-2">
                      <h3 className="font-semibold flex items-center gap-2">
                        <MapPin className="w-4 h-4 text-accent" />
                        Location Information
                      </h3>
                      <div className="space-y-1 text-sm">
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">IP Address:</span>
                          <span className="font-mono">{geoInfo.ip}</span>
                        </div>
                        {geoInfo.country && (
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Country:</span>
                            <span>{geoInfo.country} ({geoInfo.country_code})</span>
                          </div>
                        )}
                        {geoInfo.region && (
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Region:</span>
                            <span>{geoInfo.region}</span>
                          </div>
                        )}
                        {geoInfo.city && (
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">City:</span>
                            <span>{geoInfo.city}</span>
                          </div>
                        )}
                        {geoInfo.timezone && (
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Timezone:</span>
                            <span>{geoInfo.timezone}</span>
                          </div>
                        )}
                      </div>
                    </Card>

                    <Card className="p-4 space-y-2">
                      <h3 className="font-semibold flex items-center gap-2">
                        <Globe className="w-4 h-4 text-accent" />
                        Network Information
                      </h3>
                      <div className="space-y-1 text-sm">
                        {geoInfo.latitude && geoInfo.longitude && (
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Coordinates:</span>
                            <span className="font-mono text-xs">{geoInfo.latitude}, {geoInfo.longitude}</span>
                          </div>
                        )}
                        {geoInfo.isp && (
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">ISP:</span>
                            <span>{geoInfo.isp}</span>
                          </div>
                        )}
                        {geoInfo.org && (
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Organization:</span>
                            <span>{geoInfo.org}</span>
                          </div>
                        )}
                        {geoInfo.as && (
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">AS Number:</span>
                            <span className="font-mono">{geoInfo.as}</span>
                          </div>
                        )}
                        {geoInfo.latitude && geoInfo.longitude && (
                          <div className="pt-2">
                            <a
                              href={`https://www.google.com/maps?q=${geoInfo.latitude},${geoInfo.longitude}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-accent hover:underline text-sm flex items-center gap-1"
                            >
                              View on Google Maps
                              <ExternalLink className="w-3 h-3" />
                            </a>
                          </div>
                        )}
                      </div>
                    </Card>
                  </div>

                  <Button variant="outline" onClick={() => exportData(geoInfo, 'geolocation.json')}>
                    <Download className="w-4 h-4 mr-2" />
                    Export Results
                  </Button>
                </div>
              )}
            </div>
          </Card>
        </TabsContent>

        {/* Headers Tab */}
        <TabsContent value="headers" className="space-y-4">
          <Card className="p-6">
            <div className="space-y-4">
              <div className="flex items-center gap-2 mb-4">
                <Shield className="w-5 h-5 text-accent" />
                <h2 className="text-2xl font-bold">HTTP Headers Inspector</h2>
              </div>

              <div className="flex gap-2">
                <Input
                  placeholder="Enter URL (e.g., https://example.com)"
                  value={headerInput}
                  onChange={(e) => setHeaderInput(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && inspectHeaders(headerInput)}
                  className="flex-1"
                />
                <Button onClick={() => inspectHeaders(headerInput)} disabled={loading}>
                  {loading ? (
                    <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                  ) : (
                    <Search className="w-4 h-4 mr-2" />
                  )}
                  Inspect
                </Button>
              </div>

              <div className="text-xs text-muted-foreground">
                Note: Only works with CORS-enabled websites
              </div>

              {error && (
                <div className="bg-amber-500/10 border border-amber-500/20 rounded-lg p-3 flex items-start gap-2">
                  <AlertCircle className="w-4 h-4 text-amber-500 flex-shrink-0 mt-0.5" />
                  <span className="text-sm text-amber-500">{error}</span>
                </div>
              )}

              {headerInfo && (
                <div className="space-y-4 mt-6">
                  <Card className="p-4 space-y-2">
                    <h3 className="font-semibold flex items-center gap-2">
                      <Info className="w-4 h-4 text-accent" />
                      Response Information
                    </h3>
                    <div className="space-y-1 text-sm">
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">URL:</span>
                        <span className="font-mono text-xs truncate max-w-md">{headerInfo.url}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Status:</span>
                        <span className={`font-semibold ${
                          headerInfo.status >= 200 && headerInfo.status < 300 ? 'text-green-500' :
                          headerInfo.status >= 300 && headerInfo.status < 400 ? 'text-blue-500' :
                          'text-red-500'
                        }`}>
                          {headerInfo.status} {headerInfo.statusText}
                        </span>
                      </div>
                      {headerInfo.timings && (
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Response Time:</span>
                          <span>{headerInfo.timings.total}ms</span>
                        </div>
                      )}
                    </div>
                  </Card>

                  <Card className="p-4 space-y-2">
                    <h3 className="font-semibold flex items-center gap-2">
                      <Shield className="w-4 h-4 text-accent" />
                      HTTP Headers
                    </h3>
                    <div className="space-y-1 text-sm max-h-96 overflow-y-auto">
                      {Object.entries(headerInfo.headers).map(([key, value]) => (
                        <div key={key} className="flex justify-between border-b border-border/50 py-1">
                          <span className="text-muted-foreground font-mono text-xs">{key}:</span>
                          <div className="flex items-center gap-2">
                            <span className="font-mono text-xs max-w-md truncate">{value}</span>
                            <Button size="sm" variant="ghost" onClick={() => copyToClipboard(value)}>
                              <Copy className="w-3 h-3" />
                            </Button>
                          </div>
                        </div>
                      ))}
                    </div>
                  </Card>

                  <Button variant="outline" onClick={() => exportData(headerInfo, 'http-headers.json')}>
                    <Download className="w-4 h-4 mr-2" />
                    Export Results
                  </Button>
                </div>
              )}
            </div>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
