import React, { useState, useCallback, useMemo, useEffect } from 'react'
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
  AlertCircle,
  Eye,
  Database,
  History,
  Lock,
  FileText
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card } from '../components/ui/card'

type TabType = 'subnet' | 'dns' | 'headers' | 'shodan' | 'archive' | 'ipinfo' | 'passivedns' | 'certs'

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

interface ShodanInfo {
  ip: string
  ports: number[]
  vulns: string[]
  tags: string[]
  cpes: string[]
  hostnames: string[]
}

interface ArchiveURL {
  url: string
  timestamp?: string
}

interface IPInfoData {
  ip: string
  hostname?: string
  city?: string
  region?: string
  country?: string
  loc?: string
  org?: string
  postal?: string
  timezone?: string
  asn?: {
    asn: string
    name: string
    domain: string
    route: string
    type: string
  }
  company?: {
    name: string
    domain: string
    type: string
  }
  privacy?: {
    vpn: boolean
    proxy: boolean
    tor: boolean
    relay: boolean
    hosting: boolean
  }
  abuse?: {
    address: string
    country: string
    email: string
    name: string
    network: string
    phone: string
  }
}

interface PassiveDNSRecord {
  rrname: string
  rrtype: string
  rdata: string
  firstSeenTimestamp: number
  lastSeenTimestamp: number
  count: number
}

interface CertRecord {
  issuer_ca_id: number
  issuer_name: string
  name_value: string
  id: number
  entry_timestamp: string
  not_before: string
  not_after: string
}

export default function Network() {
  const [activeTab, setActiveTab] = useState<TabType>('subnet')
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

  // Geolocation
  const [geoInput, setGeoInput] = useState('')
  const [geoInfo, setGeoInfo] = useState<GeoInfo | null>(null)

  // Headers
  const [headerInput, setHeaderInput] = useState('')
  const [headerInfo, setHeaderInfo] = useState<HeaderInfo | null>(null)

  // Shodan InternetDB
  const [shodanInput, setShodanInput] = useState('')
  const [shodanInfo, setShodanInfo] = useState<ShodanInfo | null>(null)

  // Archive.org
  const [archiveInput, setArchiveInput] = useState('')
  const [archiveUrls, setArchiveUrls] = useState<ArchiveURL[]>([])
  const [archiveFilter, setArchiveFilter] = useState('')
  const [debouncedArchiveFilter, setDebouncedArchiveFilter] = useState('')
  const [archiveCurrentPage, setArchiveCurrentPage] = useState(1)
  const archiveResultsPerPage = 1000

  // Debounce archiveFilter
  useEffect(() => {
    const handler = setTimeout(() => {
      setDebouncedArchiveFilter(archiveFilter)
      setArchiveCurrentPage(1) // Reset to page 1 when filter changes
    }, 500) // 500ms delay

    return () => clearTimeout(handler)
  }, [archiveFilter])

  // Filter and paginate Archive URLs
  const filteredArchiveUrls = useMemo(() => {
    if (!debouncedArchiveFilter.trim()) return archiveUrls
    return archiveUrls.filter(item =>
      item.url.toLowerCase().includes(debouncedArchiveFilter.toLowerCase())
    )
  }, [archiveUrls, debouncedArchiveFilter])

  const paginatedArchiveUrls = useMemo(() => {
    const start = (archiveCurrentPage - 1) * archiveResultsPerPage
    const end = start + archiveResultsPerPage
    return filteredArchiveUrls.slice(start, end)
  }, [filteredArchiveUrls, archiveCurrentPage, archiveResultsPerPage])

  const totalArchivePages = Math.ceil(filteredArchiveUrls.length / archiveResultsPerPage)

  // Extract unique paths from Archive URLs
  const uniqueArchivePaths = useMemo(() => {
    const paths = new Set<string>()
    filteredArchiveUrls.forEach(item => {
      try {
        const url = new URL(item.url.startsWith('http') ? item.url : `http://${item.url}`)
        if (url.pathname && url.pathname !== '/') {
          paths.add(url.pathname)
        }
      } catch {
        // Skip invalid URLs
      }
    })
    return Array.from(paths).sort()
  }, [filteredArchiveUrls])

  // Extract potential injection points (URLs with parameters)
  const injectionPoints = useMemo(() => {
    const points: string[] = []
    filteredArchiveUrls.forEach(item => {
      try {
        const url = new URL(item.url.startsWith('http') ? item.url : `http://${item.url}`)
        if (url.search && url.search.length > 1) {
          // Check if URL has common vulnerable parameters
          const params = url.searchParams
          const vulnParams = ['id', 'page', 'file', 'url', 'path', 'redirect', 'goto', 'return', 'next', 'callback', 'data', 'load', 'include', 'dir', 'doc', 'document', 'folder', 'root', 'pg', 'p', 'cat', 'action', 'view', 'content', 'download', 'template', 'layout', 'preview', 'query', 'q']

          for (const key of params.keys()) {
            if (vulnParams.some(vp => key.toLowerCase().includes(vp))) {
              points.push(item.url)
              break
            }
          }
        }
      } catch {
        // Skip invalid URLs
      }
    })
    return [...new Set(points)].sort()
  }, [filteredArchiveUrls])

  // IPInfo.io
  const [ipinfoInput, setIpinfoInput] = useState('')
  const [ipinfoData, setIpinfoData] = useState<IPInfoData | null>(null)

  // PassiveDNS
  const [passiveDnsInput, setPassiveDnsInput] = useState('')
  const [passiveDnsRecords, setPassiveDnsRecords] = useState<PassiveDNSRecord[]>([])

  // Certificate Transparency
  const [certInput, setCertInput] = useState('')
  const [certRecords, setCertRecords] = useState<CertRecord[]>([])

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

  // DNS Lookup (Real DNS-over-HTTPS) - Fetch all record types
  const performDNSLookup = useCallback(async (domain: string) => {
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

      // Fetch all DNS record types in parallel
      const promises = Object.entries(typeMap).map(async ([typeName, typeNum]) => {
        try {
          const response = await fetch(
            `https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(domain)}&type=${typeNum}`,
            {
              headers: {
                'Accept': 'application/dns-json'
              }
            }
          )

          if (!response.ok) {
            return []
          }

          const data = await response.json()
          return data.Answer || []
        } catch {
          return []
        }
      })

      const results = await Promise.all(promises)
      const allRecords = results.flat()

      if (allRecords.length > 0) {
        setDnsRecords(allRecords)
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

  // IP Geolocation (Real API)
  const performGeolocation = useCallback(async (ip: string) => {
    setLoading(true)
    setError(null)

    try {
      const response = await fetch(`https://ip-api.com/json/${ip}?fields=status,message,country,countryCode,region,regionName,city,zip,lat,lon,timezone,isp,org,as,asname,query`)

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

  // HTTP Headers Inspection (via Vercel serverless function)
  const inspectHeaders = useCallback(async (url: string) => {
    setLoading(true)
    setError(null)

    try {
      // Use Vercel serverless function to bypass CORS
      const response = await fetch(`/api/headers?url=${encodeURIComponent(url)}`)

      if (!response.ok) {
        throw new Error(`Headers inspection failed: ${response.statusText}`)
      }

      const data = await response.json()

      setHeaderInfo(data)
    } catch (err: any) {
      setError(err.message || 'Headers inspection failed')
      setHeaderInfo(null)
    } finally {
      setLoading(false)
    }
  }, [])

  // Shodan InternetDB Lookup
  const performShodanLookup = useCallback(async (ip: string) => {
    setLoading(true)
    setError(null)

    try {
      const response = await fetch(`https://internetdb.shodan.io/${ip}`)

      if (!response.ok) {
        if (response.status === 404) {
          throw new Error('No information available for this IP')
        }
        throw new Error(`Shodan lookup failed: ${response.statusText}`)
      }

      const data = await response.json()

      setShodanInfo({
        ip: ip,
        ports: data.ports || [],
        vulns: data.vulns || [],
        tags: data.tags || [],
        cpes: data.cpes || [],
        hostnames: data.hostnames || []
      })
    } catch (err: any) {
      setError(err.message || 'Shodan lookup failed')
      setShodanInfo(null)
    } finally {
      setLoading(false)
    }
  }, [])

  // Archive.org CDX Search (via Vercel serverless function to bypass CORS)
  const performArchiveSearch = useCallback(async (domain: string) => {
    setLoading(true)
    setError(null)
    setArchiveUrls([]) // Clear previous results

    try {
      // Use Vercel serverless function to bypass CORS
      const response = await fetch(`/api/archive?url=${encodeURIComponent(domain)}`)

      if (!response.ok) {
        throw new Error(`Archive search failed: ${response.statusText}`)
      }

      const data = await response.json()

      if (data.length <= 1) {
        setArchiveUrls([])
        setError('No archived URLs found')
        return
      }

      // Skip the first row (header)
      const urls = data.slice(1).map((row: string[]) => ({
        url: row[0],
        timestamp: row[1]
      }))

      setArchiveUrls(urls)
    } catch (err: any) {
      setError(err.message || 'Archive search failed')
      setArchiveUrls([])
    } finally {
      setLoading(false)
    }
  }, [])

  // IPInfo.io Lookup
  const performIPInfoLookup = useCallback(async (ip: string) => {
    setLoading(true)
    setError(null)

    try {
      const response = await fetch(`https://ipinfo.io/${ip}/json`)

      if (!response.ok) {
        throw new Error(`IPInfo lookup failed: ${response.statusText}`)
      }

      const data = await response.json()

      if (data.error) {
        throw new Error(data.error.message || 'IPInfo lookup failed')
      }

      setIpinfoData(data)
    } catch (err: any) {
      setError(err.message || 'IPInfo lookup failed')
      setIpinfoData(null)
    } finally {
      setLoading(false)
    }
  }, [])

  // PassiveDNS Lookup (via Vercel serverless function)
  const performPassiveDNSLookup = useCallback(async (domain: string) => {
    setLoading(true)
    setError(null)

    try {
      // Use Vercel serverless function to bypass CORS
      const response = await fetch(`/api/passivedns?domain=${encodeURIComponent(domain)}`)

      if (!response.ok) {
        throw new Error(`PassiveDNS lookup failed: ${response.statusText}`)
      }

      const data = await response.json()

      if (data.data && data.data.length > 0) {
        setPassiveDnsRecords(data.data.slice(0, 100)) // Limit to 100 records
      } else {
        setPassiveDnsRecords([])
        setError('No historical DNS records found')
      }
    } catch (err: any) {
      setError(err.message || 'PassiveDNS lookup failed')
      setPassiveDnsRecords([])
    } finally {
      setLoading(false)
    }
  }, [])

  // Certificate Transparency Search (crt.sh)
  const performCertSearch = useCallback(async (domain: string) => {
    setLoading(true)
    setError(null)

    try {
      const response = await fetch(`https://crt.sh/?q=${encodeURIComponent(domain)}&output=json`)

      if (!response.ok) {
        throw new Error(`Certificate search failed: ${response.statusText}`)
      }

      const data = await response.json()

      if (data.length > 0) {
        setCertRecords(data.slice(0, 100)) // Limit to 100 records
      } else {
        setCertRecords([])
        setError('No certificates found')
      }
    } catch (err: any) {
      setError(err.message || 'Certificate search failed')
      setCertRecords([])
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
      <div className="bg-card border border-border rounded-lg">
        <div className="flex items-center gap-2 border-b border-border overflow-x-auto">
          <button
            onClick={() => setActiveTab('subnet')}
            className={`flex items-center space-x-2 px-4 py-2 rounded-t-lg transition-colors ${
              activeTab === 'subnet'
                ? 'text-accent border-b-2 border-accent bg-accent/5'
                : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'
            }`}
          >
            <Layers className="w-4 h-4" />
            <span>Subnet Calc</span>
          </button>
          <button
            onClick={() => setActiveTab('dns')}
            className={`flex items-center space-x-2 px-4 py-2 rounded-t-lg transition-colors ${
              activeTab === 'dns'
                ? 'text-accent border-b-2 border-accent bg-accent/5'
                : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'
            }`}
          >
            <Server className="w-4 h-4" />
            <span>DNS Lookup</span>
          </button>
          <button
            onClick={() => setActiveTab('headers')}
            className={`flex items-center space-x-2 px-4 py-2 rounded-t-lg transition-colors ${
              activeTab === 'headers'
                ? 'text-accent border-b-2 border-accent bg-accent/5'
                : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'
            }`}
          >
            <Shield className="w-4 h-4" />
            <span>Headers</span>
          </button>
          <button
            onClick={() => setActiveTab('shodan')}
            className={`flex items-center space-x-2 px-4 py-2 rounded-t-lg transition-colors ${
              activeTab === 'shodan'
                ? 'text-accent border-b-2 border-accent bg-accent/5'
                : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'
            }`}
          >
            <Eye className="w-4 h-4" />
            <span>Shodan</span>
          </button>
          <button
            onClick={() => setActiveTab('archive')}
            className={`flex items-center space-x-2 px-4 py-2 rounded-t-lg transition-colors ${
              activeTab === 'archive'
                ? 'text-accent border-b-2 border-accent bg-accent/5'
                : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'
            }`}
          >
            <History className="w-4 h-4" />
            <span>Archive</span>
          </button>
          <button
            onClick={() => setActiveTab('ipinfo')}
            className={`flex items-center space-x-2 px-4 py-2 rounded-t-lg transition-colors ${
              activeTab === 'ipinfo'
                ? 'text-accent border-b-2 border-accent bg-accent/5'
                : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'
            }`}
          >
            <Database className="w-4 h-4" />
            <span>IPInfo</span>
          </button>
          <button
            onClick={() => setActiveTab('passivedns')}
            className={`flex items-center space-x-2 px-4 py-2 rounded-t-lg transition-colors ${
              activeTab === 'passivedns'
                ? 'text-accent border-b-2 border-accent bg-accent/5'
                : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'
            }`}
          >
            <FileText className="w-4 h-4" />
            <span>PassiveDNS</span>
          </button>
          <button
            onClick={() => setActiveTab('certs')}
            className={`flex items-center space-x-2 px-4 py-2 rounded-t-lg transition-colors ${
              activeTab === 'certs'
                ? 'text-accent border-b-2 border-accent bg-accent/5'
                : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'
            }`}
          >
            <Lock className="w-4 h-4" />
            <span>Certificates</span>
          </button>
        </div>

        <div className="p-6 space-y-4">
        {/* Subnet Calculator Tab */}
        {activeTab === 'subnet' && (
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
        )}

        {/* DNS Lookup Tab */}
        {activeTab === 'dns' && (
          <Card className="p-6">
            <div className="space-y-4">
              <div className="flex items-center gap-2 mb-4">
                <Server className="w-5 h-5 text-accent" />
                <h2 className="text-2xl font-bold">DNS Lookup</h2>
              </div>

              <div className="flex gap-2">
                <Input
                  placeholder="Enter domain name (e.g., example.com)"
                  value={dnsInput}
                  onChange={(e) => setDnsInput(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && performDNSLookup(dnsInput)}
                  className="flex-1"
                />
                <Button onClick={() => performDNSLookup(dnsInput)} disabled={loading}>
                  {loading ? (
                    <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                  ) : (
                    <Search className="w-4 h-4 mr-2" />
                  )}
                  Lookup All
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
        )}

        {/* Headers Tab */}
        {activeTab === 'headers' && (
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
        )}

        {/* Shodan InternetDB Tab */}
        {activeTab === 'shodan' && (
          <Card className="p-6">
            <div className="space-y-4">
              <div className="flex items-center gap-2 mb-4">
                <Eye className="w-5 h-5 text-accent" />
                <h2 className="text-2xl font-bold">Shodan InternetDB</h2>
              </div>

              <div className="flex gap-2">
                <Input
                  placeholder="Enter IP address (e.g., 8.8.8.8)"
                  value={shodanInput}
                  onChange={(e) => setShodanInput(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && performShodanLookup(shodanInput)}
                  className="flex-1"
                />
                <Button onClick={() => performShodanLookup(shodanInput)} disabled={loading}>
                  {loading ? (
                    <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                  ) : (
                    <Search className="w-4 h-4 mr-2" />
                  )}
                  Lookup
                </Button>
              </div>

              <div className="text-xs text-muted-foreground">
                Free Shodan InternetDB - shows open ports, vulnerabilities, and tags
              </div>

              {error && (
                <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3 flex items-center gap-2">
                  <AlertCircle className="w-4 h-4 text-red-500" />
                  <span className="text-sm text-red-500">{error}</span>
                </div>
              )}

              {shodanInfo && (
                <div className="space-y-4 mt-6">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <Card className="p-4 space-y-2">
                      <h3 className="font-semibold flex items-center gap-2">
                        <Info className="w-4 h-4 text-accent" />
                        Open Ports
                      </h3>
                      <div className="space-y-2">
                        {shodanInfo.ports.length > 0 ? (
                          <div className="flex flex-wrap gap-2">
                            {shodanInfo.ports.map((port, idx) => (
                              <span key={idx} className="px-2 py-1 bg-accent/20 text-accent rounded text-sm font-mono">
                                {port}
                              </span>
                            ))}
                          </div>
                        ) : (
                          <span className="text-sm text-muted-foreground">No open ports found</span>
                        )}
                      </div>
                    </Card>

                    <Card className="p-4 space-y-2">
                      <h3 className="font-semibold flex items-center gap-2">
                        <AlertCircle className="w-4 h-4 text-red-500" />
                        Vulnerabilities
                      </h3>
                      <div className="space-y-1">
                        {shodanInfo.vulns.length > 0 ? (
                          shodanInfo.vulns.map((vuln, idx) => (
                            <div key={idx} className="text-sm font-mono text-red-500">
                              {vuln}
                            </div>
                          ))
                        ) : (
                          <span className="text-sm text-muted-foreground">No vulnerabilities found</span>
                        )}
                      </div>
                    </Card>
                  </div>

                  <Card className="p-4 space-y-2">
                    <h3 className="font-semibold flex items-center gap-2">
                      <Info className="w-4 h-4 text-accent" />
                      Additional Information
                    </h3>
                    <div className="space-y-2 text-sm">
                      <div>
                        <span className="text-muted-foreground">Tags: </span>
                        {shodanInfo.tags.length > 0 ? (
                          <span>{shodanInfo.tags.join(', ')}</span>
                        ) : (
                          <span className="text-muted-foreground">None</span>
                        )}
                      </div>
                      <div>
                        <span className="text-muted-foreground">Hostnames: </span>
                        {shodanInfo.hostnames.length > 0 ? (
                          <span className="font-mono">{shodanInfo.hostnames.join(', ')}</span>
                        ) : (
                          <span className="text-muted-foreground">None</span>
                        )}
                      </div>
                      <div>
                        <span className="text-muted-foreground">CPEs: </span>
                        {shodanInfo.cpes.length > 0 ? (
                          <div className="mt-1 space-y-1">
                            {shodanInfo.cpes.map((cpe, idx) => (
                              <div key={idx} className="font-mono text-xs">{cpe}</div>
                            ))}
                          </div>
                        ) : (
                          <span className="text-muted-foreground">None</span>
                        )}
                      </div>
                    </div>
                  </Card>

                  <Button variant="outline" onClick={() => exportData(shodanInfo, 'shodan-info.json')}>
                    <Download className="w-4 h-4 mr-2" />
                    Export Results
                  </Button>
                </div>
              )}
            </div>
          </Card>
        )}

        {/* Archive.org Tab */}
        {activeTab === 'archive' && (
          <Card className="p-6">
            <div className="space-y-4">
              <div className="flex items-center gap-2 mb-4">
                <History className="w-5 h-5 text-accent" />
                <h2 className="text-2xl font-bold">Archive.org URL Search</h2>
              </div>

              <div className="flex gap-2">
                <Input
                  placeholder="Enter domain (e.g., example.com)"
                  value={archiveInput}
                  onChange={(e) => setArchiveInput(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && performArchiveSearch(archiveInput)}
                  className="flex-1"
                />
                <Button onClick={() => performArchiveSearch(archiveInput)} disabled={loading}>
                  {loading ? (
                    <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                  ) : (
                    <Search className="w-4 h-4 mr-2" />
                  )}
                  Search
                </Button>
              </div>

              <div className="text-xs text-muted-foreground">
                Find historical URLs from Wayback Machine - great for finding hidden endpoints
              </div>

              {error && (
                <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3 flex items-center gap-2">
                  <AlertCircle className="w-4 h-4 text-red-500" />
                  <span className="text-sm text-red-500">{error}</span>
                </div>
              )}

              {archiveUrls.length > 0 && (
                <div className="space-y-4 mt-6">
                  {/* Filter Input */}
                  <div className="flex items-center gap-2">
                    <Input
                      placeholder="Filter URLs... (will filter after 500ms delay)"
                      value={archiveFilter}
                      onChange={(e) => setArchiveFilter(e.target.value)}
                      className="flex-1"
                    />
                    {archiveFilter && (
                      <Button variant="ghost" size="sm" onClick={() => setArchiveFilter('')}>
                        Clear
                      </Button>
                    )}
                  </div>

                  <div className="flex items-center justify-between">
                    <div className="text-sm text-muted-foreground">
                      {filteredArchiveUrls.length === archiveUrls.length
                        ? `Found ${archiveUrls.length} archived URL(s)`
                        : `Showing ${filteredArchiveUrls.length} of ${archiveUrls.length} archived URL(s)`}
                      {totalArchivePages > 1 && ` (Page ${archiveCurrentPage} of ${totalArchivePages})`}
                    </div>
                    <Button variant="outline" size="sm" onClick={() => exportData(archiveUrls, 'archive-urls.json')}>
                      <Download className="w-4 h-4 mr-2" />
                      Export All
                    </Button>
                  </div>

                  {/* URLs List */}
                  <Card className="p-4">
                    <div className="space-y-1 text-sm max-h-96 overflow-y-auto">
                      {paginatedArchiveUrls.map((item, idx) => (
                        <div key={idx} className="flex justify-between items-center border-b border-border/50 py-2 hover:bg-accent/5">
                          <a
                            href={`https://web.archive.org/web/${item.timestamp}/${item.url}`}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="font-mono text-xs text-accent hover:underline flex-1 truncate"
                          >
                            {item.url}
                          </a>
                          <Button size="sm" variant="ghost" onClick={() => copyToClipboard(item.url)}>
                            <Copy className="w-3 h-3" />
                          </Button>
                        </div>
                      ))}
                    </div>
                  </Card>

                  {/* Pagination Controls */}
                  {totalArchivePages > 1 && (
                    <div className="flex items-center justify-center gap-2">
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setArchiveCurrentPage(1)}
                        disabled={archiveCurrentPage === 1}
                      >
                        First
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setArchiveCurrentPage(prev => Math.max(1, prev - 1))}
                        disabled={archiveCurrentPage === 1}
                      >
                        Previous
                      </Button>
                      <span className="text-sm text-muted-foreground px-4">
                        Page {archiveCurrentPage} of {totalArchivePages}
                      </span>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setArchiveCurrentPage(prev => Math.min(totalArchivePages, prev + 1))}
                        disabled={archiveCurrentPage === totalArchivePages}
                      >
                        Next
                      </Button>
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => setArchiveCurrentPage(totalArchivePages)}
                        disabled={archiveCurrentPage === totalArchivePages}
                      >
                        Last
                      </Button>
                    </div>
                  )}

                  {/* Unique Paths Section */}
                  {uniqueArchivePaths.length > 0 && (
                    <Card className="p-4">
                      <div className="flex items-center justify-between mb-3">
                        <h3 className="font-semibold flex items-center gap-2">
                          <Layers className="w-4 h-4 text-accent" />
                          Unique Paths Found ({uniqueArchivePaths.length})
                        </h3>
                        <Button variant="outline" size="sm" onClick={() => exportData(uniqueArchivePaths, 'archive-paths.json')}>
                          <Download className="w-4 h-4 mr-2" />
                          Export Paths
                        </Button>
                      </div>
                      <div className="space-y-1 text-sm max-h-64 overflow-y-auto">
                        {uniqueArchivePaths.map((path, idx) => (
                          <div key={idx} className="flex justify-between items-center border-b border-border/50 py-1 hover:bg-accent/5">
                            <span className="font-mono text-xs flex-1 truncate">{path}</span>
                            <Button size="sm" variant="ghost" onClick={() => copyToClipboard(path)}>
                              <Copy className="w-3 h-3" />
                            </Button>
                          </div>
                        ))}
                      </div>
                    </Card>
                  )}

                  {/* Potential Injection Points Section */}
                  {injectionPoints.length > 0 && (
                    <Card className="p-4">
                      <div className="flex items-center justify-between mb-3">
                        <h3 className="font-semibold flex items-center gap-2">
                          <AlertCircle className="w-4 h-4 text-amber-500" />
                          Potential Injection Points ({injectionPoints.length})
                        </h3>
                        <Button variant="outline" size="sm" onClick={() => exportData(injectionPoints, 'injection-points.json')}>
                          <Download className="w-4 h-4 mr-2" />
                          Export Injection Points
                        </Button>
                      </div>
                      <div className="text-xs text-muted-foreground mb-2">
                        URLs with parameters that could be vulnerable to injection attacks
                      </div>
                      <div className="space-y-1 text-sm max-h-64 overflow-y-auto">
                        {injectionPoints.map((url, idx) => (
                          <div key={idx} className="flex justify-between items-center border-b border-border/50 py-1 hover:bg-accent/5">
                            <a
                              href={url.startsWith('http') ? url : `http://${url}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="font-mono text-xs text-accent hover:underline flex-1 truncate"
                            >
                              {url}
                            </a>
                            <Button size="sm" variant="ghost" onClick={() => copyToClipboard(url)}>
                              <Copy className="w-3 h-3" />
                            </Button>
                          </div>
                        ))}
                      </div>
                    </Card>
                  )}
                </div>
              )}
            </div>
          </Card>
        )}

        {/* IPInfo.io Tab */}
        {activeTab === 'ipinfo' && (
          <Card className="p-6">
            <div className="space-y-4">
              <div className="flex items-center gap-2 mb-4">
                <Database className="w-5 h-5 text-accent" />
                <h2 className="text-2xl font-bold">IPInfo.io Lookup</h2>
              </div>

              <div className="flex gap-2">
                <Input
                  placeholder="Enter IP address (e.g., 8.8.8.8)"
                  value={ipinfoInput}
                  onChange={(e) => setIpinfoInput(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && performIPInfoLookup(ipinfoInput)}
                  className="flex-1"
                />
                <Button onClick={() => performIPInfoLookup(ipinfoInput)} disabled={loading}>
                  {loading ? (
                    <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                  ) : (
                    <Search className="w-4 h-4 mr-2" />
                  )}
                  Lookup
                </Button>
              </div>

              <div className="text-xs text-muted-foreground">
                Detailed IP information from IPInfo.io
              </div>

              {error && (
                <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3 flex items-center gap-2">
                  <AlertCircle className="w-4 h-4 text-red-500" />
                  <span className="text-sm text-red-500">{error}</span>
                </div>
              )}

              {ipinfoData && (
                <div className="space-y-4 mt-6">
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                    <Card className="p-4 space-y-2">
                      <h3 className="font-semibold flex items-center gap-2">
                        <MapPin className="w-4 h-4 text-accent" />
                        Location Details
                      </h3>
                      <div className="space-y-1 text-sm">
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">IP:</span>
                          <span className="font-mono">{ipinfoData.ip}</span>
                        </div>
                        {ipinfoData.hostname && (
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Hostname:</span>
                            <span className="font-mono text-xs">{ipinfoData.hostname}</span>
                          </div>
                        )}
                        {ipinfoData.city && (
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">City:</span>
                            <span>{ipinfoData.city}</span>
                          </div>
                        )}
                        {ipinfoData.region && (
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Region:</span>
                            <span>{ipinfoData.region}</span>
                          </div>
                        )}
                        {ipinfoData.country && (
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Country:</span>
                            <span>{ipinfoData.country}</span>
                          </div>
                        )}
                        {ipinfoData.loc && (
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Coordinates:</span>
                            <span className="font-mono text-xs">{ipinfoData.loc}</span>
                          </div>
                        )}
                      </div>
                    </Card>

                    <Card className="p-4 space-y-2">
                      <h3 className="font-semibold flex items-center gap-2">
                        <Info className="w-4 h-4 text-accent" />
                        Network Details
                      </h3>
                      <div className="space-y-1 text-sm">
                        {ipinfoData.org && (
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Organization:</span>
                            <span className="text-xs">{ipinfoData.org}</span>
                          </div>
                        )}
                        {ipinfoData.postal && (
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Postal:</span>
                            <span>{ipinfoData.postal}</span>
                          </div>
                        )}
                        {ipinfoData.timezone && (
                          <div className="flex justify-between">
                            <span className="text-muted-foreground">Timezone:</span>
                            <span>{ipinfoData.timezone}</span>
                          </div>
                        )}
                      </div>
                    </Card>
                  </div>

                  <Button variant="outline" onClick={() => exportData(ipinfoData, 'ipinfo-data.json')}>
                    <Download className="w-4 h-4 mr-2" />
                    Export Results
                  </Button>
                </div>
              )}
            </div>
          </Card>
        )}

        {/* PassiveDNS Tab */}
        {activeTab === 'passivedns' && (
          <Card className="p-6">
            <div className="space-y-4">
              <div className="flex items-center gap-2 mb-4">
                <FileText className="w-5 h-5 text-accent" />
                <h2 className="text-2xl font-bold">PassiveDNS (Mnemonic)</h2>
              </div>

              <div className="flex gap-2">
                <Input
                  placeholder="Enter domain (e.g., example.com)"
                  value={passiveDnsInput}
                  onChange={(e) => setPassiveDnsInput(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && performPassiveDNSLookup(passiveDnsInput)}
                  className="flex-1"
                />
                <Button onClick={() => performPassiveDNSLookup(passiveDnsInput)} disabled={loading}>
                  {loading ? (
                    <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                  ) : (
                    <Search className="w-4 h-4 mr-2" />
                  )}
                  Search
                </Button>
              </div>

              <div className="text-xs text-muted-foreground">
                Historical DNS records - track DNS changes over time
              </div>

              {error && (
                <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3 flex items-center gap-2">
                  <AlertCircle className="w-4 h-4 text-red-500" />
                  <span className="text-sm text-red-500">{error}</span>
                </div>
              )}

              {passiveDnsRecords.length > 0 && (
                <div className="space-y-4 mt-6">
                  <div className="flex items-center justify-between">
                    <div className="text-sm text-muted-foreground">
                      Found {passiveDnsRecords.length} historical DNS record(s)
                    </div>
                    <Button variant="outline" size="sm" onClick={() => exportData(passiveDnsRecords, 'passivedns.json')}>
                      <Download className="w-4 h-4 mr-2" />
                      Export
                    </Button>
                  </div>

                  <div className="space-y-2">
                    {passiveDnsRecords.map((record, idx) => (
                      <Card key={idx} className="p-3">
                        <div className="grid grid-cols-1 gap-2 text-sm">
                          <div className="flex items-center gap-4">
                            <span className="font-mono text-xs font-semibold text-accent min-w-[60px]">
                              {record.rrtype}
                            </span>
                            <div className="flex-1">
                              <div className="font-mono text-xs">{record.rdata}</div>
                              <div className="text-xs text-muted-foreground">{record.rrname}</div>
                            </div>
                          </div>
                          <div className="flex items-center justify-between text-xs text-muted-foreground">
                            <span>First: {new Date(record.firstSeenTimestamp).toLocaleDateString()}</span>
                            <span>Last: {new Date(record.lastSeenTimestamp).toLocaleDateString()}</span>
                            <span>Count: {record.count}</span>
                          </div>
                        </div>
                      </Card>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </Card>
        )}

        {/* Certificate Transparency Tab */}
        {activeTab === 'certs' && (
          <Card className="p-6">
            <div className="space-y-4">
              <div className="flex items-center gap-2 mb-4">
                <Lock className="w-5 h-5 text-accent" />
                <h2 className="text-2xl font-bold">Certificate Transparency (crt.sh)</h2>
              </div>

              <div className="flex gap-2">
                <Input
                  placeholder="Enter domain (e.g., example.com)"
                  value={certInput}
                  onChange={(e) => setCertInput(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && performCertSearch(certInput)}
                  className="flex-1"
                />
                <Button onClick={() => performCertSearch(certInput)} disabled={loading}>
                  {loading ? (
                    <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                  ) : (
                    <Search className="w-4 h-4 mr-2" />
                  )}
                  Search
                </Button>
              </div>

              <div className="text-xs text-muted-foreground">
                Find subdomains via SSL certificate transparency logs
              </div>

              {error && (
                <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3 flex items-center gap-2">
                  <AlertCircle className="w-4 h-4 text-red-500" />
                  <span className="text-sm text-red-500">{error}</span>
                </div>
              )}

              {certRecords.length > 0 && (
                <div className="space-y-4 mt-6">
                  <div className="flex items-center justify-between">
                    <div className="text-sm text-muted-foreground">
                      Found {certRecords.length} certificate(s)
                    </div>
                    <Button variant="outline" size="sm" onClick={() => exportData(certRecords, 'certificates.json')}>
                      <Download className="w-4 h-4 mr-2" />
                      Export
                    </Button>
                  </div>

                  <div className="space-y-2">
                    {certRecords.map((cert, idx) => (
                      <Card key={idx} className="p-3">
                        <div className="space-y-2 text-sm">
                          <div className="flex items-center justify-between">
                            <span className="font-mono text-xs font-semibold text-accent">
                              {cert.name_value}
                            </span>
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => copyToClipboard(cert.name_value)}
                            >
                              <Copy className="w-3 h-3" />
                            </Button>
                          </div>
                          <div className="grid grid-cols-2 gap-2 text-xs text-muted-foreground">
                            <span>Issuer: {cert.issuer_name}</span>
                            <span>ID: {cert.id}</span>
                            <span>Not Before: {new Date(cert.not_before).toLocaleDateString()}</span>
                            <span>Not After: {new Date(cert.not_after).toLocaleDateString()}</span>
                          </div>
                        </div>
                      </Card>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </Card>
        )}
        </div>
      </div>
    </div>
  )
}
