import React, { useState, useEffect, useCallback } from 'react'
import {
  Network as NetworkIcon,
  Wifi,
  Server,
  Globe,
  Activity,
  Shield,
  Zap,
  Search,
  Terminal,
  Copy,
  Download,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Info,
  Layers,
  Radio,
  Lock,
  Unlock,
  Eye,
  Clock,
  TrendingUp,
  MapPin,
  Database,
  Hash
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card } from '../components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs'

type TabType = 'ip' | 'subnet' | 'ports' | 'dns' | 'trace' | 'mac' | 'packets' | 'protocols'

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
  geolocation?: {
    country?: string
    region?: string
    city?: string
    lat?: number
    lon?: number
  }
}

interface PortInfo {
  port: number
  protocol: string
  service: string
  description: string
  status: 'open' | 'closed' | 'filtered'
  risk: 'low' | 'medium' | 'high'
}

interface DNSRecord {
  type: string
  value: string
  ttl?: number
}

interface PacketInfo {
  timestamp: string
  protocol: string
  source: string
  destination: string
  length: number
  info: string
  flags?: string[]
}

export default function Network() {
  const [activeTab, setActiveTab] = useState<TabType>('ip')
  const [ipInput, setIpInput] = useState('')
  const [ipInfo, setIpInfo] = useState<IPInfo | null>(null)
  const [subnetInput, setSubnetInput] = useState('')
  const [subnetInfo, setSubnetInfo] = useState<SubnetInfo | null>(null)
  const [portScanTarget, setPortScanTarget] = useState('')
  const [portResults, setPortResults] = useState<PortInfo[]>([])
  const [isScanning, setIsScanning] = useState(false)
  const [dnsInput, setDnsInput] = useState('')
  const [dnsRecords, setDnsRecords] = useState<DNSRecord[]>([])
  const [traceInput, setTraceInput] = useState('')
  const [traceHops, setTraceHops] = useState<any[]>([])
  const [macInput, setMacInput] = useState('')
  const [macInfo, setMacInfo] = useState<any>(null)
  const [packets, setPackets] = useState<PacketInfo[]>([])
  const [protocolStats, setProtocolStats] = useState<any>(null)

  // Common port database
  const commonPorts: { [key: number]: { service: string, description: string, risk: 'low' | 'medium' | 'high' } } = {
    21: { service: 'FTP', description: 'File Transfer Protocol', risk: 'high' },
    22: { service: 'SSH', description: 'Secure Shell', risk: 'medium' },
    23: { service: 'Telnet', description: 'Telnet (unencrypted)', risk: 'high' },
    25: { service: 'SMTP', description: 'Simple Mail Transfer Protocol', risk: 'medium' },
    53: { service: 'DNS', description: 'Domain Name System', risk: 'low' },
    80: { service: 'HTTP', description: 'Hypertext Transfer Protocol', risk: 'low' },
    110: { service: 'POP3', description: 'Post Office Protocol v3', risk: 'medium' },
    143: { service: 'IMAP', description: 'Internet Message Access Protocol', risk: 'medium' },
    443: { service: 'HTTPS', description: 'HTTP over TLS/SSL', risk: 'low' },
    445: { service: 'SMB', description: 'Server Message Block', risk: 'high' },
    3306: { service: 'MySQL', description: 'MySQL Database', risk: 'high' },
    3389: { service: 'RDP', description: 'Remote Desktop Protocol', risk: 'high' },
    5432: { service: 'PostgreSQL', description: 'PostgreSQL Database', risk: 'high' },
    5900: { service: 'VNC', description: 'Virtual Network Computing', risk: 'high' },
    6379: { service: 'Redis', description: 'Redis Database', risk: 'high' },
    8080: { service: 'HTTP-ALT', description: 'Alternative HTTP port', risk: 'low' },
    27017: { service: 'MongoDB', description: 'MongoDB Database', risk: 'high' }
  }

  // IP Address Analysis
  const analyzeIP = useCallback((ip: string) => {
    const ipv4Regex = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/
    const match = ip.match(ipv4Regex)

    if (!match) {
      setIpInfo(null)
      return
    }

    const octets = match.slice(1, 5).map(Number)

    if (octets.some(o => o > 255)) {
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
  }, [])

  // Subnet Calculator
  const calculateSubnet = useCallback((cidr: string) => {
    const parts = cidr.split('/')
    if (parts.length !== 2) return

    const ip = parts[0]
    const prefix = parseInt(parts[1])

    if (prefix < 0 || prefix > 32) return

    const ipParts = ip.split('.').map(Number)
    if (ipParts.length !== 4 || ipParts.some(p => p > 255)) return

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
      binarySubnet: mask.map(m => m.toString(2).padStart(8, '0')).join('.'),
      ipClass,
      privateAddress
    })
  }, [])

  // Port Scanner (Simulated)
  const simulatePortScan = useCallback(async (target: string) => {
    setIsScanning(true)
    setPortResults([])

    // Simulate scanning common ports
    const portsToScan = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 5900, 6379, 8080, 27017]
    const results: PortInfo[] = []

    for (const port of portsToScan) {
      // Simulate random port states
      const rand = Math.random()
      let status: 'open' | 'closed' | 'filtered' = 'closed'

      if (rand > 0.7) status = 'open'
      else if (rand > 0.5) status = 'filtered'

      const portData = commonPorts[port] || { service: 'Unknown', description: 'Unknown service', risk: 'low' }

      results.push({
        port,
        protocol: 'TCP',
        service: portData.service,
        description: portData.description,
        status,
        risk: portData.risk
      })

      // Update results progressively
      await new Promise(resolve => setTimeout(resolve, 100))
      setPortResults([...results])
    }

    setIsScanning(false)
  }, [])

  // DNS Lookup (Simulated)
  const performDNSLookup = useCallback((domain: string) => {
    // Simulate DNS records
    const records: DNSRecord[] = [
      { type: 'A', value: '93.184.216.34', ttl: 3600 },
      { type: 'AAAA', value: '2606:2800:220:1:248:1893:25c8:1946', ttl: 3600 },
      { type: 'MX', value: 'mail.example.com', ttl: 3600 },
      { type: 'NS', value: 'ns1.example.com', ttl: 86400 },
      { type: 'NS', value: 'ns2.example.com', ttl: 86400 },
      { type: 'TXT', value: 'v=spf1 include:_spf.example.com ~all', ttl: 3600 },
      { type: 'CNAME', value: 'www.example.com', ttl: 3600 }
    ]

    setDnsRecords(records)
  }, [])

  // Traceroute (Simulated)
  const performTraceroute = useCallback((target: string) => {
    // Simulate traceroute hops
    const hops = []
    for (let i = 1; i <= 12; i++) {
      hops.push({
        hop: i,
        ip: `192.168.${i}.${Math.floor(Math.random() * 254 + 1)}`,
        hostname: i === 12 ? target : `hop${i}.router.example.net`,
        rtt1: Math.floor(Math.random() * 50 + 10),
        rtt2: Math.floor(Math.random() * 50 + 10),
        rtt3: Math.floor(Math.random() * 50 + 10),
        location: `Node ${i}`
      })
    }
    setTraceHops(hops)
  }, [])

  // MAC Address Lookup
  const lookupMAC = useCallback((mac: string) => {
    // Common OUI database (partial)
    const ouiDatabase: { [key: string]: string } = {
      '00:1A:A0': 'Dell Inc.',
      '00:50:56': 'VMware, Inc.',
      '08:00:27': 'Oracle VirtualBox',
      '00:0C:29': 'VMware, Inc.',
      '00:1B:63': 'Apple, Inc.',
      '00:23:32': 'Cisco Systems',
      '00:24:D7': 'Intel Corporation',
      '00:0D:3A': 'Microsoft Corporation',
      '00:15:5D': 'Microsoft Corporation',
      '52:54:00': 'QEMU Virtual NIC'
    }

    const oui = mac.substring(0, 8).toUpperCase()
    const vendor = ouiDatabase[oui] || 'Unknown Vendor'

    setMacInfo({
      mac: mac.toUpperCase(),
      oui,
      vendor,
      isLocal: parseInt(mac[1], 16) % 2 === 1,
      isUnicast: parseInt(mac[1], 16) % 2 === 0
    })
  }, [])

  // Generate sample packets
  const generateSamplePackets = useCallback(() => {
    const protocols = ['TCP', 'UDP', 'ICMP', 'HTTP', 'HTTPS', 'DNS', 'SSH', 'FTP']
    const samplePackets: PacketInfo[] = []

    for (let i = 0; i < 50; i++) {
      const protocol = protocols[Math.floor(Math.random() * protocols.length)]
      samplePackets.push({
        timestamp: new Date(Date.now() - Math.random() * 3600000).toISOString(),
        protocol,
        source: `192.168.1.${Math.floor(Math.random() * 254 + 1)}:${Math.floor(Math.random() * 65535)}`,
        destination: `10.0.0.${Math.floor(Math.random() * 254 + 1)}:${Math.floor(Math.random() * 65535)}`,
        length: Math.floor(Math.random() * 1500 + 64),
        info: `${protocol} packet`,
        flags: protocol === 'TCP' ? ['SYN', 'ACK'].filter(() => Math.random() > 0.5) : undefined
      })
    }

    setPackets(samplePackets)

    // Calculate protocol statistics
    const stats: any = {}
    protocols.forEach(p => {
      stats[p] = samplePackets.filter(pkt => pkt.protocol === p).length
    })
    setProtocolStats(stats)
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
          Comprehensive networking tools for CTF competitions and security research
        </p>
      </div>

      {/* Main Tabs */}
      <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as TabType)} className="space-y-6">
        <TabsList className="grid grid-cols-4 lg:grid-cols-8 gap-2">
          <TabsTrigger value="ip" className="flex items-center gap-2">
            <Globe className="w-4 h-4" />
            IP Analysis
          </TabsTrigger>
          <TabsTrigger value="subnet" className="flex items-center gap-2">
            <Layers className="w-4 h-4" />
            Subnet Calc
          </TabsTrigger>
          <TabsTrigger value="ports" className="flex items-center gap-2">
            <Shield className="w-4 h-4" />
            Port Scanner
          </TabsTrigger>
          <TabsTrigger value="dns" className="flex items-center gap-2">
            <Server className="w-4 h-4" />
            DNS Lookup
          </TabsTrigger>
          <TabsTrigger value="trace" className="flex items-center gap-2">
            <MapPin className="w-4 h-4" />
            Traceroute
          </TabsTrigger>
          <TabsTrigger value="mac" className="flex items-center gap-2">
            <Hash className="w-4 h-4" />
            MAC Lookup
          </TabsTrigger>
          <TabsTrigger value="packets" className="flex items-center gap-2">
            <Database className="w-4 h-4" />
            Packets
          </TabsTrigger>
          <TabsTrigger value="protocols" className="flex items-center gap-2">
            <Activity className="w-4 h-4" />
            Protocols
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
                      </div>
                    </Card>

                    <Card className="p-4 space-y-2">
                      <h3 className="font-semibold flex items-center gap-2">
                        <Hash className="w-4 h-4 text-accent" />
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

                  <div className="flex gap-2">
                    <Button variant="outline" onClick={() => exportData(ipInfo, 'ip-analysis.json')}>
                      <Download className="w-4 h-4 mr-2" />
                      Export Results
                    </Button>
                  </div>
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

        {/* Port Scanner Tab */}
        <TabsContent value="ports" className="space-y-4">
          <Card className="p-6">
            <div className="space-y-4">
              <div className="flex items-center gap-2 mb-4">
                <Shield className="w-5 h-5 text-accent" />
                <h2 className="text-2xl font-bold">Port Scanner (Simulated)</h2>
              </div>

              <div className="bg-amber-500/10 border border-amber-500/20 rounded-lg p-4 flex items-start gap-3">
                <AlertTriangle className="w-5 h-5 text-amber-500 flex-shrink-0 mt-0.5" />
                <div className="text-sm">
                  <p className="font-semibold text-amber-500 mb-1">Educational Tool</p>
                  <p className="text-muted-foreground">
                    This is a simulated port scanner for CTF training. Results are randomly generated and do not reflect actual network states.
                  </p>
                </div>
              </div>

              <div className="flex gap-2">
                <Input
                  placeholder="Enter target (e.g., 192.168.1.1 or example.com)"
                  value={portScanTarget}
                  onChange={(e) => setPortScanTarget(e.target.value)}
                  disabled={isScanning}
                  className="flex-1"
                />
                <Button
                  onClick={() => simulatePortScan(portScanTarget)}
                  disabled={isScanning || !portScanTarget}
                >
                  {isScanning ? (
                    <>
                      <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                      Scanning...
                    </>
                  ) : (
                    <>
                      <Search className="w-4 h-4 mr-2" />
                      Scan
                    </>
                  )}
                </Button>
              </div>

              {portResults.length > 0 && (
                <div className="space-y-4 mt-6">
                  <div className="flex items-center justify-between">
                    <div className="text-sm text-muted-foreground">
                      Found {portResults.filter(p => p.status === 'open').length} open ports out of {portResults.length} scanned
                    </div>
                    <Button variant="outline" size="sm" onClick={() => exportData(portResults, 'port-scan.json')}>
                      <Download className="w-4 h-4 mr-2" />
                      Export
                    </Button>
                  </div>

                  <div className="grid grid-cols-1 gap-2 max-h-96 overflow-y-auto">
                    {portResults.map((port, idx) => (
                      <Card key={idx} className="p-3">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-3">
                            <div className={`w-2 h-2 rounded-full ${
                              port.status === 'open' ? 'bg-green-500' :
                              port.status === 'filtered' ? 'bg-yellow-500' :
                              'bg-gray-500'
                            }`} />
                            <div>
                              <div className="font-semibold">
                                Port {port.port}/{port.protocol} - {port.service}
                              </div>
                              <div className="text-sm text-muted-foreground">{port.description}</div>
                            </div>
                          </div>
                          <div className="flex items-center gap-2">
                            <span className={`px-2 py-1 rounded text-xs font-semibold ${
                              port.status === 'open' ? 'bg-green-500/20 text-green-500' :
                              port.status === 'filtered' ? 'bg-yellow-500/20 text-yellow-500' :
                              'bg-gray-500/20 text-gray-500'
                            }`}>
                              {port.status.toUpperCase()}
                            </span>
                            <span className={`px-2 py-1 rounded text-xs font-semibold ${
                              port.risk === 'high' ? 'bg-red-500/20 text-red-500' :
                              port.risk === 'medium' ? 'bg-amber-500/20 text-amber-500' :
                              'bg-blue-500/20 text-blue-500'
                            }`}>
                              {port.risk.toUpperCase()} RISK
                            </span>
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

        {/* DNS Lookup Tab */}
        <TabsContent value="dns" className="space-y-4">
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
                <Button onClick={() => performDNSLookup(dnsInput)}>
                  <Search className="w-4 h-4 mr-2" />
                  Lookup
                </Button>
              </div>

              {dnsRecords.length > 0 && (
                <div className="space-y-4 mt-6">
                  <div className="flex items-center justify-between">
                    <div className="text-sm text-muted-foreground">
                      Found {dnsRecords.length} DNS records
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
                          <div className="flex items-center gap-4">
                            <span className="font-mono text-sm font-semibold text-accent min-w-[60px]">
                              {record.type}
                            </span>
                            <span className="font-mono text-sm">{record.value}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            {record.ttl && (
                              <span className="text-xs text-muted-foreground">
                                TTL: {record.ttl}s
                              </span>
                            )}
                            <Button size="sm" variant="ghost" onClick={() => copyToClipboard(record.value)}>
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

        {/* Traceroute Tab */}
        <TabsContent value="trace" className="space-y-4">
          <Card className="p-6">
            <div className="space-y-4">
              <div className="flex items-center gap-2 mb-4">
                <MapPin className="w-5 h-5 text-accent" />
                <h2 className="text-2xl font-bold">Traceroute (Simulated)</h2>
              </div>

              <div className="flex gap-2">
                <Input
                  placeholder="Enter target (e.g., example.com)"
                  value={traceInput}
                  onChange={(e) => setTraceInput(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && performTraceroute(traceInput)}
                  className="flex-1"
                />
                <Button onClick={() => performTraceroute(traceInput)}>
                  <Search className="w-4 h-4 mr-2" />
                  Trace
                </Button>
              </div>

              {traceHops.length > 0 && (
                <div className="space-y-4 mt-6">
                  <div className="flex items-center justify-between">
                    <div className="text-sm text-muted-foreground">
                      {traceHops.length} hops to destination
                    </div>
                    <Button variant="outline" size="sm" onClick={() => exportData(traceHops, 'traceroute.json')}>
                      <Download className="w-4 h-4 mr-2" />
                      Export
                    </Button>
                  </div>

                  <div className="space-y-2 max-h-96 overflow-y-auto">
                    {traceHops.map((hop, idx) => (
                      <Card key={idx} className="p-3">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-4">
                            <span className="font-mono text-sm font-semibold text-accent min-w-[30px]">
                              {hop.hop}
                            </span>
                            <div>
                              <div className="font-mono text-sm">{hop.ip}</div>
                              <div className="text-xs text-muted-foreground">{hop.hostname}</div>
                            </div>
                          </div>
                          <div className="flex items-center gap-2 text-xs text-muted-foreground">
                            <Clock className="w-3 h-3" />
                            <span>{hop.rtt1}ms</span>
                            <span>{hop.rtt2}ms</span>
                            <span>{hop.rtt3}ms</span>
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

        {/* MAC Lookup Tab */}
        <TabsContent value="mac" className="space-y-4">
          <Card className="p-6">
            <div className="space-y-4">
              <div className="flex items-center gap-2 mb-4">
                <Hash className="w-5 h-5 text-accent" />
                <h2 className="text-2xl font-bold">MAC Address Lookup</h2>
              </div>

              <div className="flex gap-2">
                <Input
                  placeholder="Enter MAC address (e.g., 00:1A:A0:12:34:56)"
                  value={macInput}
                  onChange={(e) => setMacInput(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && lookupMAC(macInput)}
                  className="flex-1"
                />
                <Button onClick={() => lookupMAC(macInput)}>
                  <Search className="w-4 h-4 mr-2" />
                  Lookup
                </Button>
              </div>

              {macInfo && (
                <div className="space-y-4 mt-6">
                  <Card className="p-4 space-y-2">
                    <h3 className="font-semibold flex items-center gap-2">
                      <Hash className="w-4 h-4 text-accent" />
                      MAC Address Information
                    </h3>
                    <div className="space-y-1 text-sm">
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">MAC Address:</span>
                        <span className="font-mono">{macInfo.mac}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">OUI:</span>
                        <span className="font-mono">{macInfo.oui}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Vendor:</span>
                        <span>{macInfo.vendor}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Address Type:</span>
                        <span>{macInfo.isUnicast ? 'Unicast' : 'Multicast'}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Administration:</span>
                        <span>{macInfo.isLocal ? 'Locally Administered' : 'Globally Unique'}</span>
                      </div>
                    </div>
                  </Card>
                </div>
              )}
            </div>
          </Card>
        </TabsContent>

        {/* Packets Tab */}
        <TabsContent value="packets" className="space-y-4">
          <Card className="p-6">
            <div className="space-y-4">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <Database className="w-5 h-5 text-accent" />
                  <h2 className="text-2xl font-bold">Packet Analysis</h2>
                </div>
                <Button onClick={generateSamplePackets}>
                  <RefreshCw className="w-4 h-4 mr-2" />
                  Generate Sample Packets
                </Button>
              </div>

              {packets.length > 0 && (
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div className="text-sm text-muted-foreground">
                      {packets.length} packets captured
                    </div>
                    <Button variant="outline" size="sm" onClick={() => exportData(packets, 'packets.json')}>
                      <Download className="w-4 h-4 mr-2" />
                      Export
                    </Button>
                  </div>

                  <div className="space-y-1 max-h-96 overflow-y-auto font-mono text-xs">
                    {packets.map((pkt, idx) => (
                      <div key={idx} className="p-2 hover:bg-muted/50 rounded border border-border">
                        <div className="grid grid-cols-6 gap-2">
                          <span className="text-muted-foreground">{idx + 1}</span>
                          <span className="text-accent font-semibold">{pkt.protocol}</span>
                          <span className="col-span-2">{pkt.source}</span>
                          <span className="col-span-2">{pkt.destination}</span>
                        </div>
                        <div className="text-muted-foreground pl-4 mt-1">
                          {pkt.info} ({pkt.length} bytes)
                          {pkt.flags && ` [${pkt.flags.join(', ')}]`}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </Card>
        </TabsContent>

        {/* Protocols Tab */}
        <TabsContent value="protocols" className="space-y-4">
          <Card className="p-6">
            <div className="space-y-4">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center gap-2">
                  <Activity className="w-5 h-5 text-accent" />
                  <h2 className="text-2xl font-bold">Protocol Statistics</h2>
                </div>
                {!protocolStats && (
                  <Button onClick={generateSamplePackets}>
                    <RefreshCw className="w-4 h-4 mr-2" />
                    Generate Data
                  </Button>
                )}
              </div>

              {protocolStats && (
                <div className="space-y-4">
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                    {Object.entries(protocolStats).map(([protocol, count]: [string, any]) => (
                      <Card key={protocol} className="p-4">
                        <div className="text-center space-y-2">
                          <div className="text-2xl font-bold text-accent">{count}</div>
                          <div className="text-sm text-muted-foreground">{protocol}</div>
                        </div>
                      </Card>
                    ))}
                  </div>

                  <Card className="p-4">
                    <h3 className="font-semibold mb-4">Protocol Distribution</h3>
                    <div className="space-y-2">
                      {Object.entries(protocolStats)
                        .sort((a: any, b: any) => b[1] - a[1])
                        .map(([protocol, count]: [string, any]) => {
                          const total = Object.values(protocolStats).reduce((sum: number, val: any) => sum + val, 0)
                          const percentage = ((count / total) * 100).toFixed(1)
                          return (
                            <div key={protocol}>
                              <div className="flex justify-between text-sm mb-1">
                                <span>{protocol}</span>
                                <span className="text-muted-foreground">{count} ({percentage}%)</span>
                              </div>
                              <div className="w-full h-2 bg-muted rounded-full overflow-hidden">
                                <div
                                  className="h-full bg-accent transition-all duration-300"
                                  style={{ width: `${percentage}%` }}
                                />
                              </div>
                            </div>
                          )
                        })}
                    </div>
                  </Card>
                </div>
              )}
            </div>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  )
}
