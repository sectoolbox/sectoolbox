// Enhanced PCAP analysis with structured results
export interface TlsCertificate {
  version: string
  serialNumber: string
  issuer: string
  subject: string
  validFrom: string
  validTo: string
  signatureAlgorithm: string
  publicKeyAlgorithm: string
  keySize: number
  fingerprint: {
    sha1: string
    sha256: string
    md5: string
  }
  extensions: Array<{
    name: string
    value: string
    critical: boolean
  }>
  chain: TlsCertificate[]
  selfSigned: boolean
  expired: boolean
  weakSignature: boolean
}

export interface NetworkFlow {
  flowId: string
  protocol: string
  srcIp: string
  srcPort: number
  destIp: string
  destPort: number
  startTime: number
  endTime: number
  duration: number
  packets: number
  bytes: number
  avgPacketSize: number
  dataRate: number
  flowDirection: 'inbound' | 'outbound' | 'internal'
  geoData?: {
    srcCountry?: string
    srcCity?: string
    destCountry?: string
    destCity?: string
    asn?: {
      srcAsn?: number
      srcOrg?: string
      destAsn?: number
      destOrg?: string
    }
  }
  suspicious: boolean
  suspiciousReasons: string[]
}

export interface ThreatIndicator {
  type: 'malware_c2' | 'dga_domain' | 'suspicious_tls' | 'data_exfiltration' | 'port_scan' | 'dos_attack' | 'tunnel_protocol' | 'tor_traffic'
  severity: 'low' | 'medium' | 'high' | 'critical'
  confidence: number
  description: string
  source: string
  destination?: string
  indicators: Record<string, any>
  mitre?: {
    technique: string
    tactic: string
    description: string
  }
  timestamp: number
  packets: number[]
}

export interface DeepPacketInspection {
  tlsConnections: Array<{
    srcIp: string
    destIp: string
    serverName?: string
    certificate?: TlsCertificate
    cipherSuite?: string
    tlsVersion?: string
    handshakeTime?: number
    suspicious: boolean
    issues: string[]
  }>
  dnsAnalysis: {
    queries: Array<{
      domain: string
      type: string
      response?: string
      queryTime: number
      responseTime?: number
      suspicious: boolean
      reasons: string[]
    }>
    suspiciousDomains: string[]
    dgaDetection: Array<{
      domain: string
      score: number
      features: Record<string, number>
    }>
    dohDetection: Array<{
      ip: string
      requests: number
      domains: string[]
    }>
  }
  protocolTunneling: Array<{
    type: 'http_over_dns' | 'ssh_tunneling' | 'icmp_tunneling' | 'custom'
    srcIp: string
    destIp: string
    confidence: number
    evidence: string[]
    packets: number[]
  }>
}

export interface PcapAnalysisResult {
  metadata: {
    filename: string
    fileSize: number
    format: string
    linkType: number | null
    snaplen?: number
    totalPackets: number
  }
  packets: Array<{
    index: number
    timestamp: string
    protocol: string
    source: string
    destination: string
    info: string
    size: number
    payload?: string
  }>
  protocols: {
    summary: Record<string, number>
    details: Array<{ name: string; count: number; percentage: number }>
  }
  httpStreams: Array<{
    method: string
    url: string
    host: string
    userAgent?: string
    payload?: string
  }>
  networkFlows: NetworkFlow[]
  deepPacketInspection: DeepPacketInspection
  threatIndicators: ThreatIndicator[]
  networkIntelligence: {
    topTalkers: Array<{ ip: string; bytes: number; packets: number }>
    protocolDistribution: Record<string, number>
    geolocation: Record<string, { country: string; city: string; asn: number; org: string }>
    bandwidth: Array<{ timestamp: number; bytes: number; packets: number }>
  }
  layers: Array<{
    step: number
    method: string
    confidence: number
    data: any
    timestamp: number
  }>
}

export async function toArrayBuffer(input: File | Blob | ArrayBuffer | string): Promise<ArrayBuffer> {
  if (!input) return new ArrayBuffer(0)

  // String (URL)
  if (typeof input === 'string') {
    const res = await fetch(input)
    return await res.arrayBuffer()
  }

  // Already an ArrayBuffer
  if (input instanceof ArrayBuffer) return input

  // If Blob/File with native arrayBuffer support (modern browsers)
  try {
    if (input && typeof (input as any).arrayBuffer === 'function') {
      // Defensive: ensure it's callable
      try {
        return await (input as any).arrayBuffer()
      } catch (e) {
        // fallthrough to FileReader fallback
      }
    }
  } catch (e) {
    // ignore
  }

  // If it's a Blob or File but arrayBuffer wasn't callable or failed, use FileReader fallback
  try {
    if (input instanceof Blob || (typeof (input as any).size === 'number' && typeof (input as any).type === 'string')) {
      return await new Promise<ArrayBuffer>((resolve, reject) => {
        const fr = new FileReader()
        fr.onload = () => {
          resolve(fr.result as ArrayBuffer)
        }
        fr.onerror = () => reject(fr.error)
        try {
          fr.readAsArrayBuffer(input as Blob)
        } catch (err) {
          reject(err)
        }
      })
    }
  } catch (e) {
    // ignore
  }

  // Try treating as URL-like string after coercion
  try {
    const maybeUrl = String((input as any))
    if (/^https?:\/\//.test(maybeUrl)) {
      const res = await fetch(maybeUrl)
      return await res.arrayBuffer()
    }
  } catch (e) {
    // ignore
  }

  throw new Error('Unsupported input type for PCAP analysis')
}

export async function performComprehensivePcapAnalysis(input: File | Blob | ArrayBuffer | string): Promise<PcapAnalysisResult> {
  const buffer = await toArrayBuffer(input)
  const basicParsing = parsePcap(buffer)
  
  const result: PcapAnalysisResult = {
    metadata: {
      filename: typeof (input as any)?.name === 'string' ? (input as any).name : 'uploaded.pcap',
      fileSize: typeof (input as any)?.size === 'number' ? (input as any).size : buffer.byteLength,
      format: basicParsing.format,
      linkType: basicParsing.linkType,
      totalPackets: basicParsing.packetCount
    },
    packets: basicParsing.packets, // Display all packets without truncation
    protocols: {
      summary: {},
      details: []
    },
    httpStreams: [],
    networkFlows: [],
    deepPacketInspection: {
      tlsConnections: [],
      dnsAnalysis: {
        queries: [],
        suspiciousDomains: [],
        dgaDetection: [],
        dohDetection: []
      },
      protocolTunneling: []
    },
    threatIndicators: [],
    networkIntelligence: {
      topTalkers: [],
      protocolDistribution: {},
      geolocation: {},
      bandwidth: []
    },
    layers: []
  }
  
  let layerStep = 0
  
  // Layer 1: File format validation
  result.layers.push({
    step: ++layerStep,
    method: 'format_validation',
    confidence: basicParsing.format === 'pcap' ? 95 : (basicParsing.format === 'pcapng' ? 70 : 10),
    data: {
      format: basicParsing.format,
      link_type: basicParsing.linkType,
      total_packets: basicParsing.packetCount
    },
    timestamp: Date.now()
  })
  
  // Layer 2: Protocol analysis
  const protocolCounts: Record<string, number> = {}
  basicParsing.packets.forEach(packet => {
    const proto = packet.protocol || 'UNKNOWN'
    protocolCounts[proto] = (protocolCounts[proto] || 0) + 1
  })
  
  result.protocols.summary = protocolCounts
  result.protocols.details = Object.entries(protocolCounts)
    .map(([name, count]) => ({
      name,
      count,
      percentage: Math.round((count / Math.max(1, basicParsing.packetCount)) * 100)
    }))
    .sort((a, b) => b.count - a.count)
  
  result.layers.push({
    step: ++layerStep,
    method: 'protocol_analysis',
    confidence: Object.keys(protocolCounts).length > 0 ? 85 : 20,
    data: {
      unique_protocols: Object.keys(protocolCounts).length,
      protocol_distribution: result.protocols.details.slice(0, 5)
    },
    timestamp: Date.now()
  })
  
  // Layer 3: HTTP stream extraction
  const httpPackets = basicParsing.packets.filter(p => 
    p.info && (p.info.includes('HTTP') || p.info.includes('GET ') || p.info.includes('POST '))
  )
  
  if (httpPackets.length > 0) {
    result.layers.push({
      step: ++layerStep,
      method: 'http_extraction',
      confidence: 80,
      data: {
        http_packets: httpPackets.length,
        sample_requests: httpPackets.slice(0, 3).map(p => p.info)
      },
      timestamp: Date.now()
    })
  }
  
  // Layer 4: Deep Packet Inspection
  try {
    result.deepPacketInspection.tlsConnections = analyzeTlsConnections(basicParsing.packets)
    result.deepPacketInspection.dnsAnalysis = analyzeDnsTraffic(basicParsing.packets)
    result.deepPacketInspection.protocolTunneling = detectProtocolTunneling(basicParsing.packets)
    
    result.layers.push({
      step: ++layerStep,
      method: 'deep_packet_inspection',
      confidence: 90,
      data: {
        tls_connections: result.deepPacketInspection.tlsConnections.length,
        dns_queries: result.deepPacketInspection.dnsAnalysis.queries.length,
        suspicious_domains: result.deepPacketInspection.dnsAnalysis.suspiciousDomains.length,
        dga_detections: result.deepPacketInspection.dnsAnalysis.dgaDetection.length,
        protocol_tunneling: result.deepPacketInspection.protocolTunneling.length
      },
      timestamp: Date.now()
    })
  } catch (error) {
    result.layers.push({
      step: ++layerStep,
      method: 'deep_packet_inspection',
      confidence: 0,
      data: { error: error instanceof Error ? error.message : 'Deep packet inspection failed' },
      timestamp: Date.now()
    })
  }
  
  // Layer 5: Network Flow Analysis
  try {
    result.networkFlows = generateNetworkFlows(basicParsing.packets)
    await enrichWithGeolocation(result.networkFlows)
    
    // Generate network intelligence
    const topTalkers = result.networkFlows
      .slice(0, 10)
      .map(flow => ({
        ip: flow.srcIp,
        bytes: flow.bytes,
        packets: flow.packets
      }))
    
    const bandwidth = result.networkFlows
      .reduce((acc, flow) => {
        const timeSlot = Math.floor(flow.startTime / 60000) * 60000 // 1-minute intervals
        const existing = acc.find(b => b.timestamp === timeSlot)
        if (existing) {
          existing.bytes += flow.bytes
          existing.packets += flow.packets
        } else {
          acc.push({ timestamp: timeSlot, bytes: flow.bytes, packets: flow.packets })
        }
        return acc
      }, [] as Array<{ timestamp: number; bytes: number; packets: number }>)
    
    result.networkIntelligence = {
      topTalkers,
      protocolDistribution: protocolCounts,
      geolocation: {}, // Would be populated with actual geolocation data
      bandwidth: bandwidth.sort((a, b) => a.timestamp - b.timestamp)
    }
    
    result.layers.push({
      step: ++layerStep,
      method: 'network_flow_analysis',
      confidence: 85,
      data: {
        total_flows: result.networkFlows.length,
        suspicious_flows: result.networkFlows.filter(f => f.suspicious).length,
        top_talkers: topTalkers.length,
        bandwidth_points: bandwidth.length
      },
      timestamp: Date.now()
    })
  } catch (error) {
    result.layers.push({
      step: ++layerStep,
      method: 'network_flow_analysis',
      confidence: 0,
      data: { error: error instanceof Error ? error.message : 'Network flow analysis failed' },
      timestamp: Date.now()
    })
  }
  
  // Layer 6: Advanced Threat Detection
  try {
    const malwareIndicators = detectMalwareC2(basicParsing.packets)
    const portScanIndicators = detectPortScanning(basicParsing.packets)
    const exfiltrationIndicators = detectDataExfiltration(basicParsing.packets, result.networkFlows)
    
    result.threatIndicators = [
      ...malwareIndicators,
      ...portScanIndicators,
      ...exfiltrationIndicators
    ].sort((a, b) => {
      const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 }
      return severityOrder[b.severity] - severityOrder[a.severity]
    })
    
    result.layers.push({
      step: ++layerStep,
      method: 'advanced_threat_detection',
      confidence: 88,
      data: {
        total_indicators: result.threatIndicators.length,
        malware_c2: malwareIndicators.length,
        port_scans: portScanIndicators.length,
        data_exfiltration: exfiltrationIndicators.length,
        severity_breakdown: result.threatIndicators.reduce((acc, indicator) => {
          acc[indicator.severity] = (acc[indicator.severity] || 0) + 1
          return acc
        }, {} as Record<string, number>)
      },
      timestamp: Date.now()
    })
  } catch (error) {
    result.layers.push({
      step: ++layerStep,
      method: 'advanced_threat_detection',
      confidence: 0,
      data: { error: error instanceof Error ? error.message : 'Threat detection failed' },
      timestamp: Date.now()
    })
  }
  
  // Layer 7: Payload analysis (enhanced)
  const payloadAnalysis = analyzePayloads(buffer)
  if (payloadAnalysis.interestingPayloads.length > 0) {
    result.layers.push({
      step: ++layerStep,
      method: 'payload_analysis',
      confidence: 70,
      data: payloadAnalysis,
      timestamp: Date.now()
    })
  }
  
  return result
}

function analyzePayloads(buffer: ArrayBuffer): any {
  // Simplified payload analysis - in real implementation would extract actual payloads
  const data = new Uint8Array(buffer)
  const strings: string[] = []
  let current: number[] = []
  
  for (let i = 0; i < Math.min(data.length, 10000); i++) { // Limit scan
    const byte = data[i]
    if (byte >= 32 && byte <= 126) {
      current.push(byte)
    } else {
      if (current.length >= 6) {
        strings.push(String.fromCharCode(...current))
      }
      current = []
    }
  }
  
  const interestingStrings = strings.filter(s => 
    s.includes('password') || 
    s.includes('token') || 
    s.includes('key') ||
    s.includes('flag') ||
    /https?:\/\//.test(s)
  )
  
  return {
    total_strings: strings.length,
    interestingPayloads: interestingStrings.slice(0, 10),
    urls: strings.filter(s => /https?:\/\//.test(s)).slice(0, 5)
  }
}

export function parsePcap(buffer: ArrayBuffer) {
  const bytes = new Uint8Array(buffer)
  if (bytes.length < 24) return { format: 'unknown', packets: [], packetCount: 0, linkType: null }

  const dv = new DataView(buffer)
  const magic = dv.getUint32(0, false)
  // pcapng magic
  if (magic === 0x0A0D0D0A) {
    return { format: 'pcapng', packets: [], packetCount: 0, linkType: null }
  }

  const magicLE = dv.getUint32(0, true)
  let littleEndian = false
  if (magic === 0xa1b2c3d4) littleEndian = false
  else if (magicLE === 0xa1b2c3d4) littleEndian = true
  else return { format: 'unknown', packets: [], packetCount: 0, linkType: null }

  // read global header
  const versionMajor = dv.getUint16(4, littleEndian)
  const versionMinor = dv.getUint16(6, littleEndian)
  const thiszone = dv.getInt32(8, littleEndian)
  const sigfigs = dv.getUint32(12, littleEndian)
  const snaplen = dv.getUint32(16, littleEndian)
  const network = dv.getUint32(20, littleEndian)

  const packets: any[] = []
  let offset = 24
  let index = 0

  function extractPrintable(pkt: Uint8Array, minLen = 6) {
    const res: string[] = []
    let cur: number[] = []
    for (let i = 0; i < pkt.length; i++) {
      const b = pkt[i]
      if (b >= 32 && b <= 126) cur.push(b)
      else {
        if (cur.length >= minLen) res.push(String.fromCharCode(...cur))
        cur = []
      }
    }
    if (cur.length >= minLen) res.push(String.fromCharCode(...cur))
    return res
  }

  while (offset + 16 <= buffer.byteLength) {
    try {
      const tsSec = dv.getUint32(offset, littleEndian)
      const tsUsec = dv.getUint32(offset + 4, littleEndian)
      const inclLen = dv.getUint32(offset + 8, littleEndian)
      const origLen = dv.getUint32(offset + 12, littleEndian)
      offset += 16
      if (offset + inclLen > buffer.byteLength) break
      const pkt = bytes.slice(offset, offset + inclLen)

      // minimal parsing: Ethernet -> IPv4 -> TCP/UDP
      let protocol = 'UNKNOWN'
      let src = ''
      let dst = ''
      let info = ''
      let srcPort: number | undefined
      let destPort: number | undefined
      let srcMac = ''
      let destMac = ''

      if (inclLen >= 14) {
        // Extract MAC addresses
        destMac = Array.from(pkt.slice(0, 6)).map(b => b.toString(16).padStart(2, '0')).join(':')
        srcMac = Array.from(pkt.slice(6, 12)).map(b => b.toString(16).padStart(2, '0')).join(':')

        const ethType = (pkt[12] << 8) | pkt[13]
        if (ethType === 0x0800 && inclLen >= 34) { // IPv4
          const ihl = (pkt[14] & 0x0f) * 4
          const proto = pkt[23]
          const srcIp = `${pkt[26]}.${pkt[27]}.${pkt[28]}.${pkt[29]}`
          const dstIp = `${pkt[30]}.${pkt[31]}.${pkt[32]}.${pkt[33]}`
          src = srcIp
          dst = dstIp
          if (proto === 6 && inclLen >= 14 + ihl + 20) {
            protocol = 'TCP'
            srcPort = (pkt[14 + ihl] << 8) | pkt[14 + ihl + 1]
            destPort = (pkt[14 + ihl + 2] << 8) | pkt[14 + ihl + 3]
            info = `TCP ${srcPort} → ${destPort}`
          } else if (proto === 17 && inclLen >= 14 + ihl + 8) {
            protocol = 'UDP'
            srcPort = (pkt[14 + ihl] << 8) | pkt[14 + ihl + 1]
            destPort = (pkt[14 + ihl + 2] << 8) | pkt[14 + ihl + 3]
            info = `UDP ${srcPort} → ${destPort}`
          } else if (proto === 1) {
            protocol = 'ICMP'
            info = 'ICMP'
          } else {
            protocol = `IP(proto:${proto})`
            info = ''
          }
        } else if (ethType === 0x86dd) {
          protocol = 'IPv6'
        } else {
          protocol = `ETH(0x${ethType.toString(16)})`
        }
      }

      // attempt to extract higher-level hints from payload strings
      const printable = extractPrintable(pkt, 6)
      let hint = ''
      for (const s of printable) {
        const l = String(s || '').toUpperCase()
        if (l.startsWith('GET ') || l.startsWith('POST ') || l.includes('HTTP/')) {
          hint = s.split('\n')[0]
          protocol = 'HTTP'
          info = hint
          break
        }
        if (s && String(s).toLowerCase().startsWith('host:')) {
          hint = s
          info = info ? `${info} | ${hint}` : hint
        }
      }

      packets.push({
        index,
        timestamp: tsSec + (tsUsec / 1000000),
        ts: new Date(tsSec * 1000 + Math.floor(tsUsec/1000)).toISOString(),
        length: inclLen,
        originalLength: origLen,
        inclLen,
        origLen,
        protocol,
        source: src,
        destination: dst,
        srcPort,
        destPort,
        srcMac,
        destMac,
        info,
        data: pkt.buffer.slice(pkt.byteOffset, pkt.byteOffset + pkt.byteLength)
      })

      offset += inclLen
      index++
    } catch (err) {
      break
    }
  }

  return { format: 'pcap', packets, packetCount: packets.length, linkType: network }
}

// Deep Packet Inspection Functions
export function analyzeTlsConnections(packets: any[]): DeepPacketInspection['tlsConnections'] {
  const tlsConnections: DeepPacketInspection['tlsConnections'] = []
  const tlsHandshakes = new Map<string, any>()

  packets.forEach(packet => {
    if (packet.protocol === 'TLS' || packet.info?.includes('TLS') || packet.info?.includes('SSL')) {
      const key = `${packet.source}-${packet.destination}`
      
      if (!tlsHandshakes.has(key)) {
        tlsHandshakes.set(key, {
          srcIp: packet.source,
          destIp: packet.destination,
          handshakeTime: packet.timestamp,
          suspicious: false,
          issues: []
        })
      }

      const connection = tlsHandshakes.get(key)
      
      // Extract TLS information from packet info
      if (packet.info?.includes('Server Hello')) {
        const serverNameMatch = packet.info.match(/Server Name: ([^\s,]+)/)
        if (serverNameMatch) connection.serverName = serverNameMatch[1]
        
        const cipherMatch = packet.info.match(/Cipher Suite: ([^,]+)/)
        if (cipherMatch) connection.cipherSuite = cipherMatch[1]
        
        const versionMatch = packet.info.match(/TLS v(\d+\.\d+)/)
        if (versionMatch) connection.tlsVersion = versionMatch[1]
      }

      // Detect suspicious TLS patterns
      if (packet.info?.includes('TLS v1.0') || packet.info?.includes('SSL v3.0')) {
        connection.suspicious = true
        connection.issues.push('Outdated TLS/SSL version')
      }

      if (packet.info?.includes('NULL') || packet.info?.includes('EXPORT')) {
        connection.suspicious = true
        connection.issues.push('Weak cipher suite')
      }

      // Self-signed or invalid certificate detection
      if (packet.info?.includes('Certificate') && packet.info?.includes('self-signed')) {
        connection.suspicious = true
        connection.issues.push('Self-signed certificate')
      }
    }
  })

  tlsHandshakes.forEach(connection => {
    tlsConnections.push(connection)
  })

  return tlsConnections
}

export function analyzeDnsTraffic(packets: any[]): DeepPacketInspection['dnsAnalysis'] {
  const queries: DeepPacketInspection['dnsAnalysis']['queries'] = []
  const suspiciousDomains: Set<string> = new Set()
  const dgaDetection: DeepPacketInspection['dnsAnalysis']['dgaDetection'] = []
  const dohDetection: Map<string, { requests: number; domains: Set<string> }> = new Map()

  // Known suspicious TLDs and patterns
  const suspiciousTlds = ['.tk', '.ml', '.ga', '.cf', '.bit', '.onion', '.i2p']
  const suspiciousPatterns = [
    /^[a-z0-9]{20,}\./, // Long random-looking domains
    /\d{1,3}-\d{1,3}-\d{1,3}-\d{1,3}/, // IP-like patterns
    /^[bcdfghjklmnpqrstvwxz]{10,}\./, // Consonant-heavy domains (DGA-like)
  ]

  packets.forEach(packet => {
    if (packet.protocol === 'DNS' || packet.info?.includes('DNS')) {
      const queryMatch = packet.info?.match(/Query: (.+?) Type: (\w+)/)
      if (queryMatch) {
        const [, domain, type] = queryMatch
        const query = {
          domain,
          type,
          queryTime: packet.timestamp,
          suspicious: false,
          reasons: [] as string[]
        }

        // Check for suspicious domains
        if (suspiciousTlds.some(tld => domain.endsWith(tld))) {
          query.suspicious = true
          query.reasons.push('Suspicious TLD')
          suspiciousDomains.add(domain)
        }

        if (suspiciousPatterns.some(pattern => pattern.test(domain))) {
          query.suspicious = true
          query.reasons.push('Suspicious domain pattern')
          suspiciousDomains.add(domain)
        }

        // DGA detection using entropy and character distribution
        const dgaScore = calculateDgaScore(domain)
        if (dgaScore > 0.7) {
          dgaDetection.push({
            domain,
            score: dgaScore,
            features: {
              entropy: calculateEntropy(domain),
              consonantRatio: calculateConsonantRatio(domain),
              digitRatio: calculateDigitRatio(domain),
              lengthScore: domain.length > 15 ? 1 : domain.length / 15
            }
          })
        }

        queries.push(query)
      }

      // DNS over HTTPS detection (port 443 DNS-like traffic)
      if (packet.destination?.includes(':443') && packet.info?.includes('DNS')) {
        const ip = packet.destination.split(':')[0]
        if (!dohDetection.has(ip)) {
          dohDetection.set(ip, { requests: 0, domains: new Set() })
        }
        const dohData = dohDetection.get(ip)!
        dohData.requests++
        if (queryMatch) {
          dohData.domains.add(queryMatch[1])
        }
      }
    }
  })

  return {
    queries,
    suspiciousDomains: Array.from(suspiciousDomains),
    dgaDetection,
    dohDetection: Array.from(dohDetection.entries()).map(([ip, data]) => ({
      ip,
      requests: data.requests,
      domains: Array.from(data.domains)
    }))
  }
}

export function detectProtocolTunneling(packets: any[]): DeepPacketInspection['protocolTunneling'] {
  const tunneling: DeepPacketInspection['protocolTunneling'] = []
  const suspiciousConnections = new Map<string, any>()

  packets.forEach((packet, index) => {
    const key = `${packet.source}-${packet.destination}`
    
    // HTTP over DNS detection
    if (packet.protocol === 'DNS' && packet.size > 512) {
      if (packet.info?.includes('TXT') || packet.info?.includes('CNAME')) {
        tunneling.push({
          type: 'http_over_dns',
          srcIp: packet.source,
          destIp: packet.destination,
          confidence: 0.8,
          evidence: ['Large DNS packet', 'TXT/CNAME record'],
          packets: [index]
        })
      }
    }

    // SSH tunneling detection (unusual SSH traffic patterns)
    if (packet.protocol === 'SSH' || packet.info?.includes('SSH')) {
      if (!suspiciousConnections.has(key)) {
        suspiciousConnections.set(key, { packets: 0, bytes: 0, duration: 0 })
      }
      const conn = suspiciousConnections.get(key)!
      conn.packets++
      conn.bytes += packet.size || 0
    }

    // ICMP tunneling detection
    if (packet.protocol === 'ICMP' && packet.size > 100) {
      tunneling.push({
        type: 'icmp_tunneling',
        srcIp: packet.source,
        destIp: packet.destination,
        confidence: 0.7,
        evidence: ['Large ICMP packet'],
        packets: [index]
      })
    }
  })

  // Analyze SSH connections for tunneling patterns
  suspiciousConnections.forEach((conn, key) => {
    if (conn.packets > 100 && conn.bytes / conn.packets > 1000) {
      const [srcIp, destIp] = key.split('-')
      tunneling.push({
        type: 'ssh_tunneling',
        srcIp,
        destIp,
        confidence: 0.9,
        evidence: ['High packet count', 'Large average packet size'],
        packets: []
      })
    }
  })

  return tunneling
}

// Advanced Threat Detection Functions
export function detectMalwareC2(packets: any[]): ThreatIndicator[] {
  const indicators: ThreatIndicator[] = []
  const connections = new Map<string, any>()

  // Known malware C2 patterns
  const c2Patterns = [
    /\/[a-f0-9]{32}/, // MD5-like paths
    /\/[a-zA-Z0-9+/]{40,}={0,2}/, // Base64-like paths
    /\/(config|update|check|ping|beacon)\.php/, // Common C2 endpoints
  ]

  const suspiciousUserAgents = [
    'Mozilla/4.0', // Outdated user agents
    'curl/', 'wget/', 'python-requests/',
    '', // Empty user agents
  ]

  packets.forEach((packet, index) => {
    if (packet.protocol === 'HTTP' && packet.info) {
      const key = `${packet.source}-${packet.destination}`
      
      if (!connections.has(key)) {
        connections.set(key, { requests: 0, patterns: new Set(), packetIndices: [] })
      }
      const conn = connections.get(key)!
      conn.requests++
      conn.packetIndices.push(index)

      // Check for C2 patterns in URL
      if (c2Patterns.some(pattern => pattern.test(packet.info))) {
        conn.patterns.add('suspicious_url_pattern')
      }

      // Check for suspicious user agents
      if (suspiciousUserAgents.some(ua => packet.info.includes(`User-Agent: ${ua}`))) {
        conn.patterns.add('suspicious_user_agent')
      }

      // Regular communication intervals (beaconing)
      if (conn.requests > 5 && conn.requests % 5 === 0) {
        conn.patterns.add('regular_beaconing')
      }
    }
  })

  connections.forEach((conn, key) => {
    if (conn.patterns.size >= 2) {
      const [source, destination] = key.split('-')
      indicators.push({
        type: 'malware_c2',
        severity: conn.patterns.has('regular_beaconing') ? 'high' : 'medium',
        confidence: Math.min(0.9, conn.patterns.size * 0.3),
        description: `Suspected malware C2 communication: ${Array.from(conn.patterns).join(', ')}`,
        source,
        destination,
        indicators: { patterns: Array.from(conn.patterns), requests: conn.requests },
        mitre: {
          technique: 'T1071.001',
          tactic: 'Command and Control',
          description: 'Application Layer Protocol: Web Protocols'
        },
        timestamp: Date.now(),
        packets: conn.packetIndices
      })
    }
  })

  return indicators
}

export function detectPortScanning(packets: any[]): ThreatIndicator[] {
  const indicators: ThreatIndicator[] = []
  const scanners = new Map<string, any>()

  packets.forEach((packet, index) => {
    if (packet.protocol === 'TCP' && packet.info?.includes('SYN')) {
      const source = packet.source
      
      if (!scanners.has(source)) {
        scanners.set(source, { 
          targets: new Set(), 
          ports: new Set(), 
          packets: [],
          timeWindow: { start: packet.timestamp, end: packet.timestamp }
        })
      }

      const scanner = scanners.get(source)!
      scanner.targets.add(packet.destination)
      
      const portMatch = packet.info.match(/→ (\d+)/)
      if (portMatch) {
        scanner.ports.add(parseInt(portMatch[1]))
      }
      
      scanner.packets.push(index)
      scanner.timeWindow.end = packet.timestamp
    }
  })

  scanners.forEach((scanner, source) => {
    const targetCount = scanner.targets.size
    const portCount = scanner.ports.size
    const timeSpan = scanner.timeWindow.end - scanner.timeWindow.start

    // Port scan detection criteria
    if ((targetCount > 5 && portCount > 10) || (targetCount > 20) || (portCount > 50)) {
      let severity: ThreatIndicator['severity'] = 'low'
      if (targetCount > 50 || portCount > 100) severity = 'high'
      else if (targetCount > 10 || portCount > 25) severity = 'medium'

      indicators.push({
        type: 'port_scan',
        severity,
        confidence: Math.min(0.95, (targetCount + portCount) / 100),
        description: `Port scanning detected: ${targetCount} targets, ${portCount} ports in ${Math.round(timeSpan)}ms`,
        source,
        indicators: { 
          targets: targetCount, 
          ports: portCount, 
          timeSpan,
          packetsCount: scanner.packets.length 
        },
        mitre: {
          technique: 'T1046',
          tactic: 'Discovery',
          description: 'Network Service Scanning'
        },
        timestamp: Date.now(),
        packets: scanner.packets.slice(0, 50) // Limit packet references
      })
    }
  })

  return indicators
}

export function detectDataExfiltration(packets: any[], flows: NetworkFlow[]): ThreatIndicator[] {
  const indicators: ThreatIndicator[] = []

  flows.forEach(flow => {
    const dataRateMbps = (flow.bytes * 8) / (flow.duration / 1000) / 1000000
    const isLargeTransfer = flow.bytes > 100 * 1024 * 1024 // 100MB
    const isHighDataRate = dataRateMbps > 10 // 10 Mbps
    const isOutbound = flow.flowDirection === 'outbound'
    const isUnusualTime = true // Simplified - would check against business hours

    if (isLargeTransfer && isOutbound && (isHighDataRate || isUnusualTime)) {
      indicators.push({
        type: 'data_exfiltration',
        severity: isLargeTransfer && isHighDataRate ? 'critical' : 'high',
        confidence: 0.8,
        description: `Suspected data exfiltration: ${Math.round(flow.bytes / 1024 / 1024)}MB transferred at ${dataRateMbps.toFixed(2)} Mbps`,
        source: flow.srcIp,
        destination: flow.destIp,
        indicators: {
          bytes: flow.bytes,
          dataRateMbps,
          duration: flow.duration,
          direction: flow.flowDirection
        },
        mitre: {
          technique: 'T1041',
          tactic: 'Exfiltration',
          description: 'Exfiltration Over C2 Channel'
        },
        timestamp: flow.startTime,
        packets: []
      })
    }
  })

  return indicators
}

// Network Flow Analysis Functions
export function generateNetworkFlows(packets: any[]): NetworkFlow[] {
  const flows: NetworkFlow[] = []
  const flowMap = new Map<string, any>()

  packets.forEach((packet, index) => {
    if (!packet.source || !packet.destination) return

    const srcPortMatch = packet.info?.match(/(\d+) →/)
    const destPortMatch = packet.info?.match(/→ (\d+)/)
    const srcPort = srcPortMatch ? parseInt(srcPortMatch[1]) : 0
    const destPort = destPortMatch ? parseInt(destPortMatch[1]) : 0

    const flowId = `${packet.source}:${srcPort}-${packet.destination}:${destPort}-${packet.protocol}`
    
    if (!flowMap.has(flowId)) {
      flowMap.set(flowId, {
        flowId,
        protocol: packet.protocol,
        srcIp: packet.source,
        srcPort,
        destIp: packet.destination,
        destPort,
        startTime: packet.timestamp,
        endTime: packet.timestamp,
        packets: 0,
        bytes: 0,
        packetSizes: []
      })
    }

    const flow = flowMap.get(flowId)!
    flow.packets++
    flow.bytes += packet.size || 0
    flow.endTime = packet.timestamp
    flow.packetSizes.push(packet.size || 0)
  })

  flowMap.forEach(flowData => {
    const duration = flowData.endTime - flowData.startTime || 1
    const avgPacketSize = flowData.bytes / flowData.packets
    const dataRate = (flowData.bytes * 8) / (duration / 1000) // bits per second

    // Determine flow direction (simplified)
    let flowDirection: NetworkFlow['flowDirection'] = 'internal'
    if (isExternalIp(flowData.srcIp) && !isExternalIp(flowData.destIp)) {
      flowDirection = 'inbound'
    } else if (!isExternalIp(flowData.srcIp) && isExternalIp(flowData.destIp)) {
      flowDirection = 'outbound'
    }

    // Detect suspicious flows
    const suspicious = detectSuspiciousFlow(flowData)

    flows.push({
      flowId: flowData.flowId,
      protocol: flowData.protocol,
      srcIp: flowData.srcIp,
      srcPort: flowData.srcPort,
      destIp: flowData.destIp,
      destPort: flowData.destPort,
      startTime: flowData.startTime,
      endTime: flowData.endTime,
      duration,
      packets: flowData.packets,
      bytes: flowData.bytes,
      avgPacketSize,
      dataRate,
      flowDirection,
      suspicious: suspicious.isSuspicious,
      suspiciousReasons: suspicious.reasons
    })
  })

  return flows.sort((a, b) => b.bytes - a.bytes)
}

// Helper Functions
function calculateDgaScore(domain: string): number {
  const entropy = calculateEntropy(domain.split('.')[0])
  const consonantRatio = calculateConsonantRatio(domain)
  const lengthScore = domain.length > 15 ? 1 : 0
  const digitRatio = calculateDigitRatio(domain)
  
  return (entropy * 0.4 + consonantRatio * 0.3 + lengthScore * 0.2 + digitRatio * 0.1)
}

function calculateEntropy(str: string): number {
  const freq: { [char: string]: number } = {}
  str.split('').forEach(char => freq[char] = (freq[char] || 0) + 1)
  
  let entropy = 0
  const length = str.length
  Object.values(freq).forEach(count => {
    const p = count / length
    entropy -= p * Math.log2(p)
  })
  
  return entropy / Math.log2(length) // Normalized entropy
}

function calculateConsonantRatio(str: string): number {
  const consonants = str.toLowerCase().match(/[bcdfghjklmnpqrstvwxz]/g) || []
  return consonants.length / str.length
}

function calculateDigitRatio(str: string): number {
  const digits = str.match(/\d/g) || []
  return digits.length / str.length
}

function isExternalIp(ip: string): boolean {
  const privateRanges = [
    /^10\./,
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
    /^192\.168\./,
    /^127\./,
    /^169\.254\./
  ]
  return !privateRanges.some(range => range.test(ip))
}

function detectSuspiciousFlow(flow: any): { isSuspicious: boolean; reasons: string[] } {
  const reasons: string[] = []
  
  if (flow.bytes > 100 * 1024 * 1024) reasons.push('Large data transfer')
  if (flow.packets > 10000) reasons.push('High packet count')
  if (flow.dataRate > 50000000) reasons.push('High data rate') // 50 Mbps
  if (flow.avgPacketSize < 64 || flow.avgPacketSize > 1500) reasons.push('Unusual packet size')
  
  return { isSuspicious: reasons.length > 0, reasons }
}

// Geolocation and ASN lookup (mock implementation)
export async function enrichWithGeolocation(flows: NetworkFlow[]): Promise<void> {
  // In a real implementation, this would query geolocation APIs
  const mockGeoData = {
    country: 'Unknown',
    city: 'Unknown',
    asn: 0,
    org: 'Unknown'
  }

  flows.forEach(flow => {
    if (isExternalIp(flow.srcIp)) {
      flow.geoData = {
        srcCountry: mockGeoData.country,
        srcCity: mockGeoData.city,
        asn: {
          srcAsn: mockGeoData.asn,
          srcOrg: mockGeoData.org
        }
      }
    }
    
    if (isExternalIp(flow.destIp)) {
      flow.geoData = {
        ...flow.geoData,
        destCountry: mockGeoData.country,
        destCity: mockGeoData.city,
        asn: {
          ...flow.geoData?.asn,
          destAsn: mockGeoData.asn,
          destOrg: mockGeoData.org
        }
      }
    }
  })
}
