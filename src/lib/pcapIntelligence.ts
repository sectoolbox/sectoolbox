// Intelligence Engine - Auto-detect interesting findings in PCAP data

export interface Finding {
  id: string;
  type: 'flag' | 'credential' | 'secret' | 'pattern' | 'security' | 'anomaly';
  severity: 'critical' | 'warning' | 'info';
  title: string;
  description: string;
  evidence: string[];
  frames: number[];
  category: string;
  autoExtracted?: string; // Decoded/extracted value
}

export function analyzeIntelligence(packets: any[], httpSessions: any[], dnsQueries: any[], conversations: any[]): Finding[] {
  const findings: Finding[] = [];
  let findingId = 0;

  // 1. FLAG DETECTION
  packets.forEach((pkt, idx) => {
    const searchIn = [
      pkt.info,
      pkt.httpUri,
      pkt.httpHost,
      pkt.dnsQuery,
      JSON.stringify(pkt.rawLayers)
    ].join(' ');

    // CTF flag patterns
    const flagPatterns = [
      /CTF\{[^}]+\}/gi,
      /FLAG\{[^}]+\}/gi,
      /flag\{[^}]+\}/gi,
      /flag=[a-zA-Z0-9_-]+/gi,
      /[a-f0-9]{32,64}/gi // MD5/SHA hashes often used as flags
    ];

    flagPatterns.forEach(pattern => {
      const matches = searchIn.match(pattern);
      if (matches) {
        matches.forEach(match => {
          findings.push({
            id: `finding-${findingId++}`,
            type: 'flag',
            severity: 'critical',
            title: 'Potential Flag Detected',
            description: `Found flag-like pattern in packet ${pkt.index}`,
            evidence: [match],
            frames: [pkt.index],
            category: 'CTF Flags'
          });
        });
      }
    });

    // Base64 encoded data (potential hidden flags)
    const base64Pattern = /[A-Za-z0-9+/]{20,}={0,2}/g;
    const base64Matches = searchIn.match(base64Pattern);
    if (base64Matches) {
      base64Matches.forEach(b64 => {
        try {
          const decoded = atob(b64);
          if (decoded.includes('flag') || decoded.includes('CTF') || decoded.includes('secret')) {
            findings.push({
              id: `finding-${findingId++}`,
              type: 'flag',
              severity: 'critical',
              title: 'Base64 Encoded Flag',
              description: `Decoded Base64 in packet ${pkt.index}`,
              evidence: [b64, `Decoded: ${decoded}`],
              frames: [pkt.index],
              category: 'Encoded Data',
              autoExtracted: decoded
            });
          }
        } catch (e) {
          // Not valid base64
        }
      });
    }
  });

  // 2. CREDENTIAL DETECTION
  httpSessions.forEach(session => {
    // HTTP Basic Auth
    if (session.authorization) {
      findings.push({
        id: `finding-${findingId++}`,
        type: 'credential',
        severity: 'critical',
        title: 'Unencrypted HTTP Authentication',
        description: `Cleartext credentials sent in HTTP request`,
        evidence: ['Authorization header present', `To: ${session.host || session.destination}`],
        frames: [session.frameNumber],
        category: 'Credentials'
      });
    }

    // Cookies with sensitive data
    if (session.cookie && (session.cookie.includes('session') || session.cookie.includes('token') || session.cookie.includes('auth'))) {
      findings.push({
        id: `finding-${findingId++}`,
        type: 'secret',
        severity: 'warning',
        title: 'Session Cookie Detected',
        description: `HTTP cookie in cleartext`,
        evidence: [session.cookie.substring(0, 100)],
        frames: [session.frameNumber],
        category: 'Session Data'
      });
    }

    // Look for password/key/secret in URLs or bodies
    const searchStr = `${session.method} ${session.uri} ${session.host}`.toLowerCase();
    if (searchStr.includes('password') || searchStr.includes('apikey') || searchStr.includes('secret') || searchStr.includes('token')) {
      findings.push({
        id: `finding-${findingId++}`,
        type: 'secret',
        severity: 'warning',
        title: 'Sensitive Parameter in URL',
        description: `URL contains sensitive keyword`,
        evidence: [`${session.method} ${session.uri}`],
        frames: [session.frameNumber],
        category: 'Secrets'
      });
    }
  });

  // 3. SUSPICIOUS DOMAINS
  const suspiciousDomains = ['pastebin', 'ngrok', 'duckdns', 'no-ip', 'freenom', 'tk', '.onion'];
  dnsQueries.forEach(dns => {
    if (dns.query) {
      const queryLower = dns.query.toLowerCase();
      suspiciousDomains.forEach(suspicious => {
        if (queryLower.includes(suspicious)) {
          findings.push({
            id: `finding-${findingId++}`,
            type: 'security',
            severity: 'warning',
            title: 'Suspicious Domain Query',
            description: `DNS query to potentially suspicious domain`,
            evidence: [dns.query, dns.answer ? `Resolved to: ${dns.answer}` : 'No response'],
            frames: [dns.frameNumber],
            category: 'Network Security'
          });
        }
      });
    }
  });

  // 4. PORT SCANS
  const portsBySource = new Map<string, Set<number>>();
  packets.forEach(pkt => {
    if (pkt.tcpFlags && pkt.source && pkt.destPort) {
      const ports = portsBySource.get(pkt.source) || new Set();
      ports.add(pkt.destPort);
      portsBySource.set(pkt.source, ports);
    }
  });

  portsBySource.forEach((ports, source) => {
    if (ports.size > 20) {
      findings.push({
        id: `finding-${findingId++}`,
        type: 'security',
        severity: 'critical',
        title: 'Port Scan Detected',
        description: `${source} scanned ${ports.size} different ports`,
        evidence: [`Ports: ${Array.from(ports).slice(0, 10).join(', ')}...`],
        frames: [], // Multiple frames
        category: 'Network Security'
      });
    }
  });

  // 5. HIGH VOLUME TRAFFIC
  conversations.forEach(conv => {
    if (conv.packets > 1000) {
      findings.push({
        id: `finding-${findingId++}`,
        type: 'anomaly',
        severity: 'warning',
        title: 'High Volume Traffic',
        description: `Unusually high packet count between two hosts`,
        evidence: [
          `${conv.source} ↔ ${conv.destination}`,
          `${conv.packets} packets`,
          `${(conv.bytes / 1024 / 1024).toFixed(2)} MB`
        ],
        frames: [],
        category: 'Traffic Patterns'
      });
    }
  });

  // 6. FAILED CONNECTIONS
  const failedConns = packets.filter(pkt =>
    pkt.tcpFlags && (pkt.info?.includes('RST') || pkt.info?.includes('refused'))
  );

  if (failedConns.length > 10) {
    findings.push({
      id: `finding-${findingId++}`,
      type: 'anomaly',
      severity: 'info',
      title: 'Multiple Failed Connections',
      description: `${failedConns.length} connection attempts failed`,
      evidence: failedConns.slice(0, 5).map(p => `Frame ${p.index}: ${p.source} → ${p.destination}`),
      frames: failedConns.slice(0, 10).map(p => p.index),
      category: 'Connection Issues'
    });
  }

  // 7. UNENCRYPTED PROTOCOLS
  const unencryptedHttp = httpSessions.filter(s => s.method && !s.host?.includes('https'));
  if (unencryptedHttp.length > 0) {
    findings.push({
      id: `finding-${findingId++}`,
      type: 'security',
      severity: 'warning',
      title: 'Unencrypted HTTP Traffic',
      description: `${unencryptedHttp.length} HTTP requests sent without encryption`,
      evidence: unencryptedHttp.slice(0, 3).map(s => `${s.method} ${s.host || s.destination}`),
      frames: unencryptedHttp.slice(0, 5).map(s => s.frameNumber),
      category: 'Encryption'
    });
  }

  // 8. LARGE DATA TRANSFERS
  conversations.forEach(conv => {
    const sizeMB = conv.bytes / 1024 / 1024;
    if (sizeMB > 5) {
      findings.push({
        id: `finding-${findingId++}`,
        type: 'pattern',
        severity: 'info',
        title: 'Large Data Transfer',
        description: `${sizeMB.toFixed(2)} MB transferred`,
        evidence: [
          `${conv.source} → ${conv.destination}`,
          `${conv.packets} packets`,
          `Protocols: ${conv.protocols.join(', ')}`
        ],
        frames: [],
        category: 'Data Transfer'
      });
    }
  });

  return findings.sort((a, b) => {
    const severityOrder = { critical: 0, warning: 1, info: 2 };
    return severityOrder[a.severity] - severityOrder[b.severity];
  });
}

export function extractStringsFromPackets(packets: any[]): string[] {
  const strings = new Set<string>();

  packets.forEach(pkt => {
    // Extract from info field
    if (pkt.info) extractPrintableStrings(pkt.info).forEach(s => strings.add(s));

    // Extract from HTTP data
    if (pkt.httpUri) strings.add(pkt.httpUri);
    if (pkt.httpHost) strings.add(pkt.httpHost);
    if (pkt.httpUserAgent) strings.add(pkt.httpUserAgent);

    // Extract from DNS
    if (pkt.dnsQuery) strings.add(pkt.dnsQuery);
  });

  return Array.from(strings).filter(s => s.length >= 4);
}

function extractPrintableStrings(text: string): string[] {
  const strings: string[] = [];
  const matches = text.match(/[a-zA-Z0-9_\-\.]{4,}/g);
  if (matches) strings.push(...matches);
  return strings;
}

export function groupPacketsByProtocol(packets: any[]): Record<string, any[]> {
  const groups: Record<string, any[]> = {};

  packets.forEach(pkt => {
    const proto = pkt.protocol || 'Unknown';
    if (!groups[proto]) groups[proto] = [];
    groups[proto].push(pkt);
  });

  return groups;
}

export function groupPacketsByConversation(packets: any[]): any[] {
  const convMap = new Map<string, any>();

  packets.forEach(pkt => {
    if (pkt.source && pkt.destination && pkt.source !== 'N/A' && pkt.destination !== 'N/A') {
      const key = `${pkt.source}:${pkt.srcPort || 0}-${pkt.destination}:${pkt.destPort || 0}`;

      if (!convMap.has(key)) {
        convMap.set(key, {
          source: pkt.source,
          destination: pkt.destination,
          srcPort: pkt.srcPort,
          destPort: pkt.destPort,
          packets: [],
          protocol: pkt.protocol,
          firstTime: pkt.timestamp,
          lastTime: pkt.timestamp
        });
      }

      const conv = convMap.get(key);
      conv.packets.push(pkt);
      conv.lastTime = pkt.timestamp;
    }
  });

  return Array.from(convMap.values());
}
