// Parse raw tshark JSON dump into UI-friendly format

export function parseTsharkPackets(rawPackets: any[]): any {
  const packets: any[] = [];
  const protocolCounts = new Map<string, number>();
  const httpSessions: any[] = [];
  const dnsQueries: any[] = [];
  const conversations = new Map<string, any>();
  const endpoints = new Set<string>();

  rawPackets.forEach((pkt, index) => {
    const layers = pkt._source?.layers || {};

    // Extract core packet info
    const frameNum = layers.frame?.['frame.number'] || (index + 1);
    const timestamp = layers.frame?.['frame.time'] || new Date().toISOString();
    const size = parseInt(layers.frame?.['frame.len'] || 0);
    const protocols = layers.frame?.['frame.protocols'] || '';

    // IP addresses
    const ipSrc = layers.ip?.['ip.src'] || layers.ipv6?.['ipv6.src'] || null;
    const ipDst = layers.ip?.['ip.dst'] || layers.ipv6?.['ipv6.dst'] || null;

    // Ports (tshark returns as arrays, extract first element)
    const srcPortRaw = layers.tcp?.['tcp.srcport'] || layers.udp?.['udp.srcport'];
    const destPortRaw = layers.tcp?.['tcp.dstport'] || layers.udp?.['udp.dstport'];
    const srcPort = Array.isArray(srcPortRaw) ? parseInt(srcPortRaw[0]) : (srcPortRaw ? parseInt(srcPortRaw) : null);
    const destPort = Array.isArray(destPortRaw) ? parseInt(destPortRaw[0]) : (destPortRaw ? parseInt(destPortRaw) : null);

    // Determine primary protocol
    let protocol = 'Unknown';
    if (layers.http) protocol = 'HTTP';
    else if (layers.tls) protocol = 'TLS';
    else if (layers.dns) protocol = 'DNS';
    else if (layers.ssh) protocol = 'SSH';
    else if (layers.ftp) protocol = 'FTP';
    else if (layers.smtp) protocol = 'SMTP';
    else if (layers.tcp) protocol = 'TCP';
    else if (layers.udp) protocol = 'UDP';
    else if (layers.icmp) protocol = 'ICMP';
    else if (layers.arp) protocol = 'ARP';
    else if (layers.ip) protocol = 'IPv4';
    else if (layers.ipv6) protocol = 'IPv6';

    protocolCounts.set(protocol, (protocolCounts.get(protocol) || 0) + 1);

    // Build packet info string
    let info = '';
    if (layers.http) {
      const method = layers.http['http.request.method'];
      const uri = layers.http['http.request.uri'];
      const status = layers.http['http.response.code'];
      if (method && uri) info = `${method} ${uri}`;
      else if (status) info = `HTTP/${layers.http['http.response.version'] || '1.1'} ${status}`;
    } else if (layers.dns) {
      const query = layers.dns['dns.qry.name'];
      const response = layers.dns['dns.a'] || layers.dns['dns.aaaa'];
      if (query) info = `Standard query ${query}`;
      else if (response) info = `Standard query response ${response}`;
    } else if (layers.tcp) {
      const flags = [];
      if (layers.tcp['tcp.flags.syn'] === '1') flags.push('SYN');
      if (layers.tcp['tcp.flags.ack'] === '1') flags.push('ACK');
      if (layers.tcp['tcp.flags.fin'] === '1') flags.push('FIN');
      if (layers.tcp['tcp.flags.reset'] === '1') flags.push('RST');
      info = `${srcPort} → ${destPort} [${flags.join(', ') || 'TCP'}]`;
    } else if (layers.udp) {
      info = `${srcPort} → ${destPort}`;
    } else {
      info = protocols || protocol;
    }

    // Color coding (Wireshark-style)
    let colorRule = 'default';
    if (layers.http?.['http.request.method'] === 'GET') colorRule = 'http-get';
    else if (layers.http?.['http.request.method'] === 'POST') colorRule = 'http-post';
    else if (layers.http) colorRule = 'http';
    else if (layers.dns) colorRule = 'dns';
    else if (layers.tcp?.['tcp.flags.syn'] === '1') colorRule = 'tcp-syn';
    else if (layers.tcp) colorRule = 'tcp';
    else if (layers.udp) colorRule = 'udp';
    else if (layers.icmp) colorRule = 'icmp';
    else if (layers.arp) colorRule = 'arp';

    // Track endpoints
    if (ipSrc) endpoints.add(ipSrc);
    if (ipDst) endpoints.add(ipDst);

    // Track conversations
    if (ipSrc && ipDst) {
      const convKey = `${ipSrc}:${srcPort || 0}-${ipDst}:${destPort || 0}`;
      const conv = conversations.get(convKey) || {
        source: ipSrc,
        destination: ipDst,
        srcPort: srcPort,
        destPort: destPort,
        packets: 0,
        bytes: 0,
        protocols: new Set(),
        firstSeen: timestamp,
        tcpStream: layers.tcp?.['tcp.stream'] // Store the first packet's stream ID
      };
      conv.packets++;
      conv.bytes += size;
      conv.protocols.add(protocol);
      conv.lastSeen = timestamp;
      conversations.set(convKey, conv);
    }

    // Extract HTTP sessions
    if (layers.http) {
      httpSessions.push({
        frameNumber: frameNum,
        timestamp,
        source: ipSrc,
        destination: ipDst,
        method: layers.http['http.request.method'],
        url: layers.http['http.request.uri'],
        host: layers.http['http.host'],
        userAgent: layers.http['http.user_agent'],
        statusCode: layers.http['http.response.code']
      });
    }

    // Extract DNS queries
    if (layers.dns) {
      dnsQueries.push({
        frameNumber: frameNum,
        timestamp,
        source: ipSrc,
        query: layers.dns['dns.qry.name'],
        type: layers.dns['dns.qry.type'],
        answer: layers.dns['dns.a'] || layers.dns['dns.aaaa'] || layers.dns['dns.cname']
      });
    }

    // Store parsed packet
    packets.push({
      index: frameNum,
      timestamp,
      size,
      capturedLength: parseInt(layers.frame?.['frame.cap_len'] || size),
      protocol,
      protocols,
      source: ipSrc || 'N/A',
      destination: ipDst || 'N/A',
      srcPort,
      destPort,
      info,
      colorRule,

      // TCP specifics
      tcpStream: layers.tcp?.['tcp.stream'],
      tcpFlags: layers.tcp?.['tcp.flags'],
      tcpSeq: layers.tcp?.['tcp.seq'],
      tcpAck: layers.tcp?.['tcp.ack'],

      // HTTP specifics
      httpMethod: layers.http?.['http.request.method'],
      httpUri: layers.http?.['http.request.uri'],
      httpHost: layers.http?.['http.host'],
      httpStatusCode: layers.http?.['http.response.code'],

      // DNS specifics
      dnsQuery: layers.dns?.['dns.qry.name'],

      // TLS specifics
      tlsSNI: layers.tls?.['tls.handshake.extensions_server_name'],

      // RAW layer data for detail tree
      rawLayers: layers,

      // Hex data
      data: layers.frame?.['frame.raw'] || layers.frame_raw?.[0]
    });
  });

  // Convert conversations to array
  const conversationsList = Array.from(conversations.values()).map(conv => ({
    ...conv,
    protocols: Array.from(conv.protocols),
    duration: new Date(conv.lastSeen).getTime() - new Date(conv.firstSeen).getTime()
  }));

  // Protocol statistics
  const protocolDetails = Array.from(protocolCounts.entries())
    .map(([name, count]) => ({
      name,
      count,
      percentage: parseFloat(((count / packets.length) * 100).toFixed(1))
    }))
    .sort((a, b) => b.count - a.count);

  return {
    packets,
    metadata: {
      totalPackets: packets.length,
      format: 'pcap'
    },
    protocols: {
      details: protocolDetails,
      summary: Object.fromEntries(protocolCounts)
    },
    httpSessions,
    dnsQueries,
    conversations: conversationsList,
    endpoints: Array.from(endpoints)
  };
}

// Detect suspicious activity
export function detectSuspiciousActivity(packets: any[], conversations: any[]): any[] {
  const threats: any[] = [];

  // Port scan detection
  const portScans = new Map<string, Set<number>>();
  packets.forEach(pkt => {
    if (pkt.tcpFlags && pkt.srcPort) {
      const ports = portScans.get(pkt.source) || new Set();
      if (pkt.destPort) ports.add(pkt.destPort);
      portScans.set(pkt.source, ports);
    }
  });

  portScans.forEach((ports, ip) => {
    if (ports.size > 20) {
      threats.push({
        type: 'Port Scan Detected',
        severity: 'high',
        confidence: 90,
        description: `${ip} contacted ${ports.size} different ports`,
        source: ip
      });
    }
  });

  // High volume
  conversations.forEach(conv => {
    if (conv.packets > 1000) {
      threats.push({
        type: 'High Volume Traffic',
        severity: 'medium',
        confidence: 75,
        description: `${conv.packets} packets between ${conv.source} and ${conv.destination}`,
        source: conv.source,
        destination: conv.destination
      });
    }
  });

  return threats;
}
