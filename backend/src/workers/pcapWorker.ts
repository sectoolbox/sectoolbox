import { spawn } from 'child_process';
import { getPcapQueue } from '../services/queue.js';
import { saveResults } from '../services/storage.js';
import { emitJobProgress, emitJobCompleted, emitJobFailed } from '../services/websocket.js';
import { promises as fs } from 'fs';
import { join, dirname } from 'path';

const queue = getPcapQueue();

queue.process(async (job) => {
  const { jobId, filePath, depth, filename } = job.data;

  emitJobProgress(jobId, {
    progress: 5,
    message: 'Starting deep PCAP analysis...',
    status: 'processing'
  });

  try {
    // Try tshark first for comprehensive analysis
    const useTshark = await checkTsharkAvailable();

    if (useTshark) {
      console.log('✅ Using tshark for deep analysis');
      const results = await analyzeWithTshark(filePath, filename, jobId, depth);
      return results;
    } else {
      console.log('⚠️ tshark not available, using enhanced custom parser');
      const results = await analyzeWithCustomParser(filePath, filename, jobId, depth);
      return results;
    }
  } catch (error: any) {
    console.error('PCAP analysis error:', error);
    emitJobFailed(jobId, error.message);
    throw error;
  }
});

async function checkTsharkAvailable(): Promise<boolean> {
  return new Promise((resolve) => {
    const tshark = spawn('tshark', ['-v']);
    tshark.on('error', () => resolve(false));
    tshark.on('close', (code) => resolve(code === 0));
  });
}

async function analyzeWithTshark(filePath: string, filename: string, jobId: string, depth: string) {
  emitJobProgress(jobId, {
    progress: 15,
    message: 'Analyzing with tshark (Wireshark)...',
    status: 'processing'
  });

  // Extract comprehensive packet data using tshark
  const tsharkData = await runTshark(filePath, jobId);

  emitJobProgress(jobId, {
    progress: 60,
    message: 'Extracting HTTP sessions...',
    status: 'processing'
  });

  // Extract HTTP traffic
  const httpSessions = await extractHttpWithTshark(filePath);

  emitJobProgress(jobId, {
    progress: 75,
    message: 'Extracting DNS queries...',
    status: 'processing'
  });

  // Extract DNS queries
  const dnsQueries = await extractDnsWithTshark(filePath);

  emitJobProgress(jobId, {
    progress: 90,
    message: 'Generating final report...',
    status: 'processing'
  });

  const results = {
    filename,
    depth,
    method: 'tshark',
    metadata: tsharkData.metadata,
    packets: tsharkData.packets,
    protocols: tsharkData.protocols,
    httpSessions,
    dnsQueries,
    conversations: tsharkData.conversations,
    endpoints: tsharkData.endpoints,
    timestamp: new Date().toISOString()
  };

  await saveResults(jobId, results);
  emitJobCompleted(jobId, results);

  return results;
}

function runTshark(filePath: string, jobId: string): Promise<any> {
  return new Promise((resolve, reject) => {
    // Use tshark to extract detailed packet info as JSON
    const tshark = spawn('tshark', [
      '-r', filePath,
      '-T', 'json',
      '-c', '1000', // Limit to 1000 packets for deep analysis
      '-e', 'frame.number',
      '-e', 'frame.time',
      '-e', 'frame.len',
      '-e', 'ip.src',
      '-e', 'ip.dst',
      '-e', 'tcp.srcport',
      '-e', 'tcp.dstport',
      '-e', 'udp.srcport',
      '-e', 'udp.dstport',
      '-e', 'frame.protocols',
      '-e', 'http.request.method',
      '-e', 'http.request.uri',
      '-e', 'http.response.code',
      '-e', 'dns.qry.name',
      '-e', 'tls.handshake.type'
    ]);

    let stdout = '';
    let stderr = '';

    tshark.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    tshark.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    tshark.on('close', (code) => {
      if (code === 0) {
        try {
          const packets = JSON.parse(stdout);
          const analysis = parseTsharkOutput(packets);
          resolve(analysis);
        } catch (err: any) {
          reject(new Error(`Failed to parse tshark output: ${err.message}`));
        }
      } else {
        reject(new Error(`tshark failed: ${stderr}`));
      }
    });

    tshark.on('error', (error) => {
      reject(new Error(`Failed to run tshark: ${error.message}`));
    });
  });
}

function parseTsharkOutput(packets: any[]): any {
  const metadata = {
    format: 'pcap',
    totalPackets: packets.length,
    linkType: 1, // Ethernet
    fileSize: 0
  };

  const protocolCounts = new Map<string, number>();
  const conversations = new Map<string, any>();
  const endpoints = new Set<string>();

  const parsedPackets = packets.map((pkt, index) => {
    const layers = pkt._source?.layers || {};

    const frameNum = layers['frame.number']?.[0] || index + 1;
    const timestamp = layers['frame.time']?.[0] || new Date().toISOString();
    const size = parseInt(layers['frame.len']?.[0] || '0');
    const protocols = layers['frame.protocols']?.[0] || 'Unknown';

    const ipSrc = layers['ip.src']?.[0];
    const ipDst = layers['ip.dst']?.[0];
    const tcpSrcPort = layers['tcp.srcport']?.[0];
    const tcpDstPort = layers['tcp.dstport']?.[0];
    const udpSrcPort = layers['udp.srcport']?.[0];
    const udpDstPort = layers['udp.dstport']?.[0];

    // Determine primary protocol
    let protocol = 'Unknown';
    if (protocols.includes('http')) protocol = 'HTTP';
    else if (protocols.includes('https') || protocols.includes('tls')) protocol = 'TLS';
    else if (protocols.includes('dns')) protocol = 'DNS';
    else if (protocols.includes('tcp')) protocol = 'TCP';
    else if (protocols.includes('udp')) protocol = 'UDP';
    else if (protocols.includes('icmp')) protocol = 'ICMP';
    else if (protocols.includes('arp')) protocol = 'ARP';

    protocolCounts.set(protocol, (protocolCounts.get(protocol) || 0) + 1);

    // Track endpoints
    if (ipSrc) endpoints.add(ipSrc);
    if (ipDst) endpoints.add(ipDst);

    // Track conversations
    if (ipSrc && ipDst) {
      const convKey = `${ipSrc}-${ipDst}`;
      const conv = conversations.get(convKey) || {
        source: ipSrc,
        destination: ipDst,
        packets: 0,
        bytes: 0,
        protocols: new Set()
      };
      conv.packets++;
      conv.bytes += size;
      conv.protocols.add(protocol);
      conversations.set(convKey, conv);
    }

    return {
      index: frameNum,
      timestamp,
      size,
      protocol,
      source: ipSrc || 'N/A',
      destination: ipDst || 'N/A',
      srcPort: tcpSrcPort || udpSrcPort,
      destPort: tcpDstPort || udpDstPort,
      info: protocols,
      httpMethod: layers['http.request.method']?.[0],
      httpUri: layers['http.request.uri']?.[0],
      httpStatus: layers['http.response.code']?.[0],
      dnsQuery: layers['dns.qry.name']?.[0],
      tlsHandshake: layers['tls.handshake.type']?.[0]
    };
  });

  const protocolDetails = Array.from(protocolCounts.entries()).map(([name, count]) => ({
    name,
    count,
    percentage: parseFloat(((count / metadata.totalPackets) * 100).toFixed(1))
  }));

  const conversationsList = Array.from(conversations.values()).map(conv => ({
    ...conv,
    protocols: Array.from(conv.protocols)
  }));

  return {
    metadata,
    packets: parsedPackets,
    protocols: { details: protocolDetails, summary: protocolDetails },
    conversations: conversationsList,
    endpoints: Array.from(endpoints)
  };
}

function extractHttpWithTshark(filePath: string): Promise<any[]> {
  return new Promise((resolve) => {
    const tshark = spawn('tshark', [
      '-r', filePath,
      '-Y', 'http.request or http.response',
      '-T', 'fields',
      '-e', 'frame.time',
      '-e', 'ip.src',
      '-e', 'ip.dst',
      '-e', 'http.request.method',
      '-e', 'http.request.uri',
      '-e', 'http.response.code',
      '-e', 'http.user_agent',
      '-E', 'header=y',
      '-E', 'separator=|'
    ]);

    let stdout = '';

    tshark.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    tshark.on('close', () => {
      const lines = stdout.trim().split('\n').slice(1); // Skip header
      const sessions = lines.map(line => {
        const [time, src, dst, method, uri, code, userAgent] = line.split('|');
        return {
          timestamp: time,
          source: src,
          destination: dst,
          method: method || 'N/A',
          url: uri || 'N/A',
          statusCode: code || 'N/A',
          userAgent: userAgent || 'N/A'
        };
      }).filter(s => s.method !== 'N/A' || s.statusCode !== 'N/A');

      resolve(sessions);
    });

    tshark.on('error', () => resolve([]));
  });
}

function extractDnsWithTshark(filePath: string): Promise<any[]> {
  return new Promise((resolve) => {
    const tshark = spawn('tshark', [
      '-r', filePath,
      '-Y', 'dns',
      '-T', 'fields',
      '-e', 'frame.time',
      '-e', 'ip.src',
      '-e', 'dns.qry.name',
      '-e', 'dns.qry.type',
      '-e', 'dns.resp.addr',
      '-E', 'header=y',
      '-E', 'separator=|'
    ]);

    let stdout = '';

    tshark.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    tshark.on('close', () => {
      const lines = stdout.trim().split('\n').slice(1); // Skip header
      const queries = lines.map(line => {
        const [time, src, query, type, answer] = line.split('|');
        return {
          timestamp: time,
          source: src,
          query: query || 'N/A',
          type: type || 'A',
          answer: answer || 'N/A'
        };
      }).filter(q => q.query !== 'N/A');

      resolve(queries);
    });

    tshark.on('error', () => resolve([]));
  });
}

async function analyzeWithCustomParser(filePath: string, filename: string, jobId: string, depth: string) {
  emitJobProgress(jobId, {
    progress: 15,
    message: 'Using custom PCAP parser...',
    status: 'processing'
  });

  const fileBuffer = await fs.readFile(filePath);

  emitJobProgress(jobId, {
    progress: 30,
    message: 'Parsing PCAP structure...',
    status: 'processing'
  });

  const analysis = await parseAdvancedPcap(fileBuffer, depth);

  emitJobProgress(jobId, {
    progress: 90,
    message: 'Finalizing analysis...',
    status: 'processing'
  });

  const results = {
    filename,
    depth,
    method: 'custom',
    metadata: analysis.metadata,
    packets: analysis.packets,
    protocols: analysis.protocols,
    httpSessions: analysis.httpSessions,
    dnsQueries: analysis.dnsQueries,
    conversations: analysis.conversations,
    suspiciousActivity: analysis.suspiciousActivity,
    timestamp: new Date().toISOString()
  };

  await saveResults(jobId, results);
  emitJobCompleted(jobId, results);

  return results;
}

async function parseAdvancedPcap(buffer: Buffer, depth: string): Promise<any> {
  const magic = buffer.readUInt32LE(0);
  const isPcap = magic === 0xa1b2c3d4 || magic === 0xd4c3b2a1;
  const isPcapng = buffer.readUInt32BE(0) === 0x0a0d0d0a;

  if (!isPcap) {
    throw new Error('Only standard PCAP format is supported in custom parser. Use tshark for PCAPNG.');
  }

  const metadata = {
    format: 'pcap',
    fileSize: buffer.length,
    totalPackets: 0,
    linkType: buffer.readUInt32LE(20),
    captureStartTime: null as string | null,
    captureEndTime: null as string | null
  };

  const packets: any[] = [];
  const protocolCounts = new Map<string, number>();
  const conversations = new Map<string, any>();
  const httpSessions: any[] = [];
  const dnsQueries: any[] = [];
  const suspiciousActivity: any[] = [];
  const ipAddresses = new Set<string>();

  let offset = 24; // Skip global header
  let packetIndex = 0;
  const maxPackets = depth === 'quick' ? 100 : 10000; // Process up to 10k packets for deep

  while (offset < buffer.length - 16 && packetIndex < maxPackets) {
    try {
      const tsSec = buffer.readUInt32LE(offset);
      const tsUsec = buffer.readUInt32LE(offset + 4);
      const inclLen = buffer.readUInt32LE(offset + 8);
      const origLen = buffer.readUInt32LE(offset + 12);

      if (inclLen > buffer.length || inclLen > 65535) break;

      const dataOffset = offset + 16;
      if (dataOffset + inclLen > buffer.length) break;

      const packetData = buffer.subarray(dataOffset, dataOffset + inclLen);
      const timestamp = new Date(tsSec * 1000 + tsUsec / 1000);

      if (packetIndex === 0) metadata.captureStartTime = timestamp.toISOString();
      metadata.captureEndTime = timestamp.toISOString();

      // Deep packet analysis
      const packetInfo = analyzePacket(packetData, packetIndex, timestamp);

      if (packetInfo) {
        protocolCounts.set(packetInfo.protocol, (protocolCounts.get(packetInfo.protocol) || 0) + 1);

        // Track conversations
        if (packetInfo.ipSrc && packetInfo.ipDst) {
          ipAddresses.add(packetInfo.ipSrc);
          ipAddresses.add(packetInfo.ipDst);

          const convKey = `${packetInfo.ipSrc}:${packetInfo.srcPort || 0}-${packetInfo.ipDst}:${packetInfo.dstPort || 0}`;
          const conv = conversations.get(convKey) || {
            source: packetInfo.ipSrc,
            destination: packetInfo.ipDst,
            srcPort: packetInfo.srcPort,
            dstPort: packetInfo.dstPort,
            packets: 0,
            bytes: 0,
            protocols: new Set(),
            firstSeen: timestamp.toISOString(),
            suspicious: false
          };
          conv.packets++;
          conv.bytes += inclLen;
          conv.protocols.add(packetInfo.protocol);
          conv.lastSeen = timestamp.toISOString();

          // Detect suspicious patterns
          if (conv.packets > 1000) conv.suspicious = true;
          if (packetInfo.dstPort && [22, 23, 3389, 5900].includes(packetInfo.dstPort)) {
            conv.suspicious = true;
            suspiciousActivity.push({
              type: 'Remote Access Protocol',
              severity: 'medium',
              description: `${packetInfo.protocol} to port ${packetInfo.dstPort}`,
              source: packetInfo.ipSrc,
              destination: packetInfo.ipDst,
              timestamp: timestamp.toISOString()
            });
          }

          conversations.set(convKey, conv);
        }

        // Extract HTTP
        if (packetInfo.httpMethod || packetInfo.httpUri) {
          httpSessions.push({
            timestamp: timestamp.toISOString(),
            source: packetInfo.ipSrc,
            destination: packetInfo.ipDst,
            method: packetInfo.httpMethod,
            url: packetInfo.httpUri,
            statusCode: packetInfo.httpStatus || 'N/A'
          });
        }

        // Extract DNS
        if (packetInfo.dnsQuery) {
          dnsQueries.push({
            timestamp: timestamp.toISOString(),
            source: packetInfo.ipSrc,
            query: packetInfo.dnsQuery,
            type: 'A'
          });
        }

        packets.push({
          index: packetIndex,
          timestamp: timestamp.toISOString(),
          size: inclLen,
          originalLength: origLen,
          protocol: packetInfo.protocol,
          source: packetInfo.ipSrc || 'N/A',
          destination: packetInfo.ipDst || 'N/A',
          srcPort: packetInfo.srcPort,
          destPort: packetInfo.dstPort,
          info: packetInfo.info
        });
      }

      offset = dataOffset + inclLen;
      packetIndex++;
    } catch (err) {
      console.error('Error parsing packet:', err);
      break;
    }
  }

  metadata.totalPackets = packetIndex;

  const protocolDetails = Array.from(protocolCounts.entries()).map(([name, count]) => ({
    name,
    count,
    percentage: parseFloat(((count / metadata.totalPackets) * 100).toFixed(1))
  }));

  const conversationsList = Array.from(conversations.values()).map(conv => ({
    ...conv,
    protocols: Array.from(conv.protocols)
  }));

  return {
    metadata,
    packets,
    protocols: { details: protocolDetails, summary: protocolDetails },
    conversations: conversationsList,
    httpSessions,
    dnsQueries,
    suspiciousActivity,
    endpoints: Array.from(ipAddresses)
  };
}

function analyzePacket(data: Buffer, index: number, timestamp: Date): any {
  if (data.length < 14) return null;

  // Ethernet header (14 bytes)
  const etherType = data.readUInt16BE(12);

  let ipSrc, ipDst, srcPort, dstPort, protocol, info = '';
  let httpMethod, httpUri, httpStatus, dnsQuery;

  // IPv4 packet
  if (etherType === 0x0800 && data.length >= 34) {
    const ipHeaderLen = (data[14] & 0x0f) * 4;
    ipSrc = `${data[26]}.${data[27]}.${data[28]}.${data[29]}`;
    ipDst = `${data[30]}.${data[31]}.${data[32]}.${data[33]}`;
    const ipProto = data[23];

    const ipPayloadOffset = 14 + ipHeaderLen;

    // TCP
    if (ipProto === 6 && data.length >= ipPayloadOffset + 20) {
      protocol = 'TCP';
      srcPort = data.readUInt16BE(ipPayloadOffset);
      dstPort = data.readUInt16BE(ipPayloadOffset + 2);
      const tcpHeaderLen = ((data[ipPayloadOffset + 12] >> 4) & 0x0f) * 4;
      const tcpPayloadOffset = ipPayloadOffset + tcpHeaderLen;

      // Extract HTTP if port 80 or payload contains HTTP
      if (data.length > tcpPayloadOffset) {
        const payload = data.subarray(tcpPayloadOffset).toString('utf8', 0, Math.min(500, data.length - tcpPayloadOffset));

        if (payload.startsWith('GET ') || payload.startsWith('POST ') || payload.startsWith('PUT ')) {
          protocol = 'HTTP';
          const lines = payload.split('\r\n');
          const requestLine = lines[0].split(' ');
          httpMethod = requestLine[0];
          httpUri = requestLine[1];
          info = `${httpMethod} ${httpUri}`;
        } else if (payload.startsWith('HTTP/')) {
          protocol = 'HTTP';
          const statusMatch = payload.match(/HTTP\/\d\.\d (\d{3})/);
          httpStatus = statusMatch ? statusMatch[1] : 'Unknown';
          info = `HTTP Response ${httpStatus}`;
        }
      }

      info = info || `${srcPort} → ${dstPort}`;
    }
    // UDP
    else if (ipProto === 17 && data.length >= ipPayloadOffset + 8) {
      protocol = 'UDP';
      srcPort = data.readUInt16BE(ipPayloadOffset);
      dstPort = data.readUInt16BE(ipPayloadOffset + 2);

      // DNS detection (port 53)
      if (srcPort === 53 || dstPort === 53) {
        protocol = 'DNS';
        const dnsPayload = data.subarray(ipPayloadOffset + 8);
        dnsQuery = parseDnsQuery(dnsPayload);
        info = `Query: ${dnsQuery || 'Unknown'}`;
      } else {
        info = `${srcPort} → ${dstPort}`;
      }
    }
    // ICMP
    else if (ipProto === 1) {
      protocol = 'ICMP';
      info = 'ICMP packet';
    }
    else {
      protocol = 'IPv4';
      info = `Protocol ${ipProto}`;
    }
  }
  // ARP
  else if (etherType === 0x0806) {
    protocol = 'ARP';
    info = 'ARP packet';
  }
  // IPv6
  else if (etherType === 0x86dd) {
    protocol = 'IPv6';
    info = 'IPv6 packet';
  }
  else {
    protocol = 'Unknown';
    info = `EtherType: 0x${etherType.toString(16)}`;
  }

  return {
    protocol,
    ipSrc,
    ipDst,
    srcPort,
    dstPort,
    info,
    httpMethod,
    httpUri,
    httpStatus,
    dnsQuery
  };
}

function parseDnsQuery(dnsPayload: Buffer): string | null {
  try {
    if (dnsPayload.length < 12) return null;

    // Skip DNS header (12 bytes) and parse query name
    let offset = 12;
    const labels: string[] = [];

    while (offset < dnsPayload.length && offset < 100) {
      const len = dnsPayload[offset];
      if (len === 0) break;
      if (len > 63) break; // Invalid label length

      offset++;
      if (offset + len > dnsPayload.length) break;

      const label = dnsPayload.subarray(offset, offset + len).toString('utf8');
      labels.push(label);
      offset += len;
    }

    return labels.join('.');
  } catch (err) {
    return null;
  }
}

console.log('✅ Enhanced PCAP worker started');
