import { spawn } from 'child_process';
import { getPcapQueue } from '../services/queue.js';
import { saveResults } from '../services/storage.js';
import { emitJobProgress, emitJobCompleted, emitJobFailed } from '../services/websocket.js';
import { promises as fs } from 'fs';
import { join, dirname } from 'path';

const queue = getPcapQueue();

queue.process(async (job) => {
  const { jobId, filePath, depth, filename } = job.data;

  console.log(`🔍 Starting deep PCAP analysis for job ${jobId}`);

  emitJobProgress(jobId, {
    progress: 5,
    message: 'Initializing Wireshark-level analysis...',
    status: 'processing'
  });

  try {
    // Check if tshark is available
    console.log('🔍 Checking for tshark...');
    const hasTshark = await checkTsharkAvailable();

    if (!hasTshark) {
      console.error('❌ tshark not available, using basic parser');
      emitJobProgress(jobId, {
        progress: 15,
        message: 'tshark not available, using basic analysis...',
        status: 'processing'
      });

      // Fall back to basic analysis instead of failing
      const fileBuffer = await fs.readFile(filePath);
      const basicResults = await basicPcapAnalysis(fileBuffer, filename, depth);

      await saveResults(jobId, basicResults);
      emitJobCompleted(jobId, basicResults);
      return basicResults;
    }

    console.log('✅ tshark available, starting comprehensive analysis');

    // Step 1: Get basic file info
    emitJobProgress(jobId, {
      progress: 10,
      message: 'Reading PCAP file metadata...',
      status: 'processing'
    });

    const fileStats = await fs.stat(filePath);
    const capinfos = await getFileInfo(filePath);

    // Step 2: Extract ALL packets with full layer data
    emitJobProgress(jobId, {
      progress: 20,
      message: 'Extracting packet data (this may take a while)...',
      status: 'processing'
    });

    const packets = await extractAllPackets(filePath, depth, jobId);

    // Step 3: Extract protocol hierarchy
    emitJobProgress(jobId, {
      progress: 40,
      message: 'Analyzing protocol hierarchy...',
      status: 'processing'
    });

    const protocolHierarchy = await getProtocolHierarchy(filePath);

    // Step 4: Extract HTTP objects
    emitJobProgress(jobId, {
      progress: 50,
      message: 'Extracting HTTP sessions...',
      status: 'processing'
    });

    const httpData = await extractHttpData(filePath, jobId);

    // Step 5: Extract DNS data
    emitJobProgress(jobId, {
      progress: 60,
      message: 'Extracting DNS queries...',
      status: 'processing'
    });

    const dnsData = await extractDnsData(filePath);

    // Step 6: Get conversation statistics
    emitJobProgress(jobId, {
      progress: 70,
      message: 'Computing conversation statistics...',
      status: 'processing'
    });

    const conversations = await getConversations(filePath);

    // Step 7: Get endpoint statistics
    emitJobProgress(jobId, {
      progress: 80,
      message: 'Analyzing endpoints...',
      status: 'processing'
    });

    const endpoints = await getEndpoints(filePath);

    // Step 8: Extract expert info (warnings, errors, notes)
    emitJobProgress(jobId, {
      progress: 85,
      message: 'Running expert analysis...',
      status: 'processing'
    });

    const expertInfo = await getExpertInfo(filePath);

    // Step 9: Extract IO graph data for timeline
    emitJobProgress(jobId, {
      progress: 90,
      message: 'Generating I/O statistics...',
      status: 'processing'
    });

    const ioStats = await getIOStats(filePath);

    // Step 10: Detect threats and anomalies
    emitJobProgress(jobId, {
      progress: 95,
      message: 'Running threat detection...',
      status: 'processing'
    });

    const threats = detectThreats(packets, conversations, httpData, dnsData, expertInfo);

    // Final results
    const results = {
      // Basic metadata
      filename,
      depth,
      method: 'tshark',

      // File info from capinfos
      metadata: {
        ...capinfos,
        fileSize: fileStats.size,
        totalPackets: packets.length,
        linkType: capinfos.linkType || null
      },

      // All packets with full layer data
      packets,

      // Protocol statistics
      protocols: protocolHierarchy,

      // Application layer data
      httpStreams: httpData.streams, // Match frontend field name
      dnsQueries: dnsData,

      // Network intelligence
      conversations,
      endpoints,

      // Wireshark expert analysis
      expertInfo,

      // Threat detection
      threatIndicators: threats,

      // I/O statistics for graphing
      ioStats,

      // Timeline data
      networkIntelligence: {
        topTalkers: conversations.slice(0, 10).map((c: any) => ({
          ip: c.source,
          bytes: c.bytes,
          packets: c.packets
        })),
        protocolDistribution: protocolHierarchy.summary,
        bandwidth: ioStats
      },

      timestamp: new Date().toISOString()
    };

    console.log(`✅ Analysis complete: ${packets.length} packets, ${conversations.length} conversations`);

    await saveResults(jobId, results);
    emitJobCompleted(jobId, results);

    return results;
  } catch (error: any) {
    console.error('❌ PCAP analysis error:', error);
    console.error('❌ Error stack:', error.stack);
    console.error('❌ Job data:', job.data);

    const errorMessage = error.message || 'Unknown error during PCAP analysis';
    emitJobFailed(jobId, errorMessage);
    throw error;
  }
});

async function checkTsharkAvailable(): Promise<boolean> {
  return new Promise((resolve) => {
    const tshark = spawn('tshark', ['-v']);
    tshark.on('error', () => resolve(false));
    tshark.on('close', (code) => resolve(code === 0));
    setTimeout(() => resolve(false), 5000);
  });
}

async function getFileInfo(filePath: string): Promise<any> {
  return new Promise((resolve, reject) => {
    const capinfos = spawn('capinfos', ['-M', filePath]);

    let stdout = '';

    capinfos.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    capinfos.on('close', (code) => {
      if (code === 0) {
        const info: any = {};
        stdout.split('\n').forEach(line => {
          const [key, value] = line.split(': ');
          if (key && value) {
            info[key.trim().replace(/ /g, '_').toLowerCase()] = value.trim();
          }
        });
        resolve(info);
      } else {
        resolve({ format: 'pcap' });
      }
    });

    capinfos.on('error', () => resolve({ format: 'pcap' }));
  });
}

async function extractAllPackets(filePath: string, depth: string, jobId: string): Promise<any[]> {
  return new Promise((resolve, reject) => {
    const maxPackets = depth === 'quick' ? 100 : 10000;

    // Export EVERYTHING tshark can provide in JSON format
    const tshark = spawn('tshark', [
      '-r', filePath,
      '-T', 'json',
      '-c', maxPackets.toString(),
      '-V' // Verbose: full packet tree
    ]);

    let stdout = '';
    let stderr = '';
    const chunks: string[] = [];

    tshark.stdout.on('data', (data) => {
      chunks.push(data.toString());
    });

    tshark.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    tshark.on('close', (code) => {
      if (code === 0 || code === null) {
        try {
          stdout = chunks.join('');
          const rawPackets = JSON.parse(stdout);

          // Transform tshark JSON to our format (keeping ALL data)
          const packets = rawPackets.map((pkt: any, index: number) => {
            const layers = pkt._source?.layers || {};

            return {
              // Core packet info
              index: parseInt(layers.frame?.['frame.number'] || index + 1),
              timestamp: layers.frame?.['frame.time'] || new Date().toISOString(),
              size: parseInt(layers.frame?.['frame.len'] || 0),
              capturedLength: parseInt(layers.frame?.['frame.cap_len'] || 0),

              // Protocol info
              protocol: determineProtocol(layers),
              protocols: layers.frame?.['frame.protocols'] || '',

              // Network layer
              source: layers.ip?.['ip.src'] || layers.ipv6?.['ipv6.src'] || layers.eth?.['eth.src'] || 'N/A',
              destination: layers.ip?.['ip.dst'] || layers.ipv6?.['ipv6.dst'] || layers.eth?.['eth.dst'] || 'N/A',

              // Transport layer
              srcPort: layers.tcp?.['tcp.srcport'] || layers.udp?.['udp.srcport'] || null,
              destPort: layers.tcp?.['tcp.dstport'] || layers.udp?.['udp.dstport'] || null,

              // TCP specific
              tcpFlags: layers.tcp?.['tcp.flags'] || null,
              tcpSeq: layers.tcp?.['tcp.seq'] || null,
              tcpAck: layers.tcp?.['tcp.ack'] || null,
              tcpStream: layers.tcp?.['tcp.stream'] || null,

              // Application layer info
              info: buildPacketInfo(layers),

              // HTTP data
              httpMethod: layers.http?.['http.request.method'],
              httpUri: layers.http?.['http.request.uri'],
              httpHost: layers.http?.['http.host'],
              httpStatusCode: layers.http?.['http.response.code'],
              httpUserAgent: layers.http?.['http.user_agent'],

              // DNS data
              dnsQuery: layers.dns?.['dns.qry.name'],
              dnsResponse: layers.dns?.['dns.resp.name'],
              dnsType: layers.dns?.['dns.qry.type'],

              // TLS data
              tlsVersion: layers.tls?.['tls.record.version'],
              tlsCipher: layers.tls?.['tls.handshake.ciphersuite'],
              tlsSNI: layers.tls?.['tls.handshake.extensions_server_name'],

              // Raw layer data (for packet detail tree)
              rawLayers: layers,

              // Hex dump
              data: layers.frame?.['frame.data'] || null,

              // Color coding (Wireshark style)
              colorRule: determineColorRule(layers)
            };
          });

          resolve(packets);
        } catch (err: any) {
          console.error('Failed to parse tshark JSON:', err);
          reject(new Error(`tshark JSON parse error: ${err.message}`));
        }
      } else {
        reject(new Error(`tshark failed (code ${code}): ${stderr}`));
      }
    });

    tshark.on('error', (error) => {
      reject(new Error(`Failed to run tshark: ${error.message}`));
    });
  });
}

function determineProtocol(layers: any): string {
  // Determine highest-level protocol
  if (layers.http) return 'HTTP';
  if (layers.https || layers.tls) return 'TLS/HTTPS';
  if (layers.dns) return 'DNS';
  if (layers.ssh) return 'SSH';
  if (layers.ftp) return 'FTP';
  if (layers.smtp) return 'SMTP';
  if (layers.telnet) return 'TELNET';
  if (layers.tcp) return 'TCP';
  if (layers.udp) return 'UDP';
  if (layers.icmp) return 'ICMP';
  if (layers.arp) return 'ARP';
  if (layers.ip) return 'IPv4';
  if (layers.ipv6) return 'IPv6';
  return 'Unknown';
}

function buildPacketInfo(layers: any): string {
  if (layers.http) {
    const method = layers.http['http.request.method'];
    const uri = layers.http['http.request.uri'];
    const status = layers.http['http.response.code'];

    if (method && uri) return `${method} ${uri}`;
    if (status) return `HTTP/1.1 ${status}`;
  }

  if (layers.dns) {
    const query = layers.dns['dns.qry.name'];
    const response = layers.dns['dns.resp.name'];
    if (query) return `Standard query ${query}`;
    if (response) return `Standard query response ${response}`;
  }

  if (layers.tcp) {
    const flags = layers.tcp['tcp.flags'];
    const srcPort = layers.tcp['tcp.srcport'];
    const dstPort = layers.tcp['tcp.dstport'];
    return `${srcPort} → ${dstPort} [${flags || 'TCP'}]`;
  }

  if (layers.udp) {
    const srcPort = layers.udp['udp.srcport'];
    const dstPort = layers.udp['udp.dstport'];
    return `${srcPort} → ${dstPort}`;
  }

  return layers.frame?.['frame.protocols'] || 'No info';
}

function determineColorRule(layers: any): string {
  // Wireshark color rules
  if (layers.http) {
    const method = layers.http['http.request.method'];
    if (method === 'GET') return 'http-get';
    if (method === 'POST') return 'http-post';
    return 'http';
  }
  if (layers.dns) return 'dns';
  if (layers.tcp) {
    const flags = layers.tcp['tcp.flags.syn'];
    if (flags === '1') return 'tcp-syn';
    return 'tcp';
  }
  if (layers.udp) return 'udp';
  if (layers.icmp) return 'icmp';
  if (layers.arp) return 'arp';
  return 'default';
}

async function getProtocolHierarchy(filePath: string): Promise<any> {
  return new Promise((resolve) => {
    const tshark = spawn('tshark', [
      '-r', filePath,
      '-q', // Quiet mode
      '-z', 'io,phs' // Protocol Hierarchy Statistics
    ]);

    let stdout = '';

    tshark.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    tshark.on('close', () => {
      const protocols = parseProtocolHierarchy(stdout);
      resolve(protocols);
    });

    tshark.on('error', () => resolve({ summary: {}, details: [] }));
  });
}

function parseProtocolHierarchy(output: string): any {
  const summary: Record<string, number> = {};
  const details: Array<{ name: string; count: number; percentage: number; bytes: number }> = [];

  const lines = output.split('\n');
  let inHierarchy = false;

  for (const line of lines) {
    if (line.includes('Protocol Hierarchy Statistics')) {
      inHierarchy = true;
      continue;
    }

    if (inHierarchy && line.trim()) {
      // Parse format: "  tcp                     frames:450  bytes:1234567"
      const match = line.match(/([a-z0-9_]+)\s+frames:(\d+)\s+bytes:(\d+)/);
      if (match) {
        const [, proto, frames, bytes] = match;
        const count = parseInt(frames);
        summary[proto] = count;
        details.push({
          name: proto.toUpperCase(),
          count,
          percentage: 0, // Will calculate after total
          bytes: parseInt(bytes)
        });
      }
    }
  }

  // Calculate percentages
  const total = details.reduce((sum, p) => sum + p.count, 0);
  details.forEach(p => {
    p.percentage = parseFloat(((p.count / total) * 100).toFixed(1));
  });

  return { summary, details };
}

async function extractHttpData(filePath: string, jobId: string): Promise<any> {
  return new Promise((resolve) => {
    const tshark = spawn('tshark', [
      '-r', filePath,
      '-Y', 'http.request or http.response',
      '-T', 'json',
      '-e', 'frame.number',
      '-e', 'frame.time',
      '-e', 'ip.src',
      '-e', 'ip.dst',
      '-e', 'tcp.srcport',
      '-e', 'tcp.dstport',
      '-e', 'http.request.method',
      '-e', 'http.request.uri',
      '-e', 'http.request.full_uri',
      '-e', 'http.host',
      '-e', 'http.user_agent',
      '-e', 'http.response.code',
      '-e', 'http.response.phrase',
      '-e', 'http.content_type',
      '-e', 'http.content_length',
      '-e', 'http.cookie',
      '-e', 'http.authorization',
      '-e', 'tcp.stream'
    ]);

    let stdout = '';

    tshark.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    tshark.on('close', () => {
      try {
        const packets = JSON.parse(stdout || '[]');

        const streams = packets.map((pkt: any) => {
          const l = pkt._source?.layers || {};
          return {
            frameNumber: l['frame.number']?.[0],
            timestamp: l['frame.time']?.[0],
            source: l['ip.src']?.[0],
            destination: l['ip.dst']?.[0],
            srcPort: l['tcp.srcport']?.[0],
            dstPort: l['tcp.dstport']?.[0],
            method: l['http.request.method']?.[0],
            uri: l['http.request.uri']?.[0],
            fullUri: l['http.request.full_uri']?.[0],
            host: l['http.host']?.[0],
            userAgent: l['http.user_agent']?.[0],
            statusCode: l['http.response.code']?.[0],
            statusPhrase: l['http.response.phrase']?.[0],
            contentType: l['http.content_type']?.[0],
            contentLength: l['http.content_length']?.[0],
            cookie: l['http.cookie']?.[0],
            authorization: l['http.authorization']?.[0],
            tcpStream: l['tcp.stream']?.[0]
          };
        });

        resolve({ streams, objects: [] });
      } catch (err) {
        resolve({ streams: [], objects: [] });
      }
    });

    tshark.on('error', () => resolve({ streams: [], objects: [] }));
  });
}

async function extractDnsData(filePath: string): Promise<any[]> {
  return new Promise((resolve) => {
    const tshark = spawn('tshark', [
      '-r', filePath,
      '-Y', 'dns',
      '-T', 'json',
      '-e', 'frame.number',
      '-e', 'frame.time',
      '-e', 'ip.src',
      '-e', 'ip.dst',
      '-e', 'dns.qry.name',
      '-e', 'dns.qry.type',
      '-e', 'dns.flags.response',
      '-e', 'dns.a',
      '-e', 'dns.aaaa',
      '-e', 'dns.cname',
      '-e', 'dns.ptr',
      '-e', 'dns.mx',
      '-e', 'dns.txt'
    ]);

    let stdout = '';

    tshark.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    tshark.on('close', () => {
      try {
        const packets = JSON.parse(stdout || '[]');

        const queries = packets.map((pkt: any) => {
          const l = pkt._source?.layers || {};
          return {
            frameNumber: l['frame.number']?.[0],
            timestamp: l['frame.time']?.[0],
            source: l['ip.src']?.[0],
            destination: l['ip.dst']?.[0],
            query: l['dns.qry.name']?.[0],
            type: l['dns.qry.type']?.[0],
            isResponse: l['dns.flags.response']?.[0] === '1',
            answer: l['dns.a']?.[0] || l['dns.aaaa']?.[0] || l['dns.cname']?.[0] || l['dns.ptr']?.[0],
            mx: l['dns.mx']?.[0],
            txt: l['dns.txt']?.[0]
          };
        });

        resolve(queries);
      } catch (err) {
        resolve([]);
      }
    });

    tshark.on('error', () => resolve([]));
  });
}

async function getConversations(filePath: string): Promise<any[]> {
  return new Promise((resolve) => {
    const tshark = spawn('tshark', [
      '-r', filePath,
      '-q',
      '-z', 'conv,ip'
    ]);

    let stdout = '';

    tshark.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    tshark.on('close', () => {
      const conversations = parseConversations(stdout);
      resolve(conversations);
    });

    tshark.on('error', () => resolve([]));
  });
}

function parseConversations(output: string): any[] {
  const conversations: any[] = [];
  const lines = output.split('\n');

  for (const line of lines) {
    // Format: "192.168.1.1  <-> 142.250.185.46    450    123456    234567    678901"
    const match = line.match(/(\d+\.\d+\.\d+\.\d+)\s+<->\s+(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)/);
    if (match) {
      const [, addr1, addr2, packets, bytes1, bytes2, totalBytes] = match;
      conversations.push({
        source: addr1,
        destination: addr2,
        packets: parseInt(packets),
        bytesAB: parseInt(bytes1),
        bytesBA: parseInt(bytes2),
        bytes: parseInt(totalBytes),
        protocols: ['IP']
      });
    }
  }

  return conversations;
}

async function getEndpoints(filePath: string): Promise<any[]> {
  return new Promise((resolve) => {
    const tshark = spawn('tshark', [
      '-r', filePath,
      '-q',
      '-z', 'endpoints,ip'
    ]);

    let stdout = '';

    tshark.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    tshark.on('close', () => {
      const endpoints = parseEndpoints(stdout);
      resolve(endpoints);
    });

    tshark.on('error', () => resolve([]));
  });
}

function parseEndpoints(output: string): any[] {
  const endpoints: any[] = [];
  const lines = output.split('\n');

  for (const line of lines) {
    // Format: "192.168.1.1    450    123456"
    const match = line.match(/(\d+\.\d+\.\d+\.\d+)\s+(\d+)\s+(\d+)/);
    if (match) {
      const [, address, packets, bytes] = match;
      endpoints.push({
        address,
        packets: parseInt(packets),
        bytes: parseInt(bytes)
      });
    }
  }

  return endpoints;
}

async function getExpertInfo(filePath: string): Promise<any[]> {
  return new Promise((resolve) => {
    const tshark = spawn('tshark', [
      '-r', filePath,
      '-q',
      '-z', 'expert'
    ]);

    let stdout = '';

    tshark.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    tshark.on('close', () => {
      const expertItems = parseExpertInfo(stdout);
      resolve(expertItems);
    });

    tshark.on('error', () => resolve([]));
  });
}

function parseExpertInfo(output: string): any[] {
  const items: any[] = [];
  const lines = output.split('\n');

  for (const line of lines) {
    // Parse expert info: severity, group, protocol, summary
    if (line.includes('Error') || line.includes('Warn') || line.includes('Note')) {
      items.push({
        severity: line.includes('Error') ? 'error' : line.includes('Warn') ? 'warning' : 'note',
        message: line.trim()
      });
    }
  }

  return items;
}

async function getIOStats(filePath: string): Promise<any[]> {
  return new Promise((resolve) => {
    const tshark = spawn('tshark', [
      '-r', filePath,
      '-q',
      '-z', 'io,stat,1' // 1 second intervals
    ]);

    let stdout = '';

    tshark.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    tshark.on('close', () => {
      const stats = parseIOStats(stdout);
      resolve(stats);
    });

    tshark.on('error', () => resolve([]));
  });
}

function parseIOStats(output: string): any[] {
  const stats: any[] = [];
  const lines = output.split('\n');

  for (const line of lines) {
    // Parse I/O stats
    const match = line.match(/(\d+\.\d+)\s+<>\s+(\d+\.\d+)\s+(\d+)\s+(\d+)/);
    if (match) {
      const [, start, end, frames, bytes] = match;
      stats.push({
        timeStart: parseFloat(start),
        timeEnd: parseFloat(end),
        packets: parseInt(frames),
        bytes: parseInt(bytes)
      });
    }
  }

  return stats;
}

function detectThreats(packets: any[], conversations: any[], httpData: any, dnsData: any[], expertInfo: any[]): any[] {
  const threats: any[] = [];

  // Detect port scans
  const portScans = new Map<string, Set<number>>();
  packets.forEach(pkt => {
    if (pkt.tcpFlags && pkt.tcpFlags.includes('S') && pkt.source) {
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
        description: `${ip} scanned ${ports.size} ports`,
        source: ip,
        evidence: Array.from(ports).slice(0, 20).map(p => `Port ${p}`)
      });
    }
  });

  // Detect suspicious domains
  const suspiciousDomains = ['pastebin.com', 'ngrok.io', 'duckdns.org'];
  dnsData.forEach(dns => {
    if (dns.query && suspiciousDomains.some(d => dns.query.includes(d))) {
      threats.push({
        type: 'Suspicious Domain Query',
        severity: 'medium',
        confidence: 70,
        description: `DNS query to ${dns.query}`,
        source: dns.source,
        evidence: [dns.query]
      });
    }
  });

  // Detect unencrypted credentials
  httpData.streams.forEach((stream: any) => {
    if (stream.authorization) {
      threats.push({
        type: 'Unencrypted Credentials',
        severity: 'high',
        confidence: 95,
        description: `HTTP Authorization header detected`,
        source: stream.source,
        destination: stream.destination,
        evidence: ['Authorization header present']
      });
    }
  });

  // High-volume conversations
  conversations.forEach(conv => {
    if (conv.packets > 5000) {
      threats.push({
        type: 'High Volume Traffic',
        severity: 'medium',
        confidence: 75,
        description: `${conv.packets} packets between ${conv.source} and ${conv.destination}`,
        source: conv.source,
        destination: conv.destination,
        evidence: [`${conv.packets} packets`, `${(conv.bytes / 1024 / 1024).toFixed(2)} MB`]
      });
    }
  });

  // Add expert info as threats
  expertInfo.forEach(info => {
    if (info.severity === 'error') {
      threats.push({
        type: 'Protocol Error',
        severity: 'high',
        confidence: 100,
        description: info.message,
        evidence: [info.message]
      });
    }
  });

  return threats;
}

async function basicPcapAnalysis(buffer: Buffer, filename: string, depth: string): Promise<any> {
  // Fallback basic parser when tshark is not available
  const magic = buffer.readUInt32LE(0);
  const isPcap = magic === 0xa1b2c3d4 || magic === 0xd4c3b2a1;

  if (!isPcap) {
    throw new Error('Unsupported PCAP format without tshark');
  }

  const metadata = {
    format: 'pcap',
    fileSize: buffer.length,
    totalPackets: 0,
    linkType: buffer.readUInt32LE(20)
  };

  const packets: any[] = [];
  const protocolCounts = new Map<string, number>();

  let offset = 24;
  let packetIndex = 0;
  const maxPackets = depth === 'quick' ? 100 : 1000;

  while (offset < buffer.length - 16 && packetIndex < maxPackets) {
    try {
      const inclLen = buffer.readUInt32LE(offset + 8);
      const origLen = buffer.readUInt32LE(offset + 12);

      if (inclLen > buffer.length || inclLen > 65535) break;

      const dataOffset = offset + 16;
      if (dataOffset + inclLen > buffer.length) break;

      const packetData = buffer.subarray(dataOffset, dataOffset + inclLen);

      let protocol = 'Unknown';
      if (inclLen >= 14) {
        const etherType = packetData.readUInt16BE(12);
        if (etherType === 0x0800) protocol = 'IPv4';
        else if (etherType === 0x0806) protocol = 'ARP';
        else if (etherType === 0x86dd) protocol = 'IPv6';

        if (protocol === 'IPv4' && inclLen >= 34) {
          const ipProto = packetData[23];
          if (ipProto === 6) protocol = 'TCP';
          else if (ipProto === 17) protocol = 'UDP';
          else if (ipProto === 1) protocol = 'ICMP';
        }
      }

      protocolCounts.set(protocol, (protocolCounts.get(protocol) || 0) + 1);

      packets.push({
        index: packetIndex,
        timestamp: new Date().toISOString(),
        size: inclLen,
        protocol,
        source: 'N/A',
        destination: 'N/A',
        info: protocol,
        colorRule: protocol.toLowerCase()
      });

      offset = dataOffset + inclLen;
      packetIndex++;
    } catch (err) {
      break;
    }
  }

  metadata.totalPackets = packetIndex;

  const protocolDetails = Array.from(protocolCounts.entries()).map(([name, count]) => ({
    name,
    count,
    percentage: parseFloat(((count / metadata.totalPackets) * 100).toFixed(1))
  }));

  return {
    filename,
    depth,
    method: 'basic',
    metadata,
    packets,
    protocols: { details: protocolDetails, summary: {} },
    httpStreams: [],
    dnsQueries: [],
    conversations: [],
    endpoints: [],
    expertInfo: [],
    threatIndicators: [],
    ioStats: [],
    networkIntelligence: {
      topTalkers: [],
      protocolDistribution: {},
      bandwidth: []
    },
    timestamp: new Date().toISOString()
  };
}

console.log('✅ Enhanced Wireshark-level PCAP worker started');
