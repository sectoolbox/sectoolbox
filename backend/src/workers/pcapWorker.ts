import { spawn } from 'child_process';
import { getPcapQueue } from '../services/queue.js';
import { saveResults } from '../services/storage.js';
import { emitJobProgress, emitJobCompleted, emitJobFailed } from '../services/websocket.js';
import { promises as fs } from 'fs';

const queue = getPcapQueue();

queue.process(async (job) => {
  const { jobId, filePath, depth, filename } = job.data;

  emitJobProgress(jobId, {
    progress: 10,
    message: 'Starting PCAP analysis...',
    status: 'processing'
  });

  try {
    // Read PCAP file
    const fileBuffer = await fs.readFile(filePath);

    emitJobProgress(jobId, {
      progress: 30,
      message: 'Parsing PCAP structure...',
      status: 'processing'
    });

    // Basic PCAP analysis
    const analysis = await analyzePcap(fileBuffer, depth);

    emitJobProgress(jobId, {
      progress: 80,
      message: 'Generating analysis report...',
      status: 'processing'
    });

    const results = {
      filename,
      depth,
      metadata: analysis.metadata,
      packets: analysis.packets,
      protocols: analysis.protocols,
      timestamp: new Date().toISOString()
    };

    await saveResults(jobId, results);

    emitJobCompleted(jobId, results);

    return results;
  } catch (error: any) {
    console.error('PCAP analysis error:', error);
    emitJobFailed(jobId, error.message);
    throw error;
  }
});

async function analyzePcap(buffer: Buffer, depth: 'quick' | 'full') {
  // Basic PCAP header parsing
  const magic = buffer.readUInt32LE(0);
  const isPcap = magic === 0xa1b2c3d4 || magic === 0xd4c3b2a1;
  const isPcapng = buffer.readUInt32BE(0) === 0x0a0d0d0a;

  const metadata = {
    format: isPcap ? 'pcap' : isPcapng ? 'pcapng' : 'unknown',
    fileSize: buffer.length,
    totalPackets: 0,
    linkType: null as number | null
  };

  const packets: any[] = [];
  const protocolCounts = new Map<string, number>();

  if (isPcap) {
    // Parse PCAP header
    const linkType = buffer.readUInt32LE(20);
    metadata.linkType = linkType;

    let offset = 24; // Skip global header
    let packetIndex = 0;

    // Parse packets (limit based on depth)
    const maxPackets = depth === 'quick' ? 100 : 1000;

    while (offset < buffer.length - 16 && packetIndex < maxPackets) {
      try {
        // Packet header: ts_sec(4) + ts_usec(4) + incl_len(4) + orig_len(4)
        const tsSecOffset = offset;
        const inclLenOffset = offset + 8;
        const origLenOffset = offset + 12;

        if (inclLenOffset + 4 > buffer.length) break;

        const inclLen = buffer.readUInt32LE(inclLenOffset);
        const origLen = buffer.readUInt32LE(origLenOffset);

        if (inclLen > buffer.length || inclLen > 65535) break;

        const dataOffset = offset + 16;
        if (dataOffset + inclLen > buffer.length) break;

        const packetData = buffer.subarray(dataOffset, dataOffset + inclLen);

        // Basic protocol detection (Ethernet)
        let protocol = 'Unknown';
        if (inclLen >= 14) {
          const etherType = packetData.readUInt16BE(12);
          if (etherType === 0x0800) protocol = 'IPv4';
          else if (etherType === 0x0806) protocol = 'ARP';
          else if (etherType === 0x86dd) protocol = 'IPv6';

          // Parse IP protocol
          if (protocol === 'IPv4' && inclLen >= 34) {
            const ipProto = packetData[23];
            if (ipProto === 6) protocol = 'TCP';
            else if (ipProto === 17) protocol = 'UDP';
            else if (ipProto === 1) protocol = 'ICMP';
          }
        }

        protocolCounts.set(protocol, (protocolCounts.get(protocol) || 0) + 1);

        if (depth === 'full' || packetIndex < 20) {
          packets.push({
            index: packetIndex,
            size: inclLen,
            originalLength: origLen,
            protocol,
            timestamp: new Date().toISOString()
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
  }

  const protocols = {
    summary: Array.from(protocolCounts.entries()).map(([name, count]) => ({
      name,
      count,
      percentage: ((count / metadata.totalPackets) * 100).toFixed(1)
    })),
    details: Array.from(protocolCounts.entries()).map(([name, count]) => ({
      name,
      count,
      percentage: parseFloat(((count / metadata.totalPackets) * 100).toFixed(1))
    }))
  };

  return {
    metadata,
    packets,
    protocols
  };
}

console.log('✅ PCAP worker started');
