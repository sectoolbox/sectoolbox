import express from 'express';
import { spawn } from 'child_process';
import { getUploadedFilePath } from '../services/storage.js';
import { promises as fs } from 'fs';
import { join } from 'path';

const router = express.Router();

// Follow TCP stream - Wireshark-style reconstruction
router.post('/tcp/:jobId/:streamId', async (req, res) => {
  try {
    const { jobId, streamId } = req.params;
    const { filename } = req.body;

    if (!filename) {
      return res.status(400).json({ error: 'Filename required' });
    }

    const filePath = getUploadedFilePath(jobId, filename);
    console.log(`Following TCP stream ${streamId} in ${filePath}`);

    // Extract stream data using tshark
    const streamData = await extractTcpStream(filePath, parseInt(streamId));

    res.json(streamData);
  } catch (error: any) {
    console.error('Follow stream error:', error);
    res.status(500).json({ error: error.message });
  }
});

async function extractTcpStream(pcapPath: string, streamId: number): Promise<any> {
  // Use tshark to extract TCP payload data as hex
  const payloads = await extractTcpPayloads(pcapPath, streamId);

  if (payloads.length === 0) {
    return {
      streamId,
      node0: 'Unknown',
      node1: 'Unknown',
      clientToServer: '',
      serverToClient: '',
      entireConversation: '',
      payloads: [],
      totalBytes: 0
    };
  }

  // Reconstruct stream
  const node0 = `${payloads[0].srcIp}:${payloads[0].srcPort}`;
  const node1 = `${payloads[0].dstIp}:${payloads[0].dstPort}`;

  let clientToServer = '';
  let serverToClient = '';
  let entireConversation = '';

  payloads.forEach((p, idx) => {
    const isClientToServer = idx === 0 || (p.srcIp === payloads[0].srcIp && p.srcPort === payloads[0].srcPort);

    if (isClientToServer) {
      clientToServer += p.data;
    } else {
      serverToClient += p.data;
    }

    entireConversation += p.data;
  });

  const totalBytes = entireConversation.length;

  return {
    streamId,
    node0,
    node1,
    clientToServer,
    serverToClient,
    entireConversation,
    payloads: payloads.map(p => ({
      frame: p.frame,
      direction: p.srcIp === payloads[0].srcIp ? 'client' : 'server',
      data: p.data,
      length: p.data.length,
      timestamp: p.timestamp
    })),
    totalBytes
  };
}

async function extractTcpPayloads(pcapPath: string, streamId: number): Promise<any[]> {
  return new Promise((resolve, reject) => {
    console.log(`=== Extracting TCP stream ${streamId} from ${pcapPath} ===`);

    // Extract TCP payload for specific stream
    const tshark = spawn('tshark', [
      '-r', pcapPath,
      '-Y', `tcp.stream eq ${streamId}`,
      '-T', 'fields',
      '-e', 'frame.number',
      '-e', 'frame.time',
      '-e', 'ip.src',
      '-e', 'ip.dst',
      '-e', 'tcp.srcport',
      '-e', 'tcp.dstport',
      '-e', 'tcp.payload',
      '-E', 'separator=|'
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
      console.log(`tshark exited with code: ${code}`);
      console.log(`tshark stdout length: ${stdout.length}`);
      console.log(`tshark stderr: ${stderr}`);

      if (code === 0 || code === null) {
        try {
          const payloads: any[] = [];
          const lines = stdout.trim().split('\n');

          console.log(`Processing ${lines.length} lines from tshark`);

          lines.forEach((line, lineIdx) => {
            if (!line.trim()) return;

            const parts = line.split('|');
            console.log(`Line ${lineIdx}: ${parts.length} parts`);

            if (parts.length >= 7) {
              const [frame, timestamp, srcIp, dstIp, srcPort, dstPort, payload] = parts;

              console.log(`Frame ${frame}: payload length = ${payload?.length || 0}`);

              if (payload && payload.trim()) {
                // Convert hex payload to ASCII
                const cleaned = payload.replace(/:/g, '').trim();
                console.log(`Payload hex (first 100 chars): ${cleaned.substring(0, 100)}`);

                const data = hexToAscii(cleaned);

                payloads.push({
                  frame: parseInt(frame),
                  timestamp,
                  srcIp,
                  dstIp,
                  srcPort: parseInt(srcPort),
                  dstPort: parseInt(dstPort),
                  data,
                  hexData: payload
                });

                console.log(`Added payload ${payloads.length}: ${data.length} bytes`);
              } else {
                console.log(`Frame ${frame}: No payload (might be ACK/handshake)`);
              }
            } else {
              console.log(`Line ${lineIdx}: Not enough parts (${parts.length}), skipping`);
            }
          });

          console.log(`✅ Total extracted: ${payloads.length} TCP payloads for stream ${streamId}`);
          resolve(payloads);
        } catch (err: any) {
          console.error('Failed to parse TCP payloads:', err);
          reject(new Error(`Parse error: ${err.message}`));
        }
      } else {
        console.error(`tshark command failed with code ${code}`);
        console.error(`stderr: ${stderr}`);
        reject(new Error(`tshark failed: ${stderr || 'Unknown error'}`));
      }
    });

    tshark.on('error', (error) => {
      console.error('tshark spawn error:', error);
      reject(new Error(`tshark error: ${error.message}`));
    });

    setTimeout(() => {
      console.log('tshark timeout - killing process');
      tshark.kill();
      reject(new Error('tshark timeout'));
    }, 60000);
  });
}

function hexToAscii(hex: string): string {
  if (!hex) {
    console.log('hexToAscii: empty hex input');
    return '';
  }

  const cleaned = hex.replace(/:/g, '').replace(/\s/g, '');
  const bytes = cleaned.match(/.{1,2}/g) || [];

  console.log(`hexToAscii: ${cleaned.length} hex chars → ${bytes.length} bytes`);

  const result = bytes
    .map(byte => {
      const code = parseInt(byte, 16);
      // Keep all printable characters and newlines/tabs
      if (code === 10 || code === 13 || code === 9) return String.fromCharCode(code);
      if (code >= 32 && code <= 126) return String.fromCharCode(code);
      return '.';
    })
    .join('');

  console.log(`Result length: ${result.length}`);
  return result;
}

export default router;
