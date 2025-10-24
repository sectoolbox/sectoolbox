import express from 'express';
import { spawn } from 'child_process';
import { getUploadedFilePath } from '../services/storage.js';

const router = express.Router();

// Follow TCP stream using tshark
router.post('/tcp/:jobId/:streamId', async (req, res) => {
  try {
    const { jobId, streamId } = req.params;
    const { filename } = req.body;

    if (!filename) {
      return res.status(400).json({ error: 'Filename required' });
    }

    const filePath = getUploadedFilePath(jobId, filename);

    // Use tshark to follow the stream
    const streamData = await followTcpStream(filePath, parseInt(streamId));

    res.json(streamData);
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

async function followTcpStream(pcapPath: string, streamId: number): Promise<any> {
  return new Promise((resolve, reject) => {
    console.log(`Following TCP stream ${streamId} in ${pcapPath}`);

    // Use tshark's follow feature - extracts actual TCP stream data
    const tshark = spawn('tshark', [
      '-r', pcapPath,
      '-q', // Quiet mode
      '-z', `follow,tcp,ascii,${streamId}` // Follow TCP stream in ASCII format
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
      if (code === 0 || code === null) {
        // Parse tshark follow output
        const parsed = parseFollowOutput(stdout, streamId);
        console.log(`TCP stream ${streamId} extracted: ${parsed.totalBytes} bytes`);
        resolve(parsed);
      } else {
        console.error(`tshark follow failed: ${stderr}`);
        reject(new Error(`Failed to follow stream: ${stderr}`));
      }
    });

    tshark.on('error', (error) => {
      reject(new Error(`tshark error: ${error.message}`));
    });

    setTimeout(() => {
      tshark.kill();
      reject(new Error('tshark follow timeout'));
    }, 60000);
  });
}

function parseFollowOutput(output: string, streamId: number): any {
  // tshark follow output format:
  // ===================================================================
  // Follow: tcp,ascii
  // Filter: tcp.stream eq X
  // Node 0: IP:port
  // Node 1: IP:port
  //     data from node 0...
  //     data from node 1...

  const lines = output.split('\n');
  let node0 = '';
  let node1 = '';
  let currentNode = -1;
  const node0Data: string[] = [];
  const node1Data: string[] = [];
  const combinedData: Array<{ direction: string; data: string; node: number }> = [];

  let inData = false;

  for (const line of lines) {
    if (line.includes('Node 0:')) {
      node0 = line.replace('Node 0:', '').trim();
      inData = true;
    } else if (line.includes('Node 1:')) {
      node1 = line.replace('Node 1:', '').trim();
      inData = true;
    } else if (line.trim().startsWith('===') || line.includes('Follow:') || line.includes('Filter:')) {
      inData = false;
    } else if (inData && line.trim()) {
      // Detect which node this data is from
      // tshark prefixes data with tab character for node indicator
      if (line.startsWith('\t')) {
        const data = line.substring(1);
        if (currentNode === -1) currentNode = 0;

        if (currentNode === 0) {
          node0Data.push(data);
          combinedData.push({ direction: 'client', data, node: 0 });
        } else {
          node1Data.push(data);
          combinedData.push({ direction: 'server', data, node: 1 });
        }
      } else if (line.length > 0) {
        // Switch nodes
        currentNode = currentNode === 0 ? 1 : 0;

        if (currentNode === 0) {
          node0Data.push(line);
          combinedData.push({ direction: 'client', data: line, node: 0 });
        } else {
          node1Data.push(line);
          combinedData.push({ direction: 'server', data: line, node: 1 });
        }
      }
    }
  }

  const clientData = node0Data.join('\n');
  const serverData = node1Data.join('\n');
  const totalBytes = clientData.length + serverData.length;

  return {
    streamId,
    node0,
    node1,
    clientData,
    serverData,
    combined: combinedData,
    totalBytes,
    rawOutput: output
  };
}

export default router;
