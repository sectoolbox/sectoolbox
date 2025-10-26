import { spawn } from 'child_process';
import { getPcapQueue } from '../services/queue.js';
import { saveResults } from '../services/storage.js';
import { emitJobProgress, emitJobCompleted, emitJobFailed } from '../services/websocket.js';
import { promises as fs } from 'fs';

const queue = getPcapQueue();

queue.process(async (job) => {
  const { jobId, filePath, depth, filename } = job.data;

  console.log(`Processing PCAP job ${jobId}: ${filename}`);

  // Get file size for progress messages
  const fileStats = await fs.stat(filePath);
  const fileSizeMB = (fileStats.size / 1024 / 1024).toFixed(2);

  emitJobProgress(jobId, {
    progress: 5,
    message: `File received (${fileSizeMB} MB)`,
    status: 'processing'
  });

  try {
    // Check if tshark is available
    emitJobProgress(jobId, {
      progress: 10,
      message: 'Checking analysis tools...',
      status: 'processing'
    });

    const hasTshark = await checkTsharkAvailable();

    if (!hasTshark) {
      console.warn('tshark not available, using fallback parser');
      const fileBuffer = await fs.readFile(filePath);
      const fallbackResults = createFallbackResults(fileBuffer, filename, depth);

      await saveResults(jobId, fallbackResults);
      emitJobCompleted(jobId, fallbackResults);
      return fallbackResults;
    }

    console.log('Using tshark for analysis');

    emitJobProgress(jobId, {
      progress: 15,
      message: 'Starting tshark analysis...',
      status: 'processing'
    });

    // SIMPLE: Just dump EVERYTHING from tshark as JSON
    // Increased limits: quick=500, full=50000 packets
    const maxPackets = depth === 'quick' ? 500 : 50000;

    emitJobProgress(jobId, {
      progress: 20,
      message: 'Extracting packet data...',
      status: 'processing'
    });

    const tsharkOutput = await runTsharkFullDump(filePath, maxPackets, jobId);

    emitJobProgress(jobId, {
      progress: 85,
      message: `Analyzing ${tsharkOutput.length} packets...`,
      status: 'processing'
    });

    // Return the raw tshark data + minimal metadata
    const results = {
      filename,
      depth,
      method: 'tshark',
      totalPackets: tsharkOutput.length,

      // This is the FULL tshark dump - frontend will handle it
      packets: tsharkOutput,

      timestamp: new Date().toISOString()
    };

    console.log(`Analysis complete: ${results.totalPackets} packets extracted`);

    emitJobProgress(jobId, {
      progress: 95,
      message: 'Finalizing results...',
      status: 'processing'
    });

    await saveResults(jobId, results);
    emitJobCompleted(jobId, results);

    return results;
  } catch (error: any) {
    console.error('PCAP worker error:', error);
    console.error('Stack:', error.stack);

    emitJobFailed(jobId, `PCAP analysis failed: ${error.message}`);
    throw error;
  }
});

async function checkTsharkAvailable(): Promise<boolean> {
  return new Promise((resolve) => {
    const tshark = spawn('tshark', ['-v']);
    let hasOutput = false;

    tshark.stdout.on('data', () => { hasOutput = true; });
    tshark.on('error', () => resolve(false));
    tshark.on('close', (code) => resolve(code === 0 && hasOutput));

    setTimeout(() => resolve(false), 3000);
  });
}

async function runTsharkFullDump(filePath: string, maxPackets: number, jobId: string): Promise<any[]> {
  return new Promise((resolve, reject) => {
    console.log(`Running tshark on ${filePath}, max packets: ${maxPackets}`);

    // Export EVERYTHING with -V (full packet tree)
    const tshark = spawn('tshark', [
      '-r', filePath,
      '-T', 'json',
      '-c', maxPackets.toString(),
      '-V' // VERBOSE: Full packet dissection tree (all layers, all fields)
    ]);

    const chunks: Buffer[] = [];
    let stderr = '';
    let packetCount = 0;

    tshark.stdout.on('data', (chunk: Buffer) => {
      chunks.push(chunk);
      
      // Estimate progress based on data received (rough approximation)
      packetCount += 10; // Increment counter
      const estimatedProgress = Math.min(80, 20 + Math.floor((packetCount / maxPackets) * 60));
      
      if (packetCount % 100 === 0) {
        emitJobProgress(jobId, {
          progress: estimatedProgress,
          message: `Processing packets (${Math.min(packetCount, maxPackets)} / ${maxPackets})...`,
          status: 'processing'
        });
      }
    });

    tshark.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    tshark.on('close', (code) => {
      if (code === 0 || code === null) {
        try {
          const fullOutput = Buffer.concat(chunks).toString('utf8');
          console.log(`tshark output size: ${fullOutput.length} bytes`);

          const packets = JSON.parse(fullOutput);
          console.log(`Parsed ${packets.length} packets`);

          resolve(packets);
        } catch (err: any) {
          console.error('Failed to parse tshark JSON:', err.message);
          reject(new Error(`tshark JSON parse failed: ${err.message}`));
        }
      } else {
        console.error(`tshark exited with code ${code}`);
        console.error(`stderr: ${stderr}`);
        reject(new Error(`tshark failed (code ${code}): ${stderr.substring(0, 500)}`));
      }
    });

    tshark.on('error', (error) => {
      console.error('Failed to spawn tshark:', error);
      reject(new Error(`Failed to run tshark: ${error.message}`));
    });

    // Timeout after 5 minutes
    setTimeout(() => {
      tshark.kill();
      reject(new Error('tshark timeout after 5 minutes'));
    }, 300000);
  });
}

function createFallbackResults(buffer: Buffer, filename: string, depth: string): any {
  // Ultra-simple fallback when tshark isn't available
  const magic = buffer.readUInt32LE(0);
  const isPcap = magic === 0xa1b2c3d4 || magic === 0xd4c3b2a1;

  if (!isPcap) {
    throw new Error('Not a valid PCAP file');
  }

  return {
    filename,
    depth,
    method: 'fallback',
    totalPackets: 0,
    packets: [],
    error: 'tshark not available - install Wireshark CLI for full analysis',
    timestamp: new Date().toISOString()
  };
}

console.log('Simple PCAP worker started (tshark full dump mode)');
