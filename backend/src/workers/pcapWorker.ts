import { spawn } from 'child_process';
import { getPcapQueue } from '../services/queue.js';
import { saveResults } from '../services/storage.js';
import { emitJobProgress, emitJobCompleted, emitJobFailed } from '../services/websocket.js';
import { promises as fs } from 'fs';

const queue = getPcapQueue();

queue.process(async (job) => {
  const { jobId, filePath, depth, filename } = job.data;

  console.log(`🔍 Processing PCAP job ${jobId}: ${filename}`);

  emitJobProgress(jobId, {
    progress: 10,
    message: 'Reading PCAP file...',
    status: 'processing'
  });

  try {
    // Check if tshark is available
    const hasTshark = await checkTsharkAvailable();

    if (!hasTshark) {
      console.warn('⚠️ tshark not available, using fallback parser');
      const fileBuffer = await fs.readFile(filePath);
      const fallbackResults = createFallbackResults(fileBuffer, filename, depth);

      await saveResults(jobId, fallbackResults);
      emitJobCompleted(jobId, fallbackResults);
      return fallbackResults;
    }

    console.log('✅ Using tshark for analysis');

    emitJobProgress(jobId, {
      progress: 30,
      message: 'Extracting all packet data with tshark...',
      status: 'processing'
    });

    // SIMPLE: Just dump EVERYTHING from tshark as JSON
    const maxPackets = depth === 'quick' ? 100 : 10000;

    const tsharkOutput = await runTsharkFullDump(filePath, maxPackets, jobId);

    emitJobProgress(jobId, {
      progress: 90,
      message: 'Packaging results...',
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

    console.log(`✅ Analysis complete: ${results.totalPackets} packets extracted`);

    await saveResults(jobId, results);
    emitJobCompleted(jobId, results);

    return results;
  } catch (error: any) {
    console.error('❌ PCAP worker error:', error);
    console.error('❌ Stack:', error.stack);

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
    console.log(`📡 Running tshark on ${filePath}, max packets: ${maxPackets}`);

    // Export EVERYTHING with -V (full packet tree)
    const tshark = spawn('tshark', [
      '-r', filePath,
      '-T', 'json',
      '-c', maxPackets.toString(),
      '-V' // VERBOSE: Full packet dissection tree (all layers, all fields)
    ]);

    const chunks: Buffer[] = [];
    let stderr = '';

    tshark.stdout.on('data', (chunk: Buffer) => {
      chunks.push(chunk);
    });

    tshark.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    tshark.on('close', (code) => {
      if (code === 0 || code === null) {
        try {
          const fullOutput = Buffer.concat(chunks).toString('utf8');
          console.log(`✅ tshark output size: ${fullOutput.length} bytes`);

          const packets = JSON.parse(fullOutput);
          console.log(`✅ Parsed ${packets.length} packets`);

          resolve(packets);
        } catch (err: any) {
          console.error('❌ Failed to parse tshark JSON:', err.message);
          reject(new Error(`tshark JSON parse failed: ${err.message}`));
        }
      } else {
        console.error(`❌ tshark exited with code ${code}`);
        console.error(`❌ stderr: ${stderr}`);
        reject(new Error(`tshark failed (code ${code}): ${stderr.substring(0, 500)}`));
      }
    });

    tshark.on('error', (error) => {
      console.error('❌ Failed to spawn tshark:', error);
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

console.log('✅ Simple PCAP worker started (tshark full dump mode)');
