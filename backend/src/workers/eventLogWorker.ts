import { spawn } from 'child_process';
import path from 'path';
import fs from 'fs';
import { getEventLogQueue } from '../services/queue.js';
import { saveResults } from '../services/storage.js';
import { emitJobProgress, emitJobCompleted, emitJobFailed } from '../services/websocket.js';
import { fileURLToPath } from 'url';
import { dirname } from 'path';
import { JOB_STATUS } from '../utils/constants.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const queue = getEventLogQueue();

queue.process(async (job) => {
  const { jobId, filePath, filename } = job.data;

  console.log(`Processing Event Log job ${jobId}: ${filename}`);

  emitJobProgress(jobId, {
    progress: 10,
    message: 'Reading event log file...',
    status: JOB_STATUS.PROCESSING
  });

  try {
    emitJobProgress(jobId, {
      progress: 30,
      message: 'Parsing events with Python parser...',
      status: JOB_STATUS.PROCESSING
    });

    // Run Python script to parse the .evtx file
    // In production (Docker), scripts are in /app/python-scripts
    // In development, they're in src/scripts/pythonScripts
    const scriptPath = fs.existsSync('/app/python-scripts/evtx-parser.py')
      ? '/app/python-scripts/evtx-parser.py'
      : path.join(__dirname, '..', 'scripts', 'pythonScripts', 'evtx-parser.py');
    
    const pythonOutput = await runPythonParser(scriptPath, filePath, jobId);

    emitJobProgress(jobId, {
      progress: 90,
      message: 'Finalizing results...',
      status: JOB_STATUS.PROCESSING
    });

    // Add metadata
    const results = {
      ...pythonOutput,
      filename,
      timestamp: new Date().toISOString()
    };

    console.log(`Event log analysis complete: ${results.metadata?.totalEvents || 0} events parsed`);

    await saveResults(jobId, results);
    emitJobCompleted(jobId, results);

    return results;
  } catch (error: any) {
    console.error(`Event log analysis failed for job ${jobId}:`, error.message);
    emitJobFailed(jobId, error.message);
    throw error;
  }
});

async function runPythonParser(scriptPath: string, filePath: string, jobId: string): Promise<any> {
  return new Promise((resolve, reject) => {
    let stdout = '';
    let stderr = '';

    const pythonCmd = process.platform === 'win32' ? 'python' : '/opt/venv/bin/python3';

    const proc = spawn(pythonCmd, [scriptPath, filePath], {
      cwd: path.dirname(scriptPath)
    });

    proc.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    proc.stderr.on('data', (data) => {
      stderr += data.toString();
      console.error(`Python stderr: ${data}`);
    });

    proc.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(`Python parser failed with code ${code}: ${stderr}`));
        return;
      }

      try {
        const result = JSON.parse(stdout);

        if (result.error) {
          reject(new Error(result.error));
          return;
        }

        resolve(result);
      } catch (error: any) {
        reject(new Error(`Failed to parse Python output: ${error.message}\nOutput: ${stdout}`));
      }
    });

    proc.on('error', (error) => {
      reject(new Error(`Failed to spawn Python process: ${error.message}`));
    });

    // Progress updates (rough estimate based on time)
    let progress = 30;
    const progressInterval = setInterval(() => {
      if (progress < 85) {
        progress += 5;
        emitJobProgress(jobId, {
          progress,
          message: 'Parsing events...',
          status: JOB_STATUS.PROCESSING
        });
      }
    }, 2000);

    proc.on('close', () => {
      clearInterval(progressInterval);
    });
  });
}

console.log('Event Log worker initialized');

export default queue;
