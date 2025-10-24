import { spawn } from 'child_process';
import { getPythonQueue } from '../services/queue.js';
import { saveResults } from '../services/storage.js';
import { emitJobProgress, emitJobCompleted, emitJobFailed } from '../services/websocket.js';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const queue = getPythonQueue();

queue.process(async (job) => {
  const { jobId, scriptId, filePath, filename } = job.data;

  emitJobProgress(jobId, {
    progress: 10,
    message: 'Starting Python script execution...',
    status: 'processing'
  });

  try {
    const scriptsDir = join(__dirname, '../scripts/pythonScripts');
    const scriptPath = await findScriptPath(scriptsDir, scriptId);

    if (!scriptPath) {
      throw new Error(`Script not found: ${scriptId}`);
    }

    // Execute Python script
    const output = await executePythonScript(scriptPath, filePath, jobId);

    emitJobProgress(jobId, {
      progress: 90,
      message: 'Saving results...',
      status: 'processing'
    });

    const results = {
      output,
      scriptId,
      filename,
      timestamp: new Date().toISOString()
    };

    await saveResults(jobId, results);

    emitJobCompleted(jobId, results);

    return results;
  } catch (error: any) {
    emitJobFailed(jobId, error.message);
    throw error;
  }
});

async function findScriptPath(scriptsDir: string, scriptId: string): Promise<string | null> {
  const { promises: fs } = await import('fs');
  const categories = await fs.readdir(scriptsDir);

  for (const category of categories) {
    const categoryPath = join(scriptsDir, category);
    const stat = await fs.stat(categoryPath);

    if (stat.isDirectory()) {
      const files = await fs.readdir(categoryPath);
      for (const file of files) {
        if (file === `${scriptId}.py`) {
          return join(categoryPath, file);
        }
      }
    }
  }

  return null;
}

function executePythonScript(scriptPath: string, inputFile: string, jobId: string): Promise<string> {
  return new Promise((resolve, reject) => {
    // Modify the script to use the uploaded file
    const python = spawn('python3', [scriptPath], {
      cwd: dirname(inputFile),
      env: {
        ...process.env,
        INPUT_FILE: inputFile,
        JOB_ID: jobId
      }
    });

    let stdout = '';
    let stderr = '';

    python.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    python.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    python.on('close', (code) => {
      if (code === 0) {
        resolve(stdout);
      } else {
        reject(new Error(`Python script failed: ${stderr || stdout}`));
      }
    });

    python.on('error', (error) => {
      reject(new Error(`Failed to start Python: ${error.message}`));
    });
  });
}

console.log('✅ Python worker started');
