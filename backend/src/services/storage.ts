import { promises as fs } from 'fs';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';
import { v4 as uuidv4 } from 'uuid';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const STORAGE_PATH = process.env.STORAGE_PATH || join(__dirname, '../../storage');
const UPLOADS_PATH = join(STORAGE_PATH, 'uploads');
const RESULTS_PATH = join(STORAGE_PATH, 'results');

// Initialize storage directories
export async function initializeStorage() {
  await fs.mkdir(UPLOADS_PATH, { recursive: true });
  await fs.mkdir(RESULTS_PATH, { recursive: true });
}

// File upload
export async function saveUploadedFile(buffer: Buffer, originalName: string, jobId: string): Promise<string> {
  const jobDir = join(UPLOADS_PATH, jobId);
  await fs.mkdir(jobDir, { recursive: true });

  const filePath = join(jobDir, originalName);
  await fs.writeFile(filePath, buffer);

  return filePath;
}

// Save results
export async function saveResults(jobId: string, results: any): Promise<string> {
  const resultsDir = join(RESULTS_PATH, jobId);
  await fs.mkdir(resultsDir, { recursive: true });

  const resultsPath = join(resultsDir, 'output.json');
  await fs.writeFile(resultsPath, JSON.stringify(results, null, 2));

  return resultsPath;
}

// Read results
export async function readResults(jobId: string): Promise<any> {
  const resultsPath = join(RESULTS_PATH, jobId, 'output.json');
  const data = await fs.readFile(resultsPath, 'utf-8');
  return JSON.parse(data);
}

// Delete job files
export async function deleteJobFiles(jobId: string): Promise<void> {
  const uploadDir = join(UPLOADS_PATH, jobId);
  const resultsDir = join(RESULTS_PATH, jobId);

  try {
    await fs.rm(uploadDir, { recursive: true, force: true });
    await fs.rm(resultsDir, { recursive: true, force: true });
    console.log(`Deleted files for job: ${jobId}`);
  } catch (error) {
    console.error(`Failed to delete files for job ${jobId}:`, error);
  }
}

// Get uploaded file path
export function getUploadedFilePath(jobId: string, filename: string): string {
  return join(UPLOADS_PATH, jobId, filename);
}

// List all jobs (for cleanup)
export async function listAllJobs(): Promise<{ uploads: string[]; results: string[] }> {
  const uploads = await fs.readdir(UPLOADS_PATH).catch(() => []);
  const results = await fs.readdir(RESULTS_PATH).catch(() => []);
  return { uploads, results };
}

// Get job creation time
export async function getJobCreationTime(jobId: string): Promise<Date | null> {
  try {
    const uploadDir = join(UPLOADS_PATH, jobId);
    const stats = await fs.stat(uploadDir);
    return stats.birthtime;
  } catch (error) {
    return null;
  }
}

// Initialize storage on import
initializeStorage().catch(console.error);

export { UPLOADS_PATH, RESULTS_PATH };
