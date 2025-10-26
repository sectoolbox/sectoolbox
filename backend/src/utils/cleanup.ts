import { listAllJobs, getJobCreationTime, deleteJobFiles } from '../services/storage.js';
import { getPythonQueue, getPcapQueue, getAudioQueue, getEventLogQueue } from '../services/queue.js';

const CLEANUP_INTERVAL = 15 * 60 * 1000; // Run every 15 minutes
const MAX_FILE_AGE = 60 * 60 * 1000; // 1 hour
const MAX_QUEUE_JOB_AGE = 24 * 60 * 60 * 1000; // 24 hours for completed/failed queue jobs

export function startCleanupScheduler() {
  // Run immediately on start
  runCleanup();

  // Schedule periodic cleanup
  setInterval(runCleanup, CLEANUP_INTERVAL);

  console.log(`Cleanup scheduler started (interval: ${CLEANUP_INTERVAL / 1000}s, max age: ${MAX_FILE_AGE / 1000}s)`);
}

async function runCleanup() {
  console.log('Running cleanup...');

  try {
    const { uploads, results } = await listAllJobs();
    const allJobs = new Set([...uploads, ...results]);

    let deletedCount = 0;
    const now = Date.now();

    for (const jobId of allJobs) {
      const creationTime = await getJobCreationTime(jobId);

      if (!creationTime) {
        console.log(`Could not get creation time for job: ${jobId}`);
        continue;
      }

      const age = now - creationTime.getTime();

      if (age > MAX_FILE_AGE) {
        await deleteJobFiles(jobId);
        deletedCount++;
        console.log(`Deleted old job: ${jobId} (age: ${Math.round(age / 1000 / 60)}min)`);
      }
    }

    if (deletedCount > 0) {
      // Cleanup completed: ${deletedCount} jobs deleted
    }

    // Clean old queue jobs
    await cleanQueueJobs();
  } catch (error) {
    // Cleanup failed
  }
}

async function cleanQueueJobs() {
  try {
    const queues = [getPythonQueue(), getPcapQueue(), getAudioQueue(), getEventLogQueue()];
    const now = Date.now();
    let totalCleaned = 0;

    for (const queue of queues) {
      if (!queue) continue;

      // Clean completed jobs older than MAX_QUEUE_JOB_AGE
      const completed = await queue.getCompleted();
      const failed = await queue.getFailed();

      for (const job of [...completed, ...failed]) {
        const age = now - job.timestamp;
        if (age > MAX_QUEUE_JOB_AGE) {
          await job.remove();
          totalCleaned++;
        }
      }
    }

    if (totalCleaned > 0) {
      // Cleaned ${totalCleaned} old queue jobs
    }
  } catch (error) {
    // Queue cleanup failed
  }
}
