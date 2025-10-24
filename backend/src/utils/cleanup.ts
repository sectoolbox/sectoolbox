import { listAllJobs, getJobCreationTime, deleteJobFiles } from '../services/storage.js';

const CLEANUP_INTERVAL = 15 * 60 * 1000; // Run every 15 minutes
const MAX_FILE_AGE = 60 * 60 * 1000; // 1 hour

export function startCleanupScheduler() {
  // Run immediately on start
  runCleanup();

  // Schedule periodic cleanup
  setInterval(runCleanup, CLEANUP_INTERVAL);

  console.log(`✅ Cleanup scheduler started (interval: ${CLEANUP_INTERVAL / 1000}s, max age: ${MAX_FILE_AGE / 1000}s)`);
}

async function runCleanup() {
  console.log('🧹 Running cleanup...');

  try {
    const { uploads, results } = await listAllJobs();
    const allJobs = new Set([...uploads, ...results]);

    let deletedCount = 0;
    const now = Date.now();

    for (const jobId of allJobs) {
      const creationTime = await getJobCreationTime(jobId);

      if (!creationTime) {
        console.log(`⚠️  Could not get creation time for job: ${jobId}`);
        continue;
      }

      const age = now - creationTime.getTime();

      if (age > MAX_FILE_AGE) {
        await deleteJobFiles(jobId);
        deletedCount++;
        console.log(`🗑️  Deleted old job: ${jobId} (age: ${Math.round(age / 1000 / 60)}min)`);
      }
    }

    if (deletedCount > 0) {
      console.log(`✅ Cleanup completed: ${deletedCount} jobs deleted`);
    } else {
      console.log('✅ Cleanup completed: No old jobs to delete');
    }
  } catch (error) {
    console.error('❌ Cleanup failed:', error);
  }
}
