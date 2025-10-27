import { listAllJobs, getJobCreationTime, deleteJobFiles } from '../services/storage.js';
import { getPcapQueue, getAudioQueue, getEventLogQueue, cleanupExpiredCache, getRedisStats } from '../services/queue.js';

const CLEANUP_INTERVAL = 60 * 60 * 1000; // Run every 1 hour (reduced from 15 min)
const MAX_FILE_AGE = 60 * 60 * 1000; // 1 hour
const MAX_QUEUE_JOB_AGE = 2 * 60 * 60 * 1000; // 2 hours (synced with file age)

export function startCleanupScheduler() {
  // Run immediately on start
  runCleanup();

  // Schedule periodic cleanup
  setInterval(runCleanup, CLEANUP_INTERVAL);

  console.log(`✅ Cleanup scheduler started`);
  console.log(`   - Runs every: ${CLEANUP_INTERVAL / 1000 / 60} minutes`);
  console.log(`   - File max age: ${MAX_FILE_AGE / 1000 / 60} minutes`);
  console.log(`   - Queue job max age: ${MAX_QUEUE_JOB_AGE / 1000 / 60} minutes`);
}

async function runCleanup() {
  console.log('🧹 Running cleanup...');

  try {
    // Get Redis stats before cleanup
    const statsBefore = await getRedisStats();
    console.log(`   Redis memory: ${statsBefore.usedMemory}`);

    const { uploads, results } = await listAllJobs();
    const allJobs = new Set([...uploads, ...results]);

    let deletedCount = 0;
    const now = Date.now();

    for (const jobId of allJobs) {
      const creationTime = await getJobCreationTime(jobId);

      if (!creationTime) {
        continue;
      }

      const age = now - creationTime.getTime();

      if (age > MAX_FILE_AGE) {
        await deleteJobFiles(jobId);
        deletedCount++;
      }
    }

    if (deletedCount > 0) {
      console.log(`   ✅ Deleted ${deletedCount} old file jobs`);
    }

    // Clean old queue jobs
    const queueCleaned = await cleanQueueJobs();
    if (queueCleaned && queueCleaned > 0) {
      console.log(`   ✅ Deleted ${queueCleaned} old queue jobs`);
    }

    // Clean expired cache entries
    await cleanupExpiredCache();

    // Show Redis stats after cleanup
    const statsAfter = await getRedisStats();
    console.log(`   Redis memory after: ${statsAfter.usedMemory}`);
    console.log('✅ Cleanup complete');
  } catch (error) {
    console.error('❌ Cleanup failed:', error);
  }
}

async function cleanQueueJobs() {
  try {
    const queues = [getPcapQueue(), getAudioQueue(), getEventLogQueue()];
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

    return totalCleaned;
  } catch (error) {
    console.error('Queue cleanup error:', error);
    return 0;
  }
}
