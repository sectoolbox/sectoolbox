import Bull from 'bull';
import { createClient } from 'redis';

let pcapQueue: Bull.Queue;
let audioQueue: Bull.Queue;
let eventLogQueue: Bull.Queue;
let imageQueue: Bull.Queue;
let redisClient: ReturnType<typeof createClient>;

export async function initializeQueue() {
  const redisUrl = process.env.REDIS_URL || process.env.REDIS_PRIVATE_URL || 'redis://localhost:6379';

  try {
    // Create Redis client for caching
    redisClient = createClient({ url: redisUrl });

    redisClient.on('error', (err) => {
      // Redis Client Error
    });

    redisClient.on('connect', () => {
      // Redis client connected
    });

    await redisClient.connect();
    // Redis client ready
  } catch (error: any) {
    // Failed to connect to Redis
    throw error;
  }

  // Create Bull queues with aggressive cleanup for free Redis tier
  pcapQueue = new Bull('pcap-jobs', redisUrl, {
    defaultJobOptions: {
      attempts: 2,
      timeout: 600000, // 10 minutes
      removeOnComplete: 5,  // Keep only last 5 successful jobs
      removeOnFail: 5       // Keep only last 5 failed jobs
    }
  });

  audioQueue = new Bull('audio-jobs', redisUrl, {
    defaultJobOptions: {
      attempts: 2,
      timeout: 300000, // 5 minutes
      removeOnComplete: 5,  // Keep only last 5 successful jobs
      removeOnFail: 5       // Keep only last 5 failed jobs
    }
  });

  eventLogQueue = new Bull('eventlog-jobs', redisUrl, {
    defaultJobOptions: {
      attempts: 2,
      timeout: 600000, // 10 minutes for large files
      removeOnComplete: 5,  // Keep only last 5 successful jobs
      removeOnFail: 5       // Keep only last 5 failed jobs
    }
  });

  imageQueue = new Bull('image-jobs', redisUrl, {
    defaultJobOptions: {
      attempts: 2,
      timeout: 300000, // 5 minutes
      removeOnComplete: 5,  // Keep only last 5 successful jobs
      removeOnFail: 5       // Keep only last 5 failed jobs
    }
  });

  console.log('Bull queues initialized');
}

export function getPcapQueue() {
  if (!pcapQueue) throw new Error('PCAP queue not initialized');
  return pcapQueue;
}

export function getAudioQueue() {
  if (!audioQueue) throw new Error('Audio queue not initialized');
  return audioQueue;
}

export function getEventLogQueue() {
  if (!eventLogQueue) throw new Error('Event log queue not initialized');
  return eventLogQueue;
}

export function getImageQueue() {
  if (!imageQueue) throw new Error('Image queue not initialized');
  return imageQueue;
}

export function getRedisClient() {
  if (!redisClient) throw new Error('Redis client not initialized');
  return redisClient;
}

// Cache helpers with proper prefixing for cleanup
export async function cacheSet(key: string, value: any, ttl: number = 3600) {
  const prefixedKey = `cache:${key}`;
  await redisClient.setEx(prefixedKey, ttl, JSON.stringify(value));
}

export async function cacheGet(key: string) {
  const prefixedKey = `cache:${key}`;
  const value = await redisClient.get(prefixedKey);
  return value ? JSON.parse(value) : null;
}

export async function cacheDel(key: string) {
  const prefixedKey = `cache:${key}`;
  await redisClient.del(prefixedKey);
}

// Clean up stale jobs on startup
export async function cleanupStaleJobs() {
  try {
    console.log('Cleaning up stale jobs from Redis...');
    const queues = [pcapQueue, audioQueue, eventLogQueue];
    let totalCleaned = 0;

    for (const queue of queues) {
      if (!queue) continue;

      // Remove all completed and failed jobs older than 2 hours
      const completed = await queue.getCompleted();
      const failed = await queue.getFailed();
      const now = Date.now();
      const maxAge = 2 * 60 * 60 * 1000; // 2 hours

      for (const job of [...completed, ...failed]) {
        const age = now - job.timestamp;
        if (age > maxAge) {
          await job.remove();
          totalCleaned++;
        }
      }

      // Clean any stuck jobs
      const active = await queue.getActive();
      for (const job of active) {
        const age = now - job.timestamp;
        if (age > 30 * 60 * 1000) { // 30 minutes stuck = dead
          await job.moveToFailed({ message: 'Job timeout - cleaned on startup' }, true);
          totalCleaned++;
        }
      }
    }

    console.log(`✅ Cleaned ${totalCleaned} stale jobs from Redis`);
  } catch (error) {
    console.error('Failed to clean stale jobs:', error);
  }
}

// Cleanup expired cache keys (active cleanup, not just TTL)
export async function cleanupExpiredCache() {
  try {
    const keys = await redisClient.keys('cache:*');
    let cleaned = 0;

    for (const key of keys) {
      const ttl = await redisClient.ttl(key);
      if (ttl === -1 || ttl === -2) { // No TTL or expired
        await redisClient.del(key);
        cleaned++;
      }
    }

    if (cleaned > 0) {
      console.log(`🧹 Cleaned ${cleaned} expired cache entries`);
    }
  } catch (error) {
    console.error('Cache cleanup failed:', error);
  }
}

// Get Redis memory usage stats
export async function getRedisStats() {
  try {
    const info = await redisClient.info('memory');
    const usedMemory = info.match(/used_memory_human:(.+)/)?.[1];
    const maxMemory = info.match(/maxmemory_human:(.+)/)?.[1];
    return { usedMemory, maxMemory };
  } catch (error) {
    return { usedMemory: 'unknown', maxMemory: 'unknown' };
  }
}
