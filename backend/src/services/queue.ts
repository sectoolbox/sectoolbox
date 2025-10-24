import Bull from 'bull';
import { createClient } from 'redis';

let pythonQueue: Bull.Queue;
let pcapQueue: Bull.Queue;
let audioQueue: Bull.Queue;
let redisClient: ReturnType<typeof createClient>;

export async function initializeQueue() {
  const redisUrl = process.env.REDIS_URL || 'redis://localhost:6379';

  // Create Redis client for caching
  redisClient = createClient({ url: redisUrl });
  await redisClient.connect();

  // Create Bull queues
  pythonQueue = new Bull('python-jobs', redisUrl, {
    defaultJobOptions: {
      attempts: 3,
      backoff: {
        type: 'exponential',
        delay: 2000
      },
      removeOnComplete: 100,
      removeOnFail: 50
    }
  });

  pcapQueue = new Bull('pcap-jobs', redisUrl, {
    defaultJobOptions: {
      attempts: 2,
      timeout: 600000, // 10 minutes
      removeOnComplete: 50,
      removeOnFail: 25
    }
  });

  audioQueue = new Bull('audio-jobs', redisUrl, {
    defaultJobOptions: {
      attempts: 2,
      timeout: 300000, // 5 minutes
      removeOnComplete: 50,
      removeOnFail: 25
    }
  });

  console.log('✅ Bull queues initialized');
}

export function getPythonQueue() {
  if (!pythonQueue) throw new Error('Python queue not initialized');
  return pythonQueue;
}

export function getPcapQueue() {
  if (!pcapQueue) throw new Error('PCAP queue not initialized');
  return pcapQueue;
}

export function getAudioQueue() {
  if (!audioQueue) throw new Error('Audio queue not initialized');
  return audioQueue;
}

export function getRedisClient() {
  if (!redisClient) throw new Error('Redis client not initialized');
  return redisClient;
}

// Cache helpers
export async function cacheSet(key: string, value: any, ttl: number = 3600) {
  await redisClient.setEx(key, ttl, JSON.stringify(value));
}

export async function cacheGet(key: string) {
  const value = await redisClient.get(key);
  return value ? JSON.parse(value) : null;
}

export async function cacheDel(key: string) {
  await redisClient.del(key);
}
