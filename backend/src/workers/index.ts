import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';
import { initializeQueue } from '../services/queue.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

dotenv.config({ path: join(__dirname, '../../.env') });

async function startWorkers() {
  try {
    console.log('Starting Sectoolbox workers...');

    // Initialize Redis and Bull queues
    await initializeQueue();
    console.log('Queue initialized');

    // Import and start all workers
    await import('./pcapWorker.js');
    await import('./audioWorker.js');
    await import('./eventLogWorker.js');

    console.log('All workers started successfully');
    console.log('Workers ready to process jobs');
  } catch (error) {
    console.error('Failed to start workers:', error);
    process.exit(1);
  }
}

// Handle graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down workers...');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down workers...');
  process.exit(0);
});

startWorkers();
