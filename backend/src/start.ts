import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

console.log('🚀 Starting Sectoolbox backend services...');

// Handle graceful shutdown
let isShuttingDown = false;
const shutdown = (signal: string) => {
  if (isShuttingDown) return;
  isShuttingDown = true;
  
  console.log(`\n${signal} received, shutting down gracefully...`);
  
  if (workers) {
    workers.kill('SIGTERM');
  }
  server.kill('SIGTERM');
  
  // Force exit after 10 seconds if processes don't exit cleanly
  setTimeout(() => {
    console.error('Forced shutdown after timeout');
    process.exit(1);
  }, 10000);
};

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

// Start the API server
const server = spawn('node', [join(__dirname, 'server.js')], {
  stdio: 'inherit',
  env: process.env
});

// Only start workers if Redis is configured
let workers: any = null;
if (process.env.REDIS_URL) {
  console.log('Redis URL found, starting workers...');
  workers = spawn('node', [join(__dirname, 'workers', 'index.js')], {
    stdio: 'inherit',
    env: process.env
  });
} else {
  console.warn('REDIS_URL not set, workers disabled. Jobs will not be processed.');
  console.warn('Add Redis to Railway or set REDIS_URL environment variable.');
}

server.on('error', (error) => {
  if (!isShuttingDown) {
    console.error('Server error:', error);
    process.exit(1);
  }
});

if (workers) {
  workers.on('error', (error: any) => {
    if (!isShuttingDown) {
      console.error('Workers error:', error);
      process.exit(1);
    }
  });

  workers.on('exit', (code: any) => {
    if (!isShuttingDown) {
      console.log(`Workers exited with code ${code}`);
      server.kill();
      process.exit(code || 0);
    }
  });
}

server.on('exit', (code) => {
  if (!isShuttingDown) {
    console.log(`Server exited with code ${code}`);
    if (workers) workers.kill();
    process.exit(code || 0);
  } else {
    console.log('Server shutdown complete');
    process.exit(0);
  }
});

console.log('✅ Sectoolbox backend services started successfully');
