import { spawn } from 'child_process';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

console.log('🚀 Starting Sectoolbox backend services...');

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
  console.error('Server error:', error);
  process.exit(1);
});

if (workers) {
  workers.on('error', (error: any) => {
    console.error('Workers error:', error);
    process.exit(1);
  });

  workers.on('exit', (code: any) => {
    console.log(`Workers exited with code ${code}`);
    server.kill();
    process.exit(code || 0);
  });
}

server.on('exit', (code) => {
  console.log(`Server exited with code ${code}`);
  if (workers) workers.kill();
  process.exit(code || 0);
});

// Handle graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down...');
  server.kill('SIGTERM');
  if (workers) workers.kill('SIGTERM');
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down...');
  server.kill('SIGINT');
  if (workers) workers.kill('SIGINT');
});

console.log('Both server and workers started');
