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

// Start the workers
const workers = spawn('node', [join(__dirname, 'workers', 'index.js')], {
  stdio: 'inherit',
  env: process.env
});

server.on('error', (error) => {
  console.error('❌ Server error:', error);
  process.exit(1);
});

workers.on('error', (error) => {
  console.error('❌ Workers error:', error);
  process.exit(1);
});

server.on('exit', (code) => {
  console.log(`🛑 Server exited with code ${code}`);
  workers.kill();
  process.exit(code || 0);
});

workers.on('exit', (code) => {
  console.log(`🛑 Workers exited with code ${code}`);
  server.kill();
  process.exit(code || 0);
});

// Handle graceful shutdown
process.on('SIGTERM', () => {
  console.log('📴 SIGTERM received, shutting down...');
  server.kill('SIGTERM');
  workers.kill('SIGTERM');
});

process.on('SIGINT', () => {
  console.log('📴 SIGINT received, shutting down...');
  server.kill('SIGINT');
  workers.kill('SIGINT');
});

console.log('✅ Both server and workers started');
