import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import { createServer } from 'http';
import { Server } from 'socket.io';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

// Routes
import pythonRoutes from './routes/python.js';
import pcapRoutes from './routes/pcap.js';
import audioRoutes from './routes/audio.js';
import jobsRoutes from './routes/jobs.js';
import threatIntelRoutes from './routes/threatIntel.js';

// Services
import { initializeQueue } from './services/queue.js';
import { initializeWebSocket } from './services/websocket.js';
import { startCleanupScheduler } from './utils/cleanup.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

dotenv.config({ path: join(__dirname, '../.env') });

const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: {
    origin: process.env.ALLOWED_ORIGINS?.split(',') || '*',
    methods: ['GET', 'POST'],
    credentials: true
  }
});

const PORT = process.env.PORT || 8080;

// Middleware
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' }
}));
app.use(compression());
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || '*',
  credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Health check
app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// API Routes
app.use('/api/v1/python', pythonRoutes);
app.use('/api/v1/pcap', pcapRoutes);
app.use('/api/v1/audio', audioRoutes);
app.use('/api/v1/jobs', jobsRoutes);
app.use('/api/v1/threat-intel', threatIntelRoutes);

// Error handling
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('Error:', err);
  res.status(err.status || 500).json({
    error: err.message || 'Internal server error',
    ...(process.env.NODE_ENV === 'development' && { stack: err.stack })
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// Initialize services
async function startServer() {
  try {
    // Initialize Redis and Bull queue
    await initializeQueue();
    console.log('✅ Queue initialized');

    // Initialize WebSocket
    initializeWebSocket(io);
    console.log('✅ WebSocket initialized');

    // Start cleanup scheduler (delete files after 1 hour)
    startCleanupScheduler();
    console.log('✅ Cleanup scheduler started');

    // Start server
    httpServer.listen(PORT, () => {
      console.log(`🚀 Backend server running on port ${PORT}`);
      console.log(`📡 WebSocket server ready`);
      console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
    });
  } catch (error) {
    console.error('❌ Failed to start server:', error);
    process.exit(1);
  }
}

// Graceful shutdown
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  httpServer.close(() => {
    console.log('Server closed');
    process.exit(0);
  });
});

startServer();

export { io };
