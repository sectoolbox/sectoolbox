import express from 'express';
import cors from 'cors';
import helmet from 'helmet';
import compression from 'compression';
import rateLimit from 'express-rate-limit';
import { createServer } from 'http';
import { Server } from 'socket.io';
import dotenv from 'dotenv';
import { fileURLToPath } from 'url';
import { dirname, join } from 'path';

// Routes
import pcapRoutes from './routes/pcap.js';
import audioRoutes from './routes/audio.js';
import imageRoutes from './routes/image.js';
import jobsRoutes from './routes/jobs.js';
import followRoutes from './routes/follow.js';
import eventLogsRoutes from './routes/eventlogs.js';

// Services
import { initializeQueue, cleanupStaleJobs } from './services/queue.js';
import { initializeWebSocket } from './services/websocket.js';
import { startCleanupScheduler } from './utils/cleanup.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

dotenv.config({ path: join(__dirname, '../.env') });

// Parse allowed origins with proper trimming
const allowedOrigins = process.env.ALLOWED_ORIGINS 
  ? process.env.ALLOWED_ORIGINS.split(',').map(origin => origin.trim())
  : ['http://localhost:5173', 'http://localhost:3000'];

const app = express();
app.set('trust proxy', 1); // Trust first proxy (Railway, Vercel, etc.)
const httpServer = createServer(app);
const io = new Server(httpServer, {
  cors: {
    origin: allowedOrigins,
    methods: ['GET', 'POST'],
    credentials: true
  }
});

const PORT = process.env.PORT || 8080;

// Rate limiting
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 150, // 150 requests per 15 min
  message: 'Too many requests from this IP, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

const uploadLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 uploads per 15 min
  message: 'Too many file uploads, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

const analysisLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 200, // 200 analysis requests per 15 min (for job status polling)
  message: 'Too many analysis requests, please slow down.',
  standardHeaders: true,
  legacyHeaders: false,
});

// Middleware
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' }
}));
app.use(compression());
app.use(cors({
  origin: allowedOrigins,
  credentials: true
}));
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

// Apply general rate limiting to all routes
app.use(generalLimiter);

// Health check
app.get('/health', async (req, res) => {
  try {
    const { getRedisClient, getPcapQueue, getAudioQueue, getEventLogQueue } = await import('./services/queue.js');
    
    const redisClient = getRedisClient();
    const pcapQueue = getPcapQueue();
    const audioQueue = getAudioQueue();
    const eventLogQueue = getEventLogQueue();

    // Check Redis connection
    const redisStatus = redisClient?.isOpen ? 'connected' : 'disconnected';
    
    // Get queue stats
    const [pcapCounts, audioCounts, eventLogCounts] = await Promise.all([
      pcapQueue?.getJobCounts().catch(() => ({ waiting: 0, active: 0, completed: 0, failed: 0 })),
      audioQueue?.getJobCounts().catch(() => ({ waiting: 0, active: 0, completed: 0, failed: 0 })),
      eventLogQueue?.getJobCounts().catch(() => ({ waiting: 0, active: 0, completed: 0, failed: 0 }))
    ]);

    res.json({
      status: 'ok',
      timestamp: new Date().toISOString(),
      uptime: process.uptime(),
      redis: redisStatus,
      queues: {
        pcap: pcapCounts,
        audio: audioCounts,
        eventLog: eventLogCounts
      },
      memory: {
        used: Math.round(process.memoryUsage().heapUsed / 1024 / 1024),
        total: Math.round(process.memoryUsage().heapTotal / 1024 / 1024)
      }
    });
  } catch (error) {
    res.status(503).json({
      status: 'error',
      timestamp: new Date().toISOString(),
      error: 'Health check failed'
    });
  }
});

// API Routes with specific rate limiters
app.use('/api/v1/pcap', uploadLimiter, pcapRoutes);
app.use('/api/v1/audio', uploadLimiter, audioRoutes);
app.use('/api/v1/image', uploadLimiter, imageRoutes);
app.use('/api/v1/eventlogs', uploadLimiter, eventLogsRoutes);
app.use('/api/v1/jobs', analysisLimiter, jobsRoutes);
app.use('/api/v1/follow', followRoutes);

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

    // Clean stale jobs from previous runs
    await cleanupStaleJobs();

    // Initialize WebSocket
    initializeWebSocket(io);
    console.log('✅ WebSocket initialized');

    // Start cleanup scheduler (aggressive for free Redis tier)
    startCleanupScheduler();

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
