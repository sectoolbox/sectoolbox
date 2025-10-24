import { Server, Socket } from 'socket.io';

let io: Server;

export function initializeWebSocket(socketServer: Server) {
  io = socketServer;

  io.on('connection', (socket: Socket) => {
    console.log(`WebSocket client connected: ${socket.id}`);

    socket.on('join-job', (jobId: string) => {
      socket.join(`job-${jobId}`);
      console.log(`Client ${socket.id} joined job room: ${jobId}`);
    });

    socket.on('leave-job', (jobId: string) => {
      socket.leave(`job-${jobId}`);
      console.log(`Client ${socket.id} left job room: ${jobId}`);
    });

    socket.on('disconnect', () => {
      console.log(`WebSocket client disconnected: ${socket.id}`);
    });
  });
}

export function getIO() {
  if (!io) throw new Error('WebSocket not initialized');
  return io;
}

export function emitJobProgress(jobId: string, data: {
  progress: number;
  message: string;
  status: 'queued' | 'processing' | 'completed' | 'failed';
  data?: any;
}) {
  if (!io) return;
  io.to(`job-${jobId}`).emit('job-progress', {
    jobId,
    ...data,
    timestamp: new Date().toISOString()
  });
}

export function emitJobCompleted(jobId: string, result: any) {
  if (!io) return;
  io.to(`job-${jobId}`).emit('job-completed', {
    jobId,
    result,
    timestamp: new Date().toISOString()
  });
}

export function emitJobFailed(jobId: string, error: string) {
  if (!io) return;
  io.to(`job-${jobId}`).emit('job-failed', {
    jobId,
    error,
    timestamp: new Date().toISOString()
  });
}
