import { Server, Socket } from 'socket.io';
import { WS_EVENTS, JOB_STATUS } from '../utils/constants.js';

let io: Server;

export function initializeWebSocket(socketServer: Server) {
  io = socketServer;

  io.on('connection', (socket: Socket) => {
    console.log(`WebSocket client connected: ${socket.id}`);

    socket.on(WS_EVENTS.JOIN_JOB, (jobId: string) => {
      socket.join(`job-${jobId}`);
      console.log(`Client ${socket.id} joined job room: ${jobId}`);
    });

    socket.on(WS_EVENTS.LEAVE_JOB, (jobId: string) => {
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
  status: typeof JOB_STATUS[keyof typeof JOB_STATUS];
  data?: any;
}) {
  if (!io) return;
  io.to(`job-${jobId}`).emit(WS_EVENTS.JOB_PROGRESS, {
    jobId,
    ...data,
    timestamp: new Date().toISOString()
  });
}

export function emitJobCompleted(jobId: string, result: any) {
  if (!io) return;
  io.to(`job-${jobId}`).emit(WS_EVENTS.JOB_COMPLETED, {
    jobId,
    result,
    timestamp: new Date().toISOString()
  });
}

export function emitJobFailed(jobId: string, error: string) {
  if (!io) return;
  io.to(`job-${jobId}`).emit(WS_EVENTS.JOB_FAILED, {
    jobId,
    error,
    timestamp: new Date().toISOString()
  });
}
