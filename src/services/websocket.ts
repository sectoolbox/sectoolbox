import { io, Socket } from 'socket.io-client';

const WS_URL = import.meta.env.VITE_BACKEND_WS_URL || 'ws://localhost:8080';

class WebSocketClient {
  private socket: Socket | null = null;

  connect() {
    if (this.socket?.connected) return this.socket;

    this.socket = io(WS_URL, {
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionAttempts: 5,
    });

    this.socket.on('connect', () => {
      console.log('✅ WebSocket connected');
    });

    this.socket.on('disconnect', () => {
      console.log('❌ WebSocket disconnected');
    });

    this.socket.on('error', (error) => {
      console.error('WebSocket error:', error);
    });

    return this.socket;
  }

  joinJob(jobId: string) {
    if (!this.socket) this.connect();
    this.socket?.emit('join-job', jobId);
  }

  leaveJob(jobId: string) {
    this.socket?.emit('leave-job', jobId);
  }

  onJobProgress(callback: (data: any) => void) {
    this.socket?.on('job-progress', callback);
  }

  onJobCompleted(callback: (data: any) => void) {
    this.socket?.on('job-completed', callback);
  }

  onJobFailed(callback: (data: any) => void) {
    this.socket?.on('job-failed', callback);
  }

  disconnect() {
    this.socket?.disconnect();
    this.socket = null;
  }
}

export const wsClient = new WebSocketClient();
