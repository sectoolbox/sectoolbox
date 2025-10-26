import { io, Socket } from 'socket.io-client';
import { toast } from 'react-hot-toast';

// Derive WebSocket URL from backend API URL
const BACKEND_URL = import.meta.env.VITE_BACKEND_API_URL || 'http://localhost:8080';
const WS_URL = BACKEND_URL.replace('https://', 'wss://').replace('http://', 'ws://');

class WebSocketClient {
  private socket: Socket | null = null;
  private reconnectAttempts = 0;
  private maxReconnectAttempts = 5;

  connect() {
    if (this.socket?.connected) return this.socket;

    console.log('🔌 Connecting to WebSocket:', WS_URL);

    this.socket = io(WS_URL, {
      transports: ['websocket', 'polling'],
      reconnection: true,
      reconnectionDelay: 1000,
      reconnectionDelayMax: 5000,
      reconnectionAttempts: this.maxReconnectAttempts,
    });

    this.socket.on('connect', () => {
      this.reconnectAttempts = 0;
      console.log('✅ WebSocket connected');
    });

    this.socket.on('disconnect', (reason) => {
      console.log('❌ WebSocket disconnected:', reason);
      if (reason === 'io server disconnect') {
        // Server disconnected, attempt manual reconnect
        this.socket?.connect();
      }
    });

    this.socket.on('connect_error', (_error) => {
      this.reconnectAttempts++;
      if (this.reconnectAttempts >= this.maxReconnectAttempts) {
        toast.error('Unable to connect to server. Please check your connection.');
      }
    });

    this.socket.on('error', (_error) => {
      toast.error('Connection error. Retrying...');
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

  removeAllListeners() {
    this.socket?.removeAllListeners('job-progress');
    this.socket?.removeAllListeners('job-completed');
    this.socket?.removeAllListeners('job-failed');
  }

  disconnect() {
    this.socket?.disconnect();
    this.socket = null;
  }
}

export const wsClient = new WebSocketClient();
