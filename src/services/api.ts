import axios, { AxiosInstance } from 'axios';

const BACKEND_URL = import.meta.env.VITE_BACKEND_API_URL || 'http://localhost:8080';

class ApiClient {
  private client: AxiosInstance;

  constructor() {
    this.client = axios.create({
      baseURL: BACKEND_URL,
      timeout: 120000, // 2 minutes
      headers: {
        'Content-Type': 'application/json',
      },
    });
  }

  // PCAP analysis
  async analyzePcap(file: File, depth: 'quick' | 'full' = 'full') {
    // API call
    const formData = new FormData();
    formData.append('file', file);
    formData.append('depth', depth);

    const response = await this.client.post('/api/v1/pcap/analyze', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    // API call
    return response.data;
  }

  // Audio analysis
  async generateSpectrogram(file: File) {
    // API call
    const formData = new FormData();
    formData.append('file', file);

    const response = await this.client.post('/api/v1/audio/spectrogram', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    // API call
    return response.data;
  }

  // Event Log analysis
  async analyzeEventLog(file: File) {
    // API call
    const formData = new FormData();
    formData.append('file', file);

    const response = await this.client.post('/api/v1/eventlogs/analyze', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    // API call
    return response.data;
  }

  // Image analysis - Advanced (ELA + Steganography + File Carving)
  async analyzeImageAdvanced(
    file: File,
    options: {
      performELA?: boolean;
      elaQuality?: number;
      performSteganography?: boolean;
      performFileCarving?: boolean;
    } = {}
  ) {
    // API call
    const formData = new FormData();
    formData.append('file', file);
    formData.append('options', JSON.stringify(options));

    const response = await this.client.post('/api/v1/image/advanced-analysis', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    // API call
    return response.data;
  }

  // Image analysis - ELA only
  async analyzeImageELA(file: File, quality: number = 90) {
    // API call
    const formData = new FormData();
    formData.append('file', file);
    formData.append('quality', quality.toString());

    const response = await this.client.post('/api/v1/image/ela', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    // API call
    return response.data;
  }

  // Job status
  async getJobStatus(jobId: string) {
    // API call
    // API call
    const response = await this.client.get(`/api/v1/jobs/${jobId}`);
    return response.data;
  }

  // Health check
  async healthCheck() {
    const response = await this.client.get('/health');
    return response.data;
  }

  // Follow TCP stream
  async followTcpStream(jobId: string, streamId: number, filename: string) {
    // API call
    const response = await this.client.post(`/api/v1/follow/tcp/${jobId}/${streamId}`, {
      filename
    });
    // API call
    return response.data;
  }
}

export const apiClient = new ApiClient();
