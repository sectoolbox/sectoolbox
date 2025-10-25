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

  // Python script execution
  async listPythonScripts() {
    const response = await this.client.get('/api/v1/python/scripts');
    return response.data;
  }

  async executePythonScript(scriptId: string, file: File) {
    console.log('Executing Python script:', scriptId, 'with file:', file.name);
    const formData = new FormData();
    formData.append('scriptId', scriptId);
    formData.append('file', file);

    const response = await this.client.post('/api/v1/python/execute', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    console.log('Python execute response:', response.data);
    return response.data;
  }

  // PCAP analysis
  async analyzePcap(file: File, depth: 'quick' | 'full' = 'full') {
    console.log('Analyzing PCAP:', file.name, 'depth:', depth);
    const formData = new FormData();
    formData.append('file', file);
    formData.append('depth', depth);

    const response = await this.client.post('/api/v1/pcap/analyze', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    console.log('PCAP analyze response:', response.data);
    return response.data;
  }

  // Audio analysis
  async generateSpectrogram(file: File) {
    console.log('Generating spectrogram for:', file.name);
    const formData = new FormData();
    formData.append('file', file);

    const response = await this.client.post('/api/v1/audio/spectrogram', formData, {
      headers: {
        'Content-Type': 'multipart/form-data',
      },
    });
    console.log('Spectrogram response:', response.data);
    return response.data;
  }

  // Job status
  async getJobStatus(jobId: string) {
    console.log('Fetching job status for:', jobId);
    console.log('URL:', `/api/v1/jobs/${jobId}`);
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
    console.log('Following TCP stream:', jobId, streamId, filename);
    const response = await this.client.post(`/api/v1/follow/tcp/${jobId}/${streamId}`, {
      filename
    });
    console.log('Follow stream response:', response.data);
    return response.data;
  }
}

export const apiClient = new ApiClient();
