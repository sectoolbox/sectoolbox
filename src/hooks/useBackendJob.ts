import { useState, useEffect, useCallback } from 'react';
import { apiClient } from '../services/api';
import { wsClient } from '../services/websocket';

interface JobStatus {
  jobId: string;
  status: 'queued' | 'processing' | 'completed' | 'failed';
  progress: number;
  message?: string;
  results?: any;
  error?: string;
}

export function useBackendJob() {
  const [jobStatus, setJobStatus] = useState<JobStatus | null>(null);
  const [isLoading, setIsLoading] = useState(false);

  const startJob = useCallback(async (jobId: string) => {
    setIsLoading(true);
    setJobStatus({
      jobId,
      status: 'queued',
      progress: 0,
      message: 'Job queued...',
    });

    // Connect to WebSocket for real-time updates
    wsClient.connect();
    wsClient.joinJob(jobId);

    // Listen for progress updates
    wsClient.onJobProgress((data) => {
      setJobStatus({
        jobId: data.jobId,
        status: data.status,
        progress: data.progress,
        message: data.message,
      });
    });

    // Listen for completion
    wsClient.onJobCompleted((data) => {
      setJobStatus({
        jobId: data.jobId,
        status: 'completed',
        progress: 100,
        results: data.result,
      });
      setIsLoading(false);
      wsClient.leaveJob(jobId);
    });

    // Listen for failures
    wsClient.onJobFailed((data) => {
      setJobStatus({
        jobId: data.jobId,
        status: 'failed',
        progress: 0,
        error: data.error,
      });
      setIsLoading(false);
      wsClient.leaveJob(jobId);
    });

    // Poll for status as fallback
    const pollInterval = setInterval(async () => {
      try {
        const status = await apiClient.getJobStatus(jobId);
        if (status.status === 'completed' || status.status === 'failed') {
          clearInterval(pollInterval);
          setJobStatus(status);
          setIsLoading(false);
          wsClient.leaveJob(jobId);
        }
      } catch (error: any) {
        console.error('Failed to poll job status:', error);
        console.error('Job ID:', jobId);
        console.error('Error details:', error.response?.status, error.response?.data);
      }
    }, 3000);

    // Cleanup after 5 minutes
    setTimeout(() => {
      clearInterval(pollInterval);
      if (jobStatus?.status === 'processing') {
        setIsLoading(false);
      }
    }, 300000);
  }, []);

  useEffect(() => {
    return () => {
      if (jobStatus?.jobId) {
        wsClient.leaveJob(jobStatus.jobId);
      }
    };
  }, [jobStatus?.jobId]);

  return {
    jobStatus,
    isLoading,
    startJob,
  };
}
