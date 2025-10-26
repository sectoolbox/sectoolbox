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

    // Track polling state
    let pollInterval: NodeJS.Timeout | null = null;

    // Connect to WebSocket for real-time updates
    wsClient.connect();
    wsClient.joinJob(jobId);

    // Remove any existing listeners to prevent duplicates
    wsClient.removeAllListeners();

    // Listen for progress updates
    wsClient.onJobProgress((data) => {
      console.log('📊 Frontend received progress:', data);
      if (data.jobId === jobId) {
        setJobStatus({
          jobId: data.jobId,
          status: data.status,
          progress: data.progress,
          message: data.message,
        });
      }
    });

    // Listen for completion
    wsClient.onJobCompleted((data) => {
      if (data.jobId === jobId) {
        if (pollInterval) {
          clearInterval(pollInterval);
          pollInterval = null;
        }
        setJobStatus({
          jobId: data.jobId,
          status: 'completed',
          progress: 100,
          results: data.result,
        });
        setIsLoading(false);
        wsClient.leaveJob(jobId);
      }
    });

    // Listen for failures
    wsClient.onJobFailed((data) => {
      if (data.jobId === jobId) {
        if (pollInterval) {
          clearInterval(pollInterval);
          pollInterval = null;
        }
        setJobStatus({
          jobId: data.jobId,
          status: 'failed',
          progress: 0,
          error: data.error,
        });
        setIsLoading(false);
        wsClient.leaveJob(jobId);
      }
    });

    // Poll for status as fallback with single in-flight request
    let isPolling = false;
    pollInterval = setInterval(async () => {
      if (isPolling) return; // Skip if already polling
      
      isPolling = true;
      try {
        const status = await apiClient.getJobStatus(jobId);
        console.log('📡 Polling received status:', status);
        
        // Update progress even if not complete (for fallback when WebSocket fails)
        if (status.status === 'processing') {
          setJobStatus({
            jobId: status.jobId,
            status: status.status,
            progress: status.progress || 0,
            message: status.message,
          });
        }
        
        if (status.status === 'completed' || status.status === 'failed') {
          if (pollInterval) {
            clearInterval(pollInterval);
            pollInterval = null;
          }
          setJobStatus(status);
          setIsLoading(false);
          wsClient.leaveJob(jobId);
        }
      } catch (error: any) {
        // Silently fail - WebSocket will handle it
      } finally {
        isPolling = false;
      }
    }, 3000);

    // Cleanup after 5 minutes
    setTimeout(() => {
      if (pollInterval) {
        clearInterval(pollInterval);
      }
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
