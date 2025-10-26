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

    // Track whether WebSocket is working
    let wsConnected = false;
    let pollInterval: NodeJS.Timeout | null = null;

    // Connect to WebSocket for real-time updates
    wsClient.connect();
    wsClient.joinJob(jobId);

    // Remove any existing listeners to prevent duplicates
    wsClient.removeAllListeners();

    // Listen for progress updates
    wsClient.onJobProgress((data) => {
      if (data.jobId === jobId) {
        wsConnected = true; // WebSocket is working
        if (pollInterval) {
          clearInterval(pollInterval);
          pollInterval = null;
        }
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
        wsConnected = true; // WebSocket is working
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
        wsConnected = true; // WebSocket is working
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

    // Start polling only as fallback if WebSocket doesn't connect within 5 seconds
    const fallbackTimeout = setTimeout(() => {
      if (!wsConnected && !pollInterval) {
        pollInterval = setInterval(async () => {
          try {
            const status = await apiClient.getJobStatus(jobId);
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
          }
        }, 3000);
      }
    }, 5000);

    // Cleanup after 5 minutes
    setTimeout(() => {
      if (pollInterval) {
        clearInterval(pollInterval);
      }
      clearTimeout(fallbackTimeout);
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
