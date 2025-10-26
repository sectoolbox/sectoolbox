import express from 'express';
import { getPythonQueue, getPcapQueue, getAudioQueue, getEventLogQueue } from '../services/queue.js';
import { readResults } from '../services/storage.js';

const router = express.Router();

router.get('/:jobId', async (req, res) => {
  try {
    const { jobId } = req.params;

    // Check all queues for the job
    const queues = [getPythonQueue(), getPcapQueue(), getAudioQueue(), getEventLogQueue()];
    let job = null;

    for (const queue of queues) {
      job = await queue.getJob(jobId);
      if (job) break;
    }

    if (!job) {
      return res.status(404).json({ error: 'Job not found' });
    }

    const state = await job.getState();
    const progress = job.progress();
    const progressData = typeof progress === 'object' ? progress : { progress: progress || 0 };

    let results = null;
    if (state === 'completed') {
      try {
        results = await readResults(jobId);
      } catch (error) {
        // Results might not be saved yet
      }
    }

    res.json({
      jobId,
      status: state,
      progress: progressData.progress || 0,
      message: progressData.message || null,
      results,
      createdAt: job.timestamp,
      finishedAt: job.finishedOn
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

export default router;
