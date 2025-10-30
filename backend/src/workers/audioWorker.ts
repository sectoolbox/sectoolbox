import { spawn } from 'child_process';
import { getAudioQueue } from '../services/queue.js';
import { saveResults } from '../services/storage.js';
import { emitJobProgress, emitJobCompleted, emitJobFailed } from '../services/websocket.js';
import { JOB_STATUS } from '../utils/constants.js';
import { promises as fs } from 'fs';
import { join, dirname } from 'path';

const queue = getAudioQueue();

queue.process(async (job) => {
  const { jobId, filePath, task, filename } = job.data;

  // Helper function to update both Bull job state and WebSocket
  const updateProgress = async (progress: number, message: string) => {
    await job.progress({ progress, message });
    emitJobProgress(jobId, {
      progress,
      message,
      status: JOB_STATUS.PROCESSING
    });
  };

  await updateProgress(10, 'Starting audio analysis...');

  try {
    if (task === 'spectrogram') {
      // Generate both waveform and spectrogram automatically
      const [waveformData, spectrogramData] = await Promise.all([
        generateWaveform(filePath, jobId, job),
        generateSpectrogram(filePath, jobId, job)
      ]);

      const results = {
        filename,
        task,
        waveform: waveformData,
        spectrogram: spectrogramData,
        timestamp: new Date().toISOString()
      };

      await saveResults(jobId, results);
      emitJobCompleted(jobId, results);

      return results;
    } else {
      throw new Error(`Unknown audio task: ${task}`);
    }
  } catch (error: any) {
    console.error('Audio processing error:', error);
    emitJobFailed(jobId, error.message);
    throw error;
  }
});

async function generateWaveform(audioPath: string, jobId: string, job: any): Promise<any> {
  return new Promise((resolve, reject) => {
    // Use FFmpeg to generate waveform visualization
    const outputPath = join(dirname(audioPath), `${jobId}_waveform.png`);

    job.progress({ progress: 20, message: 'Generating waveform with FFmpeg...' });
    emitJobProgress(jobId, {
      progress: 20,
      message: 'Generating waveform with FFmpeg...',
      status: JOB_STATUS.PROCESSING
    });

    const ffmpeg = spawn('ffmpeg', [
      '-i', audioPath,
      '-filter_complex', 'showwavespic=s=1200x200:colors=#00ff88',
      '-frames:v', '1',
      '-y',
      outputPath
    ]);

    let stderr = '';

    ffmpeg.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    ffmpeg.on('close', async (code) => {
      if (code === 0) {
        job.progress({ progress: 50, message: 'Processing waveform data...' });
        emitJobProgress(jobId, {
          progress: 50,
          message: 'Processing waveform data...',
          status: JOB_STATUS.PROCESSING
        });

        try {
          // Read the generated image
          const imageBuffer = await fs.readFile(outputPath);
          const base64Image = imageBuffer.toString('base64');

          // Clean up the generated file
          await fs.unlink(outputPath).catch(() => {});

          resolve({
            width: 1200,
            height: 200,
            image: `data:image/png;base64,${base64Image}`,
            format: 'png'
          });
        } catch (err: any) {
          reject(new Error(`Failed to read waveform: ${err.message}`));
        }
      } else {
        reject(new Error(`FFmpeg waveform failed: ${stderr}`));
      }
    });

    ffmpeg.on('error', (error) => {
      reject(new Error(`Failed to start FFmpeg for waveform: ${error.message}`));
    });
  });
}

async function generateSpectrogram(audioPath: string, jobId: string, job: any): Promise<any> {
  return new Promise((resolve, reject) => {
    // Use FFmpeg to generate spectrogram
    const outputPath = join(dirname(audioPath), `${jobId}_spectrogram.png`);

    job.progress({ progress: 60, message: 'Generating spectrogram with FFmpeg...' });
    emitJobProgress(jobId, {
      progress: 60,
      message: 'Generating spectrogram with FFmpeg...',
      status: JOB_STATUS.PROCESSING
    });

    const ffmpeg = spawn('ffmpeg', [
      '-i', audioPath,
      '-lavfi', 'showspectrumpic=s=1024x512:legend=0',
      '-y',
      outputPath
    ]);

    let stderr = '';

    ffmpeg.stderr.on('data', (data) => {
      stderr += data.toString();
    });

    ffmpeg.on('close', async (code) => {
      if (code === 0) {
        job.progress({ progress: 80, message: 'Processing spectrogram data...' });
        emitJobProgress(jobId, {
          progress: 80,
          message: 'Processing spectrogram data...',
          status: JOB_STATUS.PROCESSING
        });

        try {
          // Read the generated image
          const imageBuffer = await fs.readFile(outputPath);
          const base64Image = imageBuffer.toString('base64');

          // Clean up the generated file
          await fs.unlink(outputPath).catch(() => {});

          resolve({
            width: 1024,
            height: 512,
            image: `data:image/png;base64,${base64Image}`,
            format: 'png'
          });
        } catch (err: any) {
          reject(new Error(`Failed to read spectrogram: ${err.message}`));
        }
      } else {
        reject(new Error(`FFmpeg failed: ${stderr}`));
      }
    });

    ffmpeg.on('error', (error) => {
      reject(new Error(`Failed to start FFmpeg: ${error.message}`));
    });
  });
}

console.log('Audio worker started');
