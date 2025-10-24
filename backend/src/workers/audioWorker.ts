import { spawn } from 'child_process';
import { getAudioQueue } from '../services/queue.js';
import { saveResults } from '../services/storage.js';
import { emitJobProgress, emitJobCompleted, emitJobFailed } from '../services/websocket.js';
import { promises as fs } from 'fs';
import { join, dirname } from 'path';

const queue = getAudioQueue();

queue.process(async (job) => {
  const { jobId, filePath, task, filename } = job.data;

  emitJobProgress(jobId, {
    progress: 10,
    message: 'Starting audio analysis...',
    status: 'processing'
  });

  try {
    if (task === 'spectrogram') {
      const spectrogramData = await generateSpectrogram(filePath, jobId);

      const results = {
        filename,
        task,
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

async function generateSpectrogram(audioPath: string, jobId: string): Promise<any> {
  return new Promise((resolve, reject) => {
    // Use FFmpeg to generate spectrogram
    const outputPath = join(dirname(audioPath), `${jobId}_spectrogram.png`);

    emitJobProgress(jobId, {
      progress: 30,
      message: 'Generating spectrogram with FFmpeg...',
      status: 'processing'
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
        emitJobProgress(jobId, {
          progress: 80,
          message: 'Processing spectrogram data...',
          status: 'processing'
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

console.log('✅ Audio worker started');
