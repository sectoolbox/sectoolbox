import express from 'express';
import multer from 'multer';
import { v4 as uuidv4 } from 'uuid';
import { getAudioQueue } from '../services/queue.js';
import { saveUploadedFile } from '../services/storage.js';
import { validateFileSize, validateFileType } from '../utils/validators.js';
import { FILE_SIZE_LIMITS, ALLOWED_EXTENSIONS } from '../utils/constants.js';

const router = express.Router();
const upload = multer({ 
  storage: multer.memoryStorage(), 
  limits: { fileSize: FILE_SIZE_LIMITS.AUDIO } 
});

router.post('/spectrogram', upload.single('file'), async (req, res) => {
  try {
    const file = req.file;

    if (!file) {
      return res.status(400).json({ error: 'Audio file required' });
    }

    validateFileSize(file.size, FILE_SIZE_LIMITS.AUDIO);
    validateFileType(file.originalname, ALLOWED_EXTENSIONS.AUDIO);

    const jobId = uuidv4();
    const filePath = await saveUploadedFile(file.buffer, file.originalname, jobId);

    try {
      const queue = getAudioQueue();
      await queue.add({ jobId, filePath, task: 'spectrogram', filename: file.originalname }, { jobId });

      res.json({
        jobId,
        status: 'queued',
        message: 'Audio analysis queued'
      });
    } catch (queueError: any) {
      // Queue not available - return helpful error
      console.error('Audio queue error:', queueError);
      return res.status(503).json({ 
        error: 'Audio processing queue not available. Please ensure Redis is configured on Railway.',
        details: queueError.message 
      });
    }
  } catch (error: any) {
    console.error('Audio route error:', error);
    res.status(500).json({ error: error.message });
  }
});

export default router;
