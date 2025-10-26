import express from 'express';
import multer from 'multer';
import { v4 as uuidv4 } from 'uuid';
import { getEventLogQueue } from '../services/queue.js';
import { saveUploadedFile } from '../services/storage.js';
import { validateFileSize, validateFileType } from '../utils/validators.js';

const router = express.Router();
// Allow up to 1.5GB for event log files
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 1.5 * 1024 * 1024 * 1024 } });

router.post('/analyze', upload.single('file'), async (req, res) => {
  try {
    const file = req.file;

    if (!file) {
      return res.status(400).json({ error: 'Event log file required' });
    }

    validateFileSize(file.size, 1.5 * 1024 * 1024 * 1024); // 1.5GB max
    validateFileType(file.originalname, ['evtx']);

    const jobId = uuidv4();
    const filePath = await saveUploadedFile(file.buffer, file.originalname, jobId);

    const queue = getEventLogQueue();
    await queue.add({ jobId, filePath, filename: file.originalname }, { jobId });

    res.json({
      jobId,
      status: 'queued',
      message: 'Event log analysis queued'
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

export default router;
