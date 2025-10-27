import express from 'express';
import multer from 'multer';
import { v4 as uuidv4 } from 'uuid';
import { getEventLogQueue } from '../services/queue.js';
import { saveUploadedFile } from '../services/storage.js';
import { validateFileSize, validateFileType } from '../utils/validators.js';
import { FILE_SIZE_LIMITS, ALLOWED_EXTENSIONS, JOB_STATUS } from '../utils/constants.js';

const router = express.Router();
const upload = multer({ 
  storage: multer.memoryStorage(), 
  limits: { fileSize: FILE_SIZE_LIMITS.EVTX } 
});

router.post('/analyze', upload.single('file'), async (req, res) => {
  try {
    const file = req.file;

    if (!file) {
      return res.status(400).json({ error: 'Event log file required' });
    }

    validateFileSize(file.size, FILE_SIZE_LIMITS.EVTX);
    validateFileType(file.originalname, ALLOWED_EXTENSIONS.EVTX);

    const jobId = uuidv4();
    const filePath = await saveUploadedFile(file.buffer, file.originalname, jobId);

    const queue = getEventLogQueue();
    await queue.add({ jobId, filePath, filename: file.originalname }, { jobId });

    res.json({
      jobId,
      status: JOB_STATUS.QUEUED,
      message: 'Event log analysis queued'
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

export default router;
