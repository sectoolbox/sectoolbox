import express from 'express';
import multer from 'multer';
import { v4 as uuidv4 } from 'uuid';
import { getPcapQueue } from '../services/queue.js';
import { saveUploadedFile } from '../services/storage.js';
import { validateFileSize, validateFileType } from '../utils/validators.js';

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 2 * 1024 * 1024 * 1024 } });

router.post('/analyze', upload.single('file'), async (req, res) => {
  try {
    const file = req.file;
    const { depth = 'full' } = req.body;

    if (!file) {
      return res.status(400).json({ error: 'PCAP file required' });
    }

    validateFileSize(file.size);
    validateFileType(file.originalname, ['pcap', 'pcapng', 'cap']);

    const jobId = uuidv4();
    const filePath = await saveUploadedFile(file.buffer, file.originalname, jobId);

    const queue = getPcapQueue();
    await queue.add({ jobId, filePath, depth, filename: file.originalname });

    res.json({
      jobId,
      status: 'queued',
      message: 'PCAP analysis queued'
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

export default router;
