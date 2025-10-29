import express from 'express';
import multer from 'multer';
import { v4 as uuidv4 } from 'uuid';
import { getImageQueue } from '../services/queue.js';
import { saveUploadedFile } from '../services/storage.js';
import { validateFileSize, validateFileType } from '../utils/validators.js';
import { FILE_SIZE_LIMITS, ALLOWED_EXTENSIONS, JOB_STATUS } from '../utils/constants.js';

const router = express.Router();
const upload = multer({ 
  storage: multer.memoryStorage(), 
  limits: { fileSize: FILE_SIZE_LIMITS.IMAGE || 50 * 1024 * 1024 } // 50MB default
});

/**
 * POST /api/image/advanced-analysis
 * Performs advanced forensic analysis on uploaded image
 * - ELA (Error Level Analysis)
 * - Advanced Steganography Detection (SPA, RS, Histogram)
 * - Enhanced File Carving
 */
router.post('/advanced-analysis', upload.single('file'), async (req, res) => {
  try {
    const file = req.file;

    if (!file) {
      return res.status(400).json({ error: 'Image file required' });
    }

    // Validate file
    const imageExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp', '.tiff'];
    validateFileSize(file.size, FILE_SIZE_LIMITS.IMAGE || 50 * 1024 * 1024);
    validateFileType(file.originalname, imageExtensions);

    const jobId = uuidv4();
    const filePath = await saveUploadedFile(file.buffer, file.originalname, jobId);

    // Parse options from request
    const options = {
      performELA: req.body.performELA !== 'false', // Default true
      elaQuality: parseInt(req.body.elaQuality || '90'),
      performSteganography: req.body.performSteganography !== 'false', // Default true
      performFileCarving: req.body.performFileCarving !== 'false', // Default true
      maxCarvedFiles: parseInt(req.body.maxCarvedFiles || '10')
    };

    try {
      const queue = getImageQueue();
      await queue.add(
        { 
          jobId, 
          filePath, 
          filename: file.originalname,
          options,
          task: 'advanced-analysis'
        }, 
        { jobId }
      );

      res.json({
        jobId,
        status: JOB_STATUS.QUEUED,
        message: 'Advanced image analysis queued'
      });
    } catch (queueError: any) {
      console.error('Image queue error:', queueError);
      return res.status(503).json({ 
        error: 'Image processing queue not available. Please ensure Redis is configured.',
        details: queueError.message 
      });
    }
  } catch (error: any) {
    console.error('Image route error:', error);
    res.status(500).json({ error: error.message });
  }
});

/**
 * POST /api/image/ela
 * Performs only ELA analysis (lighter operation)
 */
router.post('/ela', upload.single('file'), async (req, res) => {
  try {
    const file = req.file;

    if (!file) {
      return res.status(400).json({ error: 'Image file required' });
    }

    const imageExtensions = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.webp'];
    validateFileSize(file.size, FILE_SIZE_LIMITS.IMAGE || 50 * 1024 * 1024);
    validateFileType(file.originalname, imageExtensions);

    const jobId = uuidv4();
    const filePath = await saveUploadedFile(file.buffer, file.originalname, jobId);

    const options = {
      performELA: true,
      elaQuality: parseInt(req.body.quality || '90'),
      performSteganography: false,
      performFileCarving: false
    };

    try {
      const queue = getImageQueue();
      await queue.add(
        { 
          jobId, 
          filePath, 
          filename: file.originalname,
          options,
          task: 'ela-only'
        }, 
        { jobId }
      );

      res.json({
        jobId,
        status: JOB_STATUS.QUEUED,
        message: 'ELA analysis queued'
      });
    } catch (queueError: any) {
      console.error('Image queue error:', queueError);
      return res.status(503).json({ 
        error: 'Image processing queue not available.',
        details: queueError.message 
      });
    }
  } catch (error: any) {
    console.error('Image ELA route error:', error);
    res.status(500).json({ error: error.message });
  }
});

export default router;
