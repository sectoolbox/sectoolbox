import express from 'express';
import multer from 'multer';
import { v4 as uuidv4 } from 'uuid';
import { getPythonQueue } from '../services/queue.js';
import { saveUploadedFile } from '../services/storage.js';
import { validateFileSize, sanitizeFilename } from '../utils/validators.js';

const router = express.Router();
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 2 * 1024 * 1024 * 1024 } });

// List available Python scripts
router.get('/scripts', async (req, res) => {
  try {
    const { promises: fs } = await import('fs');
    const { join, dirname } = await import('path');
    const { fileURLToPath } = await import('url');

    const __filename = fileURLToPath(import.meta.url);
    const __dirname = dirname(__filename);
    const scriptsDir = join(__dirname, '../scripts/pythonScripts');

    const categories = await fs.readdir(scriptsDir);
    const scripts: any[] = [];

    for (const category of categories) {
      const categoryPath = join(scriptsDir, category);
      const stat = await fs.stat(categoryPath);

      if (stat.isDirectory()) {
        const files = await fs.readdir(categoryPath);

        for (const file of files) {
          if (file.endsWith('.py')) {
            const content = await fs.readFile(join(categoryPath, file), 'utf-8');
            const metadata = parseScriptMetadata(content, file, category);
            scripts.push(metadata);
          }
        }
      }
    }

    res.json({ scripts });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// Execute Python script
router.post('/execute', upload.single('file'), async (req, res) => {
  try {
    const { scriptId } = req.body;
    const file = req.file;

    if (!scriptId) {
      return res.status(400).json({ error: 'Script ID required' });
    }

    if (!file) {
      return res.status(400).json({ error: 'File required' });
    }

    validateFileSize(file.size);

    const jobId = uuidv4();
    const filename = sanitizeFilename(file.originalname);

    // Save uploaded file
    const filePath = await saveUploadedFile(file.buffer, filename, jobId);

    // Queue the job
    const queue = getPythonQueue();
    const job = await queue.add({
      jobId,
      scriptId,
      filePath,
      filename
    });

    res.json({
      jobId,
      status: 'queued',
      message: 'Python script queued for execution'
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

// Helper function to parse script metadata
function parseScriptMetadata(content: string, filename: string, category: string) {
  const lines = content.split('\n');
  let title = filename.replace('.py', '').replace(/-/g, ' ');
  let description = '';
  let author = 'Sectoolbox';

  for (const line of lines) {
    if (line.startsWith('# TITLE:')) {
      title = line.replace('# TITLE:', '').trim();
    } else if (line.startsWith('# DESCRIPTION:')) {
      description = line.replace('# DESCRIPTION:', '').trim();
    } else if (line.startsWith('# AUTHOR:')) {
      author = line.replace('# AUTHOR:', '').trim();
    }
  }

  return {
    id: filename.replace('.py', ''),
    title,
    description,
    category,
    author,
    filename
  };
}

export default router;
