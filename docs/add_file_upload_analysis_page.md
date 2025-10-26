# How to Add a New File Upload & Analysis Page

This guide shows you how to add a new file upload and analysis page similar to `/pcap` or `/eventlogs`.

## Overview

These pages follow a consistent pattern:
1. Frontend uploads file to backend API
2. Backend queues job and processes file with Python/tools
3. Frontend receives results via WebSocket
4. Results are displayed in tabbed interface

---

## Step-by-Step Guide

### 1. Create Backend Python Script

Create your analysis script in `backend/src/scripts/pythonScripts/`:

```python
#!/usr/bin/env python3
"""
Your Analysis Script - Parse and analyze files
"""

import sys
import json
import os

def analyze_file(filepath):
    """Analyze the file and return results"""
    try:
        # Your analysis logic here
        results = {
            'data': [],  # Your parsed data
            'metadata': {
                'totalItems': 0,
                'filename': os.path.basename(filepath)
            },
            'analysis': {
                # Your analysis results
            }
        }
        
        return results
        
    except Exception as e:
        return {
            'error': f'Failed to analyze file: {str(e)}',
            'data': []
        }

def main():
    if len(sys.argv) < 2:
        print(json.dumps({'error': 'No file path provided'}))
        sys.exit(1)
    
    filepath = sys.argv[1]
    
    if not os.path.exists(filepath):
        print(json.dumps({'error': f'File not found: {filepath}'}))
        sys.exit(1)
    
    # Analyze the file
    result = analyze_file(filepath)
    
    # Output result as JSON
    print(json.dumps(result, default=str))
    
    # Delete the file after processing to save disk space
    try:
        os.remove(filepath)
    except Exception as e:
        pass  # Don't fail if deletion fails

if __name__ == '__main__':
    main()
```

**Key Points:**
- Accept file path as command line argument
- Output results as JSON to stdout
- Delete file after processing (`os.remove(filepath)`)
- Handle errors gracefully

---

### 2. Update Backend Dependencies

Add any required Python packages to `backend/requirements.txt`:

```txt
# Your analysis library
your-library==1.0.0
```

The Dockerfile will automatically install these.

---

### 3. Create Backend API Route

Create `backend/src/routes/yourfeature.ts`:

```typescript
import express from 'express';
import multer from 'multer';
import { v4 as uuidv4 } from 'uuid';
import { getYourFeatureQueue } from '../services/queue.js';
import { saveUploadedFile } from '../services/storage.js';
import { validateFileSize, validateFileType } from '../utils/validators.js';

const router = express.Router();
// Set max file size (e.g., 1GB)
const upload = multer({ 
  storage: multer.memoryStorage(), 
  limits: { fileSize: 1 * 1024 * 1024 * 1024 } 
});

router.post('/analyze', upload.single('file'), async (req, res) => {
  try {
    const file = req.file;

    if (!file) {
      return res.status(400).json({ error: 'File required' });
    }

    // Validate file size and type
    validateFileSize(file.size, 1 * 1024 * 1024 * 1024); // 1GB max
    validateFileType(file.originalname, ['ext1', 'ext2']); // Allowed extensions

    const jobId = uuidv4();
    const filePath = await saveUploadedFile(file.buffer, file.originalname, jobId);

    const queue = getYourFeatureQueue();
    await queue.add({ jobId, filePath, filename: file.originalname }, { jobId });

    res.json({
      jobId,
      status: 'queued',
      message: 'Analysis queued'
    });
  } catch (error: any) {
    res.status(500).json({ error: error.message });
  }
});

export default router;
```

---

### 4. Add Queue to Queue Service

Edit `backend/src/services/queue.ts`:

**Add variable:**
```typescript
let yourFeatureQueue: Bull.Queue;
```

**Initialize queue in `initializeQueue()`:**
```typescript
yourFeatureQueue = new Bull('yourfeature-jobs', redisUrl, {
  defaultJobOptions: {
    attempts: 2,
    timeout: 600000, // 10 minutes
    removeOnComplete: 50,
    removeOnFail: 25
  }
});
```

**Export getter function:**
```typescript
export function getYourFeatureQueue() {
  if (!yourFeatureQueue) throw new Error('YourFeature queue not initialized');
  return yourFeatureQueue;
}
```

---

### 5. Create Backend Worker

Create `backend/src/workers/yourFeatureWorker.ts`:

```typescript
import { spawn } from 'child_process';
import path from 'path';
import { getYourFeatureQueue } from '../services/queue.js';
import { saveResults } from '../services/storage.js';
import { emitJobProgress, emitJobCompleted, emitJobFailed } from '../services/websocket.js';
import { fileURLToPath } from 'url';
import { dirname } from 'path';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

const queue = getYourFeatureQueue();

queue.process(async (job) => {
  const { jobId, filePath, filename } = job.data;

  console.log(`Processing YourFeature job ${jobId}: ${filename}`);

  emitJobProgress(jobId, {
    progress: 10,
    message: 'Reading file...',
    status: 'processing'
  });

  try {
    emitJobProgress(jobId, {
      progress: 30,
      message: 'Analyzing file...',
      status: 'processing'
    });

    const scriptPath = path.join(__dirname, '..', 'scripts', 'pythonScripts', 'your-script.py');
    const pythonOutput = await runPythonParser(scriptPath, filePath, jobId);

    emitJobProgress(jobId, {
      progress: 90,
      message: 'Finalizing results...',
      status: 'processing'
    });

    const results = {
      ...pythonOutput,
      filename,
      timestamp: new Date().toISOString()
    };

    console.log(`Analysis complete: ${results.metadata?.totalItems || 0} items parsed`);

    await saveResults(jobId, results);
    emitJobCompleted(jobId, results);

    return results;
  } catch (error: any) {
    console.error(`Analysis failed for job ${jobId}:`, error.message);
    emitJobFailed(jobId, error.message);
    throw error;
  }
});

async function runPythonParser(scriptPath: string, filePath: string, jobId: string): Promise<any> {
  return new Promise((resolve, reject) => {
    let stdout = '';
    let stderr = '';

    const pythonCmd = process.platform === 'win32' ? 'python' : 'python3';

    const proc = spawn(pythonCmd, [scriptPath, filePath], {
      cwd: path.dirname(scriptPath)
    });

    proc.stdout.on('data', (data) => {
      stdout += data.toString();
    });

    proc.stderr.on('data', (data) => {
      stderr += data.toString();
      console.error(`Python stderr: ${data}`);
    });

    proc.on('close', (code) => {
      if (code !== 0) {
        reject(new Error(`Python parser failed with code ${code}: ${stderr}`));
        return;
      }

      try {
        const result = JSON.parse(stdout);
        if (result.error) {
          reject(new Error(result.error));
          return;
        }
        resolve(result);
      } catch (error: any) {
        reject(new Error(`Failed to parse Python output: ${error.message}`));
      }
    });

    // Progress updates
    let progress = 30;
    const progressInterval = setInterval(() => {
      if (progress < 85) {
        progress += 5;
        emitJobProgress(jobId, {
          progress,
          message: 'Processing...',
          status: 'processing'
        });
      }
    }, 2000);

    proc.on('close', () => {
      clearInterval(progressInterval);
    });
  });
}

console.log('YourFeature worker initialized');

export default queue;
```

---

### 6. Register Route and Worker in Server

Edit `backend/src/server.ts`:

**Import route:**
```typescript
import yourFeatureRoutes from './routes/yourfeature.js';
```

**Register route:**
```typescript
app.use('/api/v1/yourfeature', yourFeatureRoutes);
```

Edit `backend/src/workers/index.ts`:

**Import worker:**
```typescript
await import('./yourFeatureWorker.js');
```

---

### 7. Update Jobs Route

Edit `backend/src/routes/jobs.ts`:

**Import queue:**
```typescript
import { getYourFeatureQueue } from '../services/queue.js';
```

**Add to queue checks:**
```typescript
const queues = [
  getPythonQueue(), 
  getPcapQueue(), 
  getAudioQueue(), 
  getEventLogQueue(),
  getYourFeatureQueue()  // Add this
];
```

**This is critical!** Without this, job status lookups will return 404.

---

### 8. Add API Client Method

Edit `src/services/api.ts`:

```typescript
// YourFeature analysis
async analyzeYourFeature(file: File) {
  console.log('Analyzing YourFeature:', file.name);
  const formData = new FormData();
  formData.append('file', file);

  const response = await this.client.post('/api/v1/yourfeature/analyze', formData, {
    headers: {
      'Content-Type': 'multipart/form-data',
    },
  });
  console.log('YourFeature analyze response:', response.data);
  return response.data;
}
```

---

### 9. Create Frontend Page

Create `src/pages/YourFeature.tsx`:

```typescript
import React, { useState, useEffect } from 'react';
import { Upload, Activity, X } from 'lucide-react';
import { Button } from '../components/ui/button';
import { Card } from '../components/ui/card';
import { useBackendJob } from '../hooks/useBackendJob';
import { toast } from '../hooks/use-toast';
import { apiClient } from '../services/api';

type TabType = 'data' | 'analysis' | 'export';

export const YourFeature: React.FC = () => {
  const [file, setFile] = useState<File | null>(null);
  const [activeTab, setActiveTab] = useState<TabType>('data');
  const [parsedData, setParsedData] = useState<any>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  
  const { jobStatus, startJob } = useBackendJob();

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0];
    if (selectedFile) {
      // Validate file type
      if (!selectedFile.name.match(/\.(ext1|ext2)$/i)) {
        toast({ 
          title: 'Invalid file type', 
          description: 'Please select a valid file', 
          variant: 'destructive' 
        });
        return;
      }
      
      // Check file size
      if (selectedFile.size > 1 * 1024 * 1024 * 1024) {
        toast({ 
          title: 'File too large', 
          description: 'Maximum file size is 1GB', 
          variant: 'destructive' 
        });
        return;
      }
      
      setFile(selectedFile);
      setParsedData(null);
    }
  };

  const handleAnalyze = async () => {
    if (!file) return;
    setIsAnalyzing(true);

    try {
      const response = await apiClient.analyzeYourFeature(file);

      if (response.jobId) {
        startJob(response.jobId);
      } else {
        toast({ 
          title: 'Error', 
          description: response.error || 'Failed to start analysis', 
          variant: 'destructive' 
        });
        setIsAnalyzing(false);
      }
    } catch (error: any) {
      toast({ title: 'Error', description: error.message, variant: 'destructive' });
      setIsAnalyzing(false);
    }
  };

  const handleReset = () => {
    setFile(null);
    setParsedData(null);
    setIsAnalyzing(false);
    setActiveTab('data');
  };

  // Watch for job status updates
  useEffect(() => {
    if (jobStatus) {
      if (jobStatus.status === 'completed') {
        setParsedData(jobStatus.results);
        setIsAnalyzing(false);
        toast({ 
          title: 'Analysis complete', 
          description: `Processed ${jobStatus.results?.metadata?.totalItems || 0} items` 
        });
      } else if (jobStatus.status === 'failed') {
        toast({ 
          title: 'Analysis failed', 
          description: jobStatus.error, 
          variant: 'destructive' 
        });
        setIsAnalyzing(false);
      }
    }
  }, [jobStatus]);

  return (
    <div className="min-h-screen bg-background p-6">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-2">
            <Activity className="w-8 h-8 text-accent" />
            Your Feature Analyzer
          </h1>
          <p className="text-muted-foreground mt-1">
            Upload and analyze your files
          </p>
        </div>

        {/* File Upload Section */}
        {!parsedData && (
          <Card className="p-8">
            <div className="space-y-6">
              <div className="flex items-center justify-center">
                <div className="text-center space-y-4">
                  <div className="flex justify-center">
                    <div className="p-4 bg-accent/10 rounded-full">
                      <Upload className="w-12 h-12 text-accent" />
                    </div>
                  </div>
                  
                  <div>
                    <h3 className="text-xl font-semibold mb-2">Upload File</h3>
                    <p className="text-muted-foreground">
                      Select a file to analyze
                      <br />
                      Maximum file size: 1GB
                    </p>
                  </div>

                  <div className="flex flex-col items-center gap-3">
                    <input
                      id="file-upload"
                      type="file"
                      accept=".ext1,.ext2"
                      onChange={handleFileSelect}
                      className="hidden"
                    />
                    <label htmlFor="file-upload">
                      <Button size="lg" className="w-full cursor-pointer" asChild>
                        <span>Choose File</span>
                      </Button>
                    </label>

                    {file && (
                      <div className="flex items-center gap-2 text-sm">
                        <span className="font-mono">{file.name}</span>
                        <span className="text-muted-foreground">
                          ({(file.size / (1024 * 1024)).toFixed(2)} MB)
                        </span>
                      </div>
                    )}

                    {file && (
                      <Button 
                        onClick={handleAnalyze}
                        size="lg"
                        disabled={isAnalyzing}
                        className="w-64"
                      >
                        {isAnalyzing ? 'Analyzing...' : 'Analyze File'}
                      </Button>
                    )}
                  </div>
                </div>
              </div>

              {/* Job Progress */}
              {isAnalyzing && jobStatus && (
                <div className="bg-muted/20 rounded-lg p-4">
                  <div className="flex items-center gap-3 mb-2">
                    <Activity className="w-5 h-5 animate-spin text-accent" />
                    <span className="font-medium">Processing...</span>
                  </div>
                  <div className="w-full bg-muted rounded-full h-2 mb-2">
                    <div 
                      className="bg-accent h-2 rounded-full transition-all duration-300"
                      style={{ width: `${jobStatus.progress || 0}%` }}
                    />
                  </div>
                  <p className="text-sm text-muted-foreground">
                    {jobStatus.progress || 0}% - {jobStatus.message || 'Processing...'}
                  </p>
                </div>
              )}
            </div>
          </Card>
        )}

        {/* Results Section */}
        {parsedData && (
          <div className="space-y-4">
            <Card className="p-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-6">
                  <div>
                    <div className="text-sm text-muted-foreground">File</div>
                    <div className="font-mono font-semibold">{parsedData.filename}</div>
                  </div>
                  <div>
                    <div className="text-sm text-muted-foreground">Total Items</div>
                    <div className="font-mono font-semibold text-accent">
                      {parsedData.metadata?.totalItems?.toLocaleString() || 0}
                    </div>
                  </div>
                </div>
                <Button variant="outline" onClick={handleReset}>
                  <X className="w-4 h-4 mr-2" />
                  Close
                </Button>
              </div>
            </Card>

            {/* Tabs */}
            <div className="flex gap-2 bg-muted/20 p-1 rounded-lg w-fit">
              <TabButton active={activeTab === 'data'} onClick={() => setActiveTab('data')}>
                Data
              </TabButton>
              <TabButton active={activeTab === 'analysis'} onClick={() => setActiveTab('analysis')}>
                Analysis
              </TabButton>
              <TabButton active={activeTab === 'export'} onClick={() => setActiveTab('export')}>
                Export
              </TabButton>
            </div>

            {/* Tab Content - Add your tab components here */}
            <div>
              {activeTab === 'data' && <div>Data tab content</div>}
              {activeTab === 'analysis' && <div>Analysis tab content</div>}
              {activeTab === 'export' && <div>Export tab content</div>}
            </div>
          </div>
        )}
      </div>
    </div>
  );
};

const TabButton: React.FC<{ active: boolean; onClick: () => void; children: React.ReactNode }> = ({ 
  active, 
  onClick, 
  children 
}) => (
  <button
    onClick={onClick}
    className={`px-4 py-2 rounded text-sm font-medium transition-colors ${
      active ? 'bg-accent text-background' : 'hover:bg-muted'
    }`}
  >
    {children}
  </button>
);

export default YourFeature;
```

---

### 10. Add Route to App

Edit `src/App.tsx`:

**Import:**
```typescript
const YourFeature = lazy(() => import('./pages/YourFeature'))
```

**Add route:**
```typescript
<Route path="/yourfeature" element={<YourFeature />} />
```

---

### 11. Add to Navigation

Edit `src/components/Layout.tsx`:

**Import icon (if needed):**
```typescript
import { YourIcon } from 'lucide-react'
```

**Add to navigation array:**
```typescript
const analysisTools: NavItem[] = [
  // ... existing items
  {
    path: '/yourfeature',
    label: 'Your Feature',
    icon: YourIcon,
    description: 'Your feature description',
    keywords: ['keyword1', 'keyword2']
  },
]
```

---

## Checklist

When adding a new file upload analysis page, make sure you:

- [ ] Create Python analysis script in `backend/src/scripts/pythonScripts/`
- [ ] Add dependencies to `backend/requirements.txt`
- [ ] Create backend API route in `backend/src/routes/`
- [ ] Add queue to `backend/src/services/queue.ts` (declare, initialize, export)
- [ ] Create worker in `backend/src/workers/`
- [ ] Register route in `backend/src/server.ts`
- [ ] Register worker in `backend/src/workers/index.ts`
- [ ] **Add queue to jobs route** in `backend/src/routes/jobs.ts` ⚠️ CRITICAL
- [ ] Add API client method to `src/services/api.ts`
- [ ] Create frontend page in `src/pages/`
- [ ] Add route to `src/App.tsx`
- [ ] Add to navigation in `src/components/Layout.tsx`
- [ ] Test file upload, job processing, and results display
- [ ] Verify file gets deleted after processing

---

## Common Issues

### 404 on job status
**Cause:** Queue not added to jobs route
**Fix:** Add `getYourFeatureQueue()` to the queues array in `backend/src/routes/jobs.ts`

### 405 Method Not Allowed
**Cause:** Using `fetch()` directly instead of `apiClient`
**Fix:** Always use `apiClient.yourMethod()` which properly routes to backend

### File not deleted
**Cause:** Python script doesn't call `os.remove(filepath)`
**Fix:** Add file deletion at the end of your Python script's `main()` function

### Python library not found
**Cause:** Not in requirements.txt or Dockerfile not rebuilt
**Fix:** Add to `backend/requirements.txt` and redeploy (Railway will rebuild)

---

## Example: See Existing Implementations

- PCAP Analysis: `backend/src/routes/pcap.ts`, `src/pages/PcapAnalysis.tsx`
- Event Logs: `backend/src/routes/eventlogs.ts`, `src/pages/EventLogs.tsx`
- Audio Analysis: `backend/src/routes/audio.ts`, `src/pages/AudioAnalysis.tsx`
