import { getImageQueue } from '../services/queue.js';
import { saveResults } from '../services/storage.js';
import { emitJobProgress, emitJobCompleted, emitJobFailed } from '../services/websocket.js';
import { JOB_STATUS } from '../utils/constants.js';
import { promises as fs } from 'fs';
import { createCanvas, loadImage, Image as CanvasImage, ImageData } from 'canvas';
import sharp from 'sharp';
import Bull from 'bull';
import { execa } from 'execa';

const queue = getImageQueue();

queue.process(async (job: Bull.Job) => {
  const { jobId, filePath, filename, options, task } = job.data;

  // Helper function to update both Bull job state and WebSocket
  const updateProgress = async (progress: number, message: string, delay: number = 300) => {
    await job.progress({ progress, message });
    emitJobProgress(jobId, {
      progress,
      message,
      status: JOB_STATUS.PROCESSING
    });
    await new Promise(resolve => setTimeout(resolve, delay));
  };

  await updateProgress(10, 'Starting image analysis...');

  try {
    const results: any = {
      filename,
      task,
      timestamp: new Date().toISOString()
    };

    // Read image file
    const imageBuffer = await fs.readFile(filePath);

    // Extract EXIF metadata with ExifTool (always run first)
    await updateProgress(15, 'Extracting EXIF metadata with ExifTool...');
    results.exif = await performExifAnalysis(filePath, jobId);

    // Perform requested analyses
    if (options.performELA) {
      await updateProgress(30, 'Performing ELA (Error Level Analysis)...');
      results.ela = await performELAAnalysis(imageBuffer, options.elaQuality || 90, jobId);
    }

    if (options.performSteganography) {
      await updateProgress(60, 'Running advanced steganography detection...');
      results.steganography = await performSteganographyAnalysis(filePath, jobId);
    }

    if (options.performFileCarving) {
      await updateProgress(85, 'Carving embedded files...');
      results.carvedFiles = await performFileCarving(imageBuffer, options.maxCarvedFiles || 10);
    }

    await updateProgress(95, 'Finalizing results...');

    await saveResults(jobId, results);
    emitJobCompleted(jobId, results);

    return results;
  } catch (error: any) {
    console.error('Image analysis error:', error);
    emitJobFailed(jobId, error.message);
    throw error;
  }
});

/**
 * ELA (Error Level Analysis)
 * Detects image manipulation by recompressing and comparing
 */
async function performELAAnalysis(imageBuffer: Buffer, quality: number, jobId: string) {
  try {
    // Get image metadata first
    const metadata = await sharp(imageBuffer).metadata();
    
    // Convert to PNG for canvas compatibility (handles webp, tiff, and other formats)
    const pngBuffer = await sharp(imageBuffer).png().toBuffer();
    
    // Load original image
    const img = await loadImage(pngBuffer);
    const canvas = createCanvas(img.width, img.height);
    const ctx = canvas.getContext('2d');
    ctx.drawImage(img, 0, 0);
    
    const originalData = ctx.getImageData(0, 0, canvas.width, canvas.height);

    // Recompress at specified quality using sharp
    const recompressed = await sharp(imageBuffer)
      .jpeg({ quality })
      .toBuffer();

    // Load recompressed image
    const recompressedImg = await loadImage(recompressed);
    const recompressedCanvas = createCanvas(recompressedImg.width, recompressedImg.height);
    const recompressedCtx = recompressedCanvas.getContext('2d');
    recompressedCtx.drawImage(recompressedImg, 0, 0);
    
    const recompressedData = recompressedCtx.getImageData(0, 0, canvas.width, canvas.height);

    // Calculate differences
    const elaData = new Uint8ClampedArray(originalData.data.length);
    let maxDiff = 0;
    let totalDiff = 0;
    const errorMap: number[][] = [];

    // Initialize error map
    for (let y = 0; y < canvas.height; y++) {
      errorMap[y] = [];
    }

    for (let i = 0; i < originalData.data.length; i += 4) {
      const diffR = Math.abs(originalData.data[i] - recompressedData.data[i]);
      const diffG = Math.abs(originalData.data[i + 1] - recompressedData.data[i + 1]);
      const diffB = Math.abs(originalData.data[i + 2] - recompressedData.data[i + 2]);

      const avgDiff = (diffR + diffG + diffB) / 3;
      const amplified = Math.min(255, avgDiff * 15);

      elaData[i] = amplified;
      elaData[i + 1] = amplified;
      elaData[i + 2] = amplified;
      elaData[i + 3] = 255;

      maxDiff = Math.max(maxDiff, avgDiff);
      totalDiff += avgDiff;

      const pixelIndex = i / 4;
      const x = pixelIndex % canvas.width;
      const y = Math.floor(pixelIndex / canvas.width);
      errorMap[y][x] = avgDiff;
    }

    const avgDiff = totalDiff / (originalData.data.length / 4);

    // Detect suspicious regions
    const suspiciousRegions = detectSuspiciousRegions(errorMap, canvas.width, canvas.height, avgDiff);

    // Create ELA visualization
    const elaCanvas = createCanvas(canvas.width, canvas.height);
    const elaCtx = elaCanvas.getContext('2d');
    const elaImageData = elaCtx.createImageData(canvas.width, canvas.height);
    elaImageData.data.set(elaData);
    elaCtx.putImageData(elaImageData, 0, 0);

    // Convert to base64
    const elaImageUrl = elaCanvas.toDataURL('image/png');

    let interpretation = '';
    if (maxDiff < 10) {
      interpretation = 'Low error levels - likely unmodified or single-generation JPEG';
    } else if (maxDiff < 30) {
      interpretation = 'Moderate error levels - some compression artifacts detected';
    } else if (suspiciousRegions.length > 0) {
      interpretation = `High error levels with ${suspiciousRegions.length} suspicious region(s) - possible image manipulation or splicing detected`;
    } else {
      interpretation = 'High error levels - heavily compressed or edited image';
    }

    return {
      elaImageUrl,
      analysis: {
        maxDifference: maxDiff,
        avgDifference: avgDiff,
        suspiciousRegions,
        interpretation
      }
    };
  } catch (error: any) {
    throw new Error(`ELA analysis failed: ${error.message}`);
  }
}

function detectSuspiciousRegions(
  errorMap: number[][],
  width: number,
  height: number,
  avgError: number
): Array<{ x: number; y: number; width: number; height: number; avgError: number }> {
  const regions: Array<{ x: number; y: number; width: number; height: number; avgError: number }> = [];
  const threshold = avgError * 2;
  const minRegionSize = 20;
  const gridSize = 32;

  for (let y = 0; y < height - gridSize; y += gridSize) {
    for (let x = 0; x < width - gridSize; x += gridSize) {
      let blockSum = 0;
      let count = 0;

      for (let by = y; by < Math.min(y + gridSize, height); by++) {
        for (let bx = x; bx < Math.min(x + gridSize, width); bx++) {
          blockSum += errorMap[by][bx];
          count++;
        }
      }

      const blockAvg = blockSum / count;

      if (blockAvg > threshold && gridSize >= minRegionSize) {
        regions.push({
          x,
          y,
          width: Math.min(gridSize, width - x),
          height: Math.min(gridSize, height - y),
          avgError: blockAvg
        });
      }
    }
  }

  return regions;
}

/**
 * Professional Steganography Analysis Using Industry-Standard Tools
 * - ZSteg: PNG/BMP LSB analysis
 * - Steghide: Universal steganography detection and extraction
 * - Binwalk: Embedded file detection and carving
 */
async function performSteganographyAnalysis(filePath: string, jobId: string) {
  try {
    const results: any = {
      tools: {},
      summary: {
        suspicious: false,
        toolsDetected: [],
        extractedData: [],
        hiddenFiles: [],
        findings: []
      }
    };

    // Get image format to optimize tool selection
    const metadata = await sharp(filePath).metadata();
    const format = metadata.format?.toUpperCase() || 'UNKNOWN';

    // Run all tools in parallel for speed
    const [zstegResult, steghideResult, binwalkResult] = await Promise.allSettled([
      runZSteg(filePath, format),
      runSteghide(filePath),
      runBinwalk(filePath, jobId)
    ]);

    // Process ZSteg results
    if (zstegResult.status === 'fulfilled') {
      results.tools.zsteg = zstegResult.value;
      if (zstegResult.value.foundData) {
        results.summary.suspicious = true;
        results.summary.extractedData.push(...zstegResult.value.extractedData);
        results.summary.findings.push('ZSteg detected LSB steganography');
      }
    }

    // Process Steghide results
    if (steghideResult.status === 'fulfilled') {
      results.tools.steghide = steghideResult.value;
      if (steghideResult.value.detected) {
        results.summary.suspicious = true;
        results.summary.toolsDetected.push('Steghide');
        if (steghideResult.value.extracted) {
          results.summary.extractedData.push(steghideResult.value.data);
          results.summary.findings.push('Steghide embedded data extracted');
        }
      }
    }

    // Process Binwalk results
    if (binwalkResult.status === 'fulfilled') {
      results.tools.binwalk = binwalkResult.value;
      if (binwalkResult.value.filesFound > 0) {
        results.summary.suspicious = true;
        results.summary.hiddenFiles.push(...binwalkResult.value.files);
        results.summary.findings.push(`Binwalk found ${binwalkResult.value.filesFound} embedded file(s)`);
      }
    }

    return results;
  } catch (error: any) {
    console.error('Steganography analysis error:', error);
    return {
      error: `Steganography analysis failed: ${error.message}`,
      tools: {},
      summary: { suspicious: false, toolsDetected: [], extractedData: [], hiddenFiles: [], findings: [] }
    };
  }
}

/**
 * Run ZSteg - Comprehensive LSB steganography detection for PNG/BMP
 */
async function runZSteg(filePath: string, format: string) {
  // ZSteg only works on PNG and BMP
  if (format !== 'PNG' && format !== 'BMP') {
    return { 
      skipped: true, 
      reason: `ZSteg only supports PNG/BMP, image is ${format}`,
      foundData: false,
      extractedData: []
    };
  }

  try {
    // Run zsteg with all analysis methods
    const { stdout, stderr } = await execa('zsteg', [
      '-a',  // All analysis methods
      '--verbose',
      filePath
    ], { timeout: 30000 }); // 30 second timeout

    const lines = stdout.split('\n').filter(line => line.trim());
    const findings: any[] = [];
    const extractedData: any[] = [];

    for (const line of lines) {
      if (line.includes('text:') || line.includes('file:')) {
        const finding = {
          method: line.split('..')[0]?.trim() || 'unknown',
          type: line.includes('text:') ? 'text' : 'file',
          content: line.split('..')[1]?.trim() || ''
        };
        findings.push(finding);

        // Extract the actual content
        if (finding.type === 'text') {
          const textMatch = line.match(/text:\s*"([^"]+)"/);
          if (textMatch) {
            extractedData.push({
              type: 'text',
              method: finding.method,
              content: textMatch[1]
            });
          }
        }
      }
    }

    return {
      foundData: findings.length > 0,
      findings,
      extractedData,
      rawOutput: stdout.slice(0, 5000) // Limit output size
    };
  } catch (error: any) {
    // If zsteg returns non-zero exit code, it might just mean no steganography found
    if (error.stdout && error.stdout.includes('nothing')) {
      return { foundData: false, extractedData: [], findings: [] };
    }
    return { error: error.message, foundData: false, extractedData: [] };
  }
}

/**
 * Run Steghide - Attempt to detect and extract Steghide-embedded data
 */
async function runSteghide(filePath: string) {
  const results: any = {
    detected: false,
    extracted: false,
    data: null,
    passwordUsed: null,
    filename: null
  };

  // Common passwords to try (add more if needed)
  const passwords = ['', 'password', '123456', 'admin', 'secret', 'hidden', 'flag'];

  try {
    // First, try to get info about embedded data
    const { stdout: infoOutput } = await execa('steghide', [
      'info',
      filePath,
      '-p', '' // Try empty password first
    ], { 
      timeout: 10000,
      reject: false 
    });

    if (infoOutput.includes('embedded')) {
      results.detected = true;
    }

    // Try extraction with different passwords
    for (const password of passwords) {
      try {
        const outputFile = `/tmp/steghide_extracted_${Date.now()}.txt`;
        
        await execa('steghide', [
          'extract',
          '-sf', filePath,
          '-xf', outputFile,
          '-p', password,
          '-f' // Force overwrite
        ], { timeout: 10000 });

        // If we get here, extraction succeeded
        results.extracted = true;
        results.passwordUsed = password || '(empty)';

        // Read extracted content
        const extractedContent = await fs.readFile(outputFile, 'utf-8');
        results.data = {
          type: 'text',
          content: extractedContent.slice(0, 10000), // Limit size
          size: extractedContent.length
        };

        // Clean up
        await fs.unlink(outputFile).catch(() => {});
        
        break; // Stop trying passwords once successful
      } catch (extractError) {
        // Password didn't work, continue to next
        continue;
      }
    }

    return results;
  } catch (error: any) {
    return { ...results, error: error.message };
  }
}

/**
 * Run Binwalk - Detect and extract embedded files
 */
async function runBinwalk(filePath: string, jobId: string) {
  try {
    const extractDir = `/tmp/binwalk_${jobId}_${Date.now()}`;
    
    // Run binwalk with extraction
    const { stdout } = await execa('binwalk', [
      '-e',  // Extract
      '-C', extractDir,  // Output directory
      filePath
    ], { 
      timeout: 30000,
      reject: false 
    });

    const lines = stdout.split('\n').filter(line => line.trim() && !line.startsWith('DECIMAL'));
    const files: any[] = [];

    for (const line of lines) {
      const match = line.match(/^(\d+)\s+0x[0-9A-F]+\s+(.+)$/);
      if (match) {
        files.push({
          offset: parseInt(match[1]),
          description: match[2].trim()
        });
      }
    }

    // Check if any files were actually extracted
    let extractedFiles: string[] = [];
    try {
      const dirExists = await fs.access(extractDir).then(() => true).catch(() => false);
      if (dirExists) {
        const entries = await fs.readdir(extractDir, { recursive: true, withFileTypes: true });
        extractedFiles = entries
          .filter(entry => entry.isFile())
          .map(entry => entry.name);
      }
    } catch (e) {
      // Directory doesn't exist or couldn't be read
    }

    // Clean up extraction directory (optional - might want to keep for user download)
    // await fs.rm(extractDir, { recursive: true, force: true }).catch(() => {});

    return {
      filesFound: files.length,
      files,
      extractedFiles,
      extractionPath: extractDir
    };
  } catch (error: any) {
    return { 
      filesFound: 0, 
      files: [], 
      extractedFiles: [],
      error: error.message 
    };
  }
}

/**
 * File Carving - Extract embedded files
 */
async function performFileCarving(imageBuffer: Buffer, maxFiles: number) {
  const data = new Uint8Array(imageBuffer);
  const files: any[] = [];

  const signatures = [
    { name: 'JPEG', header: [0xFF, 0xD8, 0xFF], footer: [0xFF, 0xD9], extension: '.jpg', mimeType: 'image/jpeg' },
    { name: 'PNG', header: [0x89, 0x50, 0x4E, 0x47], footer: [0x49, 0x45, 0x4E, 0x44], extension: '.png', mimeType: 'image/png' },
    { name: 'GIF', header: [0x47, 0x49, 0x46, 0x38], footer: [0x00, 0x3B], extension: '.gif', mimeType: 'image/gif' },
    { name: 'PDF', header: [0x25, 0x50, 0x44, 0x46], footer: [0x25, 0x25, 0x45, 0x4F, 0x46], extension: '.pdf', mimeType: 'application/pdf' },
    { name: 'ZIP', header: [0x50, 0x4B, 0x03, 0x04], footer: [0x50, 0x4B, 0x05, 0x06], extension: '.zip', mimeType: 'application/zip' }
  ];

  for (let i = 0; i < data.length - 20 && files.length < maxFiles; i++) {
    for (const sig of signatures) {
      if (!sig.header.every((byte, index) => data[i + index] === byte)) {
        continue;
      }

      let size = 0;
      if (sig.footer) {
        const maxSearchSize = 10 * 1024 * 1024;
        for (let j = i + sig.header.length; j < Math.min(i + maxSearchSize, data.length - sig.footer.length); j++) {
          if (sig.footer.every((byte, index) => data[j + index] === byte)) {
            size = j - i + sig.footer.length;
            break;
          }
        }
      }

      if (size > 0 && size <= data.length - i) {
        const fileData = data.slice(i, i + size);
        const hash = simpleHash(fileData);
        
        // Convert file data to base64 for frontend download/preview
        const base64Data = Buffer.from(fileData).toString('base64');

        files.push({
          type: sig.name,
          offset: i,
          size,
          extension: sig.extension,
          mimeType: sig.mimeType,
          hash,
          data: base64Data
        });

        i += size - 1;
        break;
      }
    }
  }

  return files;
}

function simpleHash(data: Uint8Array): string {
  let hash = 0;
  for (let i = 0; i < Math.min(data.length, 1024); i++) {
    hash = ((hash << 5) - hash) + data[i];
    hash = hash & hash;
  }
  return Math.abs(hash).toString(16).padStart(8, '0');
}

/**
 * Extract EXIF metadata using ExifTool
 * Professional-grade EXIF analysis with forensic capabilities
 */
async function performExifAnalysis(filePath: string, jobId: string) {
  try {
    // Run ExifTool with comprehensive extraction flags
    const { stdout } = await execa('exiftool', [
      '-j',           // JSON output
      '-a',           // Extract duplicate tags
      '-G1',          // Group names (EXIF:, GPS:, MakerNotes:, etc.)
      '-ee',          // Extract embedded data
      '-api', 'largefilesupport=1',  // Support large files
      filePath
    ]);

    const exifData = JSON.parse(stdout)[0];

    // Extract structured data
    const gpsData = extractGPSData(exifData);
    const cameraInfo = extractCameraInfo(exifData);
    const timeline = extractTimeline(exifData);
    const anomalies = detectExifAnomalies(exifData);

    return {
      raw: exifData,
      gps: gpsData,
      camera: cameraInfo,
      timeline,
      anomalies,
      warnings: exifData['ExifTool:Warning'] || null,
      hasGPS: !!gpsData.latitude && !!gpsData.longitude,
      hasThumbnail: !!exifData['EXIF:ThumbnailImage'],
      isModified: anomalies.length > 0 || timeline.possiblyEdited
    };
  } catch (error: any) {
    console.error('ExifTool analysis failed:', error);
    return {
      error: `ExifTool failed: ${error.message}`,
      raw: {},
      gps: {},
      camera: {},
      timeline: {},
      anomalies: [],
      warnings: null
    };
  }
}

/**
 * Extract GPS coordinates and location data
 */
function extractGPSData(exifData: any) {
  const gps: any = {
    latitude: null,
    longitude: null,
    altitude: null,
    timestamp: null,
    location: null
  };

  // Extract GPS coordinates
  if (exifData['GPS:GPSLatitude'] || exifData['EXIF:GPSLatitude']) {
    gps.latitude = exifData['GPS:GPSLatitude'] || exifData['EXIF:GPSLatitude'];
  }
  if (exifData['GPS:GPSLongitude'] || exifData['EXIF:GPSLongitude']) {
    gps.longitude = exifData['GPS:GPSLongitude'] || exifData['EXIF:GPSLongitude'];
  }
  if (exifData['GPS:GPSAltitude'] || exifData['EXIF:GPSAltitude']) {
    gps.altitude = exifData['GPS:GPSAltitude'] || exifData['EXIF:GPSAltitude'];
  }

  // Composite GPS position (already formatted)
  if (exifData['Composite:GPSPosition']) {
    gps.location = exifData['Composite:GPSPosition'];
  }

  // GPS timestamp
  if (exifData['GPS:GPSDateTime'] || exifData['GPS:GPSTimeStamp']) {
    gps.timestamp = exifData['GPS:GPSDateTime'] || exifData['GPS:GPSTimeStamp'];
  }

  return gps;
}

/**
 * Extract camera and lens information
 */
function extractCameraInfo(exifData: any) {
  const camera: any = {
    make: null,
    model: null,
    lens: null,
    settings: {},
    software: null,
    serialNumber: null
  };

  // Basic camera info
  camera.make = exifData['EXIF:Make'] || exifData['IFD0:Make'];
  camera.model = exifData['EXIF:Model'] || exifData['IFD0:Model'];
  camera.software = exifData['EXIF:Software'] || exifData['IFD0:Software'];
  camera.serialNumber = exifData['EXIF:SerialNumber'] || exifData['MakerNotes:SerialNumber'];

  // Lens information
  camera.lens = exifData['EXIF:LensModel'] || 
                exifData['Composite:LensID'] || 
                exifData['MakerNotes:LensType'];

  // Camera settings
  camera.settings = {
    iso: exifData['EXIF:ISO'],
    aperture: exifData['EXIF:FNumber'] || exifData['EXIF:ApertureValue'],
    shutterSpeed: exifData['EXIF:ExposureTime'] || exifData['EXIF:ShutterSpeedValue'],
    focalLength: exifData['EXIF:FocalLength'],
    exposureProgram: exifData['EXIF:ExposureProgram'],
    meteringMode: exifData['EXIF:MeteringMode'],
    flash: exifData['EXIF:Flash'],
    whiteBalance: exifData['EXIF:WhiteBalance']
  };

  return camera;
}

/**
 * Extract and analyze timestamps
 */
function extractTimeline(exifData: any) {
  const timeline: any = {
    created: null,
    modified: null,
    digitized: null,
    fileModified: null,
    possiblyEdited: false,
    timeDifference: null
  };

  // Extract timestamps
  timeline.created = exifData['EXIF:DateTimeOriginal'] || exifData['EXIF:CreateDate'];
  timeline.modified = exifData['EXIF:ModifyDate'] || exifData['IFD0:ModifyDate'];
  timeline.digitized = exifData['EXIF:DateTimeDigitized'];
  timeline.fileModified = exifData['File:FileModifyDate'];

  // Detect if file was edited
  if (timeline.created && timeline.modified) {
    try {
      const created = new Date(timeline.created.replace(/:/g, '-').replace(' ', 'T'));
      const modified = new Date(timeline.modified.replace(/:/g, '-').replace(' ', 'T'));
      const diffMs = modified.getTime() - created.getTime();
      const diffHours = Math.abs(diffMs) / (1000 * 60 * 60);

      timeline.timeDifference = `${Math.round(diffHours)} hours`;
      
      // If modified date is significantly different from created date
      if (diffHours > 1) {
        timeline.possiblyEdited = true;
      }
    } catch (e) {
      // Date parsing failed
    }
  }

  return timeline;
}

/**
 * Detect EXIF anomalies that indicate tampering
 */
function detectExifAnomalies(exifData: any): Array<{ type: string; description: string; severity: string }> {
  const anomalies: Array<{ type: string; description: string; severity: string }> = [];

  // Check for ExifTool warnings
  const warnings = exifData['ExifTool:Warning'];
  if (warnings) {
    const warningList = Array.isArray(warnings) ? warnings : [warnings];
    warningList.forEach((warning: string) => {
      anomalies.push({
        type: 'exiftool_warning',
        description: warning,
        severity: warning.toLowerCase().includes('trailer') ? 'high' : 'medium'
      });
    });
  }

  // Check for missing thumbnail (common when EXIF is stripped and re-added)
  if (!exifData['EXIF:ThumbnailImage'] && exifData['EXIF:Make']) {
    anomalies.push({
      type: 'missing_thumbnail',
      description: 'EXIF data present but thumbnail is missing - possible metadata manipulation',
      severity: 'medium'
    });
  }

  // Check for inconsistent timestamps
  const created = exifData['EXIF:DateTimeOriginal'];
  const modified = exifData['EXIF:ModifyDate'];
  if (created && modified && created !== modified) {
    anomalies.push({
      type: 'timestamp_mismatch',
      description: 'Image creation and modification dates differ - file was edited',
      severity: 'low'
    });
  }

  // Check for software manipulation indicators
  const software = exifData['EXIF:Software'] || '';
  const suspiciousSoftware = ['photoshop', 'gimp', 'paint.net', 'affinity', 'pixelmator'];
  if (suspiciousSoftware.some(s => software.toLowerCase().includes(s))) {
    anomalies.push({
      type: 'editing_software_detected',
      description: `Image processed with editing software: ${software}`,
      severity: 'low'
    });
  }

  // Check for GPS coordinate inconsistencies
  const gpsLat = exifData['GPS:GPSLatitude'];
  const gpsLon = exifData['GPS:GPSLongitude'];
  if ((gpsLat && !gpsLon) || (!gpsLat && gpsLon)) {
    anomalies.push({
      type: 'incomplete_gps',
      description: 'Incomplete GPS data - only one coordinate present',
      severity: 'medium'
    });
  }

  // Check for invalid or suspicious dimensions
  const width = exifData['EXIF:ExifImageWidth'] || exifData['File:ImageWidth'];
  const height = exifData['EXIF:ExifImageHeight'] || exifData['File:ImageHeight'];
  if (width && height && (width < 10 || height < 10 || width > 50000 || height > 50000)) {
    anomalies.push({
      type: 'suspicious_dimensions',
      description: `Unusual image dimensions: ${width}x${height}`,
      severity: 'low'
    });
  }

  // Check for EXIF byte order manipulation (re-written EXIF)
  const byteOrder = exifData['EXIF:ExifByteOrder'] || exifData['File:ExifByteOrder'];
  const fileModifyDate = exifData['File:FileModifyDate'];
  const exifModifyDate = exifData['EXIF:ModifyDate'];
  
  // If file modify date is much newer than EXIF modify date, metadata may have been re-added
  if (fileModifyDate && exifModifyDate) {
    try {
      const fileDate = new Date(fileModifyDate);
      const exifDate = new Date(exifModifyDate.replace(/:/g, '-').replace(' ', 'T'));
      const diffYears = (fileDate.getTime() - exifDate.getTime()) / (1000 * 60 * 60 * 24 * 365);
      
      if (diffYears > 0.5) { // More than 6 months difference
        anomalies.push({
          type: 'metadata_reinjection',
          description: `File modified ${diffYears.toFixed(1)} years after EXIF date - metadata may have been re-added`,
          severity: 'high'
        });
      }
    } catch (e) {
      // Date parsing failed
    }
  }

  // Check for missing camera-specific fields (indicates EXIF stripping)
  const hasMake = exifData['EXIF:Make'];
  const hasModel = exifData['EXIF:Model'];
  const hasISO = exifData['EXIF:ISO'];
  const hasFNumber = exifData['EXIF:FNumber'];
  const hasExposureTime = exifData['EXIF:ExposureTime'];
  
  if ((hasMake || hasModel) && !hasISO && !hasFNumber && !hasExposureTime) {
    anomalies.push({
      type: 'stripped_camera_settings',
      description: 'Camera make/model present but shooting settings missing - selective metadata removal detected',
      severity: 'high'
    });
  }

  // Check for orientation flag manipulation (common in metadata editing)
  const orientation = exifData['EXIF:Orientation'];
  if (orientation && parseInt(orientation) > 8) {
    anomalies.push({
      type: 'invalid_orientation',
      description: `Invalid orientation value: ${orientation} (valid range: 1-8)`,
      severity: 'medium'
    });
  }

  // Check for ColorSpace manipulation (often changed to hide editing)
  const colorSpace = exifData['EXIF:ColorSpace'];
  const colorSpaceData = exifData['EXIF:ColorSpaceData'];
  if (colorSpace && colorSpaceData && colorSpace !== colorSpaceData) {
    anomalies.push({
      type: 'colorspace_mismatch',
      description: 'ColorSpace tags do not match - possible metadata manipulation',
      severity: 'medium'
    });
  }

  // Check for resolution inconsistencies
  const xRes = exifData['EXIF:XResolution'];
  const yRes = exifData['EXIF:YResolution'];
  if (xRes && yRes && xRes !== yRes && xRes !== '72' && yRes !== '72') {
    // Different X and Y resolutions can indicate image manipulation
    anomalies.push({
      type: 'resolution_mismatch',
      description: `X and Y resolutions differ: ${xRes} vs ${yRes} - possible scaling/manipulation`,
      severity: 'low'
    });
  }

  // Check for missing DateTimeDigitized (should exist if camera has DateTimeOriginal)
  if (created && !exifData['EXIF:DateTimeDigitized']) {
    anomalies.push({
      type: 'missing_digitized_date',
      description: 'DateTimeOriginal exists but DateTimeDigitized is missing - incomplete metadata',
      severity: 'low'
    });
  }

  // Check for thumbnail size/quality mismatches
  const thumbWidth = exifData['EXIF:ThumbnailImageWidth'] || exifData['Composite:ThumbnailImageWidth'];
  const thumbHeight = exifData['EXIF:ThumbnailImageHeight'] || exifData['Composite:ThumbnailImageHeight'];
  if (thumbWidth && thumbHeight && width && height) {
    const thumbRatio = thumbWidth / thumbHeight;
    const imageRatio = width / height;
    const ratioDiff = Math.abs(thumbRatio - imageRatio);
    
    if (ratioDiff > 0.1) { // More than 10% difference
      anomalies.push({
        type: 'thumbnail_aspect_mismatch',
        description: 'Thumbnail aspect ratio differs from image - thumbnail may be from different image',
        severity: 'high'
      });
    }
  }

  // Check for UserComment manipulation (often used to hide data)
  const userComment = exifData['EXIF:UserComment'];
  if (userComment && (userComment.includes('ASCII\x00\x00\x00') || userComment.includes('\x00\x00\x00\x00'))) {
    anomalies.push({
      type: 'suspicious_user_comment',
      description: 'UserComment contains unusual null bytes - possible data hiding or corruption',
      severity: 'medium'
    });
  }

  return anomalies;
}

console.log('Image analysis worker started');
