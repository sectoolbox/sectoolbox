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

  emitJobProgress(jobId, {
    progress: 10,
    message: 'Starting image analysis...',
    status: JOB_STATUS.PROCESSING
  });

  try {
    const results: any = {
      filename,
      task,
      timestamp: new Date().toISOString()
    };

    // Read image file
    const imageBuffer = await fs.readFile(filePath);

    // Extract EXIF metadata with ExifTool (always run first)
    emitJobProgress(jobId, {
      progress: 15,
      message: 'Extracting EXIF metadata with ExifTool...',
      status: JOB_STATUS.PROCESSING
    });
    results.exif = await performExifAnalysis(filePath, jobId);

    // Perform requested analyses
    if (options.performELA) {
      emitJobProgress(jobId, {
        progress: 30,
        message: 'Performing ELA (Error Level Analysis)...',
        status: JOB_STATUS.PROCESSING
      });
      results.ela = await performELAAnalysis(imageBuffer, options.elaQuality || 90, jobId);
    }

    if (options.performSteganography) {
      emitJobProgress(jobId, {
        progress: 60,
        message: 'Running advanced steganography detection...',
        status: JOB_STATUS.PROCESSING
      });
      results.steganography = await performSteganographyAnalysis(imageBuffer, jobId);
    }

    if (options.performFileCarving) {
      emitJobProgress(jobId, {
        progress: 85,
        message: 'Carving embedded files...',
        status: JOB_STATUS.PROCESSING
      });
      results.carvedFiles = await performFileCarving(imageBuffer, options.maxCarvedFiles || 10);
    }

    emitJobProgress(jobId, {
      progress: 95,
      message: 'Finalizing results...',
      status: JOB_STATUS.PROCESSING
    });

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
    // Load original image
    const img = await loadImage(imageBuffer);
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
 * Advanced Steganography Detection
 * Uses SPA, RS Steganalysis, and Histogram Analysis
 */
async function performSteganographyAnalysis(imageBuffer: Buffer, jobId: string) {
  try {
    const img = await loadImage(imageBuffer);
    const canvas = createCanvas(img.width, img.height);
    const ctx = canvas.getContext('2d');
    ctx.drawImage(img, 0, 0);
    
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const data = imageData.data;

    // Sample Pairs Analysis
    const spa = performSamplePairsAnalysis(data);

    // RS Steganalysis
    const rs = performRSSteganalysis(data);

    // Histogram Analysis
    const histogram = performHistogramAnalysis(data);

    return {
      samplePairsAnalysis: spa,
      rsSteganalysis: rs,
      histogramDetection: histogram,
      overallSuspicious: spa.suspicious || rs.suspicious || histogram.suspicious
    };
  } catch (error: any) {
    throw new Error(`Steganography analysis failed: ${error.message}`);
  }
}

function performSamplePairsAnalysis(data: Uint8ClampedArray) {
  const samples = Math.min(10000, data.length / 4);
  let P = 0, X = 0, Y = 0, Z = 0;

  for (let i = 0; i < samples - 1; i++) {
    const idx1 = i * 4;
    const idx2 = (i + 1) * 4;
    const u = data[idx1];
    const v = data[idx2];

    if (u === v) P++;
    else if (u === v + 1 || u === v - 1) X++;
    else if (u === v + 2 || u === v - 2) Y++;
    else Z++;
  }

  const total = P + X + Y + Z;
  if (total === 0) {
    return { embeddingRate: 0, suspicious: false, confidence: 0 };
  }

  const a = 2 * (X + Z) / total;
  const b = 2 * P / total;

  let embeddingRate = 0;
  if (a > 0 && b > 0) {
    embeddingRate = Math.min(1, Math.max(0, (a - b) / (2 * a)));
  }

  const suspicious = embeddingRate > 0.1;
  const confidence = Math.min(100, embeddingRate * 200);

  return { embeddingRate, suspicious, confidence };
}

function performRSSteganalysis(data: Uint8ClampedArray) {
  const maskSize = 4;
  const maxBlocks = 5000;

  let Rm = 0, Sm = 0, Rn = 0, Sn = 0;
  let blocksProcessed = 0;

  for (let i = 0; i < data.length - maskSize * 4 && blocksProcessed < maxBlocks; i += maskSize * 4) {
    const block: number[] = [];
    for (let j = 0; j < maskSize; j++) {
      block.push(data[i + j * 4]);
    }

    const f0 = calculateVariation(block);
    const blockM = block.map(v => (v & 1) ? v - 1 : v + 1);
    const fM = calculateVariation(blockM);
    const blockN = block.map(v => (v & 1) ? v + 1 : v - 1);
    const fN = calculateVariation(blockN);

    if (fM > f0) Rm++;
    else if (fM < f0) Sm++;

    if (fN > f0) Rn++;
    else if (fN < f0) Sn++;

    blocksProcessed++;
  }

  const rsRatio = blocksProcessed > 0 ? (Rm - Sm) / (Rn - Sn + 0.001) : 0;
  const d = Math.abs(rsRatio - 1);
  const estimatedPayload = Math.min(1, Math.max(0, d / 2));
  const suspicious = estimatedPayload > 0.05;
  const confidence = Math.min(100, estimatedPayload * 500);

  return { estimatedPayload, suspicious, confidence, rsRatio };
}

function calculateVariation(block: number[]): number {
  let variation = 0;
  for (let i = 0; i < block.length - 1; i++) {
    variation += Math.abs(block[i + 1] - block[i]);
  }
  return variation;
}

function performHistogramAnalysis(data: Uint8ClampedArray) {
  let evenCount = 0, oddCount = 0;
  const histogram = new Array(256).fill(0);

  for (let i = 0; i < data.length; i += 4) {
    const r = data[i];
    const g = data[i + 1];
    const b = data[i + 2];

    histogram[r]++;
    histogram[g]++;
    histogram[b]++;

    if (r % 2 === 0) evenCount++;
    else oddCount++;
  }

  const total = evenCount + oddCount;
  const evenRatio = evenCount / total;
  const evenOddImbalance = Math.abs(evenRatio - 0.5);

  const anomalies: string[] = [];
  if (evenOddImbalance < 0.01) {
    anomalies.push('Near-perfect even/odd balance suggests LSB steganography');
  }

  let pairsWithSimilarFreq = 0;
  for (let i = 0; i < 255; i++) {
    const diff = Math.abs(histogram[i] - histogram[i + 1]);
    const avg = (histogram[i] + histogram[i + 1]) / 2;
    if (avg > 10 && diff < avg * 0.1) {
      pairsWithSimilarFreq++;
    }
  }

  const pairsAnomaly = pairsWithSimilarFreq > 20;
  if (pairsAnomaly) {
    anomalies.push(`${pairsWithSimilarFreq} value pairs with suspiciously similar frequencies`);
  }

  let lsbFluctuation = 0;
  for (let i = 0; i < 255; i += 2) {
    const ratio = histogram[i] > 0 ? histogram[i + 1] / histogram[i] : 0;
    lsbFluctuation += Math.abs(1 - ratio);
  }
  lsbFluctuation /= 128;

  const suspicious = anomalies.length > 0 || lsbFluctuation < 0.05;

  return {
    suspicious,
    anomalies,
    histogramAnalysis: {
      pairsAnomaly,
      lsbFluctuation,
      evenOddImbalance
    }
  };
}

/**
 * File Carving - Extract embedded files
 */
async function performFileCarving(imageBuffer: Buffer, maxFiles: number) {
  const data = new Uint8Array(imageBuffer);
  const files: any[] = [];

  const signatures = [
    { name: 'JPEG', header: [0xFF, 0xD8, 0xFF], footer: [0xFF, 0xD9], extension: '.jpg' },
    { name: 'PNG', header: [0x89, 0x50, 0x4E, 0x47], footer: [0x49, 0x45, 0x4E, 0x44], extension: '.png' },
    { name: 'GIF', header: [0x47, 0x49, 0x46, 0x38], footer: [0x00, 0x3B], extension: '.gif' },
    { name: 'PDF', header: [0x25, 0x50, 0x44, 0x46], footer: [0x25, 0x25, 0x45, 0x4F, 0x46], extension: '.pdf' },
    { name: 'ZIP', header: [0x50, 0x4B, 0x03, 0x04], footer: [0x50, 0x4B, 0x05, 0x06], extension: '.zip' }
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

        files.push({
          type: sig.name,
          offset: i,
          size,
          extension: sig.extension,
          hash
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
