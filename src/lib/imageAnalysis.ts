// Image Analysis Library for Forensics
// Provides real working functions for EXIF parsing, LSB analysis, string extraction,
// bit plane extraction, and forensic image processing

// exifreader will be dynamically imported to avoid build-time resolution issues

import { formatBytes } from './formatting';

export async function readFileAsArrayBuffer(file: File): Promise<ArrayBuffer> {
  return await file.arrayBuffer()
}

export function detectMagicFiles(buffer: ArrayBuffer) {
  const sigs: { name: string; hex: number[] }[] = [
    { name: 'PNG', hex: [0x89,0x50,0x4E,0x47] },
    { name: 'JPEG', hex: [0xFF,0xD8,0xFF] },
    { name: 'ZIP', hex: [0x50,0x4B,0x03,0x04] },
    { name: 'PDF', hex: [0x25,0x50,0x44,0x46] },
    { name: 'GZIP', hex: [0x1F,0x8B] },
    { name: 'RAR', hex: [0x52,0x61,0x72,0x21] }
  ]

  const bytes = new Uint8Array(buffer)
  const found: { name: string; offset: number }[] = []

  for (let i = 0; i < bytes.length; i++) {
    for (const s of sigs) {
      const match = s.hex.every((b, idx) => bytes[i+idx] === b)
      if (match) {
        found.push({ name: s.name, offset: i })
      }
    }
  }

  return found
}

export function extractPrintableStringsFromBuffer(buffer: ArrayBuffer, minLen = 4, maxLen = 500) {
  const bytes = new Uint8Array(buffer)
  const results: string[] = []
  const unicodeResults: string[] = []
  
  // Enhanced ASCII string extraction
  let cur: number[] = []
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i]
    if (b >= 32 && b <= 126) {
      cur.push(b)
    } else {
      if (cur.length >= minLen && cur.length <= maxLen) {
        results.push(String.fromCharCode(...cur))
      }
      cur = []
    }
  }
  if (cur.length >= minLen && cur.length <= maxLen) {
    results.push(String.fromCharCode(...cur))
  }

  // Enhanced Unicode/UTF-8 string extraction
  try {
    const decoder = new TextDecoder('utf-8', { fatal: false })
    const text = decoder.decode(buffer)
    
    // Extract meaningful UTF-8 strings
    const unicodeMatches = text.match(/[\u0020-\u007E\u00A0-\u024F\u0400-\u04FF]{4,}/g) || []
    unicodeResults.push(...unicodeMatches.filter(s => s.length <= maxLen))
  } catch (e) {
    // Ignore UTF-8 decode errors
  }

  // Enhanced UTF-16 string extraction for Windows files
  try {
    const decoder16 = new TextDecoder('utf-16le', { fatal: false })
    const text16 = decoder16.decode(buffer)
    
    // Extract meaningful UTF-16 strings
    const unicode16Matches = text16.match(/[\u0020-\u007E\u00A0-\u024F\u0400-\u04FF]{4,}/g) || []
    unicodeResults.push(...unicode16Matches.filter(s => s.length <= maxLen))
  } catch (e) {
    // Ignore UTF-16 decode errors
  }

  // Enhanced pattern-based extraction
  const combinedText = results.join(' ') + ' ' + unicodeResults.join(' ')
  const patterns = {
    emails: /[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g,
    urls: /https?:\/\/[^\s<>"']{4,200}/g,
    ipAddresses: /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g,
    base64: /[A-Za-z0-9+/]{20,}={0,2}/g,
    hexStrings: /0x[a-fA-F0-9]{8,}/g,
    filePaths: /[A-Za-z]:[\\\/][^\s<>"'|?*\x00-\x1f]{3,200}/g,
    domains: /[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)+/g,
    coordinates: /-?\d+\.\d+,\s*-?\d+\.\d+/g,
    phoneNumbers: /(\+\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}/g,
    creditCards: /\b(?:\d{4}[-\s]?){3}\d{4}\b/g,
    dates: /\b\d{1,2}[-\/]\d{1,2}[-\/]\d{2,4}\b|\b\d{4}[-\/]\d{1,2}[-\/]\d{1,2}\b/g,
    socialSecurity: /\b\d{3}-\d{2}-\d{4}\b/g,
    macAddresses: /([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})/g
  }

  const patternResults: Record<string, string[]> = {}
  
  for (const [pattern, regex] of Object.entries(patterns)) {
    const matches = combinedText.match(regex) || []
    patternResults[pattern] = [...new Set(matches)].slice(0, 100) // Dedupe and limit
  }

  // Combine all results - keep ALL strings including duplicates
  const allStrings = [
    ...results,
    ...unicodeResults
  ]

  return {
    all: allStrings, // Return all strings without deduplication
    patterns: patternResults,
    counts: {
      ascii: results.length,
      unicode: unicodeResults.length,
      total: allStrings.length,
      unique: [...new Set(allStrings)].length
    }
  }
}

export function analyzeLSBFromCanvas(ctx: CanvasRenderingContext2D, width: number, height: number, maxBytes = 20000) {
  const imageData = ctx.getImageData(0,0,width,height).data
  const maxPixels = Math.min(maxBytes, Math.floor(imageData.length / 4))

  // Collect bits for each channel
  const channels = { r: [] as number[], g: [] as number[], b: [] as number[] }

  for (let i = 0; i < maxPixels * 4; i += 4) {
    channels.r.push(imageData[i] & 1)
    channels.g.push(imageData[i+1] & 1)
    channels.b.push(imageData[i+2] & 1)
  }

  function bitsToString(bits: number[]) {
    const bytes: number[] = []
    for (let i = 0; i + 7 < bits.length; i += 8) {
      let v = 0
      for (let b=0;b<8;b++) v = (v<<1)|bits[i+b]
      bytes.push(v)
    }
    return String.fromCharCode(...bytes)
  }

  const rStr = bitsToString(channels.r)
  const gStr = bitsToString(channels.g)
  const bStr = bitsToString(channels.b)
  const composite = rStr + '\n' + gStr + '\n' + bStr

  // compute printable ratios
  function printableRatio(s: string) {
    if (!s) return 0
    const printable = s.split('').filter(c => c >= ' ' && c <= '~').length
    return printable / s.length
  }

  return {
    r: { text: rStr, ratio: printableRatio(rStr) },
    g: { text: gStr, ratio: printableRatio(gStr) },
    b: { text: bStr, ratio: printableRatio(bStr) },
    composite
  }
}

export function analyzeLSBWithDepth(ctx: CanvasRenderingContext2D, width: number, height: number, depth = 1, maxBytes = 20000) {
  // depth: number of LSB bits to collect per color channel (1 or 2 recommended)
  const imageData = ctx.getImageData(0,0,width,height).data
  const maxPixels = Math.min(maxBytes, Math.floor(imageData.length / 4))

  function collectBitsForChannel(offsetIndex: number) {
    const bits: number[] = []
    for (let i = 0; i < maxPixels * 4; i += 4) {
      const val = imageData[i + offsetIndex]
      for (let d = depth - 1; d >= 0; d--) {
        bits.push((val >> d) & 1)
      }
    }
    return bits
  }

  function bitsToString(bits: number[]) {
    const bytes: number[] = []
    for (let i = 0; i + 7 < bits.length; i += 8) {
      let v = 0
      for (let b=0;b<8;b++) v = (v<<1)|bits[i+b]
      bytes.push(v)
    }
    return String.fromCharCode(...bytes)
  }

  const rBits = collectBitsForChannel(0)
  const gBits = collectBitsForChannel(1)
  const bBits = collectBitsForChannel(2)

  const rStr = bitsToString(rBits)
  const gStr = bitsToString(gBits)
  const bStr = bitsToString(bBits)
  const composite = rStr + '\n' + gStr + '\n' + bStr

  function printableRatio(s: string) {
    if (!s) return 0
    const printable = s.split('').filter(c => c >= ' ' && c <= '~').length
    return printable / s.length
  }

  return {
    r: { text: rStr, ratio: printableRatio(rStr) },
    g: { text: gStr, ratio: printableRatio(gStr) },
    b: { text: bStr, ratio: printableRatio(bStr) },
    composite
  }
}

export async function parseExif(buffer: ArrayBuffer) {
  try {
    // Dynamically import exifreader to avoid bundling issues
    const exifModule = await import('exifreader')
    const ExifReader = (exifModule && (exifModule as any).default) ? (exifModule as any).default : exifModule
    
    // Use exifreader to extract ALL available EXIF tags with expanded options
    const tags: any = ExifReader.load(buffer, {
      expanded: true,
      includeUnknown: true, // Include unknown tags
      simplifyValues: false, // Keep all value details
      async: false
    })
    
    const exifData: Record<string, any> = {}

    // Process ALL tags comprehensively
    for (const [k, v] of Object.entries(tags)) {
      if (!v) continue
      
      try {
        const tagValue = v as any
        
        // Handle different tag value formats comprehensively
        if (tagValue.description !== undefined) {
          exifData[k] = tagValue.description
        } else if (tagValue.value !== undefined) {
          exifData[k] = Array.isArray(tagValue.value) ? tagValue.value : tagValue.value
        } else if (tagValue.text !== undefined) {
          exifData[k] = tagValue.text
        } else if (typeof tagValue === 'object' && tagValue !== null) {
          // For complex objects, preserve all properties
          const complexValue: Record<string, any> = {}
          
          // Extract all meaningful properties
          Object.keys(tagValue).forEach(prop => {
            if (prop !== 'id' && tagValue[prop] !== undefined) {
              complexValue[prop] = tagValue[prop]
            }
          })
          
          // If it has meaningful data, store it
          if (Object.keys(complexValue).length > 0) {
            exifData[k] = Object.keys(complexValue).length === 1 && complexValue.value !== undefined 
              ? complexValue.value 
              : complexValue
          } else {
            exifData[k] = tagValue
          }
        } else {
          exifData[k] = tagValue
        }
        
        // Add raw hex value for technical analysis if available
        if (tagValue.value && typeof tagValue.value === 'number') {
          exifData[`${k}_hex`] = '0x' + tagValue.value.toString(16).toUpperCase()
        }
        
      } catch (tagError) {
        // Still include problematic tags with error info
        exifData[k] = `[Parse Error: ${tagError}]`
      }
    }

    // Add comprehensive file format detection
    try {
      const view = new DataView(buffer)
      const firstBytes = new Uint8Array(buffer.slice(0, 16))
      
      // Enhanced format detection
      if (view.getUint16(0) === 0xFFD8) {
        exifData.format = 'JPEG'
        exifData.signature = 'FFD8'
        
        // JPEG specific analysis
        try {
          // Look for JPEG segments
          let offset = 2
          const segments = []
          while (offset < buffer.byteLength - 4) {
            if (view.getUint8(offset) === 0xFF) {
              const marker = view.getUint8(offset + 1)
              const length = view.getUint16(offset + 2, false)
              segments.push({
                marker: `FF${marker.toString(16).toUpperCase()}`,
                offset,
                length
              })
              offset += length + 2
              if (segments.length > 20) break // Limit segments
            } else {
              break
            }
          }
          exifData.jpegSegments = segments
        } catch (e) { /* ignore */ }
        
      } else if (view.getUint32(0) === 0x89504E47) {
        exifData.format = 'PNG'
        exifData.signature = '89504E47'
        
        // PNG specific analysis
        try {
          // Parse PNG chunks
          let offset = 8 // Skip PNG signature
          const chunks = []
          while (offset < buffer.byteLength - 8) {
            const length = view.getUint32(offset, false)
            const type = Array.from(new Uint8Array(buffer.slice(offset + 4, offset + 8)))
              .map(b => String.fromCharCode(b)).join('')
            
            chunks.push({
              type,
              offset,
              length,
              crc: view.getUint32(offset + 8 + length, false).toString(16).toUpperCase()
            })
            
            offset += 12 + length
            if (chunks.length > 50) break // Limit chunks
          }
          exifData.pngChunks = chunks
        } catch (e) { /* ignore */ }
        
      } else if (view.getUint32(0) === 0x47494638) {
        exifData.format = 'GIF'
        exifData.signature = '47494638'
      } else if (view.getUint16(0) === 0x424D) {
        exifData.format = 'BMP'
        exifData.signature = '424D'
      } else if (firstBytes[0] === 0x49 && firstBytes[1] === 0x49) {
        exifData.format = 'TIFF (Little Endian)'
        exifData.signature = '4949'
      } else if (firstBytes[0] === 0x4D && firstBytes[1] === 0x4D) {
        exifData.format = 'TIFF (Big Endian)'
        exifData.signature = '4D4D'
      } else {
        exifData.format = 'Unknown'
        exifData.signature = Array.from(firstBytes.slice(0, 8))
          .map(b => b.toString(16).padStart(2, '0').toUpperCase()).join('')
      }
      
    } catch (e) { 
      exifData.format = 'Detection Failed'
    }

    // Add comprehensive file metadata
    exifData.fileSize = buffer.byteLength
    exifData.fileSizeFormatted = formatBytes(buffer.byteLength)
    exifData.bufferLength = buffer.byteLength
    exifData.analysisTimestamp = new Date().toISOString()
    exifData.totalTags = Object.keys(exifData).length
    
    // Calculate file entropy for analysis
    try {
      const bytes = new Uint8Array(buffer.slice(0, Math.min(buffer.byteLength, 64 * 1024))) // First 64KB
      const frequencies = new Array(256).fill(0)
      bytes.forEach(b => frequencies[b]++)
      
      let entropy = 0
      const length = bytes.length
      frequencies.forEach(freq => {
        if (freq > 0) {
          const p = freq / length
          entropy -= p * Math.log2(p)
        }
      })
      
      exifData.entropy = entropy.toFixed(4)
      exifData.maxEntropy = '8.0'
      exifData.entropyAnalysis = entropy > 7.5 ? 'High (possible compression/encryption)' : 
                                 entropy > 6.0 ? 'Medium' : 'Low'
    } catch (e) {
      exifData.entropy = 'calculation_failed'
    }
    
    return exifData
  } catch (err) {
    return { 
      fileSize: buffer.byteLength,
      fileSizeFormatted: formatBytes(buffer.byteLength),
      error: err instanceof Error ? err.message : 'Unknown error',
      analysisTimestamp: new Date().toISOString()
    }
  }
}

/**
 * Enhanced EXIF validation and tampering detection
 * Checks for inconsistencies, metadata stripping, and suspicious patterns
 */
export interface ExifValidation {
  isTampered: boolean
  confidence: number // 0-100
  warnings: string[]
  validations: {
    timestampConsistency: { valid: boolean, message: string }
    gpsValidation: { valid: boolean, message: string }
    cameraConsistency: { valid: boolean, message: string }
    thumbnailCheck: { valid: boolean, message: string }
    metadataCompleteness: { valid: boolean, message: string }
    softwareAnalysis: { valid: boolean, message: string }
  }
}

export function validateExifData(exifData: any, fileModifiedDate?: Date): ExifValidation {
  const warnings: string[] = []
  let tamperScore = 0 // Higher score = more likely tampered
  
  // 1. Timestamp Consistency Check
  const timestampValidation = validateTimestamps(exifData, fileModifiedDate)
  if (!timestampValidation.valid) {
    warnings.push(timestampValidation.message)
    tamperScore += 15
  }
  
  // 2. GPS Validation
  const gpsValidation = validateGPSData(exifData)
  if (!gpsValidation.valid) {
    warnings.push(gpsValidation.message)
    tamperScore += 10
  }
  
  // 3. Camera Make/Model Consistency
  const cameraValidation = validateCameraConsistency(exifData)
  if (!cameraValidation.valid) {
    warnings.push(cameraValidation.message)
    tamperScore += 20
  }
  
  // 4. Thumbnail Consistency
  const thumbnailValidation = checkThumbnailConsistency(exifData)
  if (!thumbnailValidation.valid) {
    warnings.push(thumbnailValidation.message)
    tamperScore += 15
  }
  
  // 5. Metadata Completeness (stripped and re-added detection)
  const completenessValidation = checkMetadataCompleteness(exifData)
  if (!completenessValidation.valid) {
    warnings.push(completenessValidation.message)
    tamperScore += 25
  }
  
  // 6. Software/Editor Analysis
  const softwareValidation = analyzeSoftwareMetadata(exifData)
  if (!softwareValidation.valid) {
    warnings.push(softwareValidation.message)
    tamperScore += 15
  }
  
  const isTampered = tamperScore >= 30 // Threshold for tampering
  const confidence = Math.min(100, tamperScore)
  
  return {
    isTampered,
    confidence,
    warnings,
    validations: {
      timestampConsistency: timestampValidation,
      gpsValidation,
      cameraConsistency: cameraValidation,
      thumbnailCheck: thumbnailValidation,
      metadataCompleteness: completenessValidation,
      softwareAnalysis: softwareValidation
    }
  }
}

function validateTimestamps(exifData: any, fileModifiedDate?: Date): { valid: boolean, message: string } {
  try {
    const exifDate = exifData.DateTime || exifData.DateTimeOriginal || exifData.CreateDate
    const exifDigitized = exifData.DateTimeDigitized
    
    if (!exifDate && !exifDigitized) {
      return { valid: false, message: '⚠️ No timestamp data found - metadata may have been stripped' }
    }
    
    // Parse EXIF date format (YYYY:MM:DD HH:MM:SS)
    const parseExifDate = (dateStr: string) => {
      if (!dateStr || typeof dateStr !== 'string') return null
      const parts = dateStr.split(/[: ]/)
      if (parts.length < 6) return null
      return new Date(
        parseInt(parts[0]), parseInt(parts[1]) - 1, parseInt(parts[2]),
        parseInt(parts[3]), parseInt(parts[4]), parseInt(parts[5])
      )
    }
    
    const exifTimestamp = parseExifDate(exifDate)
    const digitizedTimestamp = parseExifDate(exifDigitized)
    
    // Check if EXIF date is in the future
    const now = new Date()
    if (exifTimestamp && exifTimestamp > now) {
      return { valid: false, message: '⚠️ EXIF timestamp is in the future - possible clock error or tampering' }
    }
    
    // Check if EXIF date is suspiciously old (before digital cameras existed)
    if (exifTimestamp && exifTimestamp.getFullYear() < 1990) {
      return { valid: false, message: '⚠️ EXIF timestamp predates digital photography - likely invalid' }
    }
    
    // Check consistency between different timestamp fields
    if (exifTimestamp && digitizedTimestamp) {
      const diff = Math.abs(exifTimestamp.getTime() - digitizedTimestamp.getTime())
      if (diff > 24 * 60 * 60 * 1000) { // More than 24 hours difference
        return { valid: false, message: '⚠️ Inconsistent timestamps between DateTimeOriginal and DateTimeDigitized' }
      }
    }
    
    // Check against file modified date
    if (fileModifiedDate && exifTimestamp) {
      const diff = fileModifiedDate.getTime() - exifTimestamp.getTime()
      // EXIF date should not be significantly after file modified date
      if (diff < -60000) { // More than 1 minute after
        return { valid: false, message: '⚠️ EXIF timestamp is newer than file modification date - possible tampering' }
      }
    }
    
    return { valid: true, message: '✓ Timestamp validation passed' }
  } catch (error) {
    return { valid: false, message: '⚠️ Error validating timestamps' }
  }
}

function validateGPSData(exifData: any): { valid: boolean, message: string } {
  try {
    const gpsLat = exifData.GPSLatitude || exifData.latitude
    const gpsLon = exifData.GPSLongitude || exifData.longitude
    
    if (!gpsLat && !gpsLon) {
      return { valid: true, message: 'No GPS data present' }
    }
    
    // Parse GPS coordinates
    let lat: number | null = null
    let lon: number | null = null
    
    if (typeof gpsLat === 'number') lat = gpsLat
    else if (typeof gpsLat === 'string') lat = parseFloat(gpsLat)
    
    if (typeof gpsLon === 'number') lon = gpsLon
    else if (typeof gpsLon === 'string') lon = parseFloat(gpsLon)
    
    // Validate GPS ranges
    if (lat !== null && (lat < -90 || lat > 90)) {
      return { valid: false, message: '⚠️ Invalid GPS latitude (out of range -90 to 90)' }
    }
    
    if (lon !== null && (lon < -180 || lon > 180)) {
      return { valid: false, message: '⚠️ Invalid GPS longitude (out of range -180 to 180)' }
    }
    
    // Check for null island (0,0) which is often a sign of fake GPS
    if (lat === 0 && lon === 0) {
      return { valid: false, message: '⚠️ GPS coordinates at (0,0) - likely invalid or placeholder' }
    }
    
    return { valid: true, message: '✓ GPS data is valid' }
  } catch (error) {
    return { valid: false, message: '⚠️ Error validating GPS data' }
  }
}

function validateCameraConsistency(exifData: any): { valid: boolean, message: string } {
  try {
    const make = exifData.Make || exifData.CameraMake
    const model = exifData.Model || exifData.CameraModel
    const software = exifData.Software
    
    if (!make && !model) {
      return { valid: false, message: '⚠️ No camera information - metadata may have been stripped' }
    }
    
    // Check for common inconsistencies
    const makeStr = (make || '').toString().toLowerCase()
    const modelStr = (model || '').toString().toLowerCase()
    
    // Common camera make/model pairs that should be consistent
    const inconsistencies = [
      { make: 'canon', model: 'nikon', message: 'Canon make with Nikon model' },
      { make: 'nikon', model: 'canon', message: 'Nikon make with Canon model' },
      { make: 'sony', model: 'canon', message: 'Sony make with Canon model' },
      { make: 'apple', model: 'samsung', message: 'Apple make with Samsung model' }
    ]
    
    for (const check of inconsistencies) {
      if (makeStr.includes(check.make) && modelStr.includes(check.model)) {
        return { valid: false, message: `⚠️ Inconsistent camera data: ${check.message}` }
      }
    }
    
    // Check for suspicious software tags
    if (software) {
      const softwareStr = software.toString().toLowerCase()
      const photoEditors = ['photoshop', 'gimp', 'paint.net', 'affinity', 'pixelmator', 'acdsee', 'lightroom']
      for (const editor of photoEditors) {
        if (softwareStr.includes(editor)) {
          return { valid: false, message: `⚠️ Image edited with ${editor} - original metadata may be modified` }
        }
      }
    }
    
    return { valid: true, message: '✓ Camera data is consistent' }
  } catch (error) {
    return { valid: false, message: '⚠️ Error validating camera consistency' }
  }
}

function checkThumbnailConsistency(exifData: any): { valid: boolean, message: string } {
  try {
    const hasThumbnail = exifData.ThumbnailImage || exifData.Thumbnail || exifData.thumbnail
    const thumbnailOffset = exifData.ThumbnailOffset
    const thumbnailLength = exifData.ThumbnailLength
    
    if (!hasThumbnail && !thumbnailOffset) {
      return { valid: true, message: 'No thumbnail present' }
    }
    
    // Check for thumbnail presence but missing data
    if (thumbnailOffset && !thumbnailLength) {
      return { valid: false, message: '⚠️ Thumbnail offset present but length missing - corrupted metadata' }
    }
    
    // Check for suspicious thumbnail sizes
    if (thumbnailLength && (thumbnailLength < 100 || thumbnailLength > 100000)) {
      return { valid: false, message: `⚠️ Unusual thumbnail size: ${thumbnailLength} bytes` }
    }
    
    return { valid: true, message: '✓ Thumbnail data is consistent' }
  } catch (error) {
    return { valid: false, message: '⚠️ Error checking thumbnail consistency' }
  }
}

function checkMetadataCompleteness(exifData: any): { valid: boolean, message: string } {
  try {
    // Check for minimum expected tags in legitimate camera photos
    const essentialTags = [
      'Make', 'Model', 'DateTime', 'DateTimeOriginal',
      'ExposureTime', 'FNumber', 'ISO', 'FocalLength'
    ]
    
    let missingCount = 0
    const missingTags: string[] = []
    
    for (const tag of essentialTags) {
      if (!exifData[tag] && !exifData[tag.toLowerCase()]) {
        missingCount++
        missingTags.push(tag)
      }
    }
    
    // If many essential tags are missing, metadata was likely stripped
    if (missingCount >= 6) {
      return { 
        valid: false, 
        message: `⚠️ Critical metadata missing (${missingCount}/8 tags) - likely stripped and possibly re-added` 
      }
    }
    
    // Check for suspiciously minimal metadata
    const totalTags = Object.keys(exifData).filter(k => !k.startsWith('_')).length
    if (totalTags < 10) {
      return { 
        valid: false, 
        message: `⚠️ Very minimal metadata (${totalTags} tags) - possibly stripped` 
      }
    }
    
    // Check for common stripped+re-added patterns
    const hasBasicInfo = exifData.Make && exifData.Model && exifData.DateTime
    const lacksAdvancedInfo = !exifData.LensModel && !exifData.SerialNumber && !exifData.InternalSerialNumber
    
    if (hasBasicInfo && lacksAdvancedInfo && missingCount >= 3) {
      return { 
        valid: false, 
        message: '⚠️ Basic metadata present but advanced camera info missing - possibly stripped and re-added' 
      }
    }
    
    return { valid: true, message: '✓ Metadata appears complete' }
  } catch (error) {
    return { valid: false, message: '⚠️ Error checking metadata completeness' }
  }
}

function analyzeSoftwareMetadata(exifData: any): { valid: boolean, message: string } {
  try {
    const software = exifData.Software || exifData.ProcessingSoftware
    const creatorTool = exifData.CreatorTool
    
    if (!software && !creatorTool) {
      return { valid: true, message: 'No software information' }
    }
    
    const softwareStr = ((software || '') + ' ' + (creatorTool || '')).toLowerCase()
    
    // Detect metadata manipulation tools
    const suspiciousTools = [
      'exiftool', 'jhead', 'exiv2', 'metadata', 'stripper', 
      'anonymizer', 'scrubber', 'cleaner'
    ]
    
    for (const tool of suspiciousTools) {
      if (softwareStr.includes(tool)) {
        return { 
          valid: false, 
          message: `⚠️ Image processed with metadata tool: ${tool} - EXIF may have been modified` 
        }
      }
    }
    
    // Check for version inconsistencies
    if (software && software.toString().includes('0.0') || software.toString().includes('1.0')) {
      return { 
        valid: false, 
        message: '⚠️ Suspicious software version (0.0 or 1.0) - may indicate fake metadata' 
      }
    }
    
    return { valid: true, message: '✓ Software metadata appears normal' }
  } catch (error) {
    return { valid: false, message: '⚠️ Error analyzing software metadata' }
  }
}

// Histogram computation
export function computeHistogramFromCanvas(ctx: CanvasRenderingContext2D, width: number, height: number) {
  const imageData = ctx.getImageData(0,0,width,height).data
  const histogram = { r: new Array(256).fill(0), g: new Array(256).fill(0), b: new Array(256).fill(0), l: new Array(256).fill(0) }

  for (let i = 0; i < imageData.length; i += 4) {
    const r = imageData[i]
    const g = imageData[i+1]
    const b = imageData[i+2]
    const l = Math.round(0.299*r + 0.587*g + 0.114*b)
    histogram.r[r]++
    histogram.g[g]++
    histogram.b[b]++
    histogram.l[l]++
  }

  return histogram
}

// Bit-plane extraction (returns array of canvases or byte arrays depending on use)
export function extractBitPlaneFromCanvas(ctx: CanvasRenderingContext2D, width: number, height: number, plane = 0) {
  const imageData = ctx.getImageData(0,0,width,height)
  const out = new Uint8ClampedArray(imageData.data.length)

  for (let i = 0; i < imageData.data.length; i += 4) {
    const r = imageData.data[i]
    // g and b not needed for bit plane extraction
    const bit = ((r >> plane) & 1) * 255
    out[i] = bit
    out[i+1] = bit
    out[i+2] = bit
    out[i+3] = 255
  }

  const outImageData = new ImageData(out, width, height)
  const canvas = document.createElement('canvas')
  canvas.width = width
  canvas.height = height
  const octx = canvas.getContext('2d')
  if (octx) octx.putImageData(outImageData, 0, 0)
  return canvas
}

// Real working analysis interfaces
export interface AdvancedSteganographyDetection {
  dctAnalysis: {
    suspicious: boolean
    coefficientAnalysis: {
      histogram: number[]
      entropy: number
      anomalies: Array<{ position: [number, number]; value: number; expected: number }>
    }
    jpegQuality: number
    compressionArtifacts: boolean
  }
  statisticalAnalysis: {
    chiSquareTest: { statistic: number; pValue: number; suspicious: boolean }
    benfordLaw: { conformity: number; suspicious: boolean }
    pixelValueDistribution: { entropy: number; uniformity: number }
  }
}

export interface GPSData {
  coordinates?: { latitude: number; longitude: number }
  altitude?: number
  direction?: number
  timestamp?: Date
  locationName?: string
}

export interface CameraFingerprinting {
  make: string
  model: string
  serialNumber?: string
  firmwareVersion?: string
  lensModel?: string
  cameraSettings: {
    iso?: number
    aperture?: string
    shutterSpeed?: string
    focalLength?: string
    flashUsed?: boolean
    whiteBalance?: string
    meteringMode?: string
    exposureMode?: string
  }
}

export interface ImageAnalysisResult {
  metadata: {
    filename: string
    fileSize: number
    dimensions: { width: number; height: number }
    format: string
    exif?: any
    gpsData?: GPSData
    cameraInfo?: CameraFingerprinting
  }
  signatures: Array<{ name: string; offset: number; confidence: number }>
  strings: {
    all: string[]
    base64Candidates: string[]
    urls: string[]
    totalCount: number
  }
  steganography: {
    lsb: {
      red: { text: string; ratio: number; suspicious: boolean }
      green: { text: string; ratio: number; suspicious: boolean }
      blue: { text: string; ratio: number; suspicious: boolean }
      composite: string
    }
    embeddedFiles: Array<{ type: string; offset: number; size: number; id?: string; filename?: string; recovered?: boolean }>
    detected: boolean
    advanced: AdvancedSteganographyDetection
  }
  layers: Array<{
    step: number
    method: string
    confidence: number
    data: any
    timestamp: number
  }>
}

// Advanced image processing functions for forensic analysis
export function applyEdgeDetection(ctx: CanvasRenderingContext2D, width: number, height: number): ImageData {
  const imageData = ctx.getImageData(0, 0, width, height)
  const data = imageData.data
  const output = new Uint8ClampedArray(data.length)
  
  // Sobel edge detection kernel
  const sobelX = [[-1, 0, 1], [-2, 0, 2], [-1, 0, 1]]
  const sobelY = [[-1, -2, -1], [0, 0, 0], [1, 2, 1]]
  
  for (let y = 1; y < height - 1; y++) {
    for (let x = 1; x < width - 1; x++) {
      let gx = 0, gy = 0
      
      // Apply Sobel kernels
      for (let ky = -1; ky <= 1; ky++) {
        for (let kx = -1; kx <= 1; kx++) {
          const idx = ((y + ky) * width + (x + kx)) * 4
          const gray = 0.299 * data[idx] + 0.587 * data[idx + 1] + 0.114 * data[idx + 2]
          gx += gray * sobelX[ky + 1][kx + 1]
          gy += gray * sobelY[ky + 1][kx + 1]
        }
      }
      
      const magnitude = Math.sqrt(gx * gx + gy * gy)
      const idx = (y * width + x) * 4
      const value = Math.min(255, magnitude)
      
      output[idx] = value     // R
      output[idx + 1] = value // G
      output[idx + 2] = value // B
      output[idx + 3] = 255   // A
    }
  }
  
  return new ImageData(output, width, height)
}

export function analyzeNoise(ctx: CanvasRenderingContext2D, width: number, height: number): { noiseLevel: number, analysis: string, visualData: ImageData } {
  const imageData = ctx.getImageData(0, 0, width, height)
  const data = imageData.data
  const output = new Uint8ClampedArray(data.length)
  
  let totalVariance = 0
  let pixelCount = 0
  
  // Calculate local variance to detect noise
  for (let y = 1; y < height - 1; y++) {
    for (let x = 1; x < width - 1; x++) {
      const idx = (y * width + x) * 4
      const centerGray = 0.299 * data[idx] + 0.587 * data[idx + 1] + 0.114 * data[idx + 2]
      
      let localVariance = 0
      let neighborCount = 0
      
      // Check 3x3 neighborhood
      for (let dy = -1; dy <= 1; dy++) {
        for (let dx = -1; dx <= 1; dx++) {
          const nIdx = ((y + dy) * width + (x + dx)) * 4
          const neighborGray = 0.299 * data[nIdx] + 0.587 * data[nIdx + 1] + 0.114 * data[nIdx + 2]
          localVariance += Math.pow(neighborGray - centerGray, 2)
          neighborCount++
        }
      }
      
      localVariance /= neighborCount
      totalVariance += localVariance
      pixelCount++
      
      // Visualize noise areas (high variance = bright)
      const noiseIntensity = Math.min(255, localVariance * 10)
      output[idx] = noiseIntensity
      output[idx + 1] = noiseIntensity
      output[idx + 2] = noiseIntensity
      output[idx + 3] = 255
    }
  }
  
  const averageNoise = totalVariance / pixelCount
  const noiseLevel = Math.min(100, averageNoise / 10)
  
  let analysis = 'Low noise'
  if (noiseLevel > 60) analysis = 'High noise detected'
  else if (noiseLevel > 30) analysis = 'Moderate noise'
  
  return {
    noiseLevel: Math.round(noiseLevel),
    analysis,
    visualData: new ImageData(output, width, height)
  }
}

export function applyAutoGammaCorrection(ctx: CanvasRenderingContext2D, width: number, height: number): ImageData {
  const imageData = ctx.getImageData(0, 0, width, height)
  const data = imageData.data
  const output = new Uint8ClampedArray(data.length)
  
  // Calculate histogram for gamma estimation
  const histogram = new Array(256).fill(0)
  let totalPixels = 0
  
  for (let i = 0; i < data.length; i += 4) {
    const gray = Math.round(0.299 * data[i] + 0.587 * data[i + 1] + 0.114 * data[i + 2])
    histogram[gray]++
    totalPixels++
  }
  
  // Calculate mean luminance
  let meanLuminance = 0
  for (let i = 0; i < 256; i++) {
    meanLuminance += i * histogram[i]
  }
  meanLuminance /= totalPixels
  
  // Estimate optimal gamma
  const targetMean = 128
  const gamma = Math.log(targetMean / 255) / Math.log(meanLuminance / 255)
  const clampedGamma = Math.max(0.3, Math.min(3.0, gamma))
  
  // Apply gamma correction
  const gammaTable = new Array(256)
  for (let i = 0; i < 256; i++) {
    gammaTable[i] = Math.round(255 * Math.pow(i / 255, 1 / clampedGamma))
  }
  
  for (let i = 0; i < data.length; i += 4) {
    output[i] = gammaTable[data[i]]         // R
    output[i + 1] = gammaTable[data[i + 1]] // G
    output[i + 2] = gammaTable[data[i + 2]] // B
    output[i + 3] = data[i + 3]             // A
  }
  
  return new ImageData(output, width, height)
}

export function applyHistogramEqualization(ctx: CanvasRenderingContext2D, width: number, height: number): ImageData {
  const imageData = ctx.getImageData(0, 0, width, height)
  const data = imageData.data
  const output = new Uint8ClampedArray(data.length)
  
  // Calculate histogram for each channel
  const histR = new Array(256).fill(0)
  const histG = new Array(256).fill(0)
  const histB = new Array(256).fill(0)
  const totalPixels = width * height
  
  for (let i = 0; i < data.length; i += 4) {
    histR[data[i]]++
    histG[data[i + 1]]++
    histB[data[i + 2]]++
  }
  
  // Calculate cumulative distribution function for each channel
  const cdfR = new Array(256)
  const cdfG = new Array(256)
  const cdfB = new Array(256)
  
  cdfR[0] = histR[0]
  cdfG[0] = histG[0]
  cdfB[0] = histB[0]
  
  for (let i = 1; i < 256; i++) {
    cdfR[i] = cdfR[i - 1] + histR[i]
    cdfG[i] = cdfG[i - 1] + histG[i]
    cdfB[i] = cdfB[i - 1] + histB[i]
  }
  
  // Create equalization lookup tables
  const eqR = new Array(256)
  const eqG = new Array(256)
  const eqB = new Array(256)
  
  for (let i = 0; i < 256; i++) {
    eqR[i] = Math.round((cdfR[i] / totalPixels) * 255)
    eqG[i] = Math.round((cdfG[i] / totalPixels) * 255)
    eqB[i] = Math.round((cdfB[i] / totalPixels) * 255)
  }
  
  // Apply equalization
  for (let i = 0; i < data.length; i += 4) {
    output[i] = eqR[data[i]]         // R
    output[i + 1] = eqG[data[i + 1]] // G
    output[i + 2] = eqB[data[i + 2]] // B
    output[i + 3] = data[i + 3]      // A
  }
  
  return new ImageData(output, width, height)
}

/**
 * Error Level Analysis (ELA) - Real forensic technique to detect image manipulation
 * Compresses image at known quality and measures pixel-level differences
 * Areas with different error levels indicate potential tampering or splicing
 */
export async function performELA(file: File, quality: number = 90): Promise<{
  elaImageUrl: string
  analysis: {
    maxDifference: number
    avgDifference: number
    suspiciousRegions: Array<{ x: number, y: number, width: number, height: number, avgError: number }>
    interpretation: string
  }
}> {
  return new Promise((resolve, reject) => {
    const img = new Image()
    img.onload = async () => {
      try {
        // Create canvas with original image
        const canvas = document.createElement('canvas')
        const ctx = canvas.getContext('2d')
        if (!ctx) throw new Error('Canvas context not available')
        
        canvas.width = img.width
        canvas.height = img.height
        ctx.drawImage(img, 0, 0)
        
        // Get original image data
        const originalData = ctx.getImageData(0, 0, canvas.width, canvas.height)
        
        // Re-compress image at specified quality
        const recompressedBlob = await new Promise<Blob>((res, rej) => {
          canvas.toBlob((blob) => {
            if (blob) res(blob)
            else rej(new Error('Failed to compress image'))
          }, 'image/jpeg', quality / 100)
        })
        
        // Load recompressed image
        const recompressedImg = new Image()
        const recompressedUrl = URL.createObjectURL(recompressedBlob)
        
        recompressedImg.onload = () => {
          // Draw recompressed image
          ctx.clearRect(0, 0, canvas.width, canvas.height)
          ctx.drawImage(recompressedImg, 0, 0)
          const recompressedData = ctx.getImageData(0, 0, canvas.width, canvas.height)
          
          // Calculate difference (error level)
          const elaData = new Uint8ClampedArray(originalData.data.length)
          let maxDiff = 0
          let totalDiff = 0
          const errorMap: number[][] = []
          
          // Initialize error map
          for (let y = 0; y < canvas.height; y++) {
            errorMap[y] = []
          }
          
          for (let i = 0; i < originalData.data.length; i += 4) {
            const diffR = Math.abs(originalData.data[i] - recompressedData.data[i])
            const diffG = Math.abs(originalData.data[i + 1] - recompressedData.data[i + 1])
            const diffB = Math.abs(originalData.data[i + 2] - recompressedData.data[i + 2])
            
            // Amplify differences for visibility (multiply by 15)
            const avgDiff = (diffR + diffG + diffB) / 3
            const amplified = Math.min(255, avgDiff * 15)
            
            elaData[i] = amplified
            elaData[i + 1] = amplified
            elaData[i + 2] = amplified
            elaData[i + 3] = 255
            
            maxDiff = Math.max(maxDiff, avgDiff)
            totalDiff += avgDiff
            
            // Store in error map
            const pixelIndex = i / 4
            const x = pixelIndex % canvas.width
            const y = Math.floor(pixelIndex / canvas.width)
            errorMap[y][x] = avgDiff
          }
          
          const avgDiff = totalDiff / (originalData.data.length / 4)
          
          // Detect suspicious regions (areas with significantly different error levels)
          const suspiciousRegions = detectSuspiciousRegions(errorMap, canvas.width, canvas.height, avgDiff)
          
          // Create ELA visualization
          ctx.putImageData(new ImageData(elaData, canvas.width, canvas.height), 0, 0)
          const elaImageUrl = canvas.toDataURL()
          
          // Cleanup
          URL.revokeObjectURL(recompressedUrl)
          
          // Interpretation
          let interpretation = ''
          if (maxDiff < 10) {
            interpretation = 'Low error levels - likely unmodified or single-generation JPEG'
          } else if (maxDiff < 30) {
            interpretation = 'Moderate error levels - some compression artifacts detected'
          } else if (suspiciousRegions.length > 0) {
            interpretation = `High error levels with ${suspiciousRegions.length} suspicious region(s) - possible image manipulation or splicing detected`
          } else {
            interpretation = 'High error levels - heavily compressed or edited image'
          }
          
          resolve({
            elaImageUrl,
            analysis: {
              maxDifference: maxDiff,
              avgDifference: avgDiff,
              suspiciousRegions,
              interpretation
            }
          })
        }
        
        recompressedImg.onerror = () => reject(new Error('Failed to load recompressed image'))
        recompressedImg.src = recompressedUrl
      } catch (error) {
        reject(error)
      }
    }
    
    img.onerror = () => reject(new Error('Failed to load image'))
    img.src = URL.createObjectURL(file)
  })
}

// Helper function to detect suspicious regions in ELA
function detectSuspiciousRegions(
  errorMap: number[][], 
  width: number, 
  height: number, 
  avgError: number
): Array<{ x: number, y: number, width: number, height: number, avgError: number }> {
  const regions: Array<{ x: number, y: number, width: number, height: number, avgError: number }> = []
  const threshold = avgError * 2 // Areas with 2x average error are suspicious
  const minRegionSize = 20 // Minimum 20x20 pixel region
  const gridSize = 32 // Check in 32x32 blocks
  
  for (let y = 0; y < height - gridSize; y += gridSize) {
    for (let x = 0; x < width - gridSize; x += gridSize) {
      let blockSum = 0
      let count = 0
      
      // Calculate average error in this block
      for (let by = y; by < Math.min(y + gridSize, height); by++) {
        for (let bx = x; bx < Math.min(x + gridSize, width); bx++) {
          blockSum += errorMap[by][bx]
          count++
        }
      }
      
      const blockAvg = blockSum / count
      
      // If block has significantly higher error than average, mark as suspicious
      if (blockAvg > threshold && gridSize >= minRegionSize) {
        regions.push({
          x,
          y,
          width: Math.min(gridSize, width - x),
          height: Math.min(gridSize, height - y),
          avgError: blockAvg
        })
      }
    }
  }
  
  return regions
}

export async function performComprehensiveImageAnalysis(file: File): Promise<ImageAnalysisResult> {
  const buffer = await readFileAsArrayBuffer(file)
  
  // Initialize result structure
  const result: ImageAnalysisResult = {
    metadata: {
      filename: file.name,
      fileSize: file.size,
      dimensions: { width: 0, height: 0 },
      format: file.type || 'unknown'
    },
    signatures: [],
    strings: {
      all: [],
      base64Candidates: [],
      urls: [],
      totalCount: 0
    },
    steganography: {
      lsb: {
        red: { text: '', ratio: 0, suspicious: false },
        green: { text: '', ratio: 0, suspicious: false },
        blue: { text: '', ratio: 0, suspicious: false },
        composite: ''
      },
      embeddedFiles: [],
      detected: false,
      advanced: {
        dctAnalysis: {
          suspicious: false,
          coefficientAnalysis: { histogram: [], entropy: 0, anomalies: [] },
          jpegQuality: 0,
          compressionArtifacts: false
        },
        statisticalAnalysis: {
          chiSquareTest: { statistic: 0, pValue: 0, suspicious: false },
          benfordLaw: { conformity: 0, suspicious: false },
          pixelValueDistribution: { entropy: 0, uniformity: 0 }
        }
      }
    },
    layers: []
  }
  
  let layerStep = 0
  
  // Layer 1: Basic metadata and EXIF
  try {
    const exif = await parseExif(buffer)
    
    // Get image dimensions
    const url = URL.createObjectURL(file)
    const img = new Image()
    img.src = url
    await new Promise((resolve, reject) => {
      img.onload = () => resolve(true)
      img.onerror = reject
    })
    
    result.metadata.dimensions = {
      width: img.naturalWidth,
      height: img.naturalHeight
    }
    result.metadata.exif = exif
    
    result.layers.push({
      step: ++layerStep,
      method: 'metadata_extraction',
      confidence: exif ? 90 : 50,
      data: { dimensions: result.metadata.dimensions, exif },
      timestamp: Date.now()
    })
    
    URL.revokeObjectURL(url)
  } catch (error) {
    result.layers.push({
      step: ++layerStep,
      method: 'metadata_extraction',
      confidence: 0,
      data: { error: error instanceof Error ? error.message : 'Unknown error' },
      timestamp: Date.now()
    })
  }
  
  // Layer 2: File signature detection
  result.signatures = detectMagicFiles(buffer).map(sig => ({
    name: sig.name,
    offset: sig.offset,
    confidence: sig.offset === 0 ? 95 : 85 // Higher confidence for expected location
  }))
  
  result.layers.push({
    step: ++layerStep,
    method: 'signature_detection',
    confidence: result.signatures.length > 0 ? 85 : 20,
    data: { signatures: result.signatures },
    timestamp: Date.now()
  })
  
  // Layer 3: Enhanced string extraction and analysis
  const stringResults = extractPrintableStringsFromBuffer(buffer, 4)
  const allStrings = stringResults.all
  const patterns = stringResults.patterns
  
  result.strings = {
    all: allStrings.slice(0, 500), // Increased limit for better analysis
    base64Candidates: patterns.base64 || [],
    urls: patterns.urls || [],
    totalCount: allStrings.length
  }
  
  result.layers.push({
    step: ++layerStep,
    method: 'enhanced_string_extraction',
    confidence: allStrings.length > 10 ? 85 : 40,
    data: {
      total_strings: allStrings.length,
      unique_strings: stringResults.counts.unique,
      base64_count: patterns.base64?.length || 0,
      url_count: patterns.urls?.length || 0,
      email_count: patterns.emails?.length || 0,
      ip_count: patterns.ipAddresses?.length || 0,
      file_path_count: patterns.filePaths?.length || 0,
      pattern_summary: Object.keys(patterns).reduce((acc, key) => {
        acc[key] = patterns[key]?.length || 0
        return acc
      }, {} as Record<string, number>),
      sample_strings: allStrings.slice(0, 15)
    },
    timestamp: Date.now()
  })
  
  // Layer 4: LSB Steganography Analysis
  try {
    const canvas = document.createElement('canvas')
    canvas.width = result.metadata.dimensions.width
    canvas.height = result.metadata.dimensions.height
    const ctx = canvas.getContext('2d')
    
    if (ctx && result.metadata.dimensions.width > 0) {
      const img = new Image()
      const url = URL.createObjectURL(file)
      img.src = url
      
      await new Promise((resolve, reject) => {
        img.onload = () => resolve(true)
        img.onerror = reject
      })
      
      ctx.drawImage(img, 0, 0)
      const lsbAnalysis = analyzeLSBFromCanvas(ctx, result.metadata.dimensions.width, result.metadata.dimensions.height, 20000)
      
      result.steganography.lsb = {
        red: { ...lsbAnalysis.r, suspicious: lsbAnalysis.r.ratio > 0.7 },
        green: { ...lsbAnalysis.g, suspicious: lsbAnalysis.g.ratio > 0.7 },
        blue: { ...lsbAnalysis.b, suspicious: lsbAnalysis.b.ratio > 0.7 },
        composite: lsbAnalysis.composite
      }
      
      const suspiciousChannels = [
        result.steganography.lsb.red.suspicious,
        result.steganography.lsb.green.suspicious,
        result.steganography.lsb.blue.suspicious
      ].filter(Boolean).length
      
      result.layers.push({
        step: ++layerStep,
        method: 'lsb_steganography',
        confidence: suspiciousChannels > 0 ? 80 : 20,
        data: {
          suspicious_channels: suspiciousChannels,
          channel_analysis: {
            red: { ratio: lsbAnalysis.r.ratio, suspicious: result.steganography.lsb.red.suspicious },
            green: { ratio: lsbAnalysis.g.ratio, suspicious: result.steganography.lsb.green.suspicious },
            blue: { ratio: lsbAnalysis.b.ratio, suspicious: result.steganography.lsb.blue.suspicious }
          }
        },
        timestamp: Date.now()
      })
      
      URL.revokeObjectURL(url)
    }
  } catch (error) {
    result.layers.push({
      step: ++layerStep,
      method: 'lsb_steganography',
      confidence: 0,
      data: { error: error instanceof Error ? error.message : 'LSB analysis failed' },
      timestamp: Date.now()
    })
  }
  
  // Layer 5: Embedded file detection using signatures and carving
  const embeddedFiles = result.signatures
    .filter(sig => sig.offset > 0) // Not at the beginning
    .map(sig => ({
      type: sig.name,
      offset: sig.offset,
      size: Math.min(1024, buffer.byteLength - sig.offset)
    }))
  
  // Additionally perform lightweight carving to find embedded files
  try {
    const carves = carveFiles(new Uint8Array(buffer), 64)
    for (const c of carves) {
      embeddedFiles.push({ type: c.type, offset: c.offset, size: c.size })
    }
  } catch (e) {
    // ignore carving errors
  }

  result.steganography.embeddedFiles = embeddedFiles

  // Mark detected if suspicious LSB channels or embedded files exist
  const suspiciousChannelsFinal = [
    result.steganography.lsb.red.suspicious,
    result.steganography.lsb.green.suspicious,
    result.steganography.lsb.blue.suspicious
  ].filter(Boolean).length
  result.steganography.detected = suspiciousChannelsFinal > 0 || embeddedFiles.length > 0
  
  result.layers.push({
    step: ++layerStep,
    method: 'embedded_file_detection',
    confidence: embeddedFiles.length > 0 ? 90 : 15,
    data: { embedded_files: embeddedFiles },
    timestamp: Date.now()
  })
  
  // Layer 6: Advanced Steganography Detection (Real statistical analysis only)
  try {
    const canvas = document.createElement('canvas')
    canvas.width = result.metadata.dimensions.width
    canvas.height = result.metadata.dimensions.height
    const ctx = canvas.getContext('2d')
    
    if (ctx && result.metadata.dimensions.width > 0) {
      const img = new Image()
      const url = URL.createObjectURL(file)
      img.src = url
      
      await new Promise((resolve, reject) => {
        img.onload = () => resolve(true)
        img.onerror = reject
      })
      
      ctx.drawImage(img, 0, 0)
      
      // Perform real advanced steganography detection (DCT, statistical tests)
      result.steganography.advanced = performAdvancedSteganographyDetection(ctx, result.metadata.dimensions.width, result.metadata.dimensions.height)
      
      const suspiciousCount = [
        result.steganography.advanced.dctAnalysis.suspicious,
        result.steganography.advanced.statisticalAnalysis.chiSquareTest.suspicious,
        result.steganography.advanced.statisticalAnalysis.benfordLaw.suspicious
      ].filter(Boolean).length
      
      result.layers.push({
        step: ++layerStep,
        method: 'advanced_steganography_detection',
        confidence: 95,
        data: {
          dct_analysis: {
            suspicious: result.steganography.advanced.dctAnalysis.suspicious,
            entropy: result.steganography.advanced.dctAnalysis.coefficientAnalysis.entropy,
            anomalies_count: result.steganography.advanced.dctAnalysis.coefficientAnalysis.anomalies.length
          },
          statistical_analysis: {
            chi_square_suspicious: result.steganography.advanced.statisticalAnalysis.chiSquareTest.suspicious,
            benford_suspicious: result.steganography.advanced.statisticalAnalysis.benfordLaw.suspicious,
            pixel_entropy: result.steganography.advanced.statisticalAnalysis.pixelValueDistribution.entropy
          },
          overall_suspicious_count: suspiciousCount
        },
        timestamp: Date.now()
      })
      
      URL.revokeObjectURL(url)
    }
  } catch (error) {
    result.layers.push({
      step: ++layerStep,
      method: 'advanced_steganography_detection',
      confidence: 0,
      data: { error: error instanceof Error ? error.message : 'Advanced steganography detection failed' },
      timestamp: Date.now()
    })
  }
  
  // Layer 7: Extract GPS and Camera metadata (Real EXIF parsing)
  try {
    const exif = result.metadata.exif
    if (exif) {
      // Extract GPS data
      const gpsData = extractGPSData(exif)
      if (gpsData.coordinates) {
        result.metadata.gpsData = gpsData
      }
      
      // Extract camera info
      const cameraInfo = extractCameraInfo(exif)
      if (cameraInfo.make || cameraInfo.model) {
        result.metadata.cameraInfo = cameraInfo
      }
      
      result.layers.push({
        step: ++layerStep,
        method: 'gps_camera_metadata_extraction',
        confidence: 90,
        data: {
          has_gps: !!(gpsData.coordinates),
          gps_location: gpsData.locationName,
          camera_make: cameraInfo.make,
          camera_model: cameraInfo.model,
          has_settings: Object.keys(cameraInfo.cameraSettings || {}).length > 0
        },
        timestamp: Date.now()
      })
    }
  } catch (error) {
    result.layers.push({
      step: ++layerStep,
      method: 'gps_camera_metadata_extraction',
      confidence: 0,
      data: { error: error instanceof Error ? error.message : 'GPS/Camera metadata extraction failed' },
      timestamp: Date.now()
    })
  }

  // Layer 8: Iterative decoding of Base64 candidates
  for (const b64Candidate of result.strings.base64Candidates.slice(0, 5)) { // Limit iterations
    try {
      const decoded = atob(b64Candidate)
      if (decoded.length > 10) {
        result.layers.push({
          step: ++layerStep,
          method: 'base64_decoding',
          confidence: 70,
          data: {
            original: b64Candidate.substring(0, 50) + '...',
            decoded: decoded.substring(0, 100) + (decoded.length > 100 ? '...' : ''),
            original_length: b64Candidate.length,
            decoded_length: decoded.length
          },
          timestamp: Date.now()
        })
      }
    } catch (error) {
      // Invalid base64, skip
    }
  }
  
  return result
}

// Real Advanced Steganography Detection (DCT + Statistical Analysis Only)
export function performAdvancedSteganographyDetection(ctx: CanvasRenderingContext2D, width: number, height: number): AdvancedSteganographyDetection {
  const imageData = ctx.getImageData(0, 0, width, height)
  
  // Perform all detection methods
  const dctAnalysis = performDCTAnalysis(imageData, width, height)
  const statisticalAnalysis = performStatisticalAnalysis(imageData)
  const spaAnalysis = performSamplePairsAnalysis(imageData)
  const rsAnalysis = performRSSteganalysis(imageData)
  const histogramAnalysis = performHistogramSteganographyDetection(imageData)
  
  // Combine results into statistical analysis
  const enhancedStatistical = {
    ...statisticalAnalysis,
    samplePairsAnalysis: {
      embeddingRate: spaAnalysis.embeddingRate,
      suspicious: spaAnalysis.suspicious,
      confidence: spaAnalysis.confidence
    },
    rsSteganalysis: {
      estimatedPayload: rsAnalysis.estimatedPayload,
      suspicious: rsAnalysis.suspicious,
      confidence: rsAnalysis.confidence,
      rsRatio: rsAnalysis.rsRatio
    },
    histogramDetection: {
      suspicious: histogramAnalysis.suspicious,
      anomalies: histogramAnalysis.anomalies,
      analysis: histogramAnalysis.histogramAnalysis
    }
  }
  
  return {
    dctAnalysis,
    statisticalAnalysis: enhancedStatistical
  }
}

function performDCTAnalysis(imageData: ImageData, width: number, height: number): AdvancedSteganographyDetection['dctAnalysis'] {
  const data = imageData.data
  const dctCoeffs: number[] = []
  const blockSize = 8
  
  // Simplified DCT analysis for JPEG steganography detection
  for (let y = 0; y < height - blockSize; y += blockSize) {
    for (let x = 0; x < width - blockSize; x += blockSize) {
      const block: number[] = []
      for (let by = 0; by < blockSize; by++) {
        for (let bx = 0; bx < blockSize; bx++) {
          const idx = ((y + by) * width + (x + bx)) * 4
          const gray = 0.299 * data[idx] + 0.587 * data[idx + 1] + 0.114 * data[idx + 2]
          block.push(gray)
        }
      }
      
      // Simplified DCT coefficient calculation
      const dctBlock = simpleDCT(block, blockSize)
      dctCoeffs.push(...dctBlock)
    }
  }
  
  const histogram = calculateHistogram(dctCoeffs, 256)
  const entropy = calculateImageEntropy(histogram)
  const anomalies = detectDCTAnomalies(dctCoeffs, blockSize)
  
  return {
    suspicious: entropy > 7.8 || anomalies.length > 10,
    coefficientAnalysis: {
      histogram,
      entropy,
      anomalies: anomalies.slice(0, 50) // Limit to first 50 anomalies
    },
    jpegQuality: estimateJPEGQuality(histogram),
    compressionArtifacts: detectCompressionArtifacts(dctCoeffs)
  }
}

/**
 * Sample Pairs Analysis (SPA) - Real steganalysis technique
 * Detects LSB steganography by analyzing pixel pair correlations
 */
function performSamplePairsAnalysis(imageData: ImageData): { 
  embeddingRate: number
  suspicious: boolean
  confidence: number
} {
  const data = imageData.data
  const samples = Math.min(10000, data.length / 4) // Sample 10k pixels max
  
  let P = 0, X = 0, Y = 0, Z = 0
  
  // Sample pairs of adjacent pixels
  for (let i = 0; i < samples - 1; i++) {
    const idx1 = i * 4
    const idx2 = (i + 1) * 4
    
    // Use red channel for analysis
    const u = data[idx1]
    const v = data[idx2]
    
    // Count pixel pair relationships for LSB detection
    if (u === v) P++
    else if (u === v + 1 || u === v - 1) X++
    else if (u === v + 2 || u === v - 2) Y++
    else Z++
  }
  
  // Calculate embedding rate using SPA formula
  const total = P + X + Y + Z
  if (total === 0) {
    return { embeddingRate: 0, suspicious: false, confidence: 0 }
  }
  
  // SPA estimator
  const a = 2 * (X + Z) / total
  const b = 2 * P / total
  
  let embeddingRate = 0
  if (a > 0 && b > 0) {
    embeddingRate = Math.min(1, Math.max(0, (a - b) / (2 * a)))
  }
  
  const suspicious = embeddingRate > 0.1 // More than 10% embedding is suspicious
  const confidence = Math.min(100, embeddingRate * 200)
  
  return { embeddingRate, suspicious, confidence }
}

/**
 * RS Steganalysis - Another real technique for LSB detection
 * Measures smoothness changes when flipping LSBs
 */
function performRSSteganalysis(imageData: ImageData): {
  estimatedPayload: number
  suspicious: boolean
  confidence: number
  rsRatio: number
} {
  const data = imageData.data
  const maskSize = 4
  const maxBlocks = 5000 // Limit computation
  
  let Rm = 0, Sm = 0, Rn = 0, Sn = 0
  let blocksProcessed = 0
  
  // Process image in small blocks
  for (let i = 0; i < data.length - maskSize * 4 && blocksProcessed < maxBlocks; i += maskSize * 4) {
    const block: number[] = []
    for (let j = 0; j < maskSize; j++) {
      block.push(data[i + j * 4]) // Red channel
    }
    
    // Calculate variation function
    const f0 = calculateVariation(block)
    
    // Apply mask M (flip LSBs)
    const blockM = block.map(v => (v & 1) ? v - 1 : v + 1)
    const fM = calculateVariation(blockM)
    
    // Apply mask N (flip LSBs differently)
    const blockN = block.map(v => (v & 1) ? v + 1 : v - 1)
    const fN = calculateVariation(blockN)
    
    // Count regular and singular groups
    if (fM > f0) Rm++
    else if (fM < f0) Sm++
    
    if (fN > f0) Rn++
    else if (fN < f0) Sn++
    
    blocksProcessed++
  }
  
  // Calculate RS ratio
  const rsRatio = blocksProcessed > 0 ? (Rm - Sm) / (Rn - Sn + 0.001) : 0
  
  // Estimate payload (simplified RS formula)
  const d = Math.abs(rsRatio - 1)
  const estimatedPayload = Math.min(1, Math.max(0, d / 2))
  
  const suspicious = estimatedPayload > 0.05 // More than 5% payload is suspicious
  const confidence = Math.min(100, estimatedPayload * 500)
  
  return { estimatedPayload, suspicious, confidence, rsRatio }
}

// Helper: Calculate variation for RS analysis
function calculateVariation(block: number[]): number {
  let variation = 0
  for (let i = 0; i < block.length - 1; i++) {
    variation += Math.abs(block[i + 1] - block[i])
  }
  return variation
}

/**
 * Enhanced histogram analysis for steganography detection
 */
function performHistogramSteganographyDetection(imageData: ImageData): {
  suspicious: boolean
  anomalies: string[]
  histogramAnalysis: {
    pairsAnomaly: boolean
    lsbFluctuation: number
    evenOddImbalance: number
  }
} {
  const data = imageData.data
  const anomalies: string[] = []
  
  // Count even/odd pixel values (LSB analysis)
  let evenCount = 0, oddCount = 0
  const histogram = new Array(256).fill(0)
  
  for (let i = 0; i < data.length; i += 4) {
    const r = data[i]
    const g = data[i + 1]
    const b = data[i + 2]
    
    histogram[r]++
    histogram[g]++
    histogram[b]++
    
    if (r % 2 === 0) evenCount++
    else oddCount++
  }
  
  // Check for even/odd imbalance (sign of LSB embedding)
  const total = evenCount + oddCount
  const evenRatio = evenCount / total
  const evenOddImbalance = Math.abs(evenRatio - 0.5)
  
  if (evenOddImbalance < 0.01) {
    anomalies.push('Near-perfect even/odd balance suggests LSB steganography')
  }
  
  // Check for pairs of values (n, n+1) having similar frequencies
  let pairsWithSimilarFreq = 0
  for (let i = 0; i < 255; i++) {
    const diff = Math.abs(histogram[i] - histogram[i + 1])
    const avg = (histogram[i] + histogram[i + 1]) / 2
    if (avg > 10 && diff < avg * 0.1) {
      pairsWithSimilarFreq++
    }
  }
  
  const pairsAnomaly = pairsWithSimilarFreq > 20
  if (pairsAnomaly) {
    anomalies.push(`${pairsWithSimilarFreq} value pairs with suspiciously similar frequencies`)
  }
  
  // Calculate LSB fluctuation
  let lsbFluctuation = 0
  for (let i = 0; i < 255; i += 2) {
    const ratio = histogram[i] > 0 ? histogram[i + 1] / histogram[i] : 0
    lsbFluctuation += Math.abs(1 - ratio)
  }
  lsbFluctuation /= 128
  
  const suspicious = anomalies.length > 0 || lsbFluctuation < 0.05
  
  return {
    suspicious,
    anomalies,
    histogramAnalysis: {
      pairsAnomaly,
      lsbFluctuation,
      evenOddImbalance
    }
  }
}

function performStatisticalAnalysis(imageData: ImageData): AdvancedSteganographyDetection['statisticalAnalysis'] {
  const data = imageData.data
  const pixelValues: number[] = []
  
  // Extract pixel values
  for (let i = 0; i < data.length; i += 4) {
    pixelValues.push(data[i], data[i + 1], data[i + 2]) // RGB values
  }
  
  const chiSquare = performChiSquareTest(pixelValues)
  const benford = analyzeBenfordLaw(pixelValues)
  const distribution = analyzePixelValueDistribution(pixelValues)
  
  return {
    chiSquareTest: chiSquare,
    benfordLaw: benford,
    pixelValueDistribution: distribution
  }
}

// Helper function to extract GPS data from EXIF
function extractGPSData(exifData: any): GPSData {
  const gps: GPSData = {}
  
  if (exifData.GPSLatitude && exifData.GPSLongitude) {
    const lat = parseGPSCoordinate(exifData.GPSLatitude, exifData.GPSLatitudeRef)
    const lon = parseGPSCoordinate(exifData.GPSLongitude, exifData.GPSLongitudeRef)
    
    if (lat !== null && lon !== null) {
      gps.coordinates = { latitude: lat, longitude: lon }
      gps.locationName = `${lat.toFixed(6)}, ${lon.toFixed(6)}`
    }
  }
  
  if (exifData.GPSAltitude) {
    gps.altitude = parseFloat(exifData.GPSAltitude)
  }
  
  if (exifData.GPSImgDirection) {
    gps.direction = parseFloat(exifData.GPSImgDirection)
  }
  
  if (exifData.GPSTimeStamp && exifData.GPSDateStamp) {
    try {
      gps.timestamp = new Date(`${exifData.GPSDateStamp} ${exifData.GPSTimeStamp}`)
    } catch (e) {
      // Invalid date format
    }
  }
  
  return gps
}

// Helper function to extract camera information from EXIF
function extractCameraInfo(exifData: any): CameraFingerprinting {
  const cameraSettings = {
    iso: exifData.ISO ? parseInt(exifData.ISO) : undefined,
    aperture: exifData.FNumber || exifData.ApertureValue,
    shutterSpeed: exifData.ExposureTime || exifData.ShutterSpeedValue,
    focalLength: exifData.FocalLength,
    flashUsed: exifData.Flash ? exifData.Flash !== 'No Flash' : undefined,
    whiteBalance: exifData.WhiteBalance,
    meteringMode: exifData.MeteringMode,
    exposureMode: exifData.ExposureMode
  }
  
  return {
    make: exifData.Make || 'Unknown',
    model: exifData.Model || 'Unknown',
    serialNumber: exifData.SerialNumber,
    firmwareVersion: exifData.Software,
    lensModel: exifData.LensModel || exifData.LensSpecification,
    cameraSettings
  }
}

function parseGPSCoordinate(coord: any, ref: string): number | null {
  if (!coord) return null
  
  // Simplified GPS coordinate parsing
  if (typeof coord === 'string') {
    const parts = coord.match(/(\d+)°(\d+)'([\d.]+)"?/)
    if (parts) {
      const degrees = parseInt(parts[1])
      const minutes = parseInt(parts[2])
      const seconds = parseFloat(parts[3])
      
      let decimal = degrees + minutes / 60 + seconds / 3600
      if (ref === 'S' || ref === 'W') decimal *= -1
      
      return decimal
    }
  }
  
  return null
}

// Helper Functions for Statistical Analysis
function simpleDCT(block: number[], blockSize: number): number[] {
  // Simplified 1D DCT implementation
  const dct: number[] = []
  const N = blockSize * blockSize
  
  for (let k = 0; k < N; k++) {
    let sum = 0
    for (let n = 0; n < N; n++) {
      sum += block[n] * Math.cos((Math.PI * k * (2 * n + 1)) / (2 * N))
    }
    dct.push(sum)
  }
  
  return dct
}

function calculateHistogram(values: number[], bins: number): number[] {
  const histogram = new Array(bins).fill(0)
  const min = Math.min(...values)
  const max = Math.max(...values)
  const binSize = (max - min) / bins
  
  values.forEach(value => {
    const bin = Math.min(Math.floor((value - min) / binSize), bins - 1)
    histogram[bin]++
  })
  
  return histogram
}

function calculateImageEntropy(histogram: number[]): number {
  const total = histogram.reduce((sum, count) => sum + count, 0)
  let entropy = 0
  
  histogram.forEach(count => {
    if (count > 0) {
      const p = count / total
      entropy -= p * Math.log2(p)
    }
  })
  
  return entropy
}

function detectDCTAnomalies(coeffs: number[], blockSize: number): Array<{ position: [number, number]; value: number; expected: number }> {
  const anomalies: Array<{ position: [number, number]; value: number; expected: number }> = []
  const threshold = 10 // Threshold for anomaly detection
  
  for (let i = 0; i < coeffs.length - 1; i++) {
    const diff = Math.abs(coeffs[i] - coeffs[i + 1])
    if (diff > threshold) {
      anomalies.push({
        position: [i % blockSize, Math.floor(i / blockSize)],
        value: coeffs[i],
        expected: coeffs[i + 1]
      })
    }
  }
  
  return anomalies
}

function estimateJPEGQuality(histogram: number[]): number {
  // Simplified JPEG quality estimation based on histogram spread
  const nonZeroBins = histogram.filter(bin => bin > 0).length
  return Math.max(1, Math.min(100, Math.round((nonZeroBins / histogram.length) * 100)))
}

function detectCompressionArtifacts(coeffs: number[]): boolean {
  // Simplified compression artifact detection
  const mean = coeffs.reduce((sum, val) => sum + val, 0) / coeffs.length
  const variance = coeffs.reduce((sum, val) => sum + Math.pow(val - mean, 2), 0) / coeffs.length
  return variance > 1000 // Threshold for detecting compression artifacts
}

function performChiSquareTest(values: number[]): { statistic: number; pValue: number; suspicious: boolean } {
  // Simplified chi-square test for randomness
  const observed = calculateHistogram(values, 256)
  const expected = values.length / 256
  
  let chiSquare = 0
  observed.forEach(obs => {
    chiSquare += Math.pow(obs - expected, 2) / expected
  })
  
  // Simplified p-value calculation (in reality would use proper chi-square distribution)
  const pValue = Math.exp(-chiSquare / 100)
  
  return {
    statistic: chiSquare,
    pValue,
    suspicious: pValue < 0.05
  }
}

function analyzeBenfordLaw(values: number[]): { conformity: number; suspicious: boolean } {
  const firstDigits = values
    .filter(v => v > 0)
    .map(v => parseInt(v.toString()[0]))
    .filter(d => d >= 1 && d <= 9)
  
  const observed = new Array(10).fill(0)
  firstDigits.forEach(digit => observed[digit]++)
  
  // Benford's law expected frequencies
  const benfordExpected = [0, 30.1, 17.6, 12.5, 9.7, 7.9, 6.7, 5.8, 5.1, 4.6]
  
  let deviation = 0
  for (let i = 1; i <= 9; i++) {
    const observedPercent = (observed[i] / firstDigits.length) * 100
    deviation += Math.abs(observedPercent - benfordExpected[i])
  }
  
  const conformity = Math.max(0, 100 - deviation)
  
  return {
    conformity,
    suspicious: conformity < 60 // Threshold for suspicious deviation from Benford's law
  }
}

function analyzePixelValueDistribution(values: number[]): { entropy: number; uniformity: number } {
  const histogram = calculateHistogram(values, 256)
  const entropy = calculateImageEntropy(histogram)
  const uniformity = 1 / histogram.reduce((sum, count) => sum + count * count, 0)
  
  return { entropy, uniformity }
}

// Enhanced file carving with actual file extraction
export interface CarvedFile {
  type: string
  offset: number
  size: number
  extension: string
  data?: Uint8Array
  dataUrl?: string
  hash?: string
}

export function carveFiles(data: Uint8Array, maxFiles: number = 10): CarvedFile[] {
  const files: CarvedFile[] = []
  
  // Comprehensive file signatures with headers and footers
  const signatures = [
    { 
      name: 'JPEG', 
      header: [0xFF, 0xD8, 0xFF], 
      footer: [0xFF, 0xD9],
      extension: '.jpg',
      mimeType: 'image/jpeg'
    },
    { 
      name: 'PNG', 
      header: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], 
      footer: [0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82],
      extension: '.png',
      mimeType: 'image/png'
    },
    { 
      name: 'GIF89a', 
      header: [0x47, 0x49, 0x46, 0x38, 0x39, 0x61], 
      footer: [0x00, 0x3B],
      extension: '.gif',
      mimeType: 'image/gif'
    },
    { 
      name: 'GIF87a', 
      header: [0x47, 0x49, 0x46, 0x38, 0x37, 0x61], 
      footer: [0x00, 0x3B],
      extension: '.gif',
      mimeType: 'image/gif'
    },
    { 
      name: 'BMP', 
      header: [0x42, 0x4D], 
      footer: null,
      extension: '.bmp',
      mimeType: 'image/bmp',
      sizeOffset: 2 // BMP stores size at offset 2
    },
    { 
      name: 'TIFF (LE)', 
      header: [0x49, 0x49, 0x2A, 0x00], 
      footer: null,
      extension: '.tif',
      mimeType: 'image/tiff'
    },
    { 
      name: 'TIFF (BE)', 
      header: [0x4D, 0x4D, 0x00, 0x2A], 
      footer: null,
      extension: '.tif',
      mimeType: 'image/tiff'
    },
    { 
      name: 'WebP', 
      header: [0x52, 0x49, 0x46, 0x46], 
      footer: null,
      extension: '.webp',
      mimeType: 'image/webp',
      validation: (d: Uint8Array, i: number) => {
        // Check for WEBP signature at offset 8
        return d[i + 8] === 0x57 && d[i + 9] === 0x45 && d[i + 10] === 0x42 && d[i + 11] === 0x50
      }
    },
    { 
      name: 'PDF', 
      header: [0x25, 0x50, 0x44, 0x46], 
      footer: [0x25, 0x25, 0x45, 0x4F, 0x46],
      extension: '.pdf',
      mimeType: 'application/pdf'
    },
    { 
      name: 'ZIP', 
      header: [0x50, 0x4B, 0x03, 0x04], 
      footer: [0x50, 0x4B, 0x05, 0x06],
      extension: '.zip',
      mimeType: 'application/zip'
    },
    { 
      name: 'RAR', 
      header: [0x52, 0x61, 0x72, 0x21, 0x1A, 0x07], 
      footer: null,
      extension: '.rar',
      mimeType: 'application/x-rar-compressed'
    },
    { 
      name: '7Z', 
      header: [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], 
      footer: null,
      extension: '.7z',
      mimeType: 'application/x-7z-compressed'
    },
    { 
      name: 'MP3', 
      header: [0xFF, 0xFB], 
      footer: null,
      extension: '.mp3',
      mimeType: 'audio/mpeg',
      validation: (d: Uint8Array, i: number) => {
        // ID3v2 tag check
        return (d[i] === 0xFF && (d[i + 1] & 0xE0) === 0xE0) || 
               (d[i] === 0x49 && d[i + 1] === 0x44 && d[i + 2] === 0x33)
      }
    },
    { 
      name: 'MP4', 
      header: [0x00, 0x00, 0x00], 
      footer: null,
      extension: '.mp4',
      mimeType: 'video/mp4',
      validation: (d: Uint8Array, i: number) => {
        // Check for ftyp box
        return d[i + 4] === 0x66 && d[i + 5] === 0x74 && d[i + 6] === 0x79 && d[i + 7] === 0x70
      }
    },
    { 
      name: 'AVI', 
      header: [0x52, 0x49, 0x46, 0x46], 
      footer: null,
      extension: '.avi',
      mimeType: 'video/x-msvideo',
      validation: (d: Uint8Array, i: number) => {
        // Check for AVI signature at offset 8
        return d[i + 8] === 0x41 && d[i + 9] === 0x56 && d[i + 10] === 0x49 && d[i + 11] === 0x20
      }
    }
  ]
  
  for (let i = 0; i < data.length - 20 && files.length < maxFiles; i++) {
    for (const sig of signatures) {
      // Check header match
      if (!sig.header.every((byte, index) => data[i + index] === byte)) {
        continue
      }
      
      // Additional validation if provided
      if (sig.validation && !sig.validation(data, i)) {
        continue
      }
      
      // Find file size
      let size = 0
      let fileData: Uint8Array | undefined
      let dataUrl: string | undefined
      
      if (sig.sizeOffset !== undefined && sig.name === 'BMP') {
        // BMP stores file size in header (little-endian)
        if (i + 5 < data.length) {
          size = data[i + 2] | (data[i + 3] << 8) | (data[i + 4] << 16) | (data[i + 5] << 24)
        }
      } else if (sig.footer) {
        // Search for footer
        const maxSearchSize = 10 * 1024 * 1024 // 10MB max
        for (let j = i + sig.header.length; j < Math.min(i + maxSearchSize, data.length - sig.footer.length); j++) {
          if (sig.footer.every((byte, index) => data[j + index] === byte)) {
            size = j - i + sig.footer.length
            break
          }
        }
      } else if (sig.name.startsWith('TIFF')) {
        // TIFF uses IFD structure, estimate reasonable size
        size = Math.min(data.length - i, 5 * 1024 * 1024) // 5MB max
      } else if (sig.name === 'WebP' || sig.name === 'AVI') {
        // RIFF format - size is in header
        if (i + 7 < data.length) {
          size = (data[i + 4] | (data[i + 5] << 8) | (data[i + 6] << 16) | (data[i + 7] << 24)) + 8
        }
      } else if (sig.name === 'MP4') {
        // MP4 - read atom size
        if (i + 3 < data.length) {
          size = (data[i] << 24) | (data[i + 1] << 16) | (data[i + 2] << 8) | data[i + 3]
        }
      } else {
        // Default: estimate size or extract reasonable chunk
        size = Math.min(data.length - i, 1024 * 1024) // 1MB default
      }
      
      // Validate size is reasonable
      if (size > 0 && size <= data.length - i) {
        // Extract the actual file data
        fileData = data.slice(i, i + size)
        
        // Create data URL for preview/download (only for smaller files)
        if (size < 5 * 1024 * 1024 && sig.mimeType) { // 5MB limit for data URLs
          const blob = new Blob([new Uint8Array(fileData)], { type: sig.mimeType })
          dataUrl = URL.createObjectURL(blob)
        }
        
        // Calculate simple hash for identification
        const hash = simpleHash(fileData)
        
        files.push({
          type: sig.name,
          offset: i,
          size,
          extension: sig.extension,
          data: fileData,
          dataUrl,
          hash
        })
        
        i += size - 1 // Skip ahead (minus 1 because loop will increment)
        break
      }
    }
  }
  
  return files
}

// Simple hash function for file identification
function simpleHash(data: Uint8Array): string {
  let hash = 0
  for (let i = 0; i < Math.min(data.length, 1024); i++) {
    hash = ((hash << 5) - hash) + data[i]
    hash = hash & hash // Convert to 32bit integer
  }
  return Math.abs(hash).toString(16).padStart(8, '0')
}
