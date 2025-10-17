// Folder Analysis Library
// Comprehensive folder scanning and file analysis for bulk operations

export interface FileEntry {
  id: string
  name: string
  path: string
  relativePath: string
  size: number
  type: string
  extension: string
  lastModified: Date
  isHidden: boolean
  file: File
  analyzed: boolean
  analysisResult?: FileAnalysisResult
}

export interface FileAnalysisResult {
  isEmpty: boolean
  hasStrings: boolean
  stringCount: number
  entropy: number
  hash: {
    md5?: string
    sha256?: string
  }
  magicBytes: string
  detectedType: string
  printableStrings: string[]
  utf16DecodedStrings?: string[] // UTF-16 endianness-fixed strings
  hasUtf16EncodingIssue?: boolean // True if CJK/rare Unicode detected and fixed
  interestingPatterns: {
    urls: string[]
    emails: string[]
    ips: string[]
    base64: string[]
    hexStrings: string[]
  }
  hexDump?: string // Hex dump of first 1KB for binary files
  rawPreview?: string // Raw bytes preview
  metadata?: Record<string, any>
}

export interface FolderScanResult {
  totalFiles: number
  totalSize: number
  scannedFiles: number
  fileTypes: Record<string, number>
  hiddenFileCount: number
  emptyFileCount: number
  files: FileEntry[]
  scanDuration: number
}

export interface FilterOptions {
  minSize?: number
  maxSize?: number
  extensions?: string[]
  excludeExtensions?: string[]
  hasContent?: boolean // true = only non-empty, false = only empty, undefined = all
  hasStrings?: boolean
  searchTerm?: string
  searchCaseSensitive?: boolean
  searchRegex?: boolean
  minEntropy?: number
  maxEntropy?: number
  fileType?: string
  showHidden?: boolean
}

export type MetadataFormat =
  | 'uint-le'      // Unsigned Integer Little Endian
  | 'uint-be'      // Unsigned Integer Big Endian
  | 'int-le'       // Signed Integer Little Endian
  | 'int-be'       // Signed Integer Big Endian
  | 'filetime'     // Windows FILETIME (64-bit)
  | 'unix32'       // Unix Timestamp 32-bit
  | 'unix64'       // Unix Timestamp 64-bit
  | 'ascii'        // ASCII String
  | 'hex'          // Raw Bytes (hex comparison)

export interface MetadataSortConfig {
  enabled: boolean
  startByte: number
  length: number
  format: MetadataFormat
  ascending: boolean
}

export interface ByteExtractionConfig {
  enabled: boolean
  filenamePattern: string
  bytePositions: string // "8" or "8,16,24" or "8-12"
  sortBy: 'name' | 'name-reverse' | 'natural' | 'modified' | 'modified-reverse' | 'created' | 'size' | 'size-reverse' | 'metadata'
  metadataSort?: MetadataSortConfig
  hideNullBytes?: boolean // Hide null bytes (0x00 / ASCII 0) from results
  onlyPrintable?: boolean // Only extract printable ASCII characters (32-126)
}

export interface ByteExtractionResult {
  filename: string
  relativePath: string
  position: number
  char: string
  hex: string
  ascii: number
}

export interface CombinedExtractionResult {
  combinedString: string
  details: ByteExtractionResult[]
  filesProcessed: number
}

// Scan entire folder recursively
export async function scanFolder(files: FileList | File[]): Promise<FolderScanResult> {
  const startTime = performance.now()
  const fileArray = Array.from(files)

  const entries: FileEntry[] = []
  const fileTypes: Record<string, number> = {}
  let totalSize = 0
  let hiddenCount = 0
  let emptyCount = 0

  for (const file of fileArray) {
    const relativePath = (file as any).webkitRelativePath || file.name
    const pathParts = relativePath.split('/')
    const fileName = pathParts[pathParts.length - 1]

    // Detect hidden files (start with . or in hidden directory)
    const isHidden = fileName.startsWith('.') || pathParts.some(part => part.startsWith('.'))

    // Get extension
    const extension = fileName.includes('.')
      ? fileName.substring(fileName.lastIndexOf('.')).toLowerCase()
      : ''

    // Count file types
    const fileType = extension || 'no extension'
    fileTypes[fileType] = (fileTypes[fileType] || 0) + 1

    // Track empty files
    if (file.size === 0) {
      emptyCount++
    }

    if (isHidden) {
      hiddenCount++
    }

    totalSize += file.size

    const entry: FileEntry = {
      id: `${relativePath}-${file.size}-${file.lastModified}`,
      name: fileName,
      path: relativePath,
      relativePath,
      size: file.size,
      type: file.type || 'application/octet-stream',
      extension,
      lastModified: new Date(file.lastModified),
      isHidden,
      file,
      analyzed: false
    }

    entries.push(entry)
  }

  const endTime = performance.now()

  return {
    totalFiles: entries.length,
    totalSize,
    scannedFiles: 0,
    fileTypes,
    hiddenFileCount: hiddenCount,
    emptyFileCount: emptyCount,
    files: entries,
    scanDuration: endTime - startTime
  }
}

// Analyze individual file in depth
export async function analyzeFile(entry: FileEntry): Promise<FileAnalysisResult> {
  const buffer = await entry.file.arrayBuffer()
  const bytes = new Uint8Array(buffer)

  // Check if empty
  const isEmpty = entry.size === 0

  // Get magic bytes (first 16 bytes)
  const magicBytes = Array.from(bytes.slice(0, 16))
    .map(b => b.toString(16).padStart(2, '0'))
    .join(' ')

  // Detect file type from magic bytes
  const detectedType = detectFileType(bytes)

  // Calculate entropy
  const entropy = calculateEntropy(bytes)

  // Extract strings
  const strings = extractStrings(buffer)
  const hasStrings = strings.length > 0

  // Detect UTF-16 encoding issues and fix if needed
  const hasUtf16Issue = detectUtf16EncodingIssue(strings)
  const utf16DecodedStrings = hasUtf16Issue ? fixUtf16Encoding(strings) : undefined

  // Find interesting patterns (search in both raw and decoded strings)
  const allStringsForPatterns = hasUtf16Issue && utf16DecodedStrings
    ? [...strings, ...utf16DecodedStrings].join(' ')
    : strings.join(' ')
  const patterns = extractPatterns(allStringsForPatterns)

  // Calculate hashes (for small files only, < 10MB)
  const hashes: { md5?: string; sha256?: string } = {}
  if (entry.size < 10 * 1024 * 1024) {
    hashes.sha256 = await calculateSHA256(buffer)
  }

  // Generate hex dump for first 1KB (useful for binary files)
  const hexDump = generateHexDump(bytes, 1024)

  // Generate raw preview (first 512 bytes as hex)
  const rawPreview = Array.from(bytes.slice(0, 512))
    .map(b => b.toString(16).padStart(2, '0'))
    .join(' ')

  return {
    isEmpty,
    hasStrings,
    stringCount: strings.length,
    entropy,
    hash: hashes,
    magicBytes,
    detectedType,
    printableStrings: strings.slice(0, 100), // Limit to first 100 strings
    utf16DecodedStrings: utf16DecodedStrings ? utf16DecodedStrings.slice(0, 100) : undefined,
    hasUtf16EncodingIssue: hasUtf16Issue,
    interestingPatterns: patterns,
    hexDump,
    rawPreview,
    metadata: {}
  }
}

// Batch analyze multiple files with progress callback
export async function batchAnalyzeFiles(
  entries: FileEntry[],
  onProgress?: (current: number, total: number) => void
): Promise<FileEntry[]> {
  const analyzed: FileEntry[] = []

  for (let i = 0; i < entries.length; i++) {
    try {
      const result = await analyzeFile(entries[i])
      analyzed.push({
        ...entries[i],
        analyzed: true,
        analysisResult: result
      })
    } catch (error) {
      // If analysis fails, mark as analyzed but with minimal result
      analyzed.push({
        ...entries[i],
        analyzed: true,
        analysisResult: {
          isEmpty: entries[i].size === 0,
          hasStrings: false,
          stringCount: 0,
          entropy: 0,
          hash: {},
          magicBytes: '',
          detectedType: 'unknown',
          printableStrings: [],
          interestingPatterns: {
            urls: [],
            emails: [],
            ips: [],
            base64: [],
            hexStrings: []
          }
        }
      })
    }

    if (onProgress) {
      onProgress(i + 1, entries.length)
    }
  }

  return analyzed
}

// Filter files based on criteria
export function filterFiles(files: FileEntry[], options: FilterOptions): FileEntry[] {
  let filtered = [...files]

  // Size filters
  if (options.minSize !== undefined) {
    filtered = filtered.filter(f => f.size >= options.minSize!)
  }
  if (options.maxSize !== undefined) {
    filtered = filtered.filter(f => f.size <= options.maxSize!)
  }

  // Extension filters
  if (options.extensions && options.extensions.length > 0) {
    filtered = filtered.filter(f => options.extensions!.includes(f.extension))
  }
  if (options.excludeExtensions && options.excludeExtensions.length > 0) {
    filtered = filtered.filter(f => !options.excludeExtensions!.includes(f.extension))
  }

  // Hidden files
  if (options.showHidden === false) {
    filtered = filtered.filter(f => !f.isHidden)
  }

  // Content filters (requires analysis)
  if (options.hasContent !== undefined) {
    filtered = filtered.filter(f => {
      if (!f.analyzed || !f.analysisResult) return true
      return options.hasContent ? !f.analysisResult.isEmpty : f.analysisResult.isEmpty
    })
  }

  if (options.hasStrings !== undefined) {
    filtered = filtered.filter(f => {
      if (!f.analyzed || !f.analysisResult) return true
      return f.analysisResult.hasStrings === options.hasStrings
    })
  }

  // Entropy filters
  if (options.minEntropy !== undefined) {
    filtered = filtered.filter(f => {
      if (!f.analyzed || !f.analysisResult) return true
      return f.analysisResult.entropy >= options.minEntropy!
    })
  }
  if (options.maxEntropy !== undefined) {
    filtered = filtered.filter(f => {
      if (!f.analyzed || !f.analysisResult) return true
      return f.analysisResult.entropy <= options.maxEntropy!
    })
  }

  // Search term (in filename or content)
  if (options.searchTerm && options.searchTerm.trim()) {
    const term = options.searchCaseSensitive
      ? options.searchTerm
      : options.searchTerm.toLowerCase()

    if (options.searchRegex) {
      try {
        const regex = new RegExp(term, options.searchCaseSensitive ? '' : 'i')
        filtered = filtered.filter(f => {
          // Search in filename and path
          if (regex.test(f.name) || regex.test(f.relativePath)) return true

          // Search in content strings (only for analyzed files)
          if (f.analyzed && f.analysisResult && f.analysisResult.printableStrings.length > 0) {
            // Search in raw strings
            if (f.analysisResult.printableStrings.some(s => regex.test(s))) return true

            // Search in UTF-16 decoded strings if available
            if (f.analysisResult.utf16DecodedStrings && f.analysisResult.utf16DecodedStrings.length > 0) {
              return f.analysisResult.utf16DecodedStrings.some(s => regex.test(s))
            }
          }
          return false
        })
      } catch (e) {
        // Invalid regex - log error and fall back to string search
        console.warn('Invalid regex pattern:', term, e)
        filtered = filtered.filter(f => {
          const fileName = options.searchCaseSensitive ? f.name : f.name.toLowerCase()
          const filePath = options.searchCaseSensitive ? f.relativePath : f.relativePath.toLowerCase()
          if (fileName.includes(term) || filePath.includes(term)) return true

          if (f.analyzed && f.analysisResult && f.analysisResult.printableStrings.length > 0) {
            // Search in raw strings
            const foundInRaw = f.analysisResult.printableStrings.some(s => {
              const str = options.searchCaseSensitive ? s : s.toLowerCase()
              return str.includes(term)
            })
            if (foundInRaw) return true

            // Search in UTF-16 decoded strings if available
            if (f.analysisResult.utf16DecodedStrings && f.analysisResult.utf16DecodedStrings.length > 0) {
              return f.analysisResult.utf16DecodedStrings.some(s => {
                const str = options.searchCaseSensitive ? s : s.toLowerCase()
                return str.includes(term)
              })
            }
          }
          return false
        })
      }
    } else {
      // Simple string search
      filtered = filtered.filter(f => {
        const fileName = options.searchCaseSensitive ? f.name : f.name.toLowerCase()
        const filePath = options.searchCaseSensitive ? f.relativePath : f.relativePath.toLowerCase()
        if (fileName.includes(term) || filePath.includes(term)) return true

        // Search in content strings (only for analyzed files)
        if (f.analyzed && f.analysisResult && f.analysisResult.printableStrings.length > 0) {
          // Search in raw strings
          const foundInRaw = f.analysisResult.printableStrings.some(s => {
            const str = options.searchCaseSensitive ? s : s.toLowerCase()
            return str.includes(term)
          })
          if (foundInRaw) return true

          // Search in UTF-16 decoded strings if available
          if (f.analysisResult.utf16DecodedStrings && f.analysisResult.utf16DecodedStrings.length > 0) {
            return f.analysisResult.utf16DecodedStrings.some(s => {
              const str = options.searchCaseSensitive ? s : s.toLowerCase()
              return str.includes(term)
            })
          }
        }
        return false
      })
    }
  }

  return filtered
}

// Export results to JSON
export function exportToJSON(files: FileEntry[]): string {
  const exportData = files.map(f => ({
    name: f.name,
    path: f.relativePath,
    size: f.size,
    type: f.type,
    extension: f.extension,
    isHidden: f.isHidden,
    lastModified: f.lastModified.toISOString(),
    analysis: f.analysisResult ? {
      isEmpty: f.analysisResult.isEmpty,
      hasStrings: f.analysisResult.hasStrings,
      stringCount: f.analysisResult.stringCount,
      entropy: f.analysisResult.entropy,
      detectedType: f.analysisResult.detectedType,
      hash: f.analysisResult.hash,
      interestingPatterns: f.analysisResult.interestingPatterns
    } : null
  }))

  return JSON.stringify(exportData, null, 2)
}

// Export results to CSV
export function exportToCSV(files: FileEntry[]): string {
  const headers = [
    'Name',
    'Path',
    'Size',
    'Type',
    'Extension',
    'Hidden',
    'Last Modified',
    'Is Empty',
    'Has Strings',
    'String Count',
    'Entropy',
    'SHA256'
  ]

  const rows = files.map(f => [
    f.name,
    f.relativePath,
    f.size.toString(),
    f.type,
    f.extension,
    f.isHidden ? 'Yes' : 'No',
    f.lastModified.toISOString(),
    f.analysisResult ? (f.analysisResult.isEmpty ? 'Yes' : 'No') : 'N/A',
    f.analysisResult ? (f.analysisResult.hasStrings ? 'Yes' : 'No') : 'N/A',
    f.analysisResult ? f.analysisResult.stringCount.toString() : 'N/A',
    f.analysisResult ? f.analysisResult.entropy.toFixed(2) : 'N/A',
    f.analysisResult?.hash.sha256 || 'N/A'
  ])

  const csvContent = [
    headers.join(','),
    ...rows.map(row => row.map(cell => `"${cell}"`).join(','))
  ].join('\n')

  return csvContent
}

// Helper: Extract printable strings from buffer
function extractStrings(buffer: ArrayBuffer, minLength = 4): string[] {
  const bytes = new Uint8Array(buffer)
  const allStrings: Set<string> = new Set()

  // Limit processing to first 5MB for large files to prevent memory issues
  const maxBytesToProcess = 5 * 1024 * 1024 // 5MB
  const bytesToProcess = bytes.length > maxBytesToProcess
    ? bytes.slice(0, maxBytesToProcess)
    : bytes

  // Extract ASCII strings (original method)
  const asciiStrings = extractASCIIStrings(bytesToProcess, minLength)
  asciiStrings.forEach(s => allStrings.add(s))

  // Extract UTF-8 strings
  const utf8Strings = extractUTF8Strings(bytesToProcess, minLength)
  utf8Strings.forEach(s => allStrings.add(s))

  // Extract UTF-16 LE strings (Windows binaries)
  const utf16LEStrings = extractUTF16LEStrings(bytesToProcess, minLength)
  utf16LEStrings.forEach(s => allStrings.add(s))

  // Extract UTF-16 BE strings
  const utf16BEStrings = extractUTF16BEStrings(bytesToProcess, minLength)
  utf16BEStrings.forEach(s => allStrings.add(s))

  // Limit total strings returned to prevent UI performance issues
  const stringArray = Array.from(allStrings)
  return stringArray.length > 5000 ? stringArray.slice(0, 5000) : stringArray
}

// Extract ASCII printable strings
function extractASCIIStrings(bytes: Uint8Array, minLength = 4): string[] {
  const strings: string[] = []
  let current: number[] = []

  for (let i = 0; i < bytes.length; i++) {
    const byte = bytes[i]
    if (byte >= 32 && byte <= 126) {
      current.push(byte)
    } else {
      if (current.length >= minLength) {
        strings.push(String.fromCharCode(...current))
      }
      current = []
    }
  }

  if (current.length >= minLength) {
    strings.push(String.fromCharCode(...current))
  }

  return strings
}

// Extract UTF-8 strings
function extractUTF8Strings(bytes: Uint8Array, minLength = 4): string[] {
  const strings: string[] = []
  const decoder = new TextDecoder('utf-8', { fatal: false })

  // Try to decode the entire buffer as UTF-8
  try {
    const fullText = decoder.decode(bytes)
    // Split on non-printable characters and filter by length
    const parts = fullText.split(/[\x00-\x1F\x7F-\x9F]+/)
    for (const part of parts) {
      const trimmed = part.trim()
      if (trimmed.length >= minLength) {
        strings.push(trimmed)
      }
    }
  } catch (e) {
    // Ignore decoding errors
  }

  return strings
}

// Extract UTF-16 Little Endian strings (common in Windows)
function extractUTF16LEStrings(bytes: Uint8Array, minLength = 4): string[] {
  const strings: string[] = []
  let current: number[] = []

  for (let i = 0; i < bytes.length - 1; i += 2) {
    const char = bytes[i] | (bytes[i + 1] << 8)

    // Check if it's a printable character
    if ((char >= 32 && char <= 126) || (char >= 0xA0 && char <= 0xFFFF)) {
      current.push(char)
    } else if (char === 0) {
      // Null terminator
      if (current.length >= minLength) {
        try {
          strings.push(String.fromCharCode(...current))
        } catch (e) {
          // Skip invalid sequences
        }
      }
      current = []
    } else {
      if (current.length >= minLength) {
        try {
          strings.push(String.fromCharCode(...current))
        } catch (e) {
          // Skip invalid sequences
        }
      }
      current = []
    }
  }

  if (current.length >= minLength) {
    try {
      strings.push(String.fromCharCode(...current))
    } catch (e) {
      // Skip invalid sequences
    }
  }

  return strings
}

// Extract UTF-16 Big Endian strings
function extractUTF16BEStrings(bytes: Uint8Array, minLength = 4): string[] {
  const strings: string[] = []
  let current: number[] = []

  for (let i = 0; i < bytes.length - 1; i += 2) {
    const char = (bytes[i] << 8) | bytes[i + 1]

    // Check if it's a printable character
    if ((char >= 32 && char <= 126) || (char >= 0xA0 && char <= 0xFFFF)) {
      current.push(char)
    } else if (char === 0) {
      // Null terminator
      if (current.length >= minLength) {
        try {
          strings.push(String.fromCharCode(...current))
        } catch (e) {
          // Skip invalid sequences
        }
      }
      current = []
    } else {
      if (current.length >= minLength) {
        try {
          strings.push(String.fromCharCode(...current))
        } catch (e) {
          // Skip invalid sequences
        }
      }
      current = []
    }
  }

  if (current.length >= minLength) {
    try {
      strings.push(String.fromCharCode(...current))
    } catch (e) {
      // Skip invalid sequences
    }
  }

  return strings
}

// Helper: Extract interesting patterns from strings
function extractPatterns(text: string): FileAnalysisResult['interestingPatterns'] {
  // Limit text length to prevent ReDoS attacks
  const maxLength = 100000
  const safeText = text.length > maxLength ? text.substring(0, maxLength) : text

  return {
    urls: [...new Set(safeText.match(/https?:\/\/[^\s<>"']{4,200}?/g) || [])],
    emails: [...new Set(safeText.match(/[a-zA-Z0-9._%+-]+?@[a-zA-Z0-9.-]+?\.[a-zA-Z]{2,10}/g) || [])],
    ips: [...new Set(safeText.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g) || [])],
    base64: [...new Set(safeText.match(/[A-Za-z0-9+/]{20,100}?={0,2}/g) || [])].slice(0, 10),
    hexStrings: [...new Set(safeText.match(/0x[a-fA-F0-9]{8,20}?/g) || [])].slice(0, 10)
  }
}

// Helper: Calculate Shannon entropy
function calculateEntropy(bytes: Uint8Array): number {
  if (bytes.length === 0) return 0

  const frequencies: Record<number, number> = {}
  for (const byte of bytes) {
    frequencies[byte] = (frequencies[byte] || 0) + 1
  }

  let entropy = 0
  const len = bytes.length

  for (const count of Object.values(frequencies)) {
    const probability = count / len
    entropy -= probability * Math.log2(probability)
  }

  return entropy
}

// Helper: Detect file type from magic bytes
function detectFileType(bytes: Uint8Array): string {
  const signatures: { type: string; magic: number[] }[] = [
    { type: 'PNG', magic: [0x89, 0x50, 0x4E, 0x47] },
    { type: 'JPEG', magic: [0xFF, 0xD8, 0xFF] },
    { type: 'GIF', magic: [0x47, 0x49, 0x46, 0x38] },
    { type: 'PDF', magic: [0x25, 0x50, 0x44, 0x46] },
    { type: 'ZIP', magic: [0x50, 0x4B, 0x03, 0x04] },
    { type: 'RAR', magic: [0x52, 0x61, 0x72, 0x21] },
    { type: 'GZIP', magic: [0x1F, 0x8B] },
    { type: 'BMP', magic: [0x42, 0x4D] },
    { type: '7Z', magic: [0x37, 0x7A, 0xBC, 0xAF] },
    { type: 'EXE', magic: [0x4D, 0x5A] },
    { type: 'ELF', magic: [0x7F, 0x45, 0x4C, 0x46] },
    { type: 'PCAP', magic: [0xD4, 0xC3, 0xB2, 0xA1] },
    { type: 'PCAPNG', magic: [0x0A, 0x0D, 0x0D, 0x0A] }
  ]

  for (const sig of signatures) {
    if (sig.magic.every((byte, idx) => bytes[idx] === byte)) {
      return sig.type
    }
  }

  return 'unknown'
}

// Helper: Calculate SHA-256 hash
async function calculateSHA256(buffer: ArrayBuffer): Promise<string> {
  try {
    const hashBuffer = await crypto.subtle.digest('SHA-256', buffer)
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
  } catch (e) {
    return ''
  }
}

// Format file size for display
export function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`
}

// Get color for entropy value (for visualization)
export function getEntropyColor(entropy: number): string {
  if (entropy < 1) return 'text-gray-400' // Very low entropy
  if (entropy < 4) return 'text-green-400' // Low entropy (plaintext)
  if (entropy < 6) return 'text-yellow-400' // Medium entropy
  if (entropy < 7.5) return 'text-orange-400' // High entropy (compressed)
  return 'text-red-400' // Very high entropy (encrypted)
}

// Fix UTF-16 endianness issues (extract high byte from misencoded characters)
function fixUtf16Encoding(strings: string[]): string[] {
  const decoded: string[] = []

  for (const text of strings) {
    let decodedStr = ''
    let hasChanges = false

    for (let i = 0; i < text.length; i++) {
      const code = text.charCodeAt(i)

      // If character is in CJK/rare Unicode range (U+3000-U+FFFF), extract high byte
      if (code >= 0x3000 && code <= 0xFFFF) {
        const highByte = (code >> 8) & 0xFF

        // Check if high byte is printable ASCII
        if (highByte >= 0x20 && highByte <= 0x7E) {
          decodedStr += String.fromCharCode(highByte)
          hasChanges = true
          continue
        }
      }

      // Otherwise keep original character
      decodedStr += text[i]
    }

    // Only add if it was actually decoded and different
    if (hasChanges && decodedStr !== text) {
      decoded.push(decodedStr)
    }
  }

  return decoded
}

// Detect if strings have UTF-16 encoding issues (high ratio of CJK/rare Unicode)
function detectUtf16EncodingIssue(strings: string[]): boolean {
  if (strings.length === 0) return false

  let totalChars = 0
  let cjkRareChars = 0

  for (const str of strings) {
    for (let i = 0; i < str.length; i++) {
      const code = str.charCodeAt(i)
      totalChars++

      // Count CJK/rare Unicode characters
      if (code >= 0x3000 && code <= 0xFFFF) {
        cjkRareChars++
      }
    }
  }

  // If more than 30% of characters are CJK/rare Unicode, likely encoding issue
  const ratio = totalChars > 0 ? cjkRareChars / totalChars : 0
  return ratio > 0.3
}

// Natural sort comparator (handles numbers in strings correctly)
function naturalSort(a: string, b: string): number {
  const regex = /(\d+)|(\D+)/g
  const aParts = a.match(regex) || []
  const bParts = b.match(regex) || []

  for (let i = 0; i < Math.max(aParts.length, bParts.length); i++) {
    const aPart = aParts[i] || ''
    const bPart = bParts[i] || ''

    // If both are numbers, compare numerically
    if (/^\d+$/.test(aPart) && /^\d+$/.test(bPart)) {
      const diff = parseInt(aPart, 10) - parseInt(bPart, 10)
      if (diff !== 0) return diff
    } else {
      // Otherwise compare as strings
      const diff = aPart.localeCompare(bPart)
      if (diff !== 0) return diff
    }
  }

  return 0
}

// Parse metadata value from bytes
function parseMetadata(bytes: Uint8Array, config: MetadataSortConfig): number | string {
  const { startByte, length, format } = config

  // Extract bytes
  if (startByte + length > bytes.length) {
    return 0 // Return default if out of bounds
  }

  const slice = bytes.slice(startByte, startByte + length)

  switch (format) {
    case 'uint-le': {
      // Unsigned integer little endian
      let value = 0
      for (let i = 0; i < slice.length; i++) {
        value += slice[i] << (i * 8)
      }
      return value >>> 0 // Ensure unsigned
    }

    case 'uint-be': {
      // Unsigned integer big endian
      let value = 0
      for (let i = 0; i < slice.length; i++) {
        value = (value << 8) + slice[i]
      }
      return value >>> 0
    }

    case 'int-le': {
      // Signed integer little endian
      let value = 0
      for (let i = 0; i < slice.length; i++) {
        value += slice[i] << (i * 8)
      }
      // Sign extend if negative
      const bits = slice.length * 8
      const signBit = 1 << (bits - 1)
      if (value & signBit) {
        value = value - (1 << bits)
      }
      return value
    }

    case 'int-be': {
      // Signed integer big endian
      let value = 0
      for (let i = 0; i < slice.length; i++) {
        value = (value << 8) + slice[i]
      }
      const bits = slice.length * 8
      const signBit = 1 << (bits - 1)
      if (value & signBit) {
        value = value - (1 << bits)
      }
      return value
    }

    case 'filetime': {
      // Windows FILETIME (64-bit): 100-nanosecond intervals since 1601-01-01
      if (slice.length !== 8) return 0

      const low = slice[0] + (slice[1] << 8) + (slice[2] << 16) + (slice[3] << 24)
      const high = slice[4] + (slice[5] << 8) + (slice[6] << 16) + (slice[7] << 24)

      // Convert to JavaScript timestamp (milliseconds since 1970-01-01)
      const filetime = (high * 0x100000000 + low) / 10000
      const unixEpoch = 11644473600000 // Milliseconds between 1601 and 1970
      return filetime - unixEpoch
    }

    case 'unix32': {
      // Unix timestamp 32-bit (seconds since 1970-01-01)
      if (slice.length !== 4) return 0

      const timestamp = slice[0] + (slice[1] << 8) + (slice[2] << 16) + (slice[3] << 24)
      return timestamp * 1000 // Convert to milliseconds
    }

    case 'unix64': {
      // Unix timestamp 64-bit (milliseconds since 1970-01-01)
      if (slice.length !== 8) return 0

      const low = slice[0] + (slice[1] << 8) + (slice[2] << 16) + (slice[3] << 24)
      const high = slice[4] + (slice[5] << 8) + (slice[6] << 16) + (slice[7] << 24)

      return high * 0x100000000 + low
    }

    case 'ascii': {
      // ASCII string
      return String.fromCharCode(...slice.filter(b => b >= 32 && b <= 126))
    }

    case 'hex': {
      // Raw hex comparison
      return Array.from(slice).map(b => b.toString(16).padStart(2, '0')).join('')
    }

    default:
      return 0
  }
}

// Parse byte positions string into array of positions
function parseBytePositions(positionsStr: string): number[] {
  const positions: number[] = []

  // Split by comma for multiple positions
  const parts = positionsStr.split(',').map(p => p.trim())

  for (const part of parts) {
    if (part.includes('-')) {
      // Range: "8-12"
      const [start, end] = part.split('-').map(n => parseInt(n.trim(), 10))
      if (!isNaN(start) && !isNaN(end)) {
        for (let i = start; i <= end; i++) {
          positions.push(i)
        }
      }
    } else {
      // Single position: "8"
      const pos = parseInt(part, 10)
      if (!isNaN(pos)) {
        positions.push(pos)
      }
    }
  }

  return positions
}

// Extract bytes from files matching pattern
export async function extractBytesFromFiles(
  files: FileEntry[],
  config: ByteExtractionConfig
): Promise<CombinedExtractionResult> {
  if (!config.enabled || !config.filenamePattern.trim()) {
    return {
      combinedString: '',
      details: [],
      filesProcessed: 0
    }
  }

  // Parse byte positions
  const positions = parseBytePositions(config.bytePositions)
  if (positions.length === 0) {
    return {
      combinedString: '',
      details: [],
      filesProcessed: 0
    }
  }

  // Filter files by pattern (support wildcards and regex)
  let pattern: RegExp
  try {
    // Escape all special regex characters except * and ?
    // Then convert wildcards to regex
    const regexPattern = config.filenamePattern
      .replace(/[.+^${}()|[\]\\]/g, '\\$&')  // Escape special regex chars including $
      .replace(/\*/g, '.*')   // Convert * to .*
      .replace(/\?/g, '.')    // Convert ? to .

    console.log('Original pattern:', config.filenamePattern)
    console.log('Converted regex:', regexPattern)

    pattern = new RegExp(regexPattern, 'i')
  } catch (e) {
    // Invalid pattern
    console.error('Pattern conversion error:', e)
    return {
      combinedString: '',
      details: [],
      filesProcessed: 0
    }
  }

  // Filter matching files
  const matchingFiles = files.filter(f => pattern.test(f.name))

  // For metadata sorting, need to read files and extract metadata values
  const filesWithMetadata: Array<{ file: FileEntry; metadataValue: number | string }> = []

  if (config.sortBy === 'metadata' && config.metadataSort?.enabled) {
    for (const file of matchingFiles) {
      try {
        const buffer = await file.file.arrayBuffer()
        const bytes = new Uint8Array(buffer)
        const metadataValue = parseMetadata(bytes, config.metadataSort)
        filesWithMetadata.push({ file, metadataValue })
      } catch (error) {
        console.error('Error reading file for metadata sort:', file.name, error)
        filesWithMetadata.push({ file, metadataValue: 0 })
      }
    }
  }

  // Sort files based on config
  const sortedFiles = config.sortBy === 'metadata' && config.metadataSort?.enabled
    ? filesWithMetadata.sort((a, b) => {
        const aVal = a.metadataValue
        const bVal = b.metadataValue

        if (typeof aVal === 'number' && typeof bVal === 'number') {
          return config.metadataSort!.ascending ? aVal - bVal : bVal - aVal
        } else {
          const compareResult = String(aVal).localeCompare(String(bVal))
          return config.metadataSort!.ascending ? compareResult : -compareResult
        }
      }).map(item => item.file)
    : [...matchingFiles].sort((a, b) => {
        switch (config.sortBy) {
          case 'name':
            return a.name.localeCompare(b.name)
          case 'name-reverse':
            return b.name.localeCompare(a.name)
          case 'natural':
            return naturalSort(a.name, b.name)
          case 'modified':
            return a.lastModified.getTime() - b.lastModified.getTime()
          case 'modified-reverse':
            return b.lastModified.getTime() - a.lastModified.getTime()
          case 'created':
            // Use lastModified as fallback (created date not always available in browser)
            return a.lastModified.getTime() - b.lastModified.getTime()
          case 'size':
            return a.size - b.size
          case 'size-reverse':
            return b.size - a.size
          default:
            return 0
        }
      })

  // Extract bytes from each file
  const results: ByteExtractionResult[] = []
  let combinedString = ''

  for (const file of sortedFiles) {
    try {
      const buffer = await file.file.arrayBuffer()
      const bytes = new Uint8Array(buffer)

      for (const pos of positions) {
        if (pos < bytes.length) {
          const byte = bytes[pos]

          // Skip null bytes if hideNullBytes option is enabled
          if (config.hideNullBytes && byte === 0) {
            continue
          }

          // Skip non-printable characters if onlyPrintable option is enabled
          if (config.onlyPrintable && (byte < 32 || byte > 126)) {
            continue
          }

          const char = byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.'
          const hex = byte.toString(16).padStart(2, '0').toUpperCase()

          results.push({
            filename: file.name,
            relativePath: file.relativePath,
            position: pos,
            char,
            hex,
            ascii: byte
          })

          combinedString += char
        }
      }
    } catch (error) {
      console.error('Error extracting bytes from file:', file.name, error)
    }
  }

  return {
    combinedString,
    details: results,
    filesProcessed: sortedFiles.length
  }
}

// Generate formatted hex dump with ASCII sidebar
function generateHexDump(bytes: Uint8Array, maxBytes = 1024): string {
  const lines: string[] = []
  const limit = Math.min(bytes.length, maxBytes)

  for (let i = 0; i < limit; i += 16) {
    // Offset
    const offset = i.toString(16).padStart(8, '0')

    // Hex bytes
    const hexPart: string[] = []
    const asciiPart: string[] = []

    for (let j = 0; j < 16; j++) {
      if (i + j < limit) {
        const byte = bytes[i + j]
        hexPart.push(byte.toString(16).padStart(2, '0'))

        // ASCII representation
        if (byte >= 32 && byte <= 126) {
          asciiPart.push(String.fromCharCode(byte))
        } else {
          asciiPart.push('.')
        }
      } else {
        hexPart.push('  ')
        asciiPart.push(' ')
      }
    }

    // Format: offset | hex bytes | ASCII
    const hexStr = hexPart.join(' ')
    const asciiStr = asciiPart.join('')
    lines.push(`${offset}  ${hexStr}  |${asciiStr}|`)
  }

  return lines.join('\n')
}
