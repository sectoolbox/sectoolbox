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
  interestingPatterns: {
    urls: string[]
    emails: string[]
    ips: string[]
    base64: string[]
    hexStrings: string[]
  }
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

  // Find interesting patterns
  const patterns = extractPatterns(strings.join(' '))

  // Calculate hashes (for small files only, < 10MB)
  const hashes: { md5?: string; sha256?: string } = {}
  if (entry.size < 10 * 1024 * 1024) {
    hashes.sha256 = await calculateSHA256(buffer)
  }

  return {
    isEmpty,
    hasStrings,
    stringCount: strings.length,
    entropy,
    hash: hashes,
    magicBytes,
    detectedType,
    printableStrings: strings.slice(0, 100), // Limit to first 100 strings
    interestingPatterns: patterns,
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
          // Search in filename
          if (regex.test(f.name)) return true

          // Search in content strings
          if (f.analyzed && f.analysisResult) {
            return f.analysisResult.printableStrings.some(s => regex.test(s))
          }
          return false
        })
      } catch (e) {
        // Invalid regex, fall back to string search
        filtered = filtered.filter(f => {
          const fileName = options.searchCaseSensitive ? f.name : f.name.toLowerCase()
          if (fileName.includes(term)) return true

          if (f.analyzed && f.analysisResult) {
            return f.analysisResult.printableStrings.some(s => {
              const str = options.searchCaseSensitive ? s : s.toLowerCase()
              return str.includes(term)
            })
          }
          return false
        })
      }
    } else {
      // Simple string search
      filtered = filtered.filter(f => {
        const fileName = options.searchCaseSensitive ? f.name : f.name.toLowerCase()
        if (fileName.includes(term)) return true

        if (f.analyzed && f.analysisResult) {
          return f.analysisResult.printableStrings.some(s => {
            const str = options.searchCaseSensitive ? s : s.toLowerCase()
            return str.includes(term)
          })
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

// Helper: Extract interesting patterns from strings
function extractPatterns(text: string): FileAnalysisResult['interestingPatterns'] {
  return {
    urls: [...new Set(text.match(/https?:\/\/[^\s<>"']{4,200}/g) || [])],
    emails: [...new Set(text.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/g) || [])],
    ips: [...new Set(text.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g) || [])],
    base64: [...new Set(text.match(/[A-Za-z0-9+/]{20,}={0,2}/g) || [])].slice(0, 10),
    hexStrings: [...new Set(text.match(/0x[a-fA-F0-9]{8,}/g) || [])].slice(0, 10)
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
