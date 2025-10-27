import React, { useState, useRef, useEffect } from 'react'
import {
  FolderOpen,
  Upload,
  Search,
  Filter,
  Download,
  FileText,
  Eye,
  Hash,
  Activity,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Layers,
  Database,
  ArrowUpDown,
  ArrowUp,
  ArrowDown,
  RefreshCw,
  File,
  EyeOff,
  Zap,
  Copy,
  Target
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card } from '../components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs'
import {
  scanFolder,
  batchAnalyzeFiles,
  filterFiles,
  exportToJSON,
  exportToCSV,
  formatFileSize,
  getEntropyColor,
  extractBytesFromFiles,
  type FileEntry,
  type FolderScanResult,
  type FilterOptions,
  type ByteExtractionConfig,
  type CombinedExtractionResult,
  type MetadataFormat
} from '../lib/folderAnalysis'

type SortField = 'name' | 'size' | 'type' | 'entropy' | 'strings' | 'modified'
type SortDirection = 'asc' | 'desc'

// Extraction Pattern type for multi-pattern byte extraction
type ExtractionPattern = {
  id: string
  name: string
  enabled: boolean
  filenamePattern: string
  bytePositions: string
  sortBy: string
  outputFormat: 'hex' | 'ascii' | 'decimal' | 'binary'
}

const FolderScanner: React.FC = () => {
  const [scanResult, setScanResult] = useState<FolderScanResult | null>(null)
  const [analyzedFiles, setAnalyzedFiles] = useState<FileEntry[]>([])
  const [filteredFiles, setFilteredFiles] = useState<FileEntry[]>([])
  const [selectedFile, setSelectedFile] = useState<FileEntry | null>(null)
  const [isScanning, setIsScanning] = useState(false)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [analysisProgress, setAnalysisProgress] = useState({ current: 0, total: 0 })
  const [activeTab, setActiveTab] = useState<'overview' | 'files' | 'preview' | 'insights'>('overview')

  // CTF Mode state
  const [ctfMode, setCtfMode] = useState(false)
  const [flagPattern, setFlagPattern] = useState('flag{')
  const [flagPatternEnd, setFlagPatternEnd] = useState('}')
  const [checkEncodedFlags, setCheckEncodedFlags] = useState(true)
  const [flagResults, setFlagResults] = useState<Array<{ file: FileEntry, flags: string[], encoded?: boolean }>>([])
  const [globalSearchTerm, setGlobalSearchTerm] = useState('')
  const [globalSearchResults, setGlobalSearchResults] = useState<Array<{ file: FileEntry, matches: string[] }>>([])
  const [isGlobalSearching, setIsGlobalSearching] = useState(false)

  // Filter state
  const [filters, setFilters] = useState<FilterOptions>({
    showHidden: true,
    hasContent: undefined,
    hasStrings: undefined,
    searchTerm: '',
    searchCaseSensitive: false,
    searchRegex: false,
    minSize: undefined,
    maxSize: undefined,
    minEntropy: undefined,
    maxEntropy: undefined
  })

  // Sort state
  const [sortField, setSortField] = useState<SortField>('name')
  const [sortDirection, setSortDirection] = useState<SortDirection>('asc')

  // UI state
  const [showFilters, setShowFilters] = useState(false)
  const [searchInput, setSearchInput] = useState('')
  const fileInputRef = useRef<HTMLInputElement>(null)

  // Filter history for undo/redo
  const [filterHistory, setFilterHistory] = useState<FilterOptions[]>([])
  const [historyIndex, setHistoryIndex] = useState(-1)

  // Filter suggestions
  const [filterSuggestions, setFilterSuggestions] = useState<Array<{
    id: string
    message: string
    action: () => void
    dismissed: boolean
  }>>([])

  // Multi-pattern byte extraction state
  const [extractionPatterns, setExtractionPatterns] = useState<ExtractionPattern[]>([])
  const [extractionResults, setExtractionResults] = useState<Map<string, CombinedExtractionResult>>(new Map())
  const [isExtracting, setIsExtracting] = useState(false)
  const [extractionError, setExtractionError] = useState<string | null>(null)
  const [showPatternLibrary, setShowPatternLibrary] = useState(false)

  // Duplicate detection state
  const [duplicateGroups, setDuplicateGroups] = useState<Map<string, FileEntry[]>>(new Map())
  const [totalDuplicateSize, setTotalDuplicateSize] = useState(0)

  // File carving state
  const [carvedFiles, setCarvedFiles] = useState<Array<{ sourceFile: FileEntry, signatures: Array<{ type: string, offset: number, size?: number }> }>>([])
  const [isCarving, setIsCarving] = useState(false)

  // Apply filters and sorting whenever they change
  useEffect(() => {
    if (!scanResult) return

    const filesToFilter = analyzedFiles.length > 0 ? analyzedFiles : scanResult.files
    let filtered = filterFiles(filesToFilter, filters)

    // Apply sorting
    filtered = sortFiles(filtered, sortField, sortDirection)

    setFilteredFiles(filtered)
  }, [filters, analyzedFiles, scanResult, sortField, sortDirection])

  // Auto-run duplicate detection and file carving after analysis
  useEffect(() => {
    if (analyzedFiles.length > 0) {
      detectDuplicates()
      performFileCarving()
      generateFilterSuggestions()
    }
  }, [analyzedFiles])

  const handleFolderSelect = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files
    if (!files || files.length === 0) return

    setIsScanning(true)
    setAnalyzedFiles([])
    setFilteredFiles([])
    setSelectedFile(null)

    try {
      const result = await scanFolder(files)
      setScanResult(result)
      setFilteredFiles(result.files)
      setIsScanning(false)

      // Auto-analyze after scan completes
      await analyzeFilesAfterScan(result)
    } catch (error) {
      console.error('Folder scan error:', error)
      alert('Failed to scan folder')
      setIsScanning(false)
    }
  }

  const analyzeFilesAfterScan = async (result: FolderScanResult) => {
    setIsAnalyzing(true)
    setAnalysisProgress({ current: 0, total: result.files.length })

    try {
      const analyzed = await batchAnalyzeFiles(
        result.files,
        (current, total) => {
          setAnalysisProgress({ current, total })
        }
      )
      setAnalyzedFiles(analyzed)
      setScanResult({ ...result, scannedFiles: analyzed.length })
    } catch (error) {
      console.error('Analysis error:', error)
      alert('Failed to analyze files')
    } finally {
      setIsAnalyzing(false)
    }
  }

  const handleAnalyzeAll = async () => {
    if (!scanResult) return

    setIsAnalyzing(true)
    setAnalysisProgress({ current: 0, total: scanResult.files.length })

    try {
      const analyzed = await batchAnalyzeFiles(
        scanResult.files,
        (current, total) => {
          setAnalysisProgress({ current, total })
        }
      )
      setAnalyzedFiles(analyzed)
      setScanResult({ ...scanResult, scannedFiles: analyzed.length })
    } catch (error) {
      console.error('Analysis error:', error)
      alert('Failed to analyze files')
    } finally {
      setIsAnalyzing(false)
    }
  }

  const handleExport = (format: 'json' | 'csv') => {
    const filesToExport = filteredFiles.length > 0 ? filteredFiles : scanResult?.files || []

    let content: string
    let filename: string
    let mimeType: string

    if (format === 'json') {
      content = exportToJSON(filesToExport)
      filename = `folder-scan-${Date.now()}.json`
      mimeType = 'application/json'
    } else {
      content = exportToCSV(filesToExport)
      filename = `folder-scan-${Date.now()}.csv`
      mimeType = 'text/csv'
    }

    const blob = new Blob([content], { type: mimeType })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    a.click()
    URL.revokeObjectURL(url)
  }

  // Export files to timeline format (chronological order)
  const handleTimelineExport = (format: 'json' | 'csv') => {
    const filesToExport = filteredFiles.length > 0 ? filteredFiles : scanResult?.files || []
    
    // Create timeline events
    const events: Array<{
      timestamp: number
      date: string
      event: string
      filename: string
      path: string
      size: number
      hash?: string
    }> = []

    for (const file of filesToExport) {
      // Modified event
      events.push({
        timestamp: file.lastModified.getTime(),
        date: file.lastModified.toISOString(),
        event: 'Modified',
        filename: file.name,
        path: file.path,
        size: file.size,
        hash: file.analysisResult?.hash?.sha256
      })

      // Could add created/accessed if available in file metadata
      // For now we only have lastModified reliably
    }

    // Sort by timestamp (oldest first)
    events.sort((a, b) => a.timestamp - b.timestamp)

    let content: string
    let filename: string
    let mimeType: string

    if (format === 'json') {
      content = JSON.stringify({ 
        timeline: events,
        generatedAt: new Date().toISOString(),
        totalEvents: events.length,
        fileCount: filesToExport.length
      }, null, 2)
      filename = `timeline-${Date.now()}.json`
      mimeType = 'application/json'
    } else {
      // CSV format
      const headers = ['Timestamp', 'Date', 'Event', 'Filename', 'Path', 'Size', 'Hash']
      const rows = events.map(e => [
        e.timestamp,
        e.date,
        e.event,
        e.filename,
        e.path,
        e.size,
        e.hash || ''
      ])
      content = [
        headers.join(','),
        ...rows.map(row => row.map(cell => `"${cell}"`).join(','))
      ].join('\n')
      filename = `timeline-${Date.now()}.csv`
      mimeType = 'text/csv'
    }

    const blob = new Blob([content], { type: mimeType })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    a.click()
    URL.revokeObjectURL(url)
  }

  const sortFiles = (files: FileEntry[], field: SortField, direction: SortDirection): FileEntry[] => {
    const sorted = [...files].sort((a, b) => {
      let aVal: any
      let bVal: any

      switch (field) {
        case 'name':
          aVal = a.name.toLowerCase()
          bVal = b.name.toLowerCase()
          break
        case 'size':
          aVal = a.size
          bVal = b.size
          break
        case 'type':
          aVal = a.extension
          bVal = b.extension
          break
        case 'entropy':
          aVal = a.analysisResult?.entropy || 0
          bVal = b.analysisResult?.entropy || 0
          break
        case 'strings':
          aVal = a.analysisResult?.stringCount || 0
          bVal = b.analysisResult?.stringCount || 0
          break
        case 'modified':
          aVal = a.lastModified.getTime()
          bVal = b.lastModified.getTime()
          break
        default:
          return 0
      }

      if (aVal < bVal) return direction === 'asc' ? -1 : 1
      if (aVal > bVal) return direction === 'asc' ? 1 : -1
      return 0
    })

    return sorted
  }

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc')
    } else {
      setSortField(field)
      setSortDirection('asc')
    }
  }

  const SortIcon = ({ field }: { field: SortField }) => {
    if (sortField !== field) return <ArrowUpDown className="w-3 h-3 ml-1 opacity-50" />
    return sortDirection === 'asc' ? (
      <ArrowUp className="w-3 h-3 ml-1 text-accent" />
    ) : (
      <ArrowDown className="w-3 h-3 ml-1 text-accent" />
    )
  }

  const applySearch = () => {
    setFilters({ ...filters, searchTerm: searchInput })
  }

  const resetFilters = () => {
    setFilters({
      showHidden: true,
      hasContent: undefined,
      hasStrings: undefined,
      searchTerm: '',
      searchCaseSensitive: false,
      searchRegex: false,
      minSize: undefined,
      maxSize: undefined,
      minEntropy: undefined,
      maxEntropy: undefined
    })
    setSearchInput('')
  }

  // Count active filters
  const countActiveFilters = (): number => {
    let count = 0
    if (filters.searchTerm) count++
    if (filters.minSize !== undefined) count++
    if (filters.maxSize !== undefined) count++
    if (filters.minEntropy !== undefined) count++
    if (filters.maxEntropy !== undefined) count++
    if (filters.hasContent !== undefined) count++
    if (filters.hasStrings !== undefined) count++
    if (!filters.showHidden) count++
    return count
  }

  // Remove specific filter
  const removeFilter = (filterType: string) => {
    const newFilters = { ...filters }
    switch (filterType) {
      case 'search':
        newFilters.searchTerm = ''
        setSearchInput('')
        break
      case 'minSize':
        newFilters.minSize = undefined
        break
      case 'maxSize':
        newFilters.maxSize = undefined
        break
      case 'minEntropy':
        newFilters.minEntropy = undefined
        break
      case 'maxEntropy':
        newFilters.maxEntropy = undefined
        break
      case 'hasContent':
        newFilters.hasContent = undefined
        break
      case 'hasStrings':
        newFilters.hasStrings = undefined
        break
      case 'showHidden':
        newFilters.showHidden = true
        break
    }
    setFilters(newFilters)
  }

  // Generate filter suggestions based on analysis
  const generateFilterSuggestions = () => {
    if (!scanResult || analyzedFiles.length === 0) return

    const suggestions: Array<{ id: string, message: string, action: () => void, dismissed: boolean }> = []

    // High entropy files
    const highEntropyFiles = analyzedFiles.filter(f => f.analysisResult && f.analysisResult.entropy > 7.5)
    if (highEntropyFiles.length > 0 && highEntropyFiles.length < analyzedFiles.length * 0.3) {
      suggestions.push({
        id: 'high-entropy',
        message: `Found ${highEntropyFiles.length} high-entropy files (possible encryption) - Show only these?`,
        action: () => {
          setFilters({ ...filters, minEntropy: 7.5 })
          dismissSuggestion('high-entropy')
        },
        dismissed: false
      })
    }

    // Empty files
    const emptyFiles = scanResult.files.filter(f => f.size === 0)
    if (emptyFiles.length > 5) {
      suggestions.push({
        id: 'empty-files',
        message: `Found ${emptyFiles.length} empty files - Filter them out?`,
        action: () => {
          setFilters({ ...filters, hasContent: true })
          dismissSuggestion('empty-files')
        },
        dismissed: false
      })
    }

    // Files with Base64
    const base64Files = analyzedFiles.filter(f => 
      f.analysisResult?.interestingPatterns.base64 && f.analysisResult.interestingPatterns.base64.length > 0
    )
    if (base64Files.length > 0 && base64Files.length < analyzedFiles.length * 0.2) {
      suggestions.push({
        id: 'base64-files',
        message: `Found ${base64Files.length} files with Base64 patterns - Investigate these?`,
        action: () => {
          // Filter to show only files with base64
          const base64Hashes = new Set(base64Files.map(f => f.analysisResult?.hash?.sha256).filter(Boolean))
          setFilteredFiles(analyzedFiles.filter(f => base64Hashes.has(f.analysisResult?.hash?.sha256)))
          dismissSuggestion('base64-files')
        },
        dismissed: false
      })
    }

    // Hidden files
    if (scanResult.hiddenFileCount > analyzedFiles.length * 0.5) {
      suggestions.push({
        id: 'hidden-files',
        message: `${Math.round(scanResult.hiddenFileCount / scanResult.totalFiles * 100)}% are hidden files - Hide them for cleaner view?`,
        action: () => {
          setFilters({ ...filters, showHidden: false })
          dismissSuggestion('hidden-files')
        },
        dismissed: false
      })
    }

    setFilterSuggestions(suggestions)
  }

  const dismissSuggestion = (id: string) => {
    setFilterSuggestions(prev => 
      prev.map(s => s.id === id ? { ...s, dismissed: true } : s)
    )
  }

  // CTF Mode: Search for flags across all files
  const searchForFlags = async () => {
    if (!scanResult) return

    const filesToSearch = analyzedFiles.length > 0 ? analyzedFiles : scanResult.files
    const results: Array<{ file: FileEntry, flags: string[], encoded?: boolean }> = []

    // Build regex pattern from user input
    const escapeRegex = (str: string) => str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    const flagRegex = new RegExp(
      `${escapeRegex(flagPattern)}[^${escapeRegex(flagPatternEnd)}]+${escapeRegex(flagPatternEnd)}`,
      'gi'
    )

    for (const file of filesToSearch) {
      const flags: string[] = []
      
      // Search in extracted strings
      if (file.analysisResult?.printableStrings) {
        for (const str of file.analysisResult.printableStrings) {
          const matches = str.match(flagRegex)
          if (matches) flags.push(...matches)
        }
      }

      // Search in UTF-16 decoded strings
      if (file.analysisResult?.utf16DecodedStrings) {
        for (const str of file.analysisResult.utf16DecodedStrings) {
          const matches = str.match(flagRegex)
          if (matches) flags.push(...matches)
        }
      }

      // Check for encoded flags (base64, hex, rot13)
      if (checkEncodedFlags && file.analysisResult?.interestingPatterns.base64) {
        for (const b64 of file.analysisResult.interestingPatterns.base64) {
          try {
            const decoded = atob(b64)
            const matches = decoded.match(flagRegex)
            if (matches) {
              flags.push(...matches.map(m => `${m} (base64: ${b64})`))
            }
          } catch {}
        }
      }

      if (flags.length > 0) {
        results.push({ file, flags: [...new Set(flags)] })
      }
    }

    setFlagResults(results)
  }

  // Global content search across all files
  const handleGlobalSearch = async () => {
    if (!globalSearchTerm.trim() || !scanResult) return

    setIsGlobalSearching(true)
    const filesToSearch = analyzedFiles.length > 0 ? analyzedFiles : scanResult.files
    const results: Array<{ file: FileEntry, matches: string[] }> = []
    const searchLower = globalSearchTerm.toLowerCase()

    for (const file of filesToSearch) {
      const matches: string[] = []

      // Search in filename
      if (file.name.toLowerCase().includes(searchLower)) {
        matches.push(`Filename: ${file.name}`)
      }

      // Search in strings
      if (file.analysisResult?.printableStrings) {
        for (const str of file.analysisResult.printableStrings) {
          if (str.toLowerCase().includes(searchLower)) {
            matches.push(str)
          }
        }
      }

      // Search in UTF-16 strings
      if (file.analysisResult?.utf16DecodedStrings) {
        for (const str of file.analysisResult.utf16DecodedStrings) {
          if (str.toLowerCase().includes(searchLower)) {
            matches.push(str)
          }
        }
      }

      if (matches.length > 0) {
        results.push({ file, matches: matches.slice(0, 10) }) // Limit to 10 matches per file
      }
    }

    setGlobalSearchResults(results)
    setIsGlobalSearching(false)
  }

  // Detect duplicate files based on SHA-256 hashes
  const detectDuplicates = () => {
    if (!scanResult) return

    const filesToCheck = analyzedFiles.length > 0 ? analyzedFiles : scanResult.files
    const hashMap = new Map<string, FileEntry[]>()
    let wastedSpace = 0

    // Group files by hash
    for (const file of filesToCheck) {
      if (file.analysisResult?.hash?.sha256) {
        const hash = file.analysisResult.hash.sha256
        if (!hashMap.has(hash)) {
          hashMap.set(hash, [])
        }
        hashMap.get(hash)!.push(file)
      }
    }

    // Filter to only keep groups with duplicates (2+ files with same hash)
    const duplicates = new Map<string, FileEntry[]>()
    for (const [hash, files] of hashMap.entries()) {
      if (files.length > 1) {
        duplicates.set(hash, files)
        // Calculate wasted space (all copies except one)
        const fileSize = files[0].size
        wastedSpace += fileSize * (files.length - 1)
      }
    }

    setDuplicateGroups(duplicates)
    setTotalDuplicateSize(wastedSpace)
  }

  // File carving: Detect file signatures within files
  const performFileCarving = async () => {
    if (!scanResult) return

    setIsCarving(true)
    const filesToCarve = analyzedFiles.length > 0 ? analyzedFiles : scanResult.files
    const results: Array<{ sourceFile: FileEntry, signatures: Array<{ type: string, offset: number, size?: number }> }> = []

    // Common file signatures (magic bytes)
    const signatures = [
      { type: 'JPEG', signature: [0xFF, 0xD8, 0xFF], extension: '.jpg' },
      { type: 'PNG', signature: [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A], extension: '.png' },
      { type: 'GIF', signature: [0x47, 0x49, 0x46, 0x38], extension: '.gif' },
      { type: 'PDF', signature: [0x25, 0x50, 0x44, 0x46], extension: '.pdf' },
      { type: 'ZIP', signature: [0x50, 0x4B, 0x03, 0x04], extension: '.zip' },
      { type: 'RAR', signature: [0x52, 0x61, 0x72, 0x21], extension: '.rar' },
      { type: 'EXE', signature: [0x4D, 0x5A], extension: '.exe' },
      { type: 'ELF', signature: [0x7F, 0x45, 0x4C, 0x46], extension: '' },
      { type: '7Z', signature: [0x37, 0x7A, 0xBC, 0xAF, 0x27, 0x1C], extension: '.7z' },
      { type: 'TAR', signature: [0x75, 0x73, 0x74, 0x61, 0x72], extension: '.tar', offset: 257 }, // ustar at offset 257
    ]

    for (const file of filesToCarve) {
      if (file.size === 0 || file.size > 10 * 1024 * 1024) continue // Skip empty or very large files (>10MB)

      try {
        const arrayBuffer = await file.file.arrayBuffer()
        const bytes = new Uint8Array(arrayBuffer)
        const foundSignatures: Array<{ type: string, offset: number, size?: number }> = []

        // Search for each signature
        for (const sig of signatures) {
          const searchStart = sig.offset || 0
          for (let i = searchStart; i < bytes.length - sig.signature.length; i++) {
            let match = true
            for (let j = 0; j < sig.signature.length; j++) {
              if (bytes[i + j] !== sig.signature[j]) {
                match = false
                break
              }
            }
            if (match) {
              foundSignatures.push({ 
                type: sig.type, 
                offset: i,
                size: undefined // Could be calculated for some formats
              })
              // Skip ahead to avoid finding the same signature multiple times in close proximity
              i += sig.signature.length + 100
            }
          }
        }

        if (foundSignatures.length > 0) {
          results.push({ sourceFile: file, signatures: foundSignatures })
        }
      } catch (error) {
        console.error(`Error carving file ${file.name}:`, error)
      }
    }

    setCarvedFiles(results)
    setIsCarving(false)
  }

  // Pattern management functions
  const addPattern = () => {
    const newPattern: ExtractionPattern = {
      id: `pattern-${Date.now()}`,
      name: `Pattern ${extractionPatterns.length + 1}`,
      enabled: true,
      filenamePattern: '',
      bytePositions: '0',
      sortBy: 'name',
      outputFormat: 'ascii'
    }
    setExtractionPatterns([...extractionPatterns, newPattern])
  }

  const updatePattern = (id: string, updates: Partial<ExtractionPattern>) => {
    setExtractionPatterns(prev =>
      prev.map(p => p.id === id ? { ...p, ...updates } : p)
    )
  }

  const deletePattern = (id: string) => {
    setExtractionPatterns(prev => prev.filter(p => p.id !== id))
    setExtractionResults(prev => {
      const newResults = new Map(prev)
      newResults.delete(id)
      return newResults
    })
  }

  const loadPatternPreset = (preset: 'ntfs' | 'png' | 'jpeg' | 'zip' | 'flag-parts') => {
    let pattern: Partial<ExtractionPattern> = {}
    
    switch (preset) {
      case 'ntfs':
        pattern = {
          name: 'NTFS Recycle Bin',
          filenamePattern: '$I*.txt',
          bytePositions: '8',
          sortBy: 'name',
          outputFormat: 'ascii'
        }
        break
      case 'png':
        pattern = {
          name: 'PNG Magic Bytes',
          filenamePattern: '*.png',
          bytePositions: '0-3',
          sortBy: 'name',
          outputFormat: 'hex'
        }
        break
      case 'jpeg':
        pattern = {
          name: 'JPEG Header',
          filenamePattern: '*.jpg',
          bytePositions: '0,1',
          sortBy: 'name',
          outputFormat: 'hex'
        }
        break
      case 'zip':
        pattern = {
          name: 'ZIP Signature',
          filenamePattern: '*.zip',
          bytePositions: '0-3',
          sortBy: 'name',
          outputFormat: 'hex'
        }
        break
      case 'flag-parts':
        pattern = {
          name: 'Sequential Flag Parts',
          filenamePattern: 'flag*.txt',
          bytePositions: '0',
          sortBy: 'natural',
          outputFormat: 'ascii'
        }
        break
    }

    const newPattern: ExtractionPattern = {
      id: `pattern-${Date.now()}`,
      enabled: true,
      ...pattern
    } as ExtractionPattern

    setExtractionPatterns([...extractionPatterns, newPattern])
  }

  const executeAllPatterns = async () => {
    if (!scanResult) {
      setExtractionError('No folder scanned. Please scan a folder first.')
      return
    }

    const enabledPatterns = extractionPatterns.filter(p => p.enabled)
    if (enabledPatterns.length === 0) {
      setExtractionError('No enabled patterns. Please add and enable at least one pattern.')
      return
    }

    setIsExtracting(true)
    setExtractionError(null)
    const newResults = new Map<string, CombinedExtractionResult>()

    try {
      for (const pattern of enabledPatterns) {
        if (!pattern.filenamePattern.trim() || !pattern.bytePositions.trim()) {
          continue
        }

        const config: ByteExtractionConfig = {
          enabled: true,
          filenamePattern: pattern.filenamePattern,
          bytePositions: pattern.bytePositions,
          sortBy: pattern.sortBy as any,
          metadataSort: {
            enabled: false,
            startByte: 0,
            length: 8,
            format: 'filetime',
            ascending: true
          }
        }

        const result = await extractBytesFromFiles(scanResult.files, config)
        newResults.set(pattern.id, result)
      }

      setExtractionResults(newResults)

      if (newResults.size === 0) {
        setExtractionError('No patterns produced results. Check your filename patterns.')
      }
    } catch (error) {
      console.error('Pattern extraction error:', error)
      setExtractionError(`Extraction failed: ${error instanceof Error ? error.message : 'Unknown error'}`)
    } finally {
      setIsExtracting(false)
    }
  }

  const copyPatternResult = (patternId: string) => {
    const result = extractionResults.get(patternId)
    if (result) {
      navigator.clipboard.writeText(result.combinedString)
      alert('Copied to clipboard!')
    }
  }

  const exportPatternResult = (patternId: string) => {
    const result = extractionResults.get(patternId)
    const pattern = extractionPatterns.find(p => p.id === patternId)
    if (!result || !pattern) return

    const content = `Pattern: ${pattern.name}\nCombined Result: ${result.combinedString}\n\nDetails:\n` +
      result.details.map(d =>
        `${d.filename} [pos ${d.position}] → '${d.char}' (0x${d.hex}, ASCII ${d.ascii})`
      ).join('\n')

    const blob = new Blob([content], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `extraction-${pattern.name.toLowerCase().replace(/\s+/g, '-')}-${Date.now()}.txt`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <FolderOpen className="w-8 h-8 text-accent" />
            Folder Scanner
          </h1>
          <p className="text-muted-foreground mt-1">
            Bulk scan folders and filter files by content, including hidden files
          </p>
        </div>
        
        {/* CTF Mode Toggle */}
        {scanResult && (
          <Button
            onClick={() => setCtfMode(!ctfMode)}
            variant={ctfMode ? 'default' : 'outline'}
            className={ctfMode ? 'bg-accent hover:bg-accent/80' : ''}
          >
            <Target className="w-4 h-4 mr-2" />
            CTF Mode {ctfMode ? 'ON' : 'OFF'}
          </Button>
        )}
      </div>

      {/* CTF Mode Panel */}
      {ctfMode && scanResult && (
        <Card className="p-4 bg-accent/5 border-accent/30">
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-semibold flex items-center gap-2">
                <Target className="w-5 h-5 text-accent" />
                CTF Tools
              </h3>
            </div>

            {/* Flag Search */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="space-y-3">
                <h4 className="text-sm font-medium">Flag Pattern Search</h4>
                <div className="flex gap-2">
                  <Input
                    placeholder="flag{"
                    value={flagPattern}
                    onChange={(e) => setFlagPattern(e.target.value)}
                    className="flex-1"
                  />
                  <Input
                    placeholder="}"
                    value={flagPatternEnd}
                    onChange={(e) => setFlagPatternEnd(e.target.value)}
                    className="w-20"
                  />
                </div>
                <div className="flex items-center gap-2 text-xs text-muted-foreground">
                  <input
                    type="checkbox"
                    checked={checkEncodedFlags}
                    onChange={(e) => setCheckEncodedFlags(e.target.checked)}
                    id="check-encoded"
                  />
                  <label htmlFor="check-encoded">Check encoded (base64)</label>
                </div>
                <div className="flex flex-wrap gap-2">
                  <Button size="sm" variant="outline" onClick={() => { setFlagPattern('flag{'); setFlagPatternEnd('}') }}>flag{`{}`}</Button>
                  <Button size="sm" variant="outline" onClick={() => { setFlagPattern('HTB{'); setFlagPatternEnd('}') }}>HTB{`{}`}</Button>
                  <Button size="sm" variant="outline" onClick={() => { setFlagPattern('picoCTF{'); setFlagPatternEnd('}') }}>picoCTF{`{}`}</Button>
                  <Button size="sm" variant="outline" onClick={() => { setFlagPattern('CTF{'); setFlagPatternEnd('}') }}>CTF{`{}`}</Button>
                  <Button size="sm" variant="outline" onClick={() => { setFlagPattern('FLAG:'); setFlagPatternEnd(' ') }}>FLAG:</Button>
                </div>
                <Button onClick={searchForFlags} className="w-full">
                  <Search className="w-4 h-4 mr-2" />
                  Search for Flags
                </Button>
              </div>

              {/* Global Search */}
              <div className="space-y-3">
                <h4 className="text-sm font-medium">Global Content Search</h4>
                <Input
                  placeholder="Search in all file contents..."
                  value={globalSearchTerm}
                  onChange={(e) => setGlobalSearchTerm(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleGlobalSearch()}
                />
                <p className="text-xs text-muted-foreground">
                  Search through content of all files at once
                </p>
                <Button onClick={handleGlobalSearch} disabled={isGlobalSearching} className="w-full">
                  {isGlobalSearching ? (
                    <>
                      <Activity className="w-4 h-4 mr-2 animate-spin" />
                      Searching...
                    </>
                  ) : (
                    <>
                      <Search className="w-4 h-4 mr-2" />
                      Search All Files
                    </>
                  )}
                </Button>
              </div>
            </div>

            {/* Flag Results */}
            {flagResults.length > 0 && (
              <div className="border-t border-border pt-4">
                <h4 className="text-sm font-medium mb-2">🎯 Flags Found ({flagResults.length} files)</h4>
                <div className="space-y-2 max-h-64 overflow-auto">
                  {flagResults.map((result, idx) => (
                    <div key={idx} className="bg-green-500/10 border border-green-500/30 rounded p-3">
                      <p className="text-sm font-mono font-bold text-green-400">{result.file.name}</p>
                      {result.flags.map((flag, i) => (
                        <div key={i} className="text-sm font-mono mt-1 text-accent">{flag}</div>
                      ))}
                    </div>
                  ))}
                </div>
                <Button
                  onClick={() => {
                    const allFlags = flagResults.flatMap(r => r.flags).join('\n')
                    navigator.clipboard.writeText(allFlags)
                    alert('All flags copied to clipboard!')
                  }}
                  variant="outline"
                  size="sm"
                  className="mt-2"
                >
                  <Copy className="w-3 h-3 mr-1" />
                  Copy All Flags
                </Button>
              </div>
            )}

            {/* Global Search Results */}
            {globalSearchResults.length > 0 && (
              <div className="border-t border-border pt-4">
                <h4 className="text-sm font-medium mb-2">
                  🔍 Search Results ({globalSearchResults.length} files with matches)
                </h4>
                <div className="space-y-2 max-h-64 overflow-auto">
                  {globalSearchResults.map((result, idx) => (
                    <div key={idx} className="bg-blue-500/10 border border-blue-500/30 rounded p-3">
                      <p className="text-sm font-mono font-bold text-blue-400">{result.file.name}</p>
                      {result.matches.slice(0, 3).map((match, i) => (
                        <div key={i} className="text-xs font-mono mt-1 text-muted-foreground truncate">
                          {match}
                        </div>
                      ))}
                      {result.matches.length > 3 && (
                        <p className="text-xs text-muted-foreground mt-1">
                          +{result.matches.length - 3} more matches
                        </p>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Quick CTF Filters */}
            <div className="border-t border-border pt-4">
              <h4 className="text-sm font-medium mb-2">Quick Filters</h4>
              <div className="flex flex-wrap gap-2">
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => setFilters({ ...filters, minEntropy: 7.5 })}
                >
                  <AlertTriangle className="w-3 h-3 mr-1" />
                  Suspicious Entropy (&gt;7.5)
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => setFilters({ ...filters, minSize: 1, maxSize: 1024 })}
                >
                  Small Files (&lt;1KB)
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => resetFilters()}
                >
                  <RefreshCw className="w-3 h-3 mr-1" />
                  Clear Filters
                </Button>
              </div>
            </div>
          </div>
        </Card>
      )}

      {/* Upload Section */}
      {!scanResult ? (
        <Card className="p-6">
          <h2 className="text-lg font-semibold mb-4">Select Folder to Scan</h2>
          <div
            className="border-2 border-dashed border-border rounded-lg p-8 text-center hover:border-accent transition-colors cursor-pointer"
            onClick={() => fileInputRef.current?.click()}
          >
            <Upload className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
            <p className="text-lg font-medium mb-2">
              Click to select a folder
            </p>
            <p className="text-sm text-muted-foreground">
              All files including hidden files (starting with .) will be scanned and analyzed
            </p>
            <input
              ref={fileInputRef}
              type="file"
              /* @ts-ignore - webkitdirectory is not in types but works */
              webkitdirectory=""
              directory=""
              multiple
              onChange={handleFolderSelect}
              className="hidden"
            />
          </div>
          {(isScanning || isAnalyzing) && (
            <div className="mt-4 flex items-center justify-center gap-2 text-sm text-accent">
              <Activity className="w-4 h-4 animate-spin" />
              <span>
                {isScanning ? 'Scanning folder...' : `Analyzing ${analysisProgress.current}/${analysisProgress.total} files...`}
              </span>
            </div>
          )}
        </Card>
      ) : (
        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <FolderOpen className="w-5 h-5 text-accent" />
              <div>
                <p className="font-medium">Scanned folder with {scanResult.totalFiles} files</p>
                <p className="text-sm text-muted-foreground">{formatFileSize(scanResult.totalSize)}</p>
              </div>
            </div>
            <Button
              variant="destructive"
              size="sm"
              onClick={() => {
                setScanResult(null)
                setAnalyzedFiles([])
                setFilteredFiles([])
                setSelectedFile(null)
              }}
            >
              Clear Folder
            </Button>
          </div>
        </Card>
      )}

      {!scanResult && (
        <div className="invisible">
          {/* Spacer */}
        </div>
      )}

      {/* Results Section */}
      {scanResult && (
        <div className="space-y-4">
          {/* Action Bar */}
          <div className="flex flex-wrap items-center gap-3">
            <Button onClick={() => fileInputRef.current?.click()} variant="outline">
              <FolderOpen className="w-4 h-4 mr-2" />
              New Scan
            </Button>
            <input
              ref={fileInputRef}
              type="file"
              /* @ts-ignore */
              webkitdirectory=""
              directory=""
              multiple
              onChange={handleFolderSelect}
              className="hidden"
            />
            {isAnalyzing && (
              <div className="flex items-center gap-2 text-sm text-accent">
                <Activity className="w-4 h-4 animate-spin" />
                <span>Analyzing {analysisProgress.current}/{analysisProgress.total} files...</span>
              </div>
            )}
            {!isAnalyzing && analyzedFiles.length > 0 && (
              <div className="flex items-center gap-2 text-sm text-green-400">
                <CheckCircle className="w-4 h-4" />
                <span>Analysis Complete</span>
              </div>
            )}
            <Button 
              onClick={() => setShowFilters(!showFilters)} 
              variant="outline"
              className={countActiveFilters() > 0 ? 'border-accent text-accent' : ''}
            >
              <Filter className="w-4 h-4 mr-2" />
              Filters {countActiveFilters() > 0 && `(${countActiveFilters()})`} {showFilters ? '▲' : '▼'}
            </Button>
            <div className="flex-1" />
            <Button onClick={() => handleExport('json')} variant="outline" size="sm">
              <Download className="w-4 h-4 mr-2" />
              Export JSON
            </Button>
            <Button onClick={() => handleExport('csv')} variant="outline" size="sm">
              <Download className="w-4 h-4 mr-2" />
              Export CSV
            </Button>
            <Button onClick={() => handleTimelineExport('json')} variant="outline" size="sm">
              <Activity className="w-4 h-4 mr-2" />
              Timeline JSON
            </Button>
            <Button onClick={() => handleTimelineExport('csv')} variant="outline" size="sm">
              <Activity className="w-4 h-4 mr-2" />
              Timeline CSV
            </Button>
          </div>

          {/* Active Filters Bar */}
          {countActiveFilters() > 0 && (
            <div className="bg-accent/5 border border-accent/20 rounded px-4 py-2">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-sm font-medium text-muted-foreground">Active Filters:</span>
                
                {filters.searchTerm && (
                  <div className="flex items-center gap-1 bg-blue-500/20 border border-blue-500/30 rounded px-2 py-1 text-xs">
                    <Search className="w-3 h-3" />
                    <span>Search: "{filters.searchTerm}"</span>
                    <button 
                      onClick={() => removeFilter('search')}
                      className="ml-1 hover:text-red-400"
                    >
                      <XCircle className="w-3 h-3" />
                    </button>
                  </div>
                )}

                {filters.minSize !== undefined && (
                  <div className="flex items-center gap-1 bg-green-500/20 border border-green-500/30 rounded px-2 py-1 text-xs">
                    <span>Min Size: {formatFileSize(filters.minSize)}</span>
                    <button 
                      onClick={() => removeFilter('minSize')}
                      className="ml-1 hover:text-red-400"
                    >
                      <XCircle className="w-3 h-3" />
                    </button>
                  </div>
                )}

                {filters.maxSize !== undefined && (
                  <div className="flex items-center gap-1 bg-green-500/20 border border-green-500/30 rounded px-2 py-1 text-xs">
                    <span>Max Size: {formatFileSize(filters.maxSize)}</span>
                    <button 
                      onClick={() => removeFilter('maxSize')}
                      className="ml-1 hover:text-red-400"
                    >
                      <XCircle className="w-3 h-3" />
                    </button>
                  </div>
                )}

                {filters.minEntropy !== undefined && (
                  <div className="flex items-center gap-1 bg-orange-500/20 border border-orange-500/30 rounded px-2 py-1 text-xs">
                    <Activity className="w-3 h-3" />
                    <span>Min Entropy: {filters.minEntropy}</span>
                    <button 
                      onClick={() => removeFilter('minEntropy')}
                      className="ml-1 hover:text-red-400"
                    >
                      <XCircle className="w-3 h-3" />
                    </button>
                  </div>
                )}

                {filters.maxEntropy !== undefined && (
                  <div className="flex items-center gap-1 bg-orange-500/20 border border-orange-500/30 rounded px-2 py-1 text-xs">
                    <Activity className="w-3 h-3" />
                    <span>Max Entropy: {filters.maxEntropy}</span>
                    <button 
                      onClick={() => removeFilter('maxEntropy')}
                      className="ml-1 hover:text-red-400"
                    >
                      <XCircle className="w-3 h-3" />
                    </button>
                  </div>
                )}

                {filters.hasContent !== undefined && (
                  <div className="flex items-center gap-1 bg-purple-500/20 border border-purple-500/30 rounded px-2 py-1 text-xs">
                    <FileText className="w-3 h-3" />
                    <span>{filters.hasContent ? 'Non-empty files' : 'Empty files only'}</span>
                    <button 
                      onClick={() => removeFilter('hasContent')}
                      className="ml-1 hover:text-red-400"
                    >
                      <XCircle className="w-3 h-3" />
                    </button>
                  </div>
                )}

                {filters.hasStrings !== undefined && (
                  <div className="flex items-center gap-1 bg-cyan-500/20 border border-cyan-500/30 rounded px-2 py-1 text-xs">
                    <span>{filters.hasStrings ? 'Has strings' : 'No strings'}</span>
                    <button 
                      onClick={() => removeFilter('hasStrings')}
                      className="ml-1 hover:text-red-400"
                    >
                      <XCircle className="w-3 h-3" />
                    </button>
                  </div>
                )}

                {!filters.showHidden && (
                  <div className="flex items-center gap-1 bg-yellow-500/20 border border-yellow-500/30 rounded px-2 py-1 text-xs">
                    <EyeOff className="w-3 h-3" />
                    <span>Hidden files excluded</span>
                    <button 
                      onClick={() => removeFilter('showHidden')}
                      className="ml-1 hover:text-red-400"
                    >
                      <XCircle className="w-3 h-3" />
                    </button>
                  </div>
                )}

                <div className="ml-auto">
                  <Button onClick={resetFilters} variant="ghost" size="sm" className="text-xs h-6">
                    Clear All
                  </Button>
                </div>
              </div>

              {/* Result Stats */}
              <div className="mt-2 text-xs text-muted-foreground">
                Showing {filteredFiles.length} of {scanResult?.totalFiles || 0} files
                {filteredFiles.length < (scanResult?.totalFiles || 0) && (
                  <span className="ml-2 text-accent">
                    ({Math.round((filteredFiles.length / (scanResult?.totalFiles || 1)) * 100)}% visible)
                  </span>
                )}
              </div>
            </div>
          )}

          {/* Filter Suggestions */}
          {filterSuggestions.filter(s => !s.dismissed).length > 0 && (
            <div className="space-y-2">
              {filterSuggestions.filter(s => !s.dismissed).map(suggestion => (
                <div 
                  key={suggestion.id}
                  className="bg-blue-500/10 border border-blue-500/30 rounded p-3 flex items-center justify-between"
                >
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-blue-400" />
                    <span className="text-sm">{suggestion.message}</span>
                  </div>
                  <div className="flex gap-2">
                    <Button onClick={suggestion.action} variant="outline" size="sm">
                      Apply
                    </Button>
                    <Button 
                      onClick={() => dismissSuggestion(suggestion.id)} 
                      variant="ghost" 
                      size="sm"
                    >
                      <XCircle className="w-4 h-4" />
                    </Button>
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* Filters Panel */}
          {showFilters && (
            <Card className="p-4 space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                {/* Search */}
                <div className="md:col-span-3">
                  <label className="text-sm font-medium block mb-2">Search in Files</label>
                  <div className="flex gap-2">
                    <Input
                      placeholder="Search filename or content..."
                      value={searchInput}
                      onChange={(e) => setSearchInput(e.target.value)}
                      onKeyDown={(e) => e.key === 'Enter' && applySearch()}
                    />
                    <Button onClick={applySearch} size="sm">
                      <Search className="w-4 h-4" />
                    </Button>
                  </div>
                  <div className="flex gap-3 mt-2">
                    <label className="flex items-center text-sm">
                      <input
                        type="checkbox"
                        checked={filters.searchCaseSensitive}
                        onChange={(e) => setFilters({ ...filters, searchCaseSensitive: e.target.checked })}
                        className="mr-2"
                      />
                      Case Sensitive
                    </label>
                    <label className="flex items-center text-sm">
                      <input
                        type="checkbox"
                        checked={filters.searchRegex}
                        onChange={(e) => setFilters({ ...filters, searchRegex: e.target.checked })}
                        className="mr-2"
                      />
                      Regex
                    </label>
                  </div>
                  {analyzedFiles.length === 0 && filters.searchTerm && (
                    <div className="mt-2 text-xs text-yellow-400 flex items-center gap-1">
                      <AlertTriangle className="w-3 h-3" />
                      Content search requires file analysis. Currently searching filenames and paths only.
                    </div>
                  )}
                </div>

                {/* Size Range */}
                <div>
                  <label className="text-sm font-medium block mb-2">Min Size (bytes)</label>
                  <Input
                    type="number"
                    placeholder="0"
                    value={filters.minSize || ''}
                    onChange={(e) => setFilters({ ...filters, minSize: e.target.value ? Number(e.target.value) : undefined })}
                  />
                </div>
                <div>
                  <label className="text-sm font-medium block mb-2">Max Size (bytes)</label>
                  <Input
                    type="number"
                    placeholder="Unlimited"
                    value={filters.maxSize || ''}
                    onChange={(e) => setFilters({ ...filters, maxSize: e.target.value ? Number(e.target.value) : undefined })}
                  />
                </div>

                {/* Content Filters */}
                <div>
                  <label className="text-sm font-medium block mb-2">Content Filter</label>
                  <select
                    className="w-full p-2 bg-background border border-border rounded"
                    value={filters.hasContent === undefined ? 'all' : filters.hasContent ? 'nonempty' : 'empty'}
                    onChange={(e) => {
                      const val = e.target.value
                      setFilters({
                        ...filters,
                        hasContent: val === 'all' ? undefined : val === 'nonempty'
                      })
                    }}
                  >
                    <option value="all">All Files</option>
                    <option value="nonempty">Non-Empty Only</option>
                    <option value="empty">Empty Only</option>
                  </select>
                </div>

                {/* Show Hidden */}
                <div className="md:col-span-3">
                  <label className="flex items-center text-sm">
                    <input
                      type="checkbox"
                      checked={filters.showHidden}
                      onChange={(e) => setFilters({ ...filters, showHidden: e.target.checked })}
                      className="mr-2"
                    />
                    Show Hidden Files (files starting with .)
                  </label>
                </div>

                {/* Strings Filter */}
                {analyzedFiles.length > 0 && (
                  <div>
                    <label className="text-sm font-medium block mb-2">Has Strings</label>
                    <select
                      className="w-full p-2 bg-background border border-border rounded"
                      value={filters.hasStrings === undefined ? 'all' : filters.hasStrings ? 'yes' : 'no'}
                      onChange={(e) => {
                        const val = e.target.value
                        setFilters({
                          ...filters,
                          hasStrings: val === 'all' ? undefined : val === 'yes'
                        })
                      }}
                    >
                      <option value="all">All</option>
                      <option value="yes">With Strings</option>
                      <option value="no">Without Strings</option>
                    </select>
                  </div>
                )}
              </div>

              {/* Multi-Pattern Byte Extractor Section */}
              <div className="border-t border-border pt-4 mt-4">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <Hash className="w-5 h-5 text-accent" />
                    <h3 className="text-base font-semibold">Multi-Pattern Byte Extractor</h3>
                  </div>
                  <div className="flex gap-2">
                    <Button onClick={() => setShowPatternLibrary(!showPatternLibrary)} variant="outline" size="sm">
                      <Layers className="w-4 h-4 mr-1" />
                      Pattern Library
                    </Button>
                    <Button onClick={addPattern} variant="outline" size="sm">
                      + Add Pattern
                    </Button>
                  </div>
                </div>

                {/* Pattern Library */}
                {showPatternLibrary && (
                  <div className="bg-muted/20 border border-border rounded p-3 mb-3">
                    <p className="text-xs font-medium mb-2 text-muted-foreground">Quick Load Presets:</p>
                    <div className="flex flex-wrap gap-2">
                      <Button onClick={() => loadPatternPreset('ntfs')} variant="outline" size="sm" className="text-xs">
                        NTFS Recycle Bin
                      </Button>
                      <Button onClick={() => loadPatternPreset('png')} variant="outline" size="sm" className="text-xs">
                        PNG Magic Bytes
                      </Button>
                      <Button onClick={() => loadPatternPreset('jpeg')} variant="outline" size="sm" className="text-xs">
                        JPEG Header
                      </Button>
                      <Button onClick={() => loadPatternPreset('zip')} variant="outline" size="sm" className="text-xs">
                        ZIP Signature
                      </Button>
                      <Button onClick={() => loadPatternPreset('flag-parts')} variant="outline" size="sm" className="text-xs">
                        Sequential Flag Parts
                      </Button>
                    </div>
                  </div>
                )}

                {/* Pattern List */}
                {extractionPatterns.length > 0 && (
                  <div className="space-y-3">
                    {extractionPatterns.map((pattern, idx) => (
                      <Card key={pattern.id} className={`p-3 ${pattern.enabled ? 'border-accent' : 'border-muted opacity-60'}`}>
                        <div className="space-y-2">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-2">
                              <input
                                type="checkbox"
                                checked={pattern.enabled}
                                onChange={(e) => updatePattern(pattern.id, { enabled: e.target.checked })}
                                className="mr-1"
                              />
                              <Input
                                value={pattern.name}
                                onChange={(e) => updatePattern(pattern.id, { name: e.target.value })}
                                className="text-sm font-medium w-48"
                                placeholder="Pattern name"
                              />
                            </div>
                            <Button onClick={() => deletePattern(pattern.id)} variant="ghost" size="sm">
                              <XCircle className="w-4 h-4 text-red-400" />
                            </Button>
                          </div>

                          <div className="grid grid-cols-3 gap-2">
                            <Input
                              value={pattern.filenamePattern}
                              onChange={(e) => updatePattern(pattern.id, { filenamePattern: e.target.value })}
                              placeholder="e.g., *.txt"
                              className="text-xs"
                            />
                            <Input
                              value={pattern.bytePositions}
                              onChange={(e) => updatePattern(pattern.id, { bytePositions: e.target.value })}
                              placeholder="e.g., 0 or 0-3"
                              className="text-xs"
                            />
                            <select
                              value={pattern.sortBy}
                              onChange={(e) => updatePattern(pattern.id, { sortBy: e.target.value })}
                              className="p-2 bg-background border border-border rounded text-xs"
                            >
                              <option value="name">Alphabetical</option>
                              <option value="natural">Natural Sort</option>
                              <option value="modified">Modified Date</option>
                              <option value="size">File Size</option>
                            </select>
                          </div>

                          {extractionResults.has(pattern.id) && (
                            <div className="bg-accent/10 border border-accent/20 rounded p-2">
                              <div className="flex items-center justify-between mb-1">
                                <span className="text-xs font-medium text-accent">Result:</span>
                                <div className="flex gap-1">
                                  <Button onClick={() => copyPatternResult(pattern.id)} variant="ghost" size="sm" className="h-6">
                                    <Copy className="w-3 h-3" />
                                  </Button>
                                  <Button onClick={() => exportPatternResult(pattern.id)} variant="ghost" size="sm" className="h-6">
                                    <Download className="w-3 h-3" />
                                  </Button>
                                </div>
                              </div>
                              <div className="bg-background border border-border rounded p-2 font-mono text-xs break-all max-h-20 overflow-y-auto">
                                {extractionResults.get(pattern.id)!.combinedString || '(empty)'}
                              </div>
                              <p className="text-xs text-muted-foreground mt-1">
                                {extractionResults.get(pattern.id)!.filesProcessed} files, {extractionResults.get(pattern.id)!.details.length} bytes
                              </p>
                            </div>
                          )}
                        </div>
                      </Card>
                    ))}

                    <Button
                      onClick={executeAllPatterns}
                      variant="default"
                      className="w-full"
                      disabled={isExtracting}
                    >
                      {isExtracting ? (
                        <>
                          <Activity className="w-4 h-4 mr-2 animate-spin" />
                          Extracting...
                        </>
                      ) : (
                        <>
                          <Zap className="w-4 h-4 mr-2" />
                          Execute All Enabled Patterns
                        </>
                      )}
                    </Button>

                    {extractionError && (
                      <div className="bg-red-500/10 border border-red-500/20 rounded p-3 text-xs text-red-400 flex items-start gap-2">
                        <AlertTriangle className="w-4 h-4 flex-shrink-0 mt-0.5" />
                        <span>{extractionError}</span>
                      </div>
                    )}
                  </div>
                )}

                {extractionPatterns.length === 0 && (
                  <div className="text-center py-8 text-muted-foreground">
                    <Hash className="w-12 h-12 mx-auto mb-2 opacity-20" />
                    <p className="text-sm">No extraction patterns defined</p>
                    <p className="text-xs mt-1">Click "Add Pattern" or load from Pattern Library</p>
                  </div>
                )}
              </div>

              <div className="flex gap-2">
                <Button onClick={resetFilters} variant="outline" size="sm">
                  <RefreshCw className="w-4 h-4 mr-2" />
                  Reset Filters
                </Button>
              </div>
            </Card>
          )}

          {/* Tabs */}
          <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as any)}>
            <TabsList>
              <TabsTrigger value="overview">
                <Database className="w-4 h-4 mr-2" />
                Overview
              </TabsTrigger>
              <TabsTrigger value="files">
                <FileText className="w-4 h-4 mr-2" />
                Files ({filteredFiles.length})
              </TabsTrigger>
              <TabsTrigger value="insights">
                <Layers className="w-4 h-4 mr-2" />
                Insights
              </TabsTrigger>
              {selectedFile && (
                <TabsTrigger value="preview">
                  <Eye className="w-4 h-4 mr-2" />
                  Preview
                </TabsTrigger>
              )}
            </TabsList>

            {/* Overview Tab */}
            <TabsContent value="overview">
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <Card className="p-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-muted-foreground">Total Files</p>
                      <p className="text-2xl font-bold">{scanResult.totalFiles}</p>
                    </div>
                    <File className="w-8 h-8 text-accent" />
                  </div>
                </Card>

                <Card className="p-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-muted-foreground">Total Size</p>
                      <p className="text-2xl font-bold">{formatFileSize(scanResult.totalSize)}</p>
                    </div>
                    <Database className="w-8 h-8 text-accent" />
                  </div>
                </Card>

                <Card className="p-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-muted-foreground">Hidden Files</p>
                      <p className="text-2xl font-bold">{scanResult.hiddenFileCount}</p>
                    </div>
                    <EyeOff className="w-8 h-8 text-yellow-400" />
                  </div>
                </Card>

                <Card className="p-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-muted-foreground">Empty Files</p>
                      <p className="text-2xl font-bold">{scanResult.emptyFileCount}</p>
                    </div>
                    <XCircle className="w-8 h-8 text-red-400" />
                  </div>
                </Card>

                <Card className="p-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-muted-foreground">Analyzed</p>
                      <p className="text-2xl font-bold">{analyzedFiles.length}</p>
                    </div>
                    <Activity className="w-8 h-8 text-green-400" />
                  </div>
                </Card>

                <Card className="p-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm text-muted-foreground">Scan Time</p>
                      <p className="text-2xl font-bold">{scanResult.scanDuration.toFixed(0)}ms</p>
                    </div>
                    <Activity className="w-8 h-8 text-blue-400" />
                  </div>
                </Card>
              </div>

              {/* File Types Breakdown */}
              <Card className="p-4 mt-4">
                <h3 className="text-lg font-semibold mb-3 flex items-center">
                  <Layers className="w-5 h-5 mr-2 text-accent" />
                  File Types Breakdown
                </h3>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  {Object.entries(scanResult.fileTypes)
                    .sort(([, a], [, b]) => b - a)
                    .map(([ext, count]) => (
                      <div key={ext} className="bg-muted/20 p-3 rounded">
                        <p className="text-sm text-muted-foreground">{ext || 'no ext'}</p>
                        <p className="text-xl font-bold">{count}</p>
                      </div>
                    ))}
                </div>
              </Card>
            </TabsContent>

            {/* Files Tab */}
            <TabsContent value="files">
              <Card className="p-4">
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-border">
                        <th className="text-left p-2 cursor-pointer hover:bg-muted/20" onClick={() => handleSort('name')}>
                          <div className="flex items-center">
                            Name
                            <SortIcon field="name" />
                          </div>
                        </th>
                        <th className="text-left p-2">Path</th>
                        <th className="text-right p-2 cursor-pointer hover:bg-muted/20" onClick={() => handleSort('size')}>
                          <div className="flex items-center justify-end">
                            Size
                            <SortIcon field="size" />
                          </div>
                        </th>
                        <th className="text-left p-2 cursor-pointer hover:bg-muted/20" onClick={() => handleSort('type')}>
                          <div className="flex items-center">
                            Type
                            <SortIcon field="type" />
                          </div>
                        </th>
                        {analyzedFiles.length > 0 && (
                          <>
                            <th className="text-right p-2 cursor-pointer hover:bg-muted/20" onClick={() => handleSort('entropy')}>
                              <div className="flex items-center justify-end">
                                Entropy
                                <SortIcon field="entropy" />
                              </div>
                            </th>
                            <th className="text-right p-2 cursor-pointer hover:bg-muted/20" onClick={() => handleSort('strings')}>
                              <div className="flex items-center justify-end">
                                Strings
                                <SortIcon field="strings" />
                              </div>
                            </th>
                          </>
                        )}
                        <th className="text-left p-2">Status</th>
                        <th className="text-left p-2">Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredFiles.map((file) => (
                        <tr key={file.id} className="border-b border-border/50 hover:bg-muted/10">
                          <td className="p-2">
                            <div className="flex items-center gap-2">
                              {file.isHidden && <EyeOff className="w-3 h-3 text-yellow-400" />}
                              {file.analysisResult?.hasUtf16EncodingIssue && <Zap className="w-3 h-3 text-orange-400" />}
                              <span className="font-mono text-xs">{file.name}</span>
                            </div>
                          </td>
                          <td className="p-2 text-muted-foreground text-xs max-w-xs truncate">
                            {file.relativePath}
                          </td>
                          <td className="p-2 text-right font-mono text-xs">
                            {formatFileSize(file.size)}
                          </td>
                          <td className="p-2">
                            <span className="text-xs px-2 py-1 bg-accent/10 text-accent rounded">
                              {file.extension || 'none'}
                            </span>
                          </td>
                          {analyzedFiles.length > 0 && (
                            <>
                              <td className="p-2 text-right">
                                {file.analysisResult ? (
                                  <span className={`font-mono text-xs ${getEntropyColor(file.analysisResult.entropy)}`}>
                                    {file.analysisResult.entropy.toFixed(2)}
                                  </span>
                                ) : (
                                  <span className="text-muted-foreground text-xs">-</span>
                                )}
                              </td>
                              <td className="p-2 text-right font-mono text-xs">
                                {file.analysisResult?.stringCount || 0}
                              </td>
                            </>
                          )}
                          <td className="p-2">
                            {file.size === 0 ? (
                              <span className="flex items-center text-xs text-red-400">
                                <XCircle className="w-3 h-3 mr-1" />
                                Empty
                              </span>
                            ) : file.analysisResult?.isEmpty ? (
                              <span className="flex items-center text-xs text-red-400">
                                <XCircle className="w-3 h-3 mr-1" />
                                No Data
                              </span>
                            ) : file.analysisResult?.hasStrings ? (
                              <span className="flex items-center text-xs text-green-400">
                                <CheckCircle className="w-3 h-3 mr-1" />
                                Has Data
                              </span>
                            ) : (
                              <span className="flex items-center text-xs text-yellow-400">
                                <AlertTriangle className="w-3 h-3 mr-1" />
                                Unknown
                              </span>
                            )}
                          </td>
                          <td className="p-2">
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => {
                                setSelectedFile(file)
                                setActiveTab('preview')
                              }}
                            >
                              <Eye className="w-3 h-3" />
                            </Button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>

                  {filteredFiles.length === 0 && (
                    <div className="text-center py-8 text-muted-foreground">
                      No files match the current filters
                    </div>
                  )}
                </div>
              </Card>
            </TabsContent>

            {/* Insights Tab */}
            <TabsContent value="insights">
              <div className="space-y-4">
                {/* File Type Distribution */}
                <Card className="p-4">
                  <h3 className="text-lg font-semibold mb-3 flex items-center">
                    <Layers className="w-5 h-5 mr-2 text-accent" />
                    File Type Distribution
                  </h3>
                  <div className="space-y-2">
                    {Object.entries(scanResult.fileTypes)
                      .sort(([, a], [, b]) => b - a)
                      .map(([ext, count]) => {
                        const percentage = (count / scanResult.totalFiles) * 100
                        return (
                          <div key={ext} className="space-y-1">
                            <div className="flex justify-between text-sm">
                              <span className="font-mono">.{ext || 'no ext'}</span>
                              <span className="text-muted-foreground">
                                {count} files ({percentage.toFixed(1)}%)
                              </span>
                            </div>
                            <div className="w-full bg-muted rounded-full h-2">
                              <div
                                className="bg-accent h-2 rounded-full transition-all"
                                style={{ width: `${percentage}%` }}
                              />
                            </div>
                          </div>
                        )
                      })}
                  </div>
                </Card>

                {/* Anomaly Detection */}
                <Card className="p-4">
                  <h3 className="text-lg font-semibold mb-3 flex items-center">
                    <AlertTriangle className="w-5 h-5 mr-2 text-orange-400" />
                    Anomalies & Outliers
                  </h3>
                  <div className="space-y-3">
                    {/* High Entropy Files */}
                    {(() => {
                      const highEntropyFiles = (analyzedFiles.length > 0 ? analyzedFiles : scanResult.files)
                        .filter(f => f.analysisResult && f.analysisResult.entropy > 7.5)
                      return highEntropyFiles.length > 0 ? (
                        <div className="bg-orange-500/10 border border-orange-500/30 rounded p-3">
                          <h4 className="text-sm font-medium mb-2 text-orange-400">
                            🔥 High Entropy Files ({highEntropyFiles.length}) - Possible Encryption/Compression
                          </h4>
                          <div className="space-y-1">
                            {highEntropyFiles.slice(0, 5).map((file, i) => (
                              <div key={i} className="text-xs font-mono flex justify-between">
                                <span>{file.name}</span>
                                <span className="text-orange-400">{file.analysisResult!.entropy.toFixed(2)}</span>
                              </div>
                            ))}
                            {highEntropyFiles.length > 5 && (
                              <p className="text-xs text-muted-foreground">
                                +{highEntropyFiles.length - 5} more
                              </p>
                            )}
                          </div>
                        </div>
                      ) : null
                    })()}

                    {/* Empty Files */}
                    {scanResult.emptyFileCount > 0 && (
                      <div className="bg-red-500/10 border border-red-500/30 rounded p-3">
                        <h4 className="text-sm font-medium mb-2 text-red-400">
                          📭 Empty Files ({scanResult.emptyFileCount})
                        </h4>
                        <div className="space-y-1">
                          {scanResult.files
                            .filter(f => f.size === 0)
                            .slice(0, 5)
                            .map((file, i) => (
                              <div key={i} className="text-xs font-mono">{file.name}</div>
                            ))}
                        </div>
                      </div>
                    )}

                    {/* Hidden Files */}
                    {scanResult.hiddenFileCount > 0 && (
                      <div className="bg-yellow-500/10 border border-yellow-500/30 rounded p-3">
                        <h4 className="text-sm font-medium mb-2 text-yellow-400">
                          👁️ Hidden Files ({scanResult.hiddenFileCount})
                        </h4>
                        <div className="space-y-1">
                          {scanResult.files
                            .filter(f => f.isHidden)
                            .slice(0, 5)
                            .map((file, i) => (
                              <div key={i} className="text-xs font-mono">{file.name}</div>
                            ))}
                        </div>
                      </div>
                    )}

                    {/* Files with URLs */}
                    {(() => {
                      const filesWithUrls = (analyzedFiles.length > 0 ? analyzedFiles : scanResult.files)
                        .filter(f => f.analysisResult?.interestingPatterns.urls && f.analysisResult.interestingPatterns.urls.length > 0)
                      return filesWithUrls.length > 0 ? (
                        <div className="bg-blue-500/10 border border-blue-500/30 rounded p-3">
                          <h4 className="text-sm font-medium mb-2 text-blue-400">
                            🌐 Files with URLs ({filesWithUrls.length})
                          </h4>
                          <div className="space-y-1">
                            {filesWithUrls.slice(0, 3).map((file, i) => (
                              <div key={i} className="text-xs">
                                <span className="font-mono">{file.name}</span>
                                <span className="text-muted-foreground ml-2">
                                  ({file.analysisResult!.interestingPatterns.urls.length} URLs)
                                </span>
                              </div>
                            ))}
                          </div>
                        </div>
                      ) : null
                    })()}

                    {/* Files with Base64 */}
                    {(() => {
                      const filesWithBase64 = (analyzedFiles.length > 0 ? analyzedFiles : scanResult.files)
                        .filter(f => f.analysisResult?.interestingPatterns.base64 && f.analysisResult.interestingPatterns.base64.length > 0)
                      return filesWithBase64.length > 0 ? (
                        <div className="bg-purple-500/10 border border-purple-500/30 rounded p-3">
                          <h4 className="text-sm font-medium mb-2 text-purple-400">
                            🔐 Files with Base64 ({filesWithBase64.length})
                          </h4>
                          <div className="space-y-1">
                            {filesWithBase64.slice(0, 3).map((file, i) => (
                              <div key={i} className="text-xs">
                                <span className="font-mono">{file.name}</span>
                                <span className="text-muted-foreground ml-2">
                                  ({file.analysisResult!.interestingPatterns.base64.length} patterns)
                                </span>
                              </div>
                            ))}
                          </div>
                        </div>
                      ) : null
                    })()}
                  </div>
                </Card>

                {/* Duplicate Files */}
                {duplicateGroups.size > 0 && (
                  <Card className="p-4">
                    <h3 className="text-lg font-semibold mb-3 flex items-center">
                      <Copy className="w-5 h-5 mr-2 text-cyan-400" />
                      Duplicate Files ({duplicateGroups.size} groups)
                    </h3>
                    <div className="mb-3 text-sm text-muted-foreground">
                      💾 Wasted space: <span className="font-bold text-cyan-400">{formatFileSize(totalDuplicateSize)}</span>
                    </div>
                    <div className="space-y-3 max-h-[400px] overflow-y-auto">
                      {Array.from(duplicateGroups.entries()).slice(0, 10).map(([hash, files], idx) => (
                        <div key={idx} className="bg-cyan-500/10 border border-cyan-500/30 rounded p-3">
                          <h4 className="text-sm font-medium mb-2 text-cyan-400">
                            Group {idx + 1}: {files.length} identical files ({formatFileSize(files[0].size)} each)
                          </h4>
                          <div className="space-y-1 ml-3">
                            {files.map((file, i) => (
                              <div key={i} className="text-xs font-mono flex items-center gap-2">
                                <span className="text-muted-foreground">•</span>
                                <span className="truncate">{file.path}</span>
                              </div>
                            ))}
                          </div>
                          <div className="mt-2 text-xs text-muted-foreground font-mono">
                            SHA-256: {hash.substring(0, 16)}...
                          </div>
                        </div>
                      ))}
                      {duplicateGroups.size > 10 && (
                        <p className="text-sm text-muted-foreground text-center">
                          +{duplicateGroups.size - 10} more duplicate groups
                        </p>
                      )}
                    </div>
                  </Card>
                )}

                {/* Carved Files */}
                {carvedFiles.length > 0 && (
                  <Card className="p-4">
                    <h3 className="text-lg font-semibold mb-3 flex items-center">
                      <Database className="w-5 h-5 mr-2 text-green-400" />
                      File Carving Results
                    </h3>
                    <div className="mb-3 text-sm text-muted-foreground">
                      Found embedded file signatures in {carvedFiles.length} files
                      {isCarving && <span className="ml-2 text-accent">Scanning...</span>}
                    </div>
                    <div className="space-y-3 max-h-[400px] overflow-y-auto">
                      {carvedFiles.slice(0, 20).map((result, idx) => (
                        <div key={idx} className="bg-green-500/10 border border-green-500/30 rounded p-3">
                          <h4 className="text-sm font-medium mb-2 text-green-400">
                            📄 {result.sourceFile.name}
                          </h4>
                          <div className="ml-3 space-y-1">
                            {result.signatures.map((sig, i) => (
                              <div key={i} className="text-xs font-mono flex items-center gap-2">
                                <span className="text-green-400">🔍</span>
                                <span className="font-bold">{sig.type}</span>
                                <span className="text-muted-foreground">at offset</span>
                                <span className="text-accent">{sig.offset}</span>
                                <span className="text-muted-foreground">(0x{sig.offset.toString(16)})</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      ))}
                      {carvedFiles.length > 20 && (
                        <p className="text-sm text-muted-foreground text-center">
                          +{carvedFiles.length - 20} more files with embedded signatures
                        </p>
                      )}
                    </div>
                  </Card>
                )}

                {/* Size Distribution */}
                <Card className="p-4">
                  <h3 className="text-lg font-semibold mb-3">File Size Distribution</h3>
                  <div className="space-y-2">
                    {(() => {
                      const sizeRanges = {
                        'Empty (0 bytes)': scanResult.files.filter(f => f.size === 0).length,
                        'Tiny (1-1KB)': scanResult.files.filter(f => f.size > 0 && f.size <= 1024).length,
                        'Small (1KB-100KB)': scanResult.files.filter(f => f.size > 1024 && f.size <= 100 * 1024).length,
                        'Medium (100KB-1MB)': scanResult.files.filter(f => f.size > 100 * 1024 && f.size <= 1024 * 1024).length,
                        'Large (>1MB)': scanResult.files.filter(f => f.size > 1024 * 1024).length
                      }
                      return Object.entries(sizeRanges).map(([range, count]) => {
                        const percentage = (count / scanResult.totalFiles) * 100
                        return count > 0 ? (
                          <div key={range} className="space-y-1">
                            <div className="flex justify-between text-sm">
                              <span>{range}</span>
                              <span className="text-muted-foreground">{count} files ({percentage.toFixed(1)}%)</span>
                            </div>
                            <div className="w-full bg-muted rounded-full h-2">
                              <div
                                className="bg-accent h-2 rounded-full transition-all"
                                style={{ width: `${percentage}%` }}
                              />
                            </div>
                          </div>
                        ) : null
                      })
                    })()}
                  </div>
                </Card>
              </div>
            </TabsContent>

            {/* Preview Tab */}
            {selectedFile && (
              <TabsContent value="preview">
                <Card className="p-4 space-y-4">
                  <div>
                    <h3 className="text-lg font-semibold mb-2">File Details</h3>
                    <div className="grid grid-cols-2 gap-3 text-sm">
                      <div>
                        <span className="text-muted-foreground">Name:</span>
                        <p className="font-mono">{selectedFile.name}</p>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Path:</span>
                        <p className="font-mono text-xs">{selectedFile.relativePath}</p>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Size:</span>
                        <p className="font-mono">{formatFileSize(selectedFile.size)}</p>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Type:</span>
                        <p className="font-mono">{selectedFile.type}</p>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Modified:</span>
                        <p className="font-mono text-xs">{selectedFile.lastModified.toLocaleString()}</p>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Hidden:</span>
                        <p>{selectedFile.isHidden ? 'Yes' : 'No'}</p>
                      </div>
                      {selectedFile.analysisResult && (
                        <>
                          <div>
                            <span className="text-muted-foreground">Entropy:</span>
                            <p className={`font-mono ${getEntropyColor(selectedFile.analysisResult.entropy)}`}>
                              {selectedFile.analysisResult.entropy.toFixed(2)}
                            </p>
                          </div>
                          <div>
                            <span className="text-muted-foreground">Detected Type:</span>
                            <p className="font-mono">{selectedFile.analysisResult.detectedType}</p>
                          </div>
                          <div>
                            <span className="text-muted-foreground">SHA-256:</span>
                            <p className="font-mono text-xs break-all">
                              {selectedFile.analysisResult.hash.sha256 || 'Not calculated'}
                            </p>
                          </div>
                          <div>
                            <span className="text-muted-foreground">Magic Bytes:</span>
                            <p className="font-mono text-xs">{selectedFile.analysisResult.magicBytes || 'None'}</p>
                          </div>
                          {selectedFile.analysisResult.hasUtf16EncodingIssue && (
                            <div className="md:col-span-2">
                              <span className="text-muted-foreground">Encoding:</span>
                              <div className="flex items-center gap-2 mt-1">
                                <span className="inline-flex items-center gap-1 px-2 py-1 bg-orange-500/10 text-orange-400 rounded text-xs border border-orange-500/20">
                                  <Zap className="w-3 h-3" />
                                  UTF-16 Encoding Issue Detected & Fixed
                                </span>
                              </div>
                            </div>
                          )}
                        </>
                      )}
                    </div>
                  </div>

                  {selectedFile.analysisResult && selectedFile.analysisResult.printableStrings.length > 0 && (
                    <div>
                      <h3 className="text-lg font-semibold mb-2">
                        {selectedFile.analysisResult.hasUtf16EncodingIssue ? 'Raw Strings' : 'Extracted Strings'}
                      </h3>
                      <div className="bg-muted/20 p-3 rounded max-h-64 overflow-auto font-mono text-xs space-y-1">
                        {selectedFile.analysisResult.printableStrings.map((str, idx) => (
                          <div key={idx} className="text-foreground">
                            {str}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {selectedFile.analysisResult?.hasUtf16EncodingIssue && selectedFile.analysisResult.utf16DecodedStrings && selectedFile.analysisResult.utf16DecodedStrings.length > 0 && (
                    <div>
                      <h3 className="text-lg font-semibold mb-2 flex items-center gap-2">
                        <Zap className="w-5 h-5 text-orange-400" />
                        UTF-16 Decoded Strings
                      </h3>
                      <div className="bg-orange-500/5 border border-orange-500/20 p-3 rounded max-h-64 overflow-auto font-mono text-xs space-y-1">
                        {selectedFile.analysisResult.utf16DecodedStrings.map((str, idx) => (
                          <div key={idx} className="text-foreground">
                            {str}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {selectedFile.analysisResult && (
                    <div>
                      <h3 className="text-lg font-semibold mb-2">Interesting Patterns</h3>
                      <div className="space-y-2">
                        {selectedFile.analysisResult.interestingPatterns.urls.length > 0 && (
                          <div>
                            <p className="text-sm text-muted-foreground">URLs:</p>
                            <div className="bg-muted/20 p-2 rounded font-mono text-xs">
                              {selectedFile.analysisResult.interestingPatterns.urls.join('\n')}
                            </div>
                          </div>
                        )}
                        {selectedFile.analysisResult.interestingPatterns.emails.length > 0 && (
                          <div>
                            <p className="text-sm text-muted-foreground">Emails:</p>
                            <div className="bg-muted/20 p-2 rounded font-mono text-xs">
                              {selectedFile.analysisResult.interestingPatterns.emails.join('\n')}
                            </div>
                          </div>
                        )}
                        {selectedFile.analysisResult.interestingPatterns.ips.length > 0 && (
                          <div>
                            <p className="text-sm text-muted-foreground">IP Addresses:</p>
                            <div className="bg-muted/20 p-2 rounded font-mono text-xs">
                              {selectedFile.analysisResult.interestingPatterns.ips.join('\n')}
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {selectedFile.analysisResult?.hexDump && (
                    <div>
                      <h3 className="text-lg font-semibold mb-2">Hex Dump (First 1KB)</h3>
                      <div className="bg-muted/20 p-3 rounded overflow-x-auto">
                        <pre className="font-mono text-xs text-foreground whitespace-pre">
                          {selectedFile.analysisResult.hexDump}
                        </pre>
                      </div>
                    </div>
                  )}
                </Card>
              </TabsContent>
            )}
          </Tabs>
        </div>
      )}
    </div>
  )
}

export default FolderScanner
