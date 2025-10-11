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
  Zap
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
  type FileEntry,
  type FolderScanResult,
  type FilterOptions
} from '../lib/folderAnalysis'

type SortField = 'name' | 'size' | 'type' | 'entropy' | 'strings' | 'modified'
type SortDirection = 'asc' | 'desc'

const FolderScanner: React.FC = () => {
  const [scanResult, setScanResult] = useState<FolderScanResult | null>(null)
  const [analyzedFiles, setAnalyzedFiles] = useState<FileEntry[]>([])
  const [filteredFiles, setFilteredFiles] = useState<FileEntry[]>([])
  const [selectedFile, setSelectedFile] = useState<FileEntry | null>(null)
  const [isScanning, setIsScanning] = useState(false)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [analysisProgress, setAnalysisProgress] = useState({ current: 0, total: 0 })
  const [activeTab, setActiveTab] = useState<'overview' | 'files' | 'preview'>('overview')

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

  // Apply filters and sorting whenever they change
  useEffect(() => {
    if (!scanResult) return

    const filesToFilter = analyzedFiles.length > 0 ? analyzedFiles : scanResult.files
    let filtered = filterFiles(filesToFilter, filters)

    // Apply sorting
    filtered = sortFiles(filtered, sortField, sortDirection)

    setFilteredFiles(filtered)
  }, [filters, analyzedFiles, scanResult, sortField, sortDirection])

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

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <FolderOpen className="w-8 h-8 text-accent" />
            Folder
          </h1>
          <p className="text-muted-foreground mt-1">
            Bulk scan folders and filter files by content, including hidden files
          </p>
        </div>
      </div>

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
            <Button onClick={() => setShowFilters(!showFilters)} variant="outline">
              <Filter className="w-4 h-4 mr-2" />
              Filters {showFilters ? '▲' : '▼'}
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
          </div>

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
                              {file.analysisResult?.hasUtf16EncodingIssue && <Zap className="w-3 h-3 text-orange-400" title="UTF-16 encoding issue detected" />}
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
