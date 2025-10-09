import React, { useState, useEffect } from 'react'
import { 
  History, 
  Download, 
  Trash2, 
  Eye, 
  Search,
  Calendar,
  FileText,
  Share
} from 'lucide-react'

interface AnalysisResult {
  id: string
  type: 'pcap' | 'image' | 'crypto' | 'web' | 'forensics'
  title: string
  description: string
  timestamp: string
  status: 'completed' | 'failed' | 'in_progress'
  fileSize: string
  findings: number
  severity: 'low' | 'medium' | 'high' | 'critical'
  tags: string[]
}

const ResultsHistory: React.FC = () => {
  const [results, setResults] = useState<AnalysisResult[]>([])
  const [filteredResults, setFilteredResults] = useState<AnalysisResult[]>([])
  const [searchTerm, setSearchTerm] = useState('')
  const [filterType, setFilterType] = useState<string>('all')
  const [filterSeverity, setFilterSeverity] = useState<string>('all')
  const [selectedResults, setSelectedResults] = useState<string[]>([])
  const [isLoading, setIsLoading] = useState(true)

  const filterResults = React.useCallback(() => {
    let filtered = results

    // Search filter
    if (searchTerm) {
      filtered = filtered.filter(result => 
        (result.title || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
        (result.description || '').toLowerCase().includes(searchTerm.toLowerCase()) ||
        (result.tags || []).some(tag => String(tag || '').toLowerCase().includes(searchTerm.toLowerCase()))
      )
    }

    // Type filter
    if (filterType !== 'all') {
      filtered = filtered.filter(result => result.type === filterType)
    }

    // Severity filter
    if (filterSeverity !== 'all') {
      filtered = filtered.filter(result => result.severity === filterSeverity)
    }

    setFilteredResults(filtered)
  }, [results, searchTerm, filterType, filterSeverity])

  useEffect(() => {
    loadResults()
  }, [])

  // ensure dependencies include filterResults to satisfy hooks rule
  useEffect(() => { filterResults() }, [results, searchTerm, filterType, filterSeverity, filterResults])

  const loadResults = async () => {
    setIsLoading(true)
    try {
      const res = await blink.db.analysisResults.list({ orderBy: { createdAt: 'desc' } })
      const mapped = res.map((r: any) => ({
        id: r.id,
        type: r.type as any,
        title: r.title || r.type || 'Analysis',
        description: r.description || '',
        timestamp: r.timestamp || r.createdAt || '',
        status: r.status || 'completed',
        fileSize: r.file_size || 'N/A',
        findings: Number(r.findings || 0),
        severity: r.severity || 'low',
        tags: r.tags ? (typeof r.tags === 'string' ? r.tags.split(',') : r.tags) : []
      }))
      setResults(mapped)
    } catch (err) {
      console.error('Failed to load results from DB', err)
      setResults([])
    } finally {
      setIsLoading(false)
    }
  }

  const toggleSelection = (id: string) => {
    setSelectedResults(prev => 
      prev.includes(id) 
        ? prev.filter(resultId => resultId !== id)
        : [...prev, id]
    )
  }

  const selectAll = () => {
    setSelectedResults(filteredResults.map(result => result.id))
  }

  const clearSelection = () => {
    setSelectedResults([])
  }

  const deleteSelected = async () => {
    if (selectedResults.length === 0) return
    try {
      for (const id of selectedResults) {
        await blink.db.analysisResults.delete(id)
      }
    } catch (err) {
      console.error('Failed to delete selected results', err)
    }
    await loadResults()
    setSelectedResults([])
  }

  const clearAllResults = async () => {
    if (!confirm('Clear all results? This action cannot be undone.')) return
    try {
      const all = await blink.db.analysisResults.list()
      for (const r of all) {
        await blink.db.analysisResults.delete(r.id)
      }
    } catch (err) {
      console.error('Failed to clear results', err)
    }
    await loadResults()
    setSelectedResults([])
  }

  const exportSelected = () => {
    const selectedData = results.filter(result => selectedResults.includes(result.id))
    const dataStr = JSON.stringify(selectedData, null, 2)
    const dataBlob = new Blob([dataStr], { type: 'application/json' })
    const url = URL.createObjectURL(dataBlob)
    const link = document.createElement('a')
    link.href = url
    link.download = `ctf-analysis-results-${new Date().toISOString().split('T')[0]}.json`
    link.click()
    URL.revokeObjectURL(url)
  }

  const getTypeIcon = (type: string) => {
    switch (type) {
      case 'pcap': return '🌐'
      case 'image': return '🖼️'
      case 'crypto': return '🔐'
      case 'web': return '🌍'
      case 'forensics': return '🔍'
      default: return '📄'
    }
  }

  const getTypeColor = (type: string) => {
    switch (type) {
      case 'pcap': return 'text-blue-400 bg-blue-400/20'
      case 'image': return 'text-purple-400 bg-purple-400/20'
      case 'crypto': return 'text-green-400 bg-green-400/20'
      case 'web': return 'text-orange-400 bg-orange-400/20'
      case 'forensics': return 'text-indigo-400 bg-indigo-400/20'
      default: return 'text-gray-400 bg-gray-400/20'
    }
  }

  const getSeverityColor = (severity: string) => {
    switch (severity) {
      case 'critical': return 'text-red-500 bg-red-500/20'
      case 'high': return 'text-red-400 bg-red-400/20'
      case 'medium': return 'text-yellow-400 bg-yellow-400/20'
      case 'low': return 'text-green-400 bg-green-400/20'
      default: return 'text-gray-400 bg-gray-400/20'
    }
  }

  const getStatusColor = (status: string) => {
    switch (status) {
      case 'completed': return 'text-green-400'
      case 'failed': return 'text-red-400'
      case 'in_progress': return 'text-yellow-400'
      default: return 'text-gray-400'
    }
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center space-x-2">
            <History className="w-6 h-6 text-accent" />
            <span>Results History</span>
          </h1>
          <p className="text-muted-foreground mt-1">Previous analysis results. This page shows saved analysis outputs; it does not implement case management workflows.</p>
        </div>
        <div className="flex items-center space-x-2">
          <button onClick={exportSelected} disabled={selectedResults.length === 0} className="flex items-center space-x-2 bg-accent text-background px-4 py-2 rounded-lg hover:bg-accent/90 transition-colors disabled:opacity-50"><Download className="w-4 h-4"/><span>Export Selected</span></button>
          <button onClick={clearAllResults} className="flex items-center space-x-2 bg-card text-muted-foreground px-4 py-2 rounded-lg hover:bg-muted/10 transition-colors"><Trash2 className="w-4 h-4"/><span>Clear All</span></button>
        </div>
      </div>

      {/* Filters and Search */}
      <div className="bg-card border border-border rounded-lg p-6">
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <div className="relative">
            <Search className="w-4 h-4 absolute left-3 top-1/2 transform -translate-y-1/2 text-muted-foreground" />
            <input type="text" placeholder="Search results..." value={searchTerm} onChange={(e)=>setSearchTerm(e.target.value)} className="w-full pl-10 pr-4 py-2 bg-background border border-border rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent" />
          </div>

          <select value={filterType} onChange={(e)=>setFilterType(e.target.value)} className="px-3 py-2 bg-background border border-border rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent">
            <option value="all">All Types</option>
            <option value="pcap">PCAP Analysis</option>
            <option value="image">Image Analysis</option>
            <option value="crypto">Cryptography</option>
            <option value="web">Web Tools</option>
            <option value="forensics">Digital Forensics</option>
          </select>

          <select value={filterSeverity} onChange={(e)=>setFilterSeverity(e.target.value)} className="px-3 py-2 bg-background border border-border rounded-lg text-sm focus:outline-none focus:ring-2 focus:ring-accent">
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>

          <div className="flex items-center space-x-2">
            <button onClick={selectAll} className="text-sm text-accent hover:text-accent/80 transition-colors">Select All</button>
            <span className="text-muted-foreground">|</span>
            <button onClick={clearSelection} className="text-sm text-muted-foreground hover:text-foreground transition-colors">Clear Selection</button>
          </div>
        </div>
      </div>

      {/* Bulk Actions */}
      {selectedResults.length > 0 && (
        <div className="bg-accent/10 border border-accent/20 rounded-lg p-4">
          <div className="flex items-center justify-between">
            <span className="text-sm text-accent">{selectedResults.length} result{selectedResults.length !== 1 ? 's' : ''} selected</span>
            <div className="flex items-center space-x-2">
              <button onClick={exportSelected} className="flex items-center space-x-1 text-sm text-accent hover:text-accent/80 transition-colors"><Download className="w-4 h-4"/><span>Export</span></button>
              <button onClick={deleteSelected} className="flex items-center space-x-1 text-sm text-red-400 hover:text-red-300 transition-colors"><Trash2 className="w-4 h-4"/><span>Delete</span></button>
            </div>
          </div>
        </div>
      )}

      {/* Results List */}
      <div className="bg-card border border-border rounded-lg">
        <div className="p-4 border-b border-border">
          <h2 className="text-lg font-semibold">Analysis Results ({filteredResults.length})</h2>
        </div>

        {isLoading ? (
          <div className="p-8 text-center"><div className="animate-spin w-8 h-8 border-2 border-accent border-t border-transparent rounded-full mx-auto mb-4"></div><p className="text-muted-foreground">Loading results...</p></div>
        ) : filteredResults.length === 0 ? (
          <div className="p-8 text-center"><FileText className="w-12 h-12 text-muted-foreground mx-auto mb-4 opacity-50" /><p className="text-muted-foreground">No results found</p><p className="text-sm text-muted-foreground mt-2">Run tools to generate analysis results</p></div>
        ) : (
          <div className="space-y-px">
            {filteredResults.map((result)=> (
              <div key={result.id} className="p-4 hover:bg-muted/30 transition-colors">
                <div className="flex items-start space-x-4">
                  <input type="checkbox" checked={selectedResults.includes(result.id)} onChange={()=>toggleSelection(result.id)} className="mt-1 w-4 h-4 text-accent bg-background border-border rounded focus:ring-accent focus:ring-2" />
                  <div className="flex-1 space-y-3">
                    <div className="flex items-start justify-between">
                      <div className="space-y-1">
                        <h3 className="font-medium text-foreground">{result.title}</h3>
                        <p className="text-sm text-muted-foreground">{result.description}</p>
                      </div>
                      <div className="flex items-center space-x-2">
                        <button className="p-1 text-muted-foreground hover:text-accent transition-colors"><Eye className="w-4 h-4"/></button>
                        <button className="p-1 text-muted-foreground hover:text-accent transition-colors"><Download className="w-4 h-4"/></button>
                        <button className="p-1 text-muted-foreground hover:text-accent transition-colors"><Share className="w-4 h-4"/></button>
                      </div>
                    </div>

                    <div className="flex items-center space-x-4 text-sm">
                      <div className={`flex items-center space-x-1 px-2 py-1 rounded text-xs font-medium ${getTypeColor(result.type)}`}><span>{getTypeIcon(result.type)}</span><span className="capitalize">{result.type}</span></div>
                      <div className={`px-2 py-1 rounded text-xs font-medium ${getSeverityColor(result.severity)}`}>{result.severity.toUpperCase()}</div>
                      <div className={`flex items-center space-x-1 ${getStatusColor(result.status)}`}><div className={`w-2 h-2 rounded-full bg-current`}></div><span className="capitalize">{result.status.replace('_',' ')}</span></div>
                      <span className="text-muted-foreground">{result.findings} findings</span>
                      <span className="text-muted-foreground">{result.fileSize}</span>
                      <div className="flex items-center space-x-1 text-muted-foreground"><Calendar className="w-3 h-3"/><span>{result.timestamp}</span></div>
                    </div>

                    <div className="flex flex-wrap gap-1">{result.tags.map((tag,i)=> (<span key={i} className="px-2 py-1 bg-muted text-muted-foreground text-xs rounded">#{tag}</span>))}</div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

export default ResultsHistory
