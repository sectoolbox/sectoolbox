import React, { useState } from 'react'
import { 
  Copy, 
  Check, 
  Download, 
  ChevronDown, 
  ChevronRight,
  AlertCircle,
  CheckCircle2,
  Radio,
  Binary,
  Activity,
  Eye,
  Zap
} from 'lucide-react'
import { Button } from '../ui/button'
import toast from 'react-hot-toast'

export interface DecoderResult {
  type: 'morse' | 'dtmf' | 'binary' | 'lsb' | 'anomaly' | 'pattern' | 'string'
  detected: boolean
  confidence: number
  data: any
  description: string
  timestamp?: number
}

interface AnalysisResultsPanelProps {
  results: DecoderResult[]
  onJumpToTimestamp?: (time: number) => void
  onExportResults?: () => void
}

export const AnalysisResultsPanel: React.FC<AnalysisResultsPanelProps> = ({
  results,
  onJumpToTimestamp,
  onExportResults
}) => {
  const [expandedResults, setExpandedResults] = useState<Set<number>>(new Set([0]))
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null)

  const toggleExpanded = (index: number) => {
    const newExpanded = new Set(expandedResults)
    if (newExpanded.has(index)) {
      newExpanded.delete(index)
    } else {
      newExpanded.add(index)
    }
    setExpandedResults(newExpanded)
  }

  const copyToClipboard = (text: string, index: number) => {
    navigator.clipboard.writeText(text)
    setCopiedIndex(index)
    toast.success('Copied to clipboard!')
    setTimeout(() => setCopiedIndex(null), 2000)
  }

  const getIconForType = (type: string) => {
    switch (type) {
      case 'morse': return <Radio className="w-4 h-4" />
      case 'dtmf': return <Zap className="w-4 h-4" />
      case 'binary': return <Binary className="w-4 h-4" />
      case 'lsb': return <Eye className="w-4 h-4" />
      case 'anomaly': return <AlertCircle className="w-4 h-4" />
      case 'pattern': return <Activity className="w-4 h-4" />
      default: return <CheckCircle2 className="w-4 h-4" />
    }
  }

  const getConfidenceColor = (confidence: number) => {
    if (confidence >= 0.8) return 'text-green-500'
    if (confidence >= 0.5) return 'text-yellow-500'
    return 'text-orange-500'
  }

  const getConfidenceBg = (confidence: number) => {
    if (confidence >= 0.8) return 'bg-green-500/20 border-green-500/30'
    if (confidence >= 0.5) return 'bg-yellow-500/20 border-yellow-500/30'
    return 'bg-orange-500/20 border-orange-500/30'
  }

  const detectedResults = results.filter(r => r.detected)
  const undetectedResults = results.filter(r => !r.detected)

  if (results.length === 0) {
    return (
      <div className="border border-border rounded-lg p-6 text-center">
        <Activity className="w-12 h-12 mx-auto text-slate-600 mb-3" />
        <p className="text-slate-400 text-sm">No analysis results yet</p>
        <p className="text-slate-500 text-xs mt-1">Upload and analyze an audio file to see results</p>
      </div>
    )
  }

  return (
    <div className="border border-border rounded-lg bg-card">
      {/* Header */}
      <div className="p-4 border-b border-border flex items-center justify-between">
        <div className="flex items-center gap-3">
          <Activity className="w-5 h-5 text-blue-500" />
          <div>
            <h3 className="font-semibold text-sm">Analysis Results</h3>
            <p className="text-xs text-slate-500">
              {detectedResults.length} detection{detectedResults.length !== 1 ? 's' : ''} found • {results.length} methods tested
            </p>
          </div>
        </div>
        {onExportResults && (
          <Button
            size="sm"
            variant="outline"
            onClick={onExportResults}
            className="h-8"
          >
            <Download className="w-3 h-3 mr-1.5" />
            Export All
          </Button>
        )}
      </div>

      {/* Results List */}
      <div className="max-h-[600px] overflow-y-auto">
        {/* Detected Results */}
        {detectedResults.length > 0 && (
          <div className="p-3 space-y-2">
            <div className="text-xs font-medium text-green-500 px-2 flex items-center gap-1.5">
              <CheckCircle2 className="w-3.5 h-3.5" />
              DETECTIONS ({detectedResults.length})
            </div>
            {detectedResults.map((result) => {
              const globalIdx = results.indexOf(result)
              const isExpanded = expandedResults.has(globalIdx)
              
              return (
                <div
                  key={globalIdx}
                  className={`border rounded-lg transition-all ${getConfidenceBg(result.confidence)}`}
                >
                  {/* Result Header */}
                  <button
                    onClick={() => toggleExpanded(globalIdx)}
                    className="w-full p-3 flex items-center gap-3 hover:bg-slate-800/30 transition-colors rounded-t-lg"
                  >
                    <div className="flex-shrink-0">
                      {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                    </div>
                    
                    <div className="flex-shrink-0 text-slate-400">
                      {getIconForType(result.type)}
                    </div>

                    <div className="flex-1 text-left">
                      <div className="font-medium text-sm">{result.description}</div>
                      <div className="text-xs text-slate-400 mt-0.5">
                        Type: {result.type.toUpperCase()} • Confidence: {' '}
                        <span className={getConfidenceColor(result.confidence)}>
                          {(result.confidence * 100).toFixed(0)}%
                        </span>
                      </div>
                    </div>

                    {result.timestamp !== undefined && onJumpToTimestamp && (
                      <Button
                        size="sm"
                        variant="ghost"
                        onClick={(e) => {
                          e.stopPropagation()
                          onJumpToTimestamp(result.timestamp!)
                        }}
                        className="h-7 text-xs"
                      >
                        Jump to {result.timestamp.toFixed(2)}s
                      </Button>
                    )}
                  </button>

                  {/* Result Details */}
                  {isExpanded && (
                    <div className="p-3 border-t border-slate-700/50 space-y-2">
                      {/* Morse Code Result */}
                      {result.type === 'morse' && result.data.message && (
                        <div className="space-y-2">
                          <div className="bg-slate-900 rounded p-3 font-mono text-sm">
                            {result.data.message}
                          </div>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => copyToClipboard(result.data.message, globalIdx)}
                            className="w-full h-8"
                          >
                            {copiedIndex === globalIdx ? (
                              <><Check className="w-3 h-3 mr-1.5" /> Copied!</>
                            ) : (
                              <><Copy className="w-3 h-3 mr-1.5" /> Copy Message</>
                            )}
                          </Button>
                        </div>
                      )}

                      {/* DTMF Result */}
                      {result.type === 'dtmf' && result.data.sequence && (
                        <div className="space-y-2">
                          <div className="bg-slate-900 rounded p-3">
                            <div className="font-mono text-2xl tracking-wider text-center">
                              {result.data.sequence}
                            </div>
                            {result.data.tones && (
                              <div className="mt-3 text-xs text-slate-400 space-y-1">
                                {result.data.tones.map((tone: any, i: number) => (
                                  <div key={i} className="flex justify-between">
                                    <span>Digit: {tone.digit}</span>
                                    <span>{tone.timestamp.toFixed(2)}s ({tone.duration.toFixed(2)}s)</span>
                                  </div>
                                ))}
                              </div>
                            )}
                          </div>
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => copyToClipboard(result.data.sequence, globalIdx)}
                            className="w-full h-8"
                          >
                            {copiedIndex === globalIdx ? (
                              <><Check className="w-3 h-3 mr-1.5" /> Copied!</>
                            ) : (
                              <><Copy className="w-3 h-3 mr-1.5" /> Copy Sequence</>
                            )}
                          </Button>
                        </div>
                      )}

                      {/* Binary/LSB Result */}
                      {(result.type === 'binary' || result.type === 'lsb') && result.data.decodedText && (
                        <div className="space-y-2">
                          <div className="text-xs text-slate-400 mb-1">Decoded Text:</div>
                          <div className="bg-slate-900 rounded p-3 font-mono text-sm max-h-40 overflow-y-auto">
                            {result.data.decodedText}
                          </div>
                          {result.data.binaryString && (
                            <details className="text-xs">
                              <summary className="cursor-pointer text-slate-500 hover:text-slate-400">
                                Show binary ({result.data.binaryString.length} bits)
                              </summary>
                              <div className="bg-slate-900 rounded p-2 font-mono text-xs mt-2 break-all max-h-20 overflow-y-auto">
                                {result.data.binaryString}
                              </div>
                            </details>
                          )}
                          <Button
                            size="sm"
                            variant="outline"
                            onClick={() => copyToClipboard(result.data.decodedText, globalIdx)}
                            className="w-full h-8"
                          >
                            {copiedIndex === globalIdx ? (
                              <><Check className="w-3 h-3 mr-1.5" /> Copied!</>
                            ) : (
                              <><Copy className="w-3 h-3 mr-1.5" /> Copy Text</>
                            )}
                          </Button>
                        </div>
                      )}

                      {/* Anomaly Result */}
                      {result.type === 'anomaly' && (
                        <div className="space-y-2">
                          <div className="grid grid-cols-2 gap-2 text-xs">
                            <div>
                              <span className="text-slate-500">Type:</span>{' '}
                              <span className="font-mono">{result.data.type || 'Unknown'}</span>
                            </div>
                            {result.data.frequency && (
                              <div>
                                <span className="text-slate-500">Frequency:</span>{' '}
                                <span className="font-mono">{result.data.frequency.toFixed(0)} Hz</span>
                              </div>
                            )}
                            {result.data.duration && (
                              <div>
                                <span className="text-slate-500">Duration:</span>{' '}
                                <span className="font-mono">{result.data.duration.toFixed(3)}s</span>
                              </div>
                            )}
                          </div>
                          {result.data.description && (
                            <div className="text-xs text-slate-400 italic">
                              {result.data.description}
                            </div>
                          )}
                        </div>
                      )}

                      {/* String Result */}
                      {result.type === 'string' && result.data.strings && (
                        <div className="bg-slate-900 rounded p-3 max-h-40 overflow-y-auto">
                          <div className="space-y-1 text-xs font-mono">
                            {result.data.strings.slice(0, 20).map((str: string, i: number) => (
                              <div key={i} className="hover:bg-slate-800 px-1 rounded">{str}</div>
                            ))}
                            {result.data.strings.length > 20 && (
                              <div className="text-slate-500 px-1">
                                ... and {result.data.strings.length - 20} more
                              </div>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )}

        {/* Undetected Results (Collapsible) */}
        {undetectedResults.length > 0 && (
          <details className="p-3 border-t border-border">
            <summary className="text-xs font-medium text-slate-500 px-2 cursor-pointer hover:text-slate-400 flex items-center gap-1.5">
              <AlertCircle className="w-3.5 h-3.5" />
              NO DETECTION ({undetectedResults.length} methods)
            </summary>
            <div className="mt-2 space-y-1">
              {undetectedResults.map((result) => {
                const globalIdx = results.indexOf(result)
                return (
                  <div
                    key={globalIdx}
                    className="p-2 rounded bg-slate-900/30 text-xs text-slate-500 flex items-center gap-2"
                  >
                    <div className="flex-shrink-0">{getIconForType(result.type)}</div>
                    <div>{result.description}</div>
                  </div>
                )
              })}
            </div>
          </details>
        )}
      </div>
    </div>
  )
}
