import React, { useState } from 'react'
import { Radio, Hash, Search, Eye, AlertTriangle, CheckCircle } from 'lucide-react'
import { Button } from '../ui/button'
import { Input } from '../ui/input'
import { Card } from '../ui/card'
import type { MorseResult, DTMFResult } from '../../lib/audioAnalysis'

interface SteganographyTabProps {
  strings: string[]
  morseResult: MorseResult | null
  dtmfResult: DTMFResult | null
  lsbData: string
  onAnalyzeMorse?: () => void
  onAnalyzeDTMF?: () => void
  onAnalyzeLSB?: () => void
  onAnalyzeStrings?: () => void
  isAnalyzing?: boolean
}

export const SteganographyTab: React.FC<SteganographyTabProps> = ({
  strings,
  morseResult,
  dtmfResult,
  lsbData,
  onAnalyzeMorse,
  onAnalyzeDTMF,
  onAnalyzeLSB,
  onAnalyzeStrings,
  isAnalyzing
}) => {
  const [stringFilter, setStringFilter] = useState('')

  const filteredStrings = strings.filter(s => 
    s.toLowerCase().includes(stringFilter.toLowerCase())
  )

  return (
    <div className="space-y-6">
      {/* Morse Code Detection */}
      <Card className="p-6 bg-card border-border">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold flex items-center gap-2">
            <Radio className="w-5 h-5 text-accent" />
            Morse Code Detection
          </h3>
          {onAnalyzeMorse && (
            <Button
              variant="outline"
              size="sm"
              onClick={onAnalyzeMorse}
              disabled={isAnalyzing}
            >
              {isAnalyzing ? 'Analyzing...' : 'Analyze'}
            </Button>
          )}
        </div>

        {morseResult ? (
          <div className="space-y-4">
            {morseResult.detected ? (
              <>
                <div className="flex items-center gap-2 text-green-500">
                  <CheckCircle className="w-4 h-4" />
                  <span className="font-semibold">Morse Code Detected!</span>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground mb-2">Decoded Message:</p>
                  <div className="p-4 bg-green-900/20 border border-green-500 rounded">
                    <p className="font-mono text-lg">{morseResult.message}</p>
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <p className="text-muted-foreground">Confidence:</p>
                    <p className="font-semibold">{(morseResult.confidence * 100).toFixed(1)}%</p>
                  </div>
                  <div>
                    <p className="text-muted-foreground">Symbols Found:</p>
                    <p className="font-semibold">{morseResult.positions.length}</p>
                  </div>
                </div>
              </>
            ) : (
              <div className="flex items-center gap-2 text-muted-foreground">
                <AlertTriangle className="w-4 h-4" />
                <span>No Morse code pattern detected</span>
              </div>
            )}
          </div>
        ) : (
          <p className="text-muted-foreground text-sm">Click Analyze to detect Morse code patterns</p>
        )}
      </Card>

      {/* DTMF Detection */}
      <Card className="p-6 bg-card border-border">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold flex items-center gap-2">
            <Hash className="w-5 h-5 text-accent" />
            DTMF Tone Detection
          </h3>
          {onAnalyzeDTMF && (
            <Button
              variant="outline"
              size="sm"
              onClick={onAnalyzeDTMF}
              disabled={isAnalyzing}
            >
              {isAnalyzing ? 'Analyzing...' : 'Analyze'}
            </Button>
          )}
        </div>

        {dtmfResult ? (
          <div className="space-y-4">
            {dtmfResult.detected ? (
              <>
                <div className="flex items-center gap-2 text-green-500">
                  <CheckCircle className="w-4 h-4" />
                  <span className="font-semibold">DTMF Tones Detected!</span>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground mb-2">Decoded Sequence:</p>
                  <div className="p-4 bg-blue-900/20 border border-blue-500 rounded">
                    <p className="font-mono text-2xl tracking-wider">{dtmfResult.sequence}</p>
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <p className="text-muted-foreground">Tones Found:</p>
                    <p className="font-semibold">{dtmfResult.tones.length}</p>
                  </div>
                </div>
                <details className="text-xs">
                  <summary className="cursor-pointer text-muted-foreground hover:text-foreground">
                    View tone details
                  </summary>
                  <div className="mt-2 space-y-1">
                    {dtmfResult.tones.map((tone, i) => (
                      <div key={i} className="font-mono p-1 bg-gray-900 rounded">
                        {tone.digit} @ {tone.timestamp.toFixed(2)}s (duration: {tone.duration.toFixed(3)}s)
                      </div>
                    ))}
                  </div>
                </details>
              </>
            ) : (
              <div className="flex items-center gap-2 text-muted-foreground">
                <AlertTriangle className="w-4 h-4" />
                <span>No DTMF tones detected</span>
              </div>
            )}
          </div>
        ) : (
          <p className="text-muted-foreground text-sm">Click Analyze to detect DTMF tones</p>
        )}
      </Card>

      {/* LSB Steganography */}
      <Card className="p-6 bg-card border-border">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold flex items-center gap-2">
            <Eye className="w-5 h-5 text-accent" />
            LSB Steganography
          </h3>
          {onAnalyzeLSB && (
            <Button
              variant="outline"
              size="sm"
              onClick={onAnalyzeLSB}
              disabled={isAnalyzing}
            >
              {isAnalyzing ? 'Analyzing...' : 'Analyze'}
            </Button>
          )}
        </div>

        {lsbData ? (
          <div className="space-y-4">
            <div className="flex items-center gap-2 text-green-500">
              <CheckCircle className="w-4 h-4" />
              <span className="font-semibold">LSB Data Extracted!</span>
            </div>
            <div>
              <p className="text-xs text-muted-foreground mb-2">Extracted Data:</p>
              <textarea
                value={lsbData}
                readOnly
                className="w-full h-40 p-3 bg-gray-900 rounded border border-border font-mono text-xs resize-none"
              />
            </div>
            <p className="text-xs text-muted-foreground">
              Length: {lsbData.length} characters
            </p>
          </div>
        ) : (
          <p className="text-muted-foreground text-sm">Click Analyze to extract LSB hidden data</p>
        )}
      </Card>

      {/* String Extraction */}
      <Card className="p-6 bg-card border-border">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold flex items-center gap-2">
            <Search className="w-5 h-5 text-accent" />
            String Extraction
          </h3>
          {onAnalyzeStrings && (
            <Button
              variant="outline"
              size="sm"
              onClick={onAnalyzeStrings}
              disabled={isAnalyzing}
            >
              {isAnalyzing ? 'Analyzing...' : 'Analyze'}
            </Button>
          )}
        </div>

        {strings.length > 0 ? (
          <div className="space-y-4">
            <div className="flex items-center justify-between">
              <span className="text-sm text-muted-foreground">
                Found {filteredStrings.length} of {strings.length} strings
              </span>
              <Input
                placeholder="Filter strings..."
                value={stringFilter}
                onChange={(e) => setStringFilter(e.target.value)}
                className="w-64"
              />
            </div>
            <div className="max-h-96 overflow-y-auto space-y-1">
              {filteredStrings.map((str, i) => (
                <div key={i} className="p-2 bg-gray-900 rounded border border-border hover:border-accent transition-colors">
                  <code className="text-xs font-mono break-all">{str}</code>
                </div>
              ))}
            </div>
          </div>
        ) : (
          <p className="text-muted-foreground text-sm">Click Analyze to extract printable strings</p>
        )}
      </Card>
    </div>
  )
}
