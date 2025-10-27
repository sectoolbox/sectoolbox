import React, { useRef, useEffect } from 'react'
import { FileAudio, Activity, Hash, Zap } from 'lucide-react'
import { Button } from '../ui/button'
import { Card } from '../ui/card'
import type { AudioMetadata } from '../../lib/audioAnalysis'

interface OverviewTabProps {
  file: File | null
  metadata: AudioMetadata | null
  waveformData: Float32Array | null
  currentTime: number
  onAnalyzeAll?: () => void
  isAnalyzing?: boolean
  formatDuration: (seconds: number) => string
  formatFileSize: (bytes: number) => string
}

export const OverviewTab: React.FC<OverviewTabProps> = ({
  file,
  metadata,
  waveformData,
  currentTime,
  onAnalyzeAll,
  isAnalyzing,
  formatDuration,
  formatFileSize
}) => {
  const canvasRef = useRef<HTMLCanvasElement>(null)

  // Draw waveform
  useEffect(() => {
    if (!waveformData || !canvasRef.current) return

    const canvas = canvasRef.current
    const ctx = canvas.getContext('2d')
    if (!ctx) return

    const width = canvas.width
    const height = canvas.height
    const samples = waveformData.length

    // Clear canvas
    ctx.fillStyle = '#1a1a1a'
    ctx.fillRect(0, 0, width, height)

    // Draw waveform
    ctx.strokeStyle = '#10b981'
    ctx.lineWidth = 2
    ctx.beginPath()

    for (let i = 0; i < samples; i++) {
      const x = (i / samples) * width
      const y = ((1 - waveformData[i]) / 2) * height
      
      if (i === 0) {
        ctx.moveTo(x, y)
      } else {
        ctx.lineTo(x, y)
      }
    }

    ctx.stroke()

    // Draw playback position
    if (metadata) {
      const progress = currentTime / metadata.duration
      const x = progress * width
      
      ctx.strokeStyle = '#3b82f6'
      ctx.lineWidth = 2
      ctx.beginPath()
      ctx.moveTo(x, 0)
      ctx.lineTo(x, height)
      ctx.stroke()
    }
  }, [waveformData, currentTime, metadata])

  if (!file || !metadata) {
    return (
      <div className="text-center py-12 text-muted-foreground">
        <FileAudio className="w-16 h-16 mx-auto mb-4 opacity-50" />
        <p>No audio file loaded</p>
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* File Info Card */}
      <Card className="p-6 bg-card border-border">
        <div className="flex items-start justify-between mb-4">
          <div>
            <h3 className="text-xl font-semibold flex items-center gap-2">
              <FileAudio className="w-5 h-5 text-accent" />
              File Information
            </h3>
          </div>
          {onAnalyzeAll && (
            <Button
              onClick={onAnalyzeAll}
              disabled={isAnalyzing}
              className="bg-accent hover:bg-accent/90"
            >
              {isAnalyzing ? (
                <>
                  <Activity className="w-4 h-4 mr-2 animate-spin" />
                  Analyzing...
                </>
              ) : (
                <>
                  <Zap className="w-4 h-4 mr-2" />
                  Analyze All
                </>
              )}
            </Button>
          )}
        </div>

        <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
          <div>
            <p className="text-xs text-muted-foreground">Filename</p>
            <p className="font-mono text-sm truncate">{file.name}</p>
          </div>
          <div>
            <p className="text-xs text-muted-foreground">Format</p>
            <p className="font-mono text-sm">{metadata.format?.toUpperCase() || 'Unknown'}</p>
          </div>
          <div>
            <p className="text-xs text-muted-foreground">Size</p>
            <p className="font-mono text-sm">{formatFileSize(metadata.size)}</p>
          </div>
          <div>
            <p className="text-xs text-muted-foreground">Duration</p>
            <p className="font-mono text-sm">{formatDuration(metadata.duration)}</p>
          </div>
          <div>
            <p className="text-xs text-muted-foreground">Sample Rate</p>
            <p className="font-mono text-sm">{metadata.sampleRate} Hz</p>
          </div>
          <div>
            <p className="text-xs text-muted-foreground">Channels</p>
            <p className="font-mono text-sm">{metadata.numberOfChannels} ({metadata.numberOfChannels === 1 ? 'Mono' : 'Stereo'})</p>
          </div>
          {metadata.bitrate && (
            <div>
              <p className="text-xs text-muted-foreground">Bitrate</p>
              <p className="font-mono text-sm">{(metadata.bitrate / 1000).toFixed(0)} kbps</p>
            </div>
          )}
          <div>
            <p className="text-xs text-muted-foreground">Bit Depth</p>
            <p className="font-mono text-sm">{metadata.bitDepth}-bit</p>
          </div>
        </div>
      </Card>

      {/* Waveform Visualization */}
      <Card className="p-6 bg-card border-border">
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <Activity className="w-5 h-5 text-accent" />
          Waveform
        </h3>
        <canvas
          ref={canvasRef}
          width={800}
          height={200}
          className="w-full rounded border border-border bg-gray-900"
        />
      </Card>

      {/* Quick Stats */}
      <Card className="p-6 bg-card border-border">
        <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
          <Hash className="w-5 h-5 text-accent" />
          Quick Analysis
        </h3>
        <div className="grid grid-cols-2 gap-4 text-sm">
          <div className="flex justify-between">
            <span className="text-muted-foreground">Sample Count:</span>
            <span className="font-mono">{(metadata.sampleRate * metadata.duration).toLocaleString()}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-muted-foreground">Data Points:</span>
            <span className="font-mono">{waveformData?.length || 0}</span>
          </div>
          <div className="flex justify-between">
            <span className="text-muted-foreground">Nyquist Frequency:</span>
            <span className="font-mono">{(metadata.sampleRate / 2).toLocaleString()} Hz</span>
          </div>
          <div className="flex justify-between">
            <span className="text-muted-foreground">Max Detectable:</span>
            <span className="font-mono">{metadata.sampleRate >= 44100 ? 'High Frequency' : 'Standard'}</span>
          </div>
        </div>
      </Card>
    </div>
  )
}
