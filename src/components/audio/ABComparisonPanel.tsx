import React from 'react'
import { Play, Repeat, ArrowLeftRight, Trash2, PlayCircle } from 'lucide-react'
import { Button } from '../ui/button'
import { AudioRegion } from './WaveformVisualizer'

interface ABComparisonPanelProps {
  regionA: AudioRegion | null
  regionB: AudioRegion | null
  selectionMode: 'none' | 'A' | 'B'
  onSelectionModeChange: (mode: 'none' | 'A' | 'B') => void
  onClearRegion: (label: 'A' | 'B') => void
  onPlayRegion: (label: 'A' | 'B') => void
  onCompareRegions: () => void
  onSwapRegions: () => void
  playbackSpeedA: number
  playbackSpeedB: number
  onSpeedChange: (label: 'A' | 'B', speed: number) => void
  isPlaying: boolean
}

export const ABComparisonPanel: React.FC<ABComparisonPanelProps> = ({
  regionA,
  regionB,
  selectionMode,
  onSelectionModeChange,
  onClearRegion,
  onPlayRegion,
  onCompareRegions,
  onSwapRegions,
  playbackSpeedA,
  playbackSpeedB,
  onSpeedChange,
  isPlaying
}) => {
  const formatDuration = (seconds: number) => {
    const mins = Math.floor(seconds / 60)
    const secs = (seconds % 60).toFixed(2)
    return `${mins}:${secs.padStart(5, '0')}`
  }

  const getRegionDuration = (region: AudioRegion | null) => {
    if (!region) return '0:00.00'
    return formatDuration(region.endTime - region.startTime)
  }

  return (
    <div className="border border-border rounded-lg p-4 space-y-4 bg-card">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold flex items-center gap-2">
          <ArrowLeftRight className="w-4 h-4" />
          A/B Region Comparison
        </h3>
        {regionA && regionB && (
          <Button
            size="sm"
            variant="default"
            onClick={onSwapRegions}
            className="h-7"
            disabled={isPlaying}
          >
            <Repeat className="w-3 h-3 mr-1" />
            Swap A ↔ B
          </Button>
        )}
      </div>

      <div className="grid grid-cols-2 gap-3">
        {/* Region A Card */}
        <div className={`border-2 rounded-lg p-3 transition-all ${
          selectionMode === 'A' 
            ? 'border-blue-500 bg-blue-500/10' 
            : 'border-slate-700 bg-slate-900/50'
        }`}>
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <div className="w-6 h-6 rounded bg-blue-500 flex items-center justify-center text-white text-xs font-bold">
                A
              </div>
              <span className="text-xs font-medium">Region A</span>
            </div>
            {regionA && (
              <button
                onClick={() => onClearRegion('A')}
                className="text-slate-400 hover:text-red-400 transition-colors"
                disabled={isPlaying}
              >
                <Trash2 className="w-3 h-3" />
              </button>
            )}
          </div>

          {regionA ? (
            <div className="space-y-2">
              <div className="text-xs text-slate-400 space-y-1">
                <div>Start: {formatDuration(regionA.startTime)}</div>
                <div>End: {formatDuration(regionA.endTime)}</div>
                <div className="font-mono text-blue-400">Duration: {getRegionDuration(regionA)}</div>
              </div>

              <div className="space-y-1">
                <label className="text-xs text-slate-400">Speed: {playbackSpeedA}x</label>
                <input
                  type="range"
                  min="0.25"
                  max="2"
                  step="0.25"
                  value={playbackSpeedA}
                  onChange={(e) => onSpeedChange('A', parseFloat(e.target.value))}
                  className="w-full h-1"
                  disabled={isPlaying}
                />
              </div>

              <Button
                size="sm"
                variant="outline"
                onClick={() => onPlayRegion('A')}
                className="w-full h-7 text-xs"
                disabled={isPlaying}
              >
                <PlayCircle className="w-3 h-3 mr-1" />
                Play A
              </Button>
            </div>
          ) : (
            <Button
              size="sm"
              variant={selectionMode === 'A' ? 'default' : 'outline'}
              onClick={() => onSelectionModeChange(selectionMode === 'A' ? 'none' : 'A')}
              className="w-full h-8 text-xs"
            >
              {selectionMode === 'A' ? 'Cancel Selection' : 'Select Region A'}
            </Button>
          )}
        </div>

        {/* Region B Card */}
        <div className={`border-2 rounded-lg p-3 transition-all ${
          selectionMode === 'B' 
            ? 'border-orange-500 bg-orange-500/10' 
            : 'border-slate-700 bg-slate-900/50'
        }`}>
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              <div className="w-6 h-6 rounded bg-orange-500 flex items-center justify-center text-white text-xs font-bold">
                B
              </div>
              <span className="text-xs font-medium">Region B</span>
            </div>
            {regionB && (
              <button
                onClick={() => onClearRegion('B')}
                className="text-slate-400 hover:text-red-400 transition-colors"
                disabled={isPlaying}
              >
                <Trash2 className="w-3 h-3" />
              </button>
            )}
          </div>

          {regionB ? (
            <div className="space-y-2">
              <div className="text-xs text-slate-400 space-y-1">
                <div>Start: {formatDuration(regionB.startTime)}</div>
                <div>End: {formatDuration(regionB.endTime)}</div>
                <div className="font-mono text-orange-400">Duration: {getRegionDuration(regionB)}</div>
              </div>

              <div className="space-y-1">
                <label className="text-xs text-slate-400">Speed: {playbackSpeedB}x</label>
                <input
                  type="range"
                  min="0.25"
                  max="2"
                  step="0.25"
                  value={playbackSpeedB}
                  onChange={(e) => onSpeedChange('B', parseFloat(e.target.value))}
                  className="w-full h-1"
                  disabled={isPlaying}
                />
              </div>

              <Button
                size="sm"
                variant="outline"
                onClick={() => onPlayRegion('B')}
                className="w-full h-7 text-xs"
                disabled={isPlaying}
              >
                <PlayCircle className="w-3 h-3 mr-1" />
                Play B
              </Button>
            </div>
          ) : (
            <Button
              size="sm"
              variant={selectionMode === 'B' ? 'default' : 'outline'}
              onClick={() => onSelectionModeChange(selectionMode === 'B' ? 'none' : 'B')}
              className="w-full h-8 text-xs"
            >
              {selectionMode === 'B' ? 'Cancel Selection' : 'Select Region B'}
            </Button>
          )}
        </div>
      </div>

      {/* Compare Button */}
      {regionA && regionB && (
        <div className="pt-2 border-t border-border">
          <Button
            size="sm"
            variant="default"
            onClick={onCompareRegions}
            className="w-full"
            disabled={isPlaying}
          >
            <Play className="w-4 h-4 mr-2" />
            Compare A → B (Sequential Playback)
          </Button>
          <p className="text-xs text-slate-500 mt-2 text-center">
            Plays Region A at {playbackSpeedA}x, then Region B at {playbackSpeedB}x
          </p>
        </div>
      )}

      {!regionA && !regionB && (
        <div className="text-xs text-slate-500 text-center py-2">
          Select regions A and B on the waveform to compare audio segments
        </div>
      )}
    </div>
  )
}
