import React, { useRef, useEffect } from 'react'
import { Play, Pause, SkipBack, SkipForward, Volume2 } from 'lucide-react'
import { Button } from '../ui/button'
import { Input } from '../ui/input'
import { Card } from '../ui/card'

interface AudioPlayerProps {
  audioBuffer: AudioBuffer | null
  isPlaying: boolean
  currentTime: number
  playbackRate: number
  stereoBalance: number
  isReversed: boolean
  onPlayPause: () => void
  onSeek: (time: number) => void
  onPlaybackRateChange: (rate: number) => void
  onStereoBalanceChange: (balance: number) => void
  onReverse: () => void
  formatDuration: (seconds: number) => string
}

export const AudioPlayer: React.FC<AudioPlayerProps> = ({
  audioBuffer,
  isPlaying,
  currentTime,
  playbackRate,
  stereoBalance,
  isReversed,
  onPlayPause,
  onSeek,
  onPlaybackRateChange,
  onStereoBalanceChange,
  onReverse,
  formatDuration
}) => {
  if (!audioBuffer) return null

  const progress = (currentTime / audioBuffer.duration) * 100

  return (
    <Card className="p-4 bg-card border-border">
      <div className="space-y-4">
        {/* Playback Controls */}
        <div className="flex items-center justify-center gap-4">
          <Button
            variant="outline"
            size="sm"
            onClick={() => onSeek(Math.max(0, currentTime - 5))}
            disabled={!audioBuffer}
          >
            <SkipBack className="w-4 h-4" />
          </Button>
          
          <Button
            variant="default"
            size="lg"
            onClick={onPlayPause}
            disabled={!audioBuffer}
            className="w-16 h-16"
          >
            {isPlaying ? (
              <Pause className="w-6 h-6" />
            ) : (
              <Play className="w-6 h-6 ml-1" />
            )}
          </Button>

          <Button
            variant="outline"
            size="sm"
            onClick={() => onSeek(Math.min(audioBuffer.duration, currentTime + 5))}
            disabled={!audioBuffer}
          >
            <SkipForward className="w-4 h-4" />
          </Button>
        </div>

        {/* Progress Bar */}
        <div className="space-y-2">
          <input
            type="range"
            min="0"
            max="100"
            value={progress}
            onChange={(e) => {
              const newTime = (parseFloat(e.target.value) / 100) * audioBuffer.duration
              onSeek(newTime)
            }}
            className="w-full h-2 bg-gray-700 rounded-lg appearance-none cursor-pointer accent-accent"
          />
          <div className="flex justify-between text-xs text-muted-foreground">
            <span>{formatDuration(currentTime)}</span>
            <span>{formatDuration(audioBuffer.duration)}</span>
          </div>
        </div>

        {/* Playback Settings */}
        <div className="grid grid-cols-2 gap-4">
          <div>
            <label className="text-xs text-muted-foreground block mb-1">
              Speed: {playbackRate.toFixed(1)}x
            </label>
            <input
              type="range"
              min="0.25"
              max="2"
              step="0.25"
              value={playbackRate}
              onChange={(e) => onPlaybackRateChange(parseFloat(e.target.value))}
              className="w-full h-1 bg-gray-700 rounded-lg appearance-none cursor-pointer accent-accent"
            />
          </div>

          <div>
            <label className="text-xs text-muted-foreground block mb-1">
              Balance: {stereoBalance > 0 ? 'R' : stereoBalance < 0 ? 'L' : 'C'} {Math.abs(stereoBalance)}
            </label>
            <input
              type="range"
              min="-100"
              max="100"
              value={stereoBalance}
              onChange={(e) => onStereoBalanceChange(parseInt(e.target.value))}
              className="w-full h-1 bg-gray-700 rounded-lg appearance-none cursor-pointer accent-accent"
            />
          </div>
        </div>

        {/* Additional Controls */}
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={onReverse}
            className={isReversed ? 'bg-accent text-white' : ''}
          >
            {isReversed ? 'Unreverse' : 'Reverse'}
          </Button>
        </div>
      </div>
    </Card>
  )
}
