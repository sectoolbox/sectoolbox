import React, { useRef, useEffect, useState } from 'react'

interface WaveformVisualizerProps {
  backendWaveform: string | null
  audioBuffer: AudioBuffer | null
  currentTime: number
  isPlaying: boolean
  onSeek: (time: number) => void
}

export const WaveformVisualizer: React.FC<WaveformVisualizerProps> = ({
  backendWaveform,
  audioBuffer,
  currentTime,
  isPlaying,
  onSeek
}) => {
  const containerRef = useRef<HTMLDivElement>(null)
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const [hoverTime, setHoverTime] = useState<number | null>(null)
  const [isDragging, setIsDragging] = useState(false)
  const animationFrameRef = useRef<number | undefined>(undefined)

  // Draw interactive overlay (playhead, hover indicator, time markers)
  const drawOverlay = () => {
    const canvas = canvasRef.current
    if (!canvas || !audioBuffer) return

    const ctx = canvas.getContext('2d')
    if (!ctx) return

    const width = canvas.width
    const height = canvas.height
    const duration = audioBuffer.duration

    // Clear canvas
    ctx.clearRect(0, 0, width, height)

    // Draw time markers every 5 seconds
    ctx.strokeStyle = 'rgba(255, 255, 255, 0.1)'
    ctx.lineWidth = 1
    ctx.font = '10px monospace'
    ctx.fillStyle = 'rgba(255, 255, 255, 0.4)'

    for (let t = 0; t <= duration; t += 5) {
      const x = (t / duration) * width
      ctx.beginPath()
      ctx.moveTo(x, 0)
      ctx.lineTo(x, height)
      ctx.stroke()
      
      // Time label
      const minutes = Math.floor(t / 60)
      const seconds = Math.floor(t % 60)
      ctx.fillText(`${minutes}:${seconds.toString().padStart(2, '0')}`, x + 2, 12)
    }

    // Draw hover indicator
    if (hoverTime !== null && !isDragging) {
      const hoverX = (hoverTime / duration) * width
      
      // Vertical line
      ctx.strokeStyle = 'rgba(147, 197, 253, 0.6)' // blue-300
      ctx.lineWidth = 2
      ctx.setLineDash([5, 5])
      ctx.beginPath()
      ctx.moveTo(hoverX, 0)
      ctx.lineTo(hoverX, height)
      ctx.stroke()
      ctx.setLineDash([])

      // Time tooltip
      const minutes = Math.floor(hoverTime / 60)
      const seconds = (hoverTime % 60).toFixed(1)
      const timeText = `${minutes}:${seconds.padStart(4, '0')}`
      
      ctx.fillStyle = 'rgba(30, 41, 59, 0.9)' // slate-800
      ctx.strokeStyle = 'rgba(147, 197, 253, 1)' // blue-300
      ctx.lineWidth = 1
      
      const textWidth = ctx.measureText(timeText).width
      const tooltipX = Math.min(Math.max(hoverX - textWidth / 2 - 8, 5), width - textWidth - 16)
      const tooltipY = 25
      
      ctx.fillRect(tooltipX, tooltipY, textWidth + 16, 24)
      ctx.strokeRect(tooltipX, tooltipY, textWidth + 16, 24)
      
      ctx.fillStyle = '#93c5fd' // blue-300
      ctx.font = '12px monospace'
      ctx.fillText(timeText, tooltipX + 8, tooltipY + 16)
    }

    // Draw playhead (current position)
    const playheadX = (currentTime / duration) * width
    
    // Playhead line
    ctx.strokeStyle = isPlaying ? '#10b981' : '#f59e0b' // green-500 : amber-500
    ctx.lineWidth = 3
    ctx.beginPath()
    ctx.moveTo(playheadX, 0)
    ctx.lineTo(playheadX, height)
    ctx.stroke()

    // Playhead triangle at top
    ctx.fillStyle = isPlaying ? '#10b981' : '#f59e0b'
    ctx.beginPath()
    ctx.moveTo(playheadX, 0)
    ctx.lineTo(playheadX - 8, 0)
    ctx.lineTo(playheadX, 12)
    ctx.lineTo(playheadX + 8, 0)
    ctx.closePath()
    ctx.fill()

    // Playhead circle at bottom
    ctx.beginPath()
    ctx.arc(playheadX, height - 8, 6, 0, Math.PI * 2)
    ctx.fill()

    // Current time display
    const currentMinutes = Math.floor(currentTime / 60)
    const currentSeconds = (currentTime % 60).toFixed(1)
    const currentTimeText = `${currentMinutes}:${currentSeconds.padStart(4, '0')}`
    
    ctx.fillStyle = 'rgba(16, 185, 129, 0.95)' // green-500
    ctx.font = 'bold 14px monospace'
    const timeTextWidth = ctx.measureText(currentTimeText).width
    const timeX = Math.min(Math.max(playheadX - timeTextWidth / 2 - 8, 5), width - timeTextWidth - 16)
    
    ctx.fillRect(timeX, height - 35, timeTextWidth + 16, 22)
    ctx.fillStyle = '#ffffff'
    ctx.fillText(currentTimeText, timeX + 8, height - 19)
  }

  // Animation loop for smooth playhead
  useEffect(() => {
    const animate = () => {
      drawOverlay()
      animationFrameRef.current = requestAnimationFrame(animate)
    }

    animate()

    return () => {
      if (animationFrameRef.current) {
        cancelAnimationFrame(animationFrameRef.current)
      }
    }
  }, [currentTime, hoverTime, isDragging, isPlaying, audioBuffer])

  // Handle mouse/touch interactions
  const handleInteractionStart = (clientX: number) => {
    if (!audioBuffer || !containerRef.current) return
    
    const rect = containerRef.current.getBoundingClientRect()
    const x = clientX - rect.left
    const progress = Math.max(0, Math.min(1, x / rect.width))
    const time = progress * audioBuffer.duration
    
    setIsDragging(true)
    onSeek(time)
  }

  const handleInteractionMove = (clientX: number) => {
    if (!audioBuffer || !containerRef.current) return
    
    const rect = containerRef.current.getBoundingClientRect()
    const x = clientX - rect.left
    const progress = Math.max(0, Math.min(1, x / rect.width))
    const time = progress * audioBuffer.duration
    
    if (isDragging) {
      onSeek(time)
    } else {
      setHoverTime(time)
    }
  }

  const handleInteractionEnd = () => {
    setIsDragging(false)
  }

  // Mouse events
  const handleMouseDown = (e: React.MouseEvent) => {
    handleInteractionStart(e.clientX)
  }

  const handleMouseMove = (e: React.MouseEvent) => {
    handleInteractionMove(e.clientX)
  }

  const handleMouseUp = () => {
    handleInteractionEnd()
  }

  const handleMouseLeave = () => {
    setHoverTime(null)
    setIsDragging(false)
  }

  // Touch events
  const handleTouchStart = (e: React.TouchEvent) => {
    if (e.touches.length > 0) {
      handleInteractionStart(e.touches[0].clientX)
    }
  }

  const handleTouchMove = (e: React.TouchEvent) => {
    if (e.touches.length > 0) {
      handleInteractionMove(e.touches[0].clientX)
    }
  }

  const handleTouchEnd = () => {
    handleInteractionEnd()
  }

  // Global mouse up handler for dragging outside canvas
  useEffect(() => {
    if (isDragging) {
      const handleGlobalMouseUp = () => setIsDragging(false)
      window.addEventListener('mouseup', handleGlobalMouseUp)
      return () => window.removeEventListener('mouseup', handleGlobalMouseUp)
    }
  }, [isDragging])

  if (!backendWaveform) {
    return (
      <div className="w-full h-[200px] bg-slate-900 border border-slate-700 rounded-lg flex items-center justify-center">
        <div className="text-slate-400 text-sm">Loading waveform...</div>
      </div>
    )
  }

  return (
    <div className="relative w-full select-none">
      <div
        ref={containerRef}
        className="relative w-full cursor-pointer overflow-hidden rounded-lg border-2 border-slate-700 hover:border-slate-600 transition-colors"
        style={{ touchAction: 'none' }}
        onMouseDown={handleMouseDown}
        onMouseMove={handleMouseMove}
        onMouseUp={handleMouseUp}
        onMouseLeave={handleMouseLeave}
        onTouchStart={handleTouchStart}
        onTouchMove={handleTouchMove}
        onTouchEnd={handleTouchEnd}
      >
        {/* Backend waveform image */}
        <img
          src={backendWaveform}
          alt="Audio Waveform"
          className="w-full block"
          style={{ display: 'block', width: '100%', height: 'auto' }}
          draggable={false}
        />

        {/* Interactive overlay canvas */}
        <canvas
          ref={canvasRef}
          width={1200}
          height={200}
          className="absolute top-0 left-0 w-full h-full pointer-events-none"
        />
      </div>

      {/* Duration display below waveform */}
      {audioBuffer && (
        <div className="flex justify-between items-center mt-2 text-xs text-slate-400 px-1">
          <span>0:00</span>
          <span className="font-mono text-slate-300">
            {Math.floor(currentTime / 60)}:{(currentTime % 60).toFixed(1).padStart(4, '0')} / {Math.floor(audioBuffer.duration / 60)}:{(audioBuffer.duration % 60).toFixed(1).padStart(4, '0')}
          </span>
          <span>{Math.floor(audioBuffer.duration / 60)}:{Math.floor(audioBuffer.duration % 60).toString().padStart(2, '0')}</span>
        </div>
      )}

      {/* Instructions */}
      <div className="mt-2 text-xs text-slate-500 text-center">
        {isDragging ? (
          <span className="text-blue-400 font-medium">Dragging...</span>
        ) : (
          <span>Click or drag to seek • Hover to preview time</span>
        )}
      </div>
    </div>
  )
}
