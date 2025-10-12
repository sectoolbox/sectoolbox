import React, { useState, useRef, useEffect } from 'react'
import { useLocation } from 'react-router-dom'
import {
  Upload,
  Music,
  Activity,
  Radio,
  Eye,
  Volume2,
  Play,
  Pause,
  SkipBack,
  SkipForward,
  FileAudio,
  Search,
  Zap,
  Download,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
  Hash,
  Waves,
  BarChart3,
  Headphones,
  ExternalLink
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card } from '../components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs'
import {
  loadAudioFile,
  extractMetadata,
  getWaveformData,
  separateChannels,
  extractStringsFromAudio,
  detectMorseCode,
  detectDTMF,
  detectLSBSteganography,
  generateSpectrogram,
  analyzeFrequencyAnomalies,
  reverseAudio,
  detectSSTVPattern,
  formatDuration,
  formatFileSize,
  applyEqualizer,
  applyNoiseReduction,
  normalizeAudio,
  exportAsWAV,
  exportSpectrogramImage,
  detectFSK,
  detectPSK,
  EQ_PRESETS,
  type AudioMetadata,
  type MorseResult,
  type DTMFResult,
  type SpectrogramData,
  type FrequencyResult,
  type SSTVResult,
  type FSKResult,
  type PSKResult,
  type EQBand
} from '../lib/audioAnalysis'

const AudioAnalysis: React.FC = () => {
  const location = useLocation()
  const [file, setFile] = useState<File | null>(null)
  const [audioBuffer, setAudioBuffer] = useState<AudioBuffer | null>(null)
  const [metadata, setMetadata] = useState<AudioMetadata | null>(null)
  const [isAnalyzing, setIsAnalyzing] = useState(false)

  // Audio playback state
  const [isPlaying, setIsPlaying] = useState(false)
  const [currentTime, setCurrentTime] = useState(0)
  const [playbackRate, setPlaybackRate] = useState(1.0)
  const [isReversed, setIsReversed] = useState(false)
  const [stereoBalance, setStereoBalance] = useState(0) // -100 (left) to +100 (right), 0 is center
  const audioContextRef = useRef<AudioContext | null>(null)
  const sourceNodeRef = useRef<AudioBufferSourceNode | null>(null)
  const pannerNodeRef = useRef<StereoPannerNode | null>(null)
  const startTimeRef = useRef<number>(0)
  const pauseTimeRef = useRef<number>(0)

  // Analysis results
  const [waveformData, setWaveformData] = useState<Float32Array | null>(null)
  const [leftChannel, setLeftChannel] = useState<Float32Array | null>(null)
  const [rightChannel, setRightChannel] = useState<Float32Array | null>(null)
  const [strings, setStrings] = useState<string[]>([])
  const [morseResult, setMorseResult] = useState<MorseResult | null>(null)
  const [dtmfResult, setDTMFResult] = useState<DTMFResult | null>(null)
  const [lsbData, setLsbData] = useState<string>('')
  const [spectrogram, setSpectrogram] = useState<SpectrogramData | null>(null)
  const [frequencyAnomalies, setFrequencyAnomalies] = useState<FrequencyResult[]>([])
  const [sstvResult, setSstvResult] = useState<SSTVResult | null>(null)
  const [fskResult, setFskResult] = useState<FSKResult | null>(null)
  const [pskResult, setPskResult] = useState<PSKResult | null>(null)

  // UI state
  const [stringFilter, setStringFilter] = useState('')
  const [debouncedStringFilter, setDebouncedStringFilter] = useState('')
  const [fftSize, setFftSize] = useState(2048)
  const [maxFrequency, setMaxFrequency] = useState(20000)
  const [morseThreshold, setMorseThreshold] = useState(0.1)
  const [activeTab, setActiveTab] = useState<'overview' | 'morse' | 'dtmf' | 'spectrum' | 'strings' | 'sstv' | 'fsk' | 'psk'>('overview')

  // Audio enhancement state
  const [eqBands, setEqBands] = useState<EQBand[]>(EQ_PRESETS['Flat'])
  const [selectedPreset, setSelectedPreset] = useState('Flat')
  const [noiseReduction, setNoiseReduction] = useState(0)
  const [enhancedBuffer, setEnhancedBuffer] = useState<AudioBuffer | null>(null)
  const [showEnhanceControls, setShowEnhanceControls] = useState(false)

  // Interactive waveform state
  const [hoverTime, setHoverTime] = useState<number | null>(null)
  const [hoverAmplitude, setHoverAmplitude] = useState<number | null>(null)

  const fileInputRef = useRef<HTMLInputElement>(null)
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const spectrogramCanvasRef = useRef<HTMLCanvasElement>(null)

  // Auto-load from dashboard
  useEffect(() => {
    if (location.state?.quickUploadFile) {
      const uploadedFile = location.state.quickUploadFile as File
      setFile(uploadedFile)
      if (location.state.quickUploadAutoAnalyze) {
        handleAnalyze(uploadedFile)
      }
    }
  }, [location.state])

  // Update playback time
  useEffect(() => {
    let interval: NodeJS.Timeout
    if (isPlaying && audioBuffer) {
      interval = setInterval(() => {
        const elapsed = (audioContextRef.current?.currentTime || 0) - startTimeRef.current + pauseTimeRef.current
        setCurrentTime(Math.min(elapsed * playbackRate, audioBuffer.duration))
      }, 100)
    }
    return () => clearInterval(interval)
  }, [isPlaying, audioBuffer, playbackRate])

  // Debounce string filter (wait 500ms after user stops typing)
  useEffect(() => {
    const timer = setTimeout(() => {
      setDebouncedStringFilter(stringFilter)
    }, 500)
    return () => clearTimeout(timer)
  }, [stringFilter])

  // Draw waveform whenever waveformData changes
  useEffect(() => {
    if (waveformData && canvasRef.current) {
      // Small delay to ensure canvas is fully rendered in DOM
      const timer = setTimeout(() => {
        drawWaveform(waveformData)
      }, 50)
      return () => clearTimeout(timer)
    }
  }, [waveformData])

  // Redraw waveform when playback position changes (works for both playing and paused states)
  useEffect(() => {
    if (waveformData) {
      drawWaveform(waveformData)
    }
  }, [currentTime, waveformData])

  const handleFileSelect = (selectedFile: File) => {
    setFile(selectedFile)
    resetAnalysis()
    // Auto-analyze on file selection
    handleAnalyze(selectedFile)
  }

  const resetAnalysis = () => {
    setAudioBuffer(null)
    setMetadata(null)
    setWaveformData(null)
    setLeftChannel(null)
    setRightChannel(null)
    setStrings([])
    setMorseResult(null)
    setDTMFResult(null)
    setLsbData('')
    setSpectrogram(null)
    setFrequencyAnomalies([])
    setSstvResult(null)
    setFskResult(null)
    setPskResult(null)
    stopAudio()
  }

  const handleAnalyze = async (selectedFile: File = file!) => {
    if (!selectedFile) return

    setIsAnalyzing(true)
    try {
      // Load audio
      const buffer = await loadAudioFile(selectedFile)
      setAudioBuffer(buffer)

      // Extract metadata
      const meta = extractMetadata(buffer, selectedFile)
      setMetadata(meta)

      // Get waveform
      const waveform = getWaveformData(buffer)
      setWaveformData(waveform)

      // Draw waveform with proper timing to ensure canvas is rendered
      await new Promise(resolve => setTimeout(resolve, 50))
      if (canvasRef.current) {
        drawWaveform(waveform)
        // Force another draw after short delay to ensure visibility
        await new Promise(resolve => setTimeout(resolve, 100))
        drawWaveform(waveform)
      }

      // Separate channels
      const channels = separateChannels(buffer)
      setLeftChannel(channels.left)
      setRightChannel(channels.right)

      // Allow UI to update
      await new Promise(resolve => setTimeout(resolve, 10))

      // Extract strings
      const extractedStrings = await extractStringsFromAudio(selectedFile)
      setStrings(extractedStrings)

      // Allow UI to update
      await new Promise(resolve => setTimeout(resolve, 10))

      // Detect morse code
      const morse = detectMorseCode(buffer, morseThreshold)
      setMorseResult(morse)

      // Allow UI to update
      await new Promise(resolve => setTimeout(resolve, 10))

      // Detect DTMF (async and limited)
      const dtmf = await detectDTMF(buffer)
      setDTMFResult(dtmf)

      // Allow UI to update
      await new Promise(resolve => setTimeout(resolve, 10))

      // LSB steganography
      const lsb = await detectLSBSteganography(selectedFile)
      setLsbData(lsb)

      // Allow UI to update
      await new Promise(resolve => setTimeout(resolve, 10))

      // Frequency anomalies
      const anomalies = analyzeFrequencyAnomalies(buffer)
      setFrequencyAnomalies(anomalies)

      // Allow UI to update
      await new Promise(resolve => setTimeout(resolve, 10))

      // Generate spectrogram (async, CPU intensive but optimized)
      const spectro = await generateSpectrogram(buffer, fftSize, maxFrequency)
      setSpectrogram(spectro)

      // Allow UI to update before drawing
      await new Promise(resolve => setTimeout(resolve, 10))
      drawSpectrogram(spectro)

      // Detect SSTV patterns
      await new Promise(resolve => setTimeout(resolve, 10))
      const sstv = await detectSSTVPattern(buffer)
      setSstvResult(sstv)

      // Detect FSK encoding
      await new Promise(resolve => setTimeout(resolve, 10))
      const fsk = await detectFSK(buffer)
      setFskResult(fsk)

      // Detect PSK encoding
      await new Promise(resolve => setTimeout(resolve, 10))
      const psk = await detectPSK(buffer)
      setPskResult(psk)
    } catch (error) {
      console.error('Analysis error:', error)
      alert('Failed to analyze audio: ' + (error as Error).message)
    } finally {
      setIsAnalyzing(false)
    }
  }

  const drawWaveform = (data: Float32Array) => {
    const canvas = canvasRef.current
    if (!canvas) return

    const ctx = canvas.getContext('2d')
    if (!ctx) return

    const width = canvas.width
    const height = canvas.height
    const halfHeight = height / 2

    ctx.fillStyle = '#1e1e2e'
    ctx.fillRect(0, 0, width, height)

    ctx.strokeStyle = '#00ff88'
    ctx.lineWidth = 2
    ctx.beginPath()

    for (let i = 0; i < data.length; i++) {
      const x = (i / data.length) * width
      const y = halfHeight - data[i] * halfHeight * 0.8

      if (i === 0) {
        ctx.moveTo(x, y)
      } else {
        ctx.lineTo(x, y)
      }
    }

    ctx.stroke()

    // Draw center line
    ctx.strokeStyle = '#444'
    ctx.lineWidth = 1
    ctx.beginPath()
    ctx.moveTo(0, halfHeight)
    ctx.lineTo(width, halfHeight)
    ctx.stroke()

    // Draw playback position indicator (playhead)
    if (audioBuffer && currentTime > 0) {
      const progress = currentTime / audioBuffer.duration
      const playheadX = progress * width

      // Draw playhead line
      ctx.strokeStyle = '#ff0088'
      ctx.lineWidth = 2
      ctx.beginPath()
      ctx.moveTo(playheadX, 0)
      ctx.lineTo(playheadX, height)
      ctx.stroke()

      // Draw played region overlay
      ctx.fillStyle = 'rgba(0, 255, 136, 0.1)'
      ctx.fillRect(0, 0, playheadX, height)
    }
  }

  const drawSpectrogram = (spectro: SpectrogramData) => {
    const canvas = spectrogramCanvasRef.current
    if (!canvas) return

    const ctx = canvas.getContext('2d')
    if (!ctx) return

    // Validate dimensions
    if (!spectro.width || !spectro.height || spectro.width < 1 || spectro.height < 1) {
      console.warn('Invalid spectrogram dimensions:', spectro.width, spectro.height)
      return
    }

    canvas.width = spectro.width
    canvas.height = spectro.height

    const imageData = ctx.createImageData(spectro.width, spectro.height)

    for (let x = 0; x < spectro.width; x++) {
      for (let y = 0; y < spectro.height; y++) {
        const value = spectro.data[x][spectro.height - 1 - y] // Flip Y
        const normalized = Math.max(0, Math.min(1, (value + 100) / 100)) // Normalize dB

        const pixelIndex = (y * spectro.width + x) * 4

        // Color mapping (black -> blue -> green -> yellow -> red)
        let r, g, b
        if (normalized < 0.25) {
          r = 0
          g = 0
          b = normalized * 4 * 255
        } else if (normalized < 0.5) {
          r = 0
          g = (normalized - 0.25) * 4 * 255
          b = 255
        } else if (normalized < 0.75) {
          r = (normalized - 0.5) * 4 * 255
          g = 255
          b = 255 - (normalized - 0.5) * 4 * 255
        } else {
          r = 255
          g = 255 - (normalized - 0.75) * 4 * 255
          b = 0
        }

        imageData.data[pixelIndex] = r
        imageData.data[pixelIndex + 1] = g
        imageData.data[pixelIndex + 2] = b
        imageData.data[pixelIndex + 3] = 255
      }
    }

    ctx.putImageData(imageData, 0, 0)
  }

  const applyEnhancements = async () => {
    if (!audioBuffer) return

    setIsAnalyzing(true)
    try {
      let processedBuffer = audioBuffer

      // Apply equalizer
      if (eqBands.some(band => band.gain !== 0)) {
        processedBuffer = await applyEqualizer(processedBuffer, eqBands)
      }

      // Apply noise reduction
      if (noiseReduction > 0) {
        processedBuffer = await applyNoiseReduction(processedBuffer, noiseReduction)
      }

      // Apply normalization (always normalize after processing)
      processedBuffer = await normalizeAudio(processedBuffer, 0.95)

      setEnhancedBuffer(processedBuffer)
      setWaveformData(getWaveformData(processedBuffer))
      drawWaveform(getWaveformData(processedBuffer))
    } catch (error) {
      console.error('Enhancement error:', error)
      alert('Failed to apply enhancements: ' + (error as Error).message)
    } finally {
      setIsAnalyzing(false)
    }
  }

  const playAudio = () => {
    if (!audioBuffer) return

    stopAudio()

    const audioContext = new (window.AudioContext || (window as any).webkitAudioContext)()
    audioContextRef.current = audioContext

    // Use enhanced buffer if available, otherwise original
    let bufferToPlay = enhancedBuffer || audioBuffer
    if (isReversed) {
      bufferToPlay = reverseAudio(bufferToPlay)
    }

    const source = audioContext.createBufferSource()
    source.buffer = bufferToPlay
    source.playbackRate.value = playbackRate

    // Create stereo panner for left/right balance control
    const panner = audioContext.createStereoPanner()
    panner.pan.value = stereoBalance / 100 // Convert -100..100 to -1..1
    pannerNodeRef.current = panner

    // Connect: source -> panner -> destination
    source.connect(panner)
    panner.connect(audioContext.destination)

    source.onended = () => {
      setIsPlaying(false)
      pauseTimeRef.current = 0
      setCurrentTime(0)
    }

    source.start(0, pauseTimeRef.current)
    startTimeRef.current = audioContext.currentTime
    sourceNodeRef.current = source
    setIsPlaying(true)
  }

  const pauseAudio = () => {
    if (sourceNodeRef.current && audioContextRef.current) {
      sourceNodeRef.current.stop()
      pauseTimeRef.current = (audioContextRef.current.currentTime - startTimeRef.current) + pauseTimeRef.current
      setIsPlaying(false)
    }
  }

  const stopAudio = () => {
    if (sourceNodeRef.current) {
      sourceNodeRef.current.stop()
      sourceNodeRef.current = null
    }
    if (audioContextRef.current) {
      audioContextRef.current.close()
      audioContextRef.current = null
    }
    setIsPlaying(false)
    pauseTimeRef.current = 0
    setCurrentTime(0)
  }

  const seekTo = (time: number) => {
    // Update time references
    pauseTimeRef.current = time
    setCurrentTime(time)

    if (isPlaying) {
      // Stop current playback without resetting time
      if (sourceNodeRef.current) {
        sourceNodeRef.current.stop()
        sourceNodeRef.current = null
      }
      if (audioContextRef.current) {
        audioContextRef.current.close()
        audioContextRef.current = null
      }
      setIsPlaying(false)

      // Restart playback from new position
      setTimeout(() => playAudio(), 50)
    } else {
      // Just update visuals when paused
      if (waveformData) {
        drawWaveform(waveformData)
      }
    }
  }

  const handleReanalyze = async () => {
    if (file && audioBuffer) {
      setIsAnalyzing(true)
      try {
        const morse = detectMorseCode(audioBuffer, morseThreshold)
        setMorseResult(morse)

        const spectro = await generateSpectrogram(audioBuffer, fftSize, maxFrequency)
        setSpectrogram(spectro)
        drawSpectrogram(spectro)
      } catch (error) {
        console.error('Reanalysis error:', error)
      } finally {
        setIsAnalyzing(false)
      }
    }
  }

  const filteredStrings = strings.filter(s =>
    s.toLowerCase().includes(debouncedStringFilter.toLowerCase())
  )

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-3xl font-bold flex items-center gap-3">
            <Music className="w-8 h-8 text-accent" />
            Audio Analysis
          </h1>
          <p className="text-muted-foreground mt-1">
            Detect hidden messages in audio files - Morse code, DTMF, LSB steganography, and more
          </p>
        </div>
      </div>

      {/* Upload Section */}
      {!file ? (
        <Card className="p-6">
          <h2 className="text-lg font-semibold mb-4">Upload Audio File</h2>
          <div
            className="border-2 border-dashed border-border rounded-lg p-8 text-center hover:border-accent transition-colors cursor-pointer"
            onClick={() => fileInputRef.current?.click()}
          >
            <Upload className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
            <p className="text-lg font-medium mb-2">
              Drop your audio file here or click to browse
            </p>
            <p className="text-sm text-muted-foreground">
              MP3, WAV, OGG, M4A, FLAC - All audio formats supported
            </p>
            <input
              ref={fileInputRef}
              type="file"
              accept="audio/*"
              onChange={(e) => {
                const selectedFile = e.target.files?.[0]
                if (selectedFile) handleFileSelect(selectedFile)
              }}
              className="hidden"
            />
          </div>
        </Card>
      ) : (
        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <FileAudio className="w-5 h-5 text-accent" />
              <div>
                <p className="font-medium">{file.name}</p>
                <p className="text-sm text-muted-foreground">{formatFileSize(file.size)}</p>
              </div>
            </div>
            <Button
              variant="destructive"
              size="sm"
              onClick={() => {
                setFile(null)
                resetAnalysis()
              }}
            >
              Remove File
            </Button>
          </div>
        </Card>
      )}

      {!file && (
        <div className="invisible">
          {/* Spacer */}
        </div>
      )}

      {/* Analysis Section */}
      {file && (
        <div className="space-y-4">
          {/* Action Bar */}
          <div className="flex flex-wrap items-center gap-3">
            <Button onClick={() => fileInputRef.current?.click()} variant="outline">
              <Upload className="w-4 h-4 mr-2" />
              New File
            </Button>
            <input
              ref={fileInputRef}
              type="file"
              accept="audio/*"
              onChange={(e) => {
                const selectedFile = e.target.files?.[0]
                if (selectedFile) handleFileSelect(selectedFile)
              }}
              className="hidden"
            />
            {isAnalyzing && (
              <div className="flex items-center gap-2 text-sm text-accent">
                <Activity className="w-4 h-4 animate-spin" />
                <span>Analyzing...</span>
              </div>
            )}
            <div className="flex-1" />
            <div className="text-sm text-muted-foreground">
              {file.name} ({formatFileSize(file.size)})
            </div>
          </div>

          {/* Audio Player */}
          {audioBuffer && (
            <Card className="p-4">
              <div className="space-y-4">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <Button
                      size="sm"
                      onClick={() => {
                        stopAudio()
                        setCurrentTime(0)
                      }}
                      variant="outline"
                    >
                      <SkipBack className="w-4 h-4" />
                    </Button>
                    <Button
                      size="sm"
                      onClick={isPlaying ? pauseAudio : playAudio}
                    >
                      {isPlaying ? <Pause className="w-4 h-4" /> : <Play className="w-4 h-4" />}
                    </Button>
                    <Button
                      size="sm"
                      onClick={stopAudio}
                      variant="outline"
                    >
                      <SkipForward className="w-4 h-4" />
                    </Button>
                    <span className="text-sm font-mono ml-2">
                      {formatDuration(currentTime)} / {formatDuration(metadata?.duration || 0)}
                    </span>
                  </div>

                  <div className="flex items-center gap-4">
                    <label className="text-sm flex items-center gap-2">
                      Speed:
                      <select
                        value={playbackRate}
                        onChange={(e) => setPlaybackRate(parseFloat(e.target.value))}
                        className="px-2 py-1 bg-background border border-border rounded text-sm"
                      >
                        <option value="0.25">0.25x</option>
                        <option value="0.5">0.5x</option>
                        <option value="0.75">0.75x</option>
                        <option value="1">1x</option>
                        <option value="1.25">1.25x</option>
                        <option value="1.5">1.5x</option>
                        <option value="2">2x</option>
                      </select>
                    </label>
                    <label className="flex items-center gap-2 text-sm">
                      <input
                        type="checkbox"
                        checked={isReversed}
                        onChange={(e) => {
                          setIsReversed(e.target.checked)
                          if (isPlaying) {
                            stopAudio()
                          }
                        }}
                      />
                      Reversed
                    </label>
                  </div>
                </div>

                {/* Stereo Balance Control */}
                <div className="mt-4">
                  <label className="text-sm font-medium block mb-2">
                    Stereo Balance: {stereoBalance === 0 ? 'Center' : stereoBalance < 0 ? `${Math.abs(stereoBalance)}% Left` : `${stereoBalance}% Right`}
                  </label>
                  <div className="flex items-center gap-3">
                    <span className="text-xs text-muted-foreground">L</span>
                    <input
                      type="range"
                      min="-100"
                      max="100"
                      step="1"
                      value={stereoBalance}
                      onChange={(e) => {
                        setStereoBalance(parseInt(e.target.value))
                        if (isPlaying && pannerNodeRef.current) {
                          pannerNodeRef.current.pan.value = parseInt(e.target.value) / 100
                        }
                      }}
                      className="flex-1"
                    />
                    <span className="text-xs text-muted-foreground">R</span>
                  </div>
                  <p className="text-xs text-muted-foreground mt-1">
                    Adjust to isolate left or right channel (useful for stereo CTF challenges)
                  </p>
                </div>

                {/* Waveform */}
                <div className="relative">
                  <canvas
                    ref={canvasRef}
                    width={800}
                    height={150}
                    className="w-full border border-border rounded cursor-pointer"
                    onClick={(e) => {
                      if (!audioBuffer) return
                      const canvas = canvasRef.current
                      if (!canvas) return

                      const rect = canvas.getBoundingClientRect()
                      const x = e.clientX - rect.left
                      const clickProgress = x / rect.width
                      const seekTime = clickProgress * audioBuffer.duration

                      // Use dedicated seekTo function
                      seekTo(seekTime)
                    }}
                    onMouseMove={(e) => {
                      if (!audioBuffer || !waveformData) return
                      const canvas = canvasRef.current
                      if (!canvas) return

                      const rect = canvas.getBoundingClientRect()
                      const x = e.clientX - rect.left
                      const progress = x / rect.width
                      const time = progress * audioBuffer.duration

                      // Get amplitude at this position
                      const dataIndex = Math.floor(progress * waveformData.length)
                      const amplitude = waveformData[dataIndex] || 0

                      setHoverTime(time)
                      setHoverAmplitude(amplitude)
                    }}
                    onMouseLeave={() => {
                      setHoverTime(null)
                      setHoverAmplitude(null)
                    }}
                  />

                  {/* Hover tooltip */}
                  {hoverTime !== null && hoverAmplitude !== null && (
                    <div className="absolute -top-16 left-1/2 transform -translate-x-1/2 bg-background border border-accent rounded px-3 py-2 text-xs font-mono shadow-lg pointer-events-none z-10">
                      <div className="text-accent font-semibold mb-1">Waveform Info</div>
                      <div>Time: {formatDuration(hoverTime)}</div>
                      <div>Amplitude: {(hoverAmplitude * 100).toFixed(1)}%</div>
                    </div>
                  )}

                  <p className="text-xs text-muted-foreground mt-2">
                    Click anywhere on the waveform to seek to that position • Hover to see details
                  </p>
                </div>

                {/* Audio Enhancement Controls */}
                <div className="border-t border-border pt-4">
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => setShowEnhanceControls(!showEnhanceControls)}
                    className="w-full"
                  >
                    <Volume2 className="w-4 h-4 mr-2" />
                    {showEnhanceControls ? 'Hide' : 'Show'} Audio Enhancement Controls
                  </Button>

                  {showEnhanceControls && (
                    <div className="mt-4 space-y-4 p-4 bg-muted/20 rounded">
                      {/* Preset Selection */}
                      <div>
                        <label className="text-sm font-medium block mb-2">EQ Preset</label>
                        <select
                          value={selectedPreset}
                          onChange={(e) => {
                            setSelectedPreset(e.target.value)
                            setEqBands(EQ_PRESETS[e.target.value])
                          }}
                          className="w-full px-3 py-2 bg-background border border-border rounded text-sm"
                        >
                          {Object.keys(EQ_PRESETS).map(preset => (
                            <option key={preset} value={preset}>{preset}</option>
                          ))}
                        </select>
                      </div>

                      {/* 10-Band Equalizer */}
                      <div>
                        <label className="text-sm font-medium block mb-3">10-Band Equalizer (±12dB)</label>
                        <div className="grid grid-cols-5 md:grid-cols-10 gap-2">
                          {eqBands.map((band, index) => (
                            <div key={index} className="flex flex-col items-center gap-1">
                              <input
                                type="range"
                                min="-12"
                                max="12"
                                step="1"
                                value={band.gain}
                                onChange={(e) => {
                                  const newBands = [...eqBands]
                                  newBands[index].gain = parseFloat(e.target.value)
                                  setEqBands(newBands)
                                  setSelectedPreset('Custom')
                                }}
                                orient="vertical"
                                className="h-24"
                                style={{ writingMode: 'bt-lr', WebkitAppearance: 'slider-vertical', width: '20px' }}
                              />
                              <span className="text-xs text-muted-foreground">{band.frequency < 1000 ? band.frequency : `${band.frequency/1000}k`}</span>
                              <span className="text-xs font-mono">{band.gain > 0 ? '+' : ''}{band.gain}</span>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Noise Reduction */}
                      <div>
                        <label className="text-sm font-medium block mb-2">
                          Noise Reduction: {Math.round(noiseReduction * 100)}%
                        </label>
                        <input
                          type="range"
                          min="0"
                          max="1"
                          step="0.05"
                          value={noiseReduction}
                          onChange={(e) => setNoiseReduction(parseFloat(e.target.value))}
                          className="w-full"
                        />
                        <div className="flex justify-between text-xs text-muted-foreground mt-1">
                          <span>Off</span>
                          <span>Maximum</span>
                        </div>
                      </div>

                      {/* Action Buttons */}
                      <div className="flex gap-2 pt-2">
                        <Button onClick={applyEnhancements} size="sm" className="flex-1" disabled={isAnalyzing}>
                          {isAnalyzing ? 'Processing...' : 'Apply Enhancements'}
                        </Button>
                        <Button
                          onClick={() => {
                            setEnhancedBuffer(null)
                            setEqBands(EQ_PRESETS['Flat'])
                            setSelectedPreset('Flat')
                            setNoiseReduction(0)
                            if (audioBuffer) {
                              setWaveformData(getWaveformData(audioBuffer))
                              drawWaveform(getWaveformData(audioBuffer))
                            }
                          }}
                          size="sm"
                          variant="outline"
                        >
                          Reset
                        </Button>
                        <Button
                          onClick={() => {
                            if (enhancedBuffer) {
                              exportAsWAV(enhancedBuffer, `${file?.name.replace(/\.[^.]+$/, '')}_enhanced.wav`)
                            } else if (audioBuffer) {
                              exportAsWAV(audioBuffer, `${file?.name.replace(/\.[^.]+$/, '')}_original.wav`)
                            }
                          }}
                          size="sm"
                          variant="outline"
                          disabled={!audioBuffer}
                        >
                          <Download className="w-4 h-4 mr-1" />
                          Export WAV
                        </Button>
                      </div>

                      {enhancedBuffer && (
                        <div className="text-sm text-accent flex items-center gap-2">
                          <CheckCircle className="w-4 h-4" />
                          Enhancements applied - playing enhanced audio
                        </div>
                      )}
                    </div>
                  )}
                </div>
              </div>
            </Card>
          )}

          {/* Tabs */}
          {audioBuffer && (
            <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as any)}>
              <TabsList className="grid grid-cols-4 md:grid-cols-8 w-full">
                <TabsTrigger value="overview">
                  <Eye className="w-4 h-4 mr-1" />
                  <span className="hidden md:inline">Overview</span>
                </TabsTrigger>
                <TabsTrigger value="morse">
                  <Radio className="w-4 h-4 mr-1" />
                  <span className="hidden md:inline">Morse</span>
                </TabsTrigger>
                <TabsTrigger value="dtmf">
                  <Hash className="w-4 h-4 mr-1" />
                  <span className="hidden md:inline">DTMF</span>
                </TabsTrigger>
                <TabsTrigger value="sstv">
                  <FileAudio className="w-4 h-4 mr-1" />
                  <span className="hidden md:inline">SSTV</span>
                </TabsTrigger>
                <TabsTrigger value="fsk">
                  <Waves className="w-4 h-4 mr-1" />
                  <span className="hidden md:inline">FSK</span>
                </TabsTrigger>
                <TabsTrigger value="psk">
                  <Activity className="w-4 h-4 mr-1" />
                  <span className="hidden md:inline">PSK</span>
                </TabsTrigger>
                <TabsTrigger value="spectrum">
                  <BarChart3 className="w-4 h-4 mr-1" />
                  <span className="hidden md:inline">Spectrum</span>
                </TabsTrigger>
                <TabsTrigger value="strings">
                  <Search className="w-4 h-4 mr-1" />
                  <span className="hidden md:inline">Strings</span>
                </TabsTrigger>
              </TabsList>

              {/* Overview Tab */}
              <TabsContent value="overview">
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  <Card className="p-4">
                    <h3 className="font-semibold mb-2 flex items-center">
                      <Music className="w-4 h-4 mr-2 text-accent" />
                      Audio Info
                    </h3>
                    <div className="space-y-1 text-sm">
                      <p><span className="text-muted-foreground">Duration:</span> {formatDuration(metadata?.duration || 0)}</p>
                      <p><span className="text-muted-foreground">Sample Rate:</span> {metadata?.sampleRate} Hz</p>
                      <p><span className="text-muted-foreground">Channels:</span> {metadata?.numberOfChannels}</p>
                      <p><span className="text-muted-foreground">Bitrate:</span> {Math.round((metadata?.bitrate || 0) / 1000)} kbps</p>
                      <p><span className="text-muted-foreground">Format:</span> {metadata?.format}</p>
                    </div>
                  </Card>

                  <Card className="p-4">
                    <h3 className="font-semibold mb-2 flex items-center">
                      <Zap className="w-4 h-4 mr-2 text-accent" />
                      Detection Results
                    </h3>
                    <div className="space-y-2 text-sm">
                      <div className="flex items-center justify-between">
                        <span className="text-muted-foreground">Morse Code:</span>
                        <div className="flex items-center gap-2">
                          {morseResult?.detected ? (
                            <>
                              <CheckCircle className="w-4 h-4 text-green-400" />
                              <span className="text-xs text-green-400">{morseResult.message.substring(0, 20)}{morseResult.message.length > 20 ? '...' : ''}</span>
                            </>
                          ) : (
                            <AlertTriangle className="w-4 h-4 text-muted-foreground" />
                          )}
                        </div>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-muted-foreground">DTMF Tones:</span>
                        <div className="flex items-center gap-2">
                          {dtmfResult?.detected ? (
                            <>
                              <CheckCircle className="w-4 h-4 text-green-400" />
                              <span className="text-xs text-green-400">{dtmfResult.sequence}</span>
                            </>
                          ) : (
                            <AlertTriangle className="w-4 h-4 text-muted-foreground" />
                          )}
                        </div>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-muted-foreground">SSTV Pattern:</span>
                        {sstvResult?.detected ? (
                          <CheckCircle className="w-4 h-4 text-green-400" />
                        ) : (
                          <AlertTriangle className="w-4 h-4 text-muted-foreground" />
                        )}
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-muted-foreground">FSK Signal:</span>
                        {fskResult?.detected ? (
                          <CheckCircle className="w-4 h-4 text-green-400" />
                        ) : (
                          <AlertTriangle className="w-4 h-4 text-muted-foreground" />
                        )}
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-muted-foreground">PSK Signal:</span>
                        {pskResult?.detected ? (
                          <CheckCircle className="w-4 h-4 text-green-400" />
                        ) : (
                          <AlertTriangle className="w-4 h-4 text-muted-foreground" />
                        )}
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-muted-foreground">LSB Data:</span>
                        {lsbData ? (
                          <CheckCircle className="w-4 h-4 text-green-400" />
                        ) : (
                          <AlertTriangle className="w-4 h-4 text-muted-foreground" />
                        )}
                      </div>
                    </div>
                  </Card>

                  <Card className="p-4">
                    <h3 className="font-semibold mb-2 flex items-center">
                      <Activity className="w-4 h-4 mr-2 text-accent" />
                      Statistics
                    </h3>
                    <div className="space-y-1 text-sm">
                      <p><span className="text-muted-foreground">Strings Found:</span> {strings.length}</p>
                      <p><span className="text-muted-foreground">Frequency Peaks:</span> {frequencyAnomalies.length}</p>
                      <p><span className="text-muted-foreground">Spectrogram Frames:</span> {spectrogram?.width || 0}</p>
                    </div>
                  </Card>
                </div>
              </TabsContent>


              {/* Morse Code Tab */}
              <TabsContent value="morse">
                <Card className="p-4">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="font-semibold">Morse Code Detection</h3>
                    <div className="flex items-center gap-2">
                      <label className="text-sm">Threshold:</label>
                      <input
                        type="number"
                        value={morseThreshold}
                        onChange={(e) => setMorseThreshold(parseFloat(e.target.value))}
                        step="0.01"
                        min="0"
                        max="1"
                        className="px-2 py-1 bg-background border border-border rounded w-20 text-sm"
                      />
                      <Button size="sm" onClick={handleReanalyze}>
                        <RefreshCw className="w-3 h-3" />
                      </Button>
                    </div>
                  </div>

                  {morseResult?.detected ? (
                    <div>
                      <div className="bg-green-500/10 border border-green-500/30 p-4 rounded mb-4">
                        <div className="flex items-center gap-2 mb-2">
                          <CheckCircle className="w-5 h-5 text-green-400" />
                          <span className="font-semibold text-green-400">Morse Code Detected!</span>
                        </div>
                        <div className="text-2xl font-mono mt-2 break-all">
                          {morseResult.message}
                        </div>
                        <p className="text-sm text-muted-foreground mt-2">
                          Confidence: {(morseResult.confidence * 100).toFixed(0)}%
                        </p>
                      </div>

                      <h4 className="font-semibold mb-2 text-sm">Detected Patterns:</h4>
                      <div className="space-y-1 max-h-48 overflow-auto">
                        {morseResult.positions.slice(0, 50).map((pos, idx) => (
                          <div key={idx} className="flex items-center gap-2 text-xs font-mono bg-muted/20 p-1 rounded">
                            <span className="text-accent">{formatDuration(pos.start)}</span>
                            <span className="text-foreground">{pos.symbol}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : (
                    <div className="text-center py-8 text-muted-foreground">
                      <Radio className="w-12 h-12 mx-auto mb-2 opacity-50" />
                      <p>No morse code detected</p>
                      <p className="text-xs mt-1">Try adjusting the threshold</p>
                    </div>
                  )}
                </Card>
              </TabsContent>

              {/* DTMF Tab */}
              <TabsContent value="dtmf">
                <Card className="p-4">
                  <h3 className="font-semibold mb-3">DTMF Tone Detection</h3>
                  {dtmfResult?.detected ? (
                    <div>
                      <div className="bg-blue-500/10 border border-blue-500/30 p-4 rounded mb-4">
                        <div className="flex items-center gap-2 mb-2">
                          <CheckCircle className="w-5 h-5 text-blue-400" />
                          <span className="font-semibold text-blue-400">DTMF Tones Detected!</span>
                        </div>
                        <div className="text-3xl font-mono mt-2 tracking-wider">
                          {dtmfResult.sequence}
                        </div>
                      </div>

                      <h4 className="font-semibold mb-2 text-sm">Detected Tones:</h4>
                      <div className="space-y-2 max-h-64 overflow-auto">
                        {dtmfResult.tones.map((tone, idx) => (
                          <div key={idx} className="bg-muted/20 p-2 rounded flex items-center justify-between text-sm">
                            <span className="text-2xl font-mono text-accent">{tone.digit}</span>
                            <div className="text-xs text-muted-foreground">
                              <div>Time: {formatDuration(tone.timestamp)}</div>
                              <div>Duration: {tone.duration.toFixed(2)}s</div>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  ) : (
                    <div className="text-center py-8 text-muted-foreground">
                      <Hash className="w-12 h-12 mx-auto mb-2 opacity-50" />
                      <p>No DTMF tones detected</p>
                    </div>
                  )}
                </Card>
              </TabsContent>

              {/* Spectrogram Tab */}
              <TabsContent value="spectrum">
                <Card className="p-4">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="font-semibold">Spectrogram Analysis</h3>
                    <div className="flex items-center gap-3">
                      <label className="text-sm flex items-center gap-2">
                        FFT Size:
                        <select
                          value={fftSize}
                          onChange={(e) => setFftSize(parseInt(e.target.value))}
                          className="px-2 py-1 bg-background border border-border rounded text-sm"
                        >
                          <option value="512">512</option>
                          <option value="1024">1024</option>
                          <option value="2048">2048</option>
                          <option value="4096">4096</option>
                        </select>
                      </label>
                      <label className="text-sm flex items-center gap-2">
                        Max Freq:
                        <input
                          type="number"
                          value={maxFrequency}
                          onChange={(e) => setMaxFrequency(parseInt(e.target.value))}
                          className="px-2 py-1 bg-background border border-border rounded w-24 text-sm"
                        />
                        Hz
                      </label>
                      <Button size="sm" onClick={handleReanalyze}>
                        <RefreshCw className="w-3 h-3" />
                      </Button>
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={async () => {
                          if (spectrogram && spectrogramCanvasRef.current) {
                            const { exportSpectrogramImage } = await import('../lib/audioAnalysisAdvanced')
                            await exportSpectrogramImage(
                              spectrogram,
                              `${file?.name.replace(/\.[^.]+$/, '')}_spectrogram.png`
                            )
                          }
                        }}
                        disabled={!spectrogram}
                      >
                        <Download className="w-3 h-3 mr-1" />
                        PNG
                      </Button>
                    </div>
                  </div>

                  <div className="bg-muted/20 p-2 rounded overflow-auto">
                    <canvas
                      ref={spectrogramCanvasRef}
                      className="w-full border border-border"
                      style={{ imageRendering: 'pixelated' }}
                    />
                  </div>

                  <p className="text-xs text-muted-foreground mt-2">
                    Look for hidden images or patterns in the spectrogram. Adjust FFT size and frequency range for better visibility.
                  </p>
                </Card>
              </TabsContent>

              {/* Strings Tab */}
              <TabsContent value="strings">
                <Card className="p-4">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="font-semibold">Extracted Strings ({strings.length})</h3>
                    <Input
                      placeholder="Filter strings..."
                      value={stringFilter}
                      onChange={(e) => setStringFilter(e.target.value)}
                      className="w-64"
                    />
                  </div>

                  <div className="space-y-1 max-h-96 overflow-auto font-mono text-xs">
                    {filteredStrings.length > 0 ? (
                      filteredStrings.map((str, idx) => (
                        <div key={idx} className="bg-muted/20 p-2 rounded break-all">
                          {str}
                        </div>
                      ))
                    ) : (
                      <p className="text-center text-muted-foreground py-8">
                        {strings.length === 0 ? 'No strings found' : 'No strings match filter'}
                      </p>
                    )}
                  </div>
                </Card>
              </TabsContent>

              {/* SSTV Tab */}
              <TabsContent value="sstv">
                <Card className="p-4">
                  <h3 className="font-semibold mb-4">SSTV / Spectral Image Detection</h3>
                  {sstvResult ? (
                    <div className="space-y-4">
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div>
                          <div className="text-sm text-muted-foreground mb-1">Detection Status</div>
                          <div className={`font-medium ${sstvResult.detected ? 'text-accent' : 'text-muted-foreground'}`}>
                            {sstvResult.detected ? '✓ SSTV Pattern Detected' : '✗ No SSTV Pattern'}
                          </div>
                        </div>
                        <div>
                          <div className="text-sm text-muted-foreground mb-1">Confidence</div>
                          <div className="font-medium">{sstvResult.confidence}%</div>
                        </div>
                      </div>

                      {sstvResult.possibleFormat && (
                        <div>
                          <div className="text-sm text-muted-foreground mb-1">Possible Format</div>
                          <div className="font-mono text-sm bg-muted/20 p-2 rounded">{sstvResult.possibleFormat}</div>
                        </div>
                      )}

                      <div>
                        <div className="text-sm text-muted-foreground mb-2">Analysis</div>
                        <div className="bg-muted/20 p-3 rounded text-sm">{sstvResult.description}</div>
                      </div>

                      {sstvResult.detected && (
                        <>
                          <div className="bg-accent/10 border border-accent/30 p-4 rounded space-y-4">
                            <div>
                              <div className="font-semibold text-accent mb-3">🖼️ Decode SSTV Image:</div>
                              <Button
                                onClick={() => window.open('https://sstv-decoder.mathieurenaud.fr/', '_blank')}
                                className="w-full"
                              >
                                <ExternalLink className="w-4 h-4 mr-2" />
                                Open Web-Based SSTV Decoder
                              </Button>
                              <p className="text-xs text-muted-foreground mt-2">
                                Upload your audio file to the online decoder to view the hidden image. Supports Robot36, Scottie, Martin, and more.
                              </p>
                            </div>

                            <div className="border-t border-accent/20 pt-4">
                              <div className="font-semibold text-accent mb-2">📻 Desktop Decoding Software:</div>
                              <ul className="text-sm space-y-1 list-disc list-inside">
                                <li><strong>QSSTV</strong> (Linux) - Full-featured SSTV decoder</li>
                                <li><strong>RX-SSTV</strong> (Windows) - Popular Windows decoder</li>
                                <li><strong>Robot36</strong> (Android) - Mobile SSTV decoder</li>
                                <li><strong>Black Cat SSTV</strong> (Windows/Mac) - Multi-mode decoder</li>
                              </ul>
                            </div>
                          </div>
                        </>
                      )}
                    </div>
                  ) : (
                    <div className="text-center text-muted-foreground py-8">Analyzing...</div>
                  )}
                </Card>
              </TabsContent>

              {/* FSK Tab */}
              <TabsContent value="fsk">
                <Card className="p-4">
                  <h3 className="font-semibold mb-4">FSK (Frequency-Shift Keying) Detection</h3>
                  {fskResult ? (
                    <div className="space-y-4">
                      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                        <div>
                          <div className="text-sm text-muted-foreground mb-1">Detection Status</div>
                          <div className={`font-medium ${fskResult.detected ? 'text-accent' : 'text-muted-foreground'}`}>
                            {fskResult.detected ? '✓ FSK Detected' : '✗ No FSK Signal'}
                          </div>
                        </div>
                        <div>
                          <div className="text-sm text-muted-foreground mb-1">Confidence</div>
                          <div className="font-medium">{fskResult.confidence}%</div>
                        </div>
                        <div>
                          <div className="text-sm text-muted-foreground mb-1">Baud Rate</div>
                          <div className="font-mono">{fskResult.baudRate} baud</div>
                        </div>
                      </div>

                      {fskResult.detected && (
                        <>
                          <div className="grid grid-cols-2 gap-4">
                            <div>
                              <div className="text-sm text-muted-foreground mb-1">Mark Frequency</div>
                              <div className="font-mono text-sm bg-muted/20 p-2 rounded">{fskResult.markFrequency} Hz</div>
                            </div>
                            <div>
                              <div className="text-sm text-muted-foreground mb-1">Space Frequency</div>
                              <div className="font-mono text-sm bg-muted/20 p-2 rounded">{fskResult.spaceFrequency} Hz</div>
                            </div>
                          </div>

                          <div>
                            <div className="text-sm text-muted-foreground mb-2">Decoded Bits ({fskResult.decodedBits.length} bits)</div>
                            <div className="bg-muted/20 p-3 rounded font-mono text-xs overflow-auto max-h-32 break-all">
                              {fskResult.decodedBits}
                            </div>
                          </div>

                          {fskResult.decodedText && (
                            <div>
                              <div className="text-sm text-muted-foreground mb-2">Decoded Text (ASCII)</div>
                              <div className="bg-accent/10 border border-accent/30 p-3 rounded font-mono text-sm">
                                {fskResult.decodedText}
                              </div>
                            </div>
                          )}
                        </>
                      )}
                    </div>
                  ) : (
                    <div className="text-center text-muted-foreground py-8">Analyzing...</div>
                  )}
                </Card>
              </TabsContent>

              {/* PSK Tab */}
              <TabsContent value="psk">
                <Card className="p-4">
                  <h3 className="font-semibold mb-4">PSK (Phase-Shift Keying) Detection</h3>
                  {pskResult ? (
                    <div className="space-y-4">
                      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                        <div>
                          <div className="text-sm text-muted-foreground mb-1">Detection Status</div>
                          <div className={`font-medium ${pskResult.detected ? 'text-accent' : 'text-muted-foreground'}`}>
                            {pskResult.detected ? '✓ PSK Detected' : '✗ No PSK Signal'}
                          </div>
                        </div>
                        <div>
                          <div className="text-sm text-muted-foreground mb-1">Confidence</div>
                          <div className="font-medium">{pskResult.confidence}%</div>
                        </div>
                        <div>
                          <div className="text-sm text-muted-foreground mb-1">Carrier Frequency</div>
                          <div className="font-mono">{pskResult.carrierFrequency} Hz</div>
                        </div>
                        <div>
                          <div className="text-sm text-muted-foreground mb-1">Baud Rate</div>
                          <div className="font-mono">{pskResult.baudRate} baud</div>
                        </div>
                      </div>

                      {pskResult.detected && (
                        <>
                          <div>
                            <div className="text-sm text-muted-foreground mb-1">PSK Type</div>
                            <div className="font-mono text-sm bg-muted/20 p-2 rounded">{pskResult.pskType}</div>
                          </div>

                          <div>
                            <div className="text-sm text-muted-foreground mb-2">Decoded Bits ({pskResult.decodedBits.length} bits)</div>
                            <div className="bg-muted/20 p-3 rounded font-mono text-xs overflow-auto max-h-32 break-all">
                              {pskResult.decodedBits}
                            </div>
                          </div>

                          {pskResult.decodedText && (
                            <div>
                              <div className="text-sm text-muted-foreground mb-2">Decoded Text (ASCII)</div>
                              <div className="bg-accent/10 border border-accent/30 p-3 rounded font-mono text-sm">
                                {pskResult.decodedText}
                              </div>
                            </div>
                          )}
                        </>
                      )}
                    </div>
                  ) : (
                    <div className="text-center text-muted-foreground py-8">Analyzing...</div>
                  )}
                </Card>
              </TabsContent>
            </Tabs>
          )}
        </div>
      )}
    </div>
  )
}

export default AudioAnalysis
