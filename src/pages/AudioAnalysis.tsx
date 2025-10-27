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
  Search,
  Zap,
  Download,
  RefreshCw,
  AlertTriangle,
  CheckCircle,
  BarChart3,
  Cloud
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { Card } from '../components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs'
import { apiClient } from '../services/api'
import { useBackendJob } from '../hooks/useBackendJob'
import toast from 'react-hot-toast'
import {
  AudioPlayer,
  OverviewTab,
  SteganographyTab,
  SpectrumTab,
  EnhanceTab,
  WaveformVisualizer,
  ABComparisonPanel,
  AnalysisResultsPanel,
  type AudioRegion,
  type DecoderResult
} from '../components/audio'
import {
  loadAudioFile,
  extractMetadata,
  getWaveformData,
  separateChannels,
  extractStringsFromAudio,
  detectMorseCode,
  detectLSBSteganography,
  generateSpectrogram,
  analyzeFrequencyAnomalies,
  reverseAudio,
  formatDuration,
  formatFileSize,
  applyEqualizer,
  applyNoiseReduction,
  normalizeAudio,
  exportAsWAV,
  EQ_PRESETS,
  type AudioMetadata,
  type MorseResult,
  type SpectrogramData,
  type FrequencyResult,
  type EQBand
} from '../lib/audioAnalysis'
import {
  detectDTMF,
  detectBinaryAudio,
  detectSpectralAnomalies,
  detectRepeatedPatterns,
  type DTMFResult,
  type BinaryAudioResult,
  type SpectralAnomaly,
  type PatternMatch
} from '../lib/audioDecoders'

const AudioAnalysis: React.FC = () => {
  const location = useLocation()
  const [file, setFile] = useState<File | null>(null)
  const [audioBuffer, setAudioBuffer] = useState<AudioBuffer | null>(null)
  const [metadata, setMetadata] = useState<AudioMetadata | null>(null)
  const [isAnalyzing, setIsAnalyzing] = useState(false)

  // Backend spectrogram
  const [useBackendFFT, setUseBackendFFT] = useState(false)
  const { jobStatus, startJob } = useBackendJob()

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
  const [lsbData, setLsbData] = useState<string>('')
  const [spectrogram, setSpectrogram] = useState<SpectrogramData | null>(null)
  const [frequencyResult, setFrequencyResult] = useState<FrequencyResult | null>(null)
  
  // Backend-generated visualizations
  const [backendWaveform, setBackendWaveform] = useState<string | null>(null)
  const [backendSpectrogram, setBackendSpectrogram] = useState<string | null>(null)

  // Analysis progress tracking
  const [analysisProgress, setAnalysisProgress] = useState<Array<{ name: string; progress: number }>>([])

  // UI state
  const [stringFilter, setStringFilter] = useState('')
  const [debouncedStringFilter, setDebouncedStringFilter] = useState('')
  const [fftSize, setFftSize] = useState(2048)
  const [maxFrequency, setMaxFrequency] = useState(20000)
  const [morseThreshold, setMorseThreshold] = useState(0.1)
  const [activeTab, setActiveTab] = useState<'overview' | 'morse' | 'spectrum' | 'auto-decode' | 'strings'>('overview')

  // Audio enhancement state
  const [eqBands, setEqBands] = useState<EQBand[]>(EQ_PRESETS['Flat'])
  const [selectedPreset, setSelectedPreset] = useState('Flat')
  const [noiseReduction, setNoiseReduction] = useState(0)
  const [enhancedBuffer, setEnhancedBuffer] = useState<AudioBuffer | null>(null)
  const [showEnhanceControls, setShowEnhanceControls] = useState(false)

  // A/B Comparison state
  const [regionA, setRegionA] = useState<AudioRegion | null>(null)
  const [regionB, setRegionB] = useState<AudioRegion | null>(null)
  const [selectionMode, setSelectionMode] = useState<'none' | 'A' | 'B'>('none')
  const [playbackSpeedA, setPlaybackSpeedA] = useState(1.0)
  const [playbackSpeedB, setPlaybackSpeedB] = useState(1.0)

  // Comprehensive analysis results
  const [analysisResults, setAnalysisResults] = useState<DecoderResult[]>([])
  const [isRunningComprehensiveAnalysis, setIsRunningComprehensiveAnalysis] = useState(false)

  // Interactive waveform state - removed (now handled by WaveformVisualizer component)
  
  const fileInputRef = useRef<HTMLInputElement>(null)
  const canvasRef = useRef<HTMLCanvasElement>(null)
  const spectrogramCanvasRef = useRef<HTMLCanvasElement>(null)

  // Handle backend job completion
  useEffect(() => {
    if (jobStatus?.status === 'completed' && jobStatus?.results) {
      const results = jobStatus.results
      
      // Extract backend-generated visualizations
      if (results.waveform?.image) {
        setBackendWaveform(results.waveform.image)
      }
      if (results.spectrogram?.image) {
        setBackendSpectrogram(results.spectrogram.image)
      }
      
      console.log('Backend visualizations received:', {
        waveform: !!results.waveform,
        spectrogram: !!results.spectrogram
      })
    }
  }, [jobStatus])

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

  // Draw waveform whenever waveformData or backendWaveform changes
  useEffect(() => {
    if ((waveformData || backendWaveform) && canvasRef.current) {
      // Small delay to ensure canvas is fully rendered in DOM
      const timer = setTimeout(() => {
        if (waveformData) {
          drawWaveform(waveformData)
        } else if (backendWaveform) {
          // Just draw overlay for backend waveform
          drawWaveform(new Float32Array())
        }
      }, 50)
      return () => clearTimeout(timer)
    }
  }, [waveformData, backendWaveform])

  // Redraw waveform when playback position changes (works for both playing and paused states)
  useEffect(() => {
    if (waveformData || backendWaveform) {
      if (waveformData) {
        drawWaveform(waveformData)
      } else if (backendWaveform) {
        drawWaveform(new Float32Array())
      }
    }
  }, [currentTime, waveformData, backendWaveform])

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
    setLsbData('')
    setSpectrogram(null)
    setFrequencyResult(null)
    setBackendWaveform(null)
    setBackendSpectrogram(null)
    stopAudio()
  }

  const triggerBackendVisualization = async (selectedFile: File) => {
    try {
      const response = await apiClient.generateSpectrogram(selectedFile)

      if (response.jobId) {
        console.log('Backend visualization job started:', response.jobId)
        // Start the job monitoring
        await startJob(response.jobId)
      } else {
        throw new Error(response.error || 'Failed to start backend visualization')
      }
    } catch (error: any) {
      console.error('Backend visualization error:', error)
      // Non-blocking - continue with client-side analysis
    }
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

      // Trigger backend waveform and spectrogram generation automatically
      triggerBackendVisualization(selectedFile)

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

      // LSB steganography
      const lsb = await detectLSBSteganography(selectedFile)
      setLsbData(lsb)

      // Allow UI to update
      await new Promise(resolve => setTimeout(resolve, 10))

      // Frequency anomalies
      const anomalies = analyzeFrequencyAnomalies(buffer)
      if (anomalies.length > 0) {
        setFrequencyResult(anomalies[0])
      }

      // Run comprehensive CTF analysis directly
      setIsRunningComprehensiveAnalysis(true)
      const results: DecoderResult[] = []

      // DTMF Detection (Phone Tones)
      const dtmfResult = detectDTMF(buffer)
      results.push({
        type: 'dtmf',
        detected: dtmfResult.detected,
        confidence: dtmfResult.confidence,
        data: dtmfResult,
        description: 'DTMF (Phone Tone) Detection'
      })

      // Binary Audio Encoding
      const binaryResult = detectBinaryAudio(buffer)
      results.push({
        type: 'binary',
        detected: binaryResult.detected,
        confidence: binaryResult.confidence,
        data: binaryResult,
        description: `Binary Audio Encoding (${binaryResult.encoding})`
      })

      // Morse (already detected above, add to results)
      results.push({
        type: 'morse',
        detected: morse.detected,
        confidence: morse.confidence,
        data: morse,
        description: 'Morse Code Detection'
      })

      // LSB (already detected above, add to results)
      results.push({
        type: 'lsb',
        detected: lsb.length > 0,
        confidence: lsb.length > 0 ? 0.8 : 0,
        data: { decodedText: lsb, binaryString: '' },
        description: 'LSB Steganography Detection'
      })

      // Spectral Anomalies
      const spectralAnomalies = detectSpectralAnomalies(buffer)
      for (const anomaly of spectralAnomalies.filter(a => a.suspicious)) {
        results.push({
          type: 'anomaly',
          detected: true,
          confidence: anomaly.confidence,
          data: anomaly,
          description: `Spectral Anomaly: ${anomaly.type}`,
          timestamp: anomaly.timestamp
        })
      }

      // Repeated Patterns
      const patterns = detectRepeatedPatterns(buffer)
      for (const pattern of patterns) {
        results.push({
          type: 'pattern',
          detected: true,
          confidence: pattern.confidence,
          data: pattern,
          description: `Repeated Pattern (${pattern.repetitions}x)`,
          timestamp: pattern.startTime
        })
      }

      setAnalysisResults(results)
      setIsRunningComprehensiveAnalysis(false)

      // Note: Waveform and spectrogram are now generated by backend automatically
      
    } catch (error) {
      console.error('Analysis error:', error)
      alert('Failed to analyze audio: ' + (error as Error).message)
      setIsRunningComprehensiveAnalysis(false)
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

    // If we have backend waveform, just draw the overlay (playhead, hover, etc.)
    if (backendWaveform) {
      // Clear canvas for overlay
      ctx.clearRect(0, 0, width, height)

      // Draw playback position indicator (playhead)
      if (audioBuffer && currentTime > 0) {
        const progress = currentTime / audioBuffer.duration
        const playheadX = progress * width

        // Draw playhead line
        ctx.strokeStyle = '#ff0088'
        ctx.lineWidth = 3
        ctx.beginPath()
        ctx.moveTo(playheadX, 0)
        ctx.lineTo(playheadX, height)
        ctx.stroke()

        // Draw played region overlay
        ctx.fillStyle = 'rgba(0, 255, 136, 0.1)'
        ctx.fillRect(0, 0, playheadX, height)
      }
      return
    }

    // Fallback: Draw full waveform if no backend image yet
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

  // AudioPlayer component handlers
  const handlePlayPause = () => {
    if (isPlaying) {
      pauseAudio()
    } else {
      playAudio()
    }
  }

  const handleSeek = (time: number) => {
    seekTo(time)
  }

  const handleReverse = async () => {
    if (!audioBuffer) return
    setIsAnalyzing(true)
    const reversed = await reverseAudio(audioBuffer)
    setAudioBuffer(reversed)
    setIsReversed(!isReversed)
    toast.success(isReversed ? 'Audio unreversed' : 'Audio reversed')
    setIsAnalyzing(false)
  }

  // Batch analysis handler
  const handleAnalyzeAll = async () => {
    if (!audioBuffer) return
    
    setIsAnalyzing(true)
    const tasks = [
      { name: 'Morse Code', fn: analyzeMorse },
      { name: 'LSB Steganography', fn: analyzeLSB },
      { name: 'String Extraction', fn: analyzeStrings },
      { name: 'Spectrogram', fn: analyzeSpectrogram },
      { name: 'Frequency Analysis', fn: analyzeFrequency }
    ]

    setAnalysisProgress(tasks.map(t => ({ name: t.name, progress: 0 })))

    for (let i = 0; i < tasks.length; i++) {
      setAnalysisProgress(prev => 
        prev.map((t, idx) => idx === i ? { ...t, progress: 50 } : t)
      )
      await tasks[i].fn()
      setAnalysisProgress(prev =>
        prev.map((t, idx) => idx === i ? { ...t, progress: 100 } : t)
      )
    }

    setAnalysisProgress([])
    setIsAnalyzing(false)
    toast.success('All analyses complete!')
  }

  // Individual analysis handlers
  const analyzeMorse = async () => {
    if (!audioBuffer) return
    const result = await detectMorseCode(audioBuffer, morseThreshold)
    setMorseResult(result)
  }

  const analyzeLSB = async () => {
    if (!file) return
    const result = await detectLSBSteganography(file)
    setLsbData(result)
  }

  const analyzeStrings = async () => {
    if (!file) return
    const result = await extractStringsFromAudio(file)
    setStrings(result)
  }

  const analyzeSpectrogram = async () => {
    if (!audioBuffer) return
    const result = await generateSpectrogram(audioBuffer, fftSize, maxFrequency)
    setSpectrogram(result)
  }

  const analyzeFrequency = async () => {
    if (!audioBuffer) return
    const result = analyzeFrequencyAnomalies(audioBuffer)
    // Convert array to single result (use first anomaly or create aggregate)
    if (result.length > 0) {
      setFrequencyResult(result[0])
    }
  }

  // Enhancement handlers
  const handleEQChange = (index: number, gain: number) => {
    const newBands = [...eqBands]
    newBands[index] = { ...newBands[index], gain }
    setEqBands(newBands)
  }

  const handleResetEQ = () => {
    setEqBands(EQ_PRESETS['Flat'])
    setSelectedPreset('Flat')
  }

  const handleExport = async () => {
    if (!audioBuffer) return
    setIsAnalyzing(true)
    
    let processedBuffer = audioBuffer
    
    // Apply EQ if not flat
    if (eqBands.some(band => band.gain !== 0)) {
      processedBuffer = await applyEqualizer(processedBuffer, eqBands)
    }
    
    // Apply noise reduction if enabled
    if (noiseReduction > 0) {
      processedBuffer = await applyNoiseReduction(processedBuffer, noiseReduction)
    }
    
    // Export as WAV
    await exportAsWAV(processedBuffer, file?.name || 'enhanced')
    
    toast.success('Audio exported successfully!')
    setIsAnalyzing(false)
  }

  // A/B Comparison handlers
  const handleRegionChange = (region: AudioRegion | null, label: 'A' | 'B') => {
    if (label === 'A') {
      setRegionA(region)
    } else {
      setRegionB(region)
    }
    // Exit selection mode after creating region
    setSelectionMode('none')
  }

  const handleClearRegion = (label: 'A' | 'B') => {
    if (label === 'A') {
      setRegionA(null)
    } else {
      setRegionB(null)
    }
  }

  const playRegion = async (region: AudioRegion, speed: number) => {
    if (!audioBuffer) return

    stopAudio()

    const audioContext = new (window.AudioContext || (window as any).webkitAudioContext)()
    audioContextRef.current = audioContext

    let bufferToPlay = enhancedBuffer || audioBuffer
    if (isReversed) {
      bufferToPlay = reverseAudio(bufferToPlay)
    }

    const source = audioContext.createBufferSource()
    source.buffer = bufferToPlay
    source.playbackRate.value = speed

    // Create stereo panner
    const panner = audioContext.createStereoPanner()
    panner.pan.value = stereoBalance / 100
    pannerNodeRef.current = panner

    source.connect(panner)
    panner.connect(audioContext.destination)

    source.onended = () => {
      setIsPlaying(false)
      pauseTimeRef.current = 0
      setCurrentTime(region.startTime)
    }

    // Start from region start time, duration is region length
    const duration = region.endTime - region.startTime
    source.start(0, region.startTime, duration)
    startTimeRef.current = audioContext.currentTime
    pauseTimeRef.current = region.startTime
    sourceNodeRef.current = source
    setIsPlaying(true)
    setCurrentTime(region.startTime)

    // Update current time during playback
    const interval = setInterval(() => {
      const elapsed = (audioContext.currentTime - startTimeRef.current) * speed
      const newTime = region.startTime + elapsed
      if (newTime <= region.endTime) {
        setCurrentTime(newTime)
      } else {
        clearInterval(interval)
      }
    }, 100)

    source.onended = () => {
      clearInterval(interval)
      setIsPlaying(false)
      setCurrentTime(region.startTime)
    }
  }

  const handlePlayRegion = (label: 'A' | 'B') => {
    const region = label === 'A' ? regionA : regionB
    const speed = label === 'A' ? playbackSpeedA : playbackSpeedB
    if (region) {
      playRegion(region, speed)
    }
  }

  const handleCompareRegions = async () => {
    if (!regionA || !regionB) return

    // Play region A, then region B
    await playRegion(regionA, playbackSpeedA)
    
    // Wait for region A to finish
    const durationA = (regionA.endTime - regionA.startTime) / playbackSpeedA
    setTimeout(() => {
      playRegion(regionB, playbackSpeedB)
    }, durationA * 1000 + 200) // Add 200ms gap between regions
  }

  const handleSwapRegions = () => {
    const tempA = regionA
    setRegionA(regionB)
    setRegionB(tempA)
  }

  // Comprehensive "Auto-Decode All" analysis
  const runComprehensiveAnalysis = async () => {
    if (!audioBuffer || !file) return

    setIsRunningComprehensiveAnalysis(true)
    const results: DecoderResult[] = []

    try {
      // 1. Morse Code Detection
      toast.loading('Analyzing morse code...')
      const morseResult = detectMorseCode(audioBuffer, morseThreshold)
      results.push({
        type: 'morse',
        detected: morseResult.detected,
        confidence: morseResult.confidence,
        data: morseResult,
        description: 'Morse Code Detection'
      })

      // 2. DTMF Detection (Phone Tones)
      toast.loading('Detecting DTMF tones...')
      const dtmfResult = detectDTMF(audioBuffer)
      results.push({
        type: 'dtmf',
        detected: dtmfResult.detected,
        confidence: dtmfResult.confidence,
        data: dtmfResult,
        description: 'DTMF (Phone Tone) Detection'
      })

      // 3. Binary Audio Encoding
      toast.loading('Detecting binary encoding...')
      const binaryResult = detectBinaryAudio(audioBuffer)
      results.push({
        type: 'binary',
        detected: binaryResult.detected,
        confidence: binaryResult.confidence,
        data: binaryResult,
        description: `Binary Audio Encoding (${binaryResult.encoding})`
      })

      // 4. LSB Steganography
      toast.loading('Analyzing LSB steganography...')
      const lsbResult = await detectLSBSteganography(file)
      results.push({
        type: 'lsb',
        detected: lsbResult.length > 0,
        confidence: lsbResult.length > 0 ? 0.8 : 0,
        data: { decodedText: lsbResult, binaryString: '' },
        description: 'LSB Steganography Detection'
      })

      // 5. Spectral Anomalies
      toast.loading('Detecting spectral anomalies...')
      const anomalies = detectSpectralAnomalies(audioBuffer)
      for (const anomaly of anomalies.filter(a => a.suspicious)) {
        results.push({
          type: 'anomaly',
          detected: true,
          confidence: anomaly.confidence,
          data: anomaly,
          description: `Spectral Anomaly: ${anomaly.type}`,
          timestamp: anomaly.timestamp
        })
      }

      // 6. Repeated Patterns
      toast.loading('Finding repeated patterns...')
      const patterns = detectRepeatedPatterns(audioBuffer)
      for (const pattern of patterns) {
        results.push({
          type: 'pattern',
          detected: true,
          confidence: pattern.confidence,
          data: pattern,
          description: `Repeated Pattern (${pattern.repetitions}x)`,
          timestamp: pattern.startTime
        })
      }

      setAnalysisResults(results)
      
      const detectedCount = results.filter(r => r.detected).length
      toast.success(`Analysis complete! ${detectedCount} detection${detectedCount !== 1 ? 's' : ''} found`)
      
    } catch (error) {
      console.error('Comprehensive analysis error:', error)
      toast.error('Analysis failed: ' + (error as Error).message)
    } finally {
      setIsRunningComprehensiveAnalysis(false)
    }
  }

  const handleExportResults = () => {
    const detectedResults = analysisResults.filter(r => r.detected)
    const exportText = detectedResults.map(r => {
      let text = `=== ${r.description} ===\n`
      text += `Confidence: ${(r.confidence * 100).toFixed(0)}%\n`
      
      if (r.data.message) text += `Message: ${r.data.message}\n`
      if (r.data.sequence) text += `Sequence: ${r.data.sequence}\n`
      if (r.data.decodedText) text += `Decoded: ${r.data.decodedText}\n`
      if (r.data.description) text += `Details: ${r.data.description}\n`
      
      return text
    }).join('\n\n')

    const blob = new Blob([exportText], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `analysis-results-${Date.now()}.txt`
    a.click()
    URL.revokeObjectURL(url)
    
    toast.success('Results exported!')
  }

  const generateSpectrogramWithBackend = async () => {
    if (!file) {
      toast.error('Please upload a file first')
      return
    }

    setIsAnalyzing(true)
    toast('Generating spectrogram on backend server...')

    try {
      const response = await apiClient.generateSpectrogram(file)

      if (response.jobId) {
        startJob(response.jobId)
      } else {
        // Immediate response with spectrogram data
        setSpectrogram(response)
        drawSpectrogram(response)
        setIsAnalyzing(false)
        toast.success('Backend spectrogram generated!')
      }
    } catch (error: any) {
      console.error('Backend spectrogram generation failed:', error)
      toast.error('Backend spectrogram failed')
      setIsAnalyzing(false)
    }
  }

  // Watch for backend job updates
  useEffect(() => {
    if (jobStatus) {
      if (jobStatus.status === 'processing') {
        toast(`Processing: ${jobStatus.progress}%`)
      } else if (jobStatus.status === 'completed') {
        setSpectrogram(jobStatus.results)
        drawSpectrogram(jobStatus.results)
        setIsAnalyzing(false)
        toast.success('Backend spectrogram completed!')
      } else if (jobStatus.status === 'failed') {
        toast.error('Backend spectrogram failed')
        setIsAnalyzing(false)
      }
    }
  }, [jobStatus])

  const handleReanalyze = async () => {
    if (useBackendFFT) {
      await generateSpectrogramWithBackend()
      return
    }

    if (file && audioBuffer) {
      setIsAnalyzing(true)
      try {
        const morse = detectMorseCode(audioBuffer, morseThreshold)
        setMorseResult(morse)

        const spectro = await generateSpectrogram(audioBuffer, fftSize, maxFrequency)
        setSpectrogram(spectro)
        drawSpectrogram(spectro)
      } catch (error) {
        // Reanalysis error
      } finally {
        setIsAnalyzing(false)
      }
    }
  }

  const filteredStrings = strings.filter(s =>
    s.toLowerCase().includes(debouncedStringFilter.toLowerCase())
  )

  return (
    <div className="flex flex-col min-h-full">
      {/* Header */}
      <div className="flex-none px-6 py-4 border-b border-border bg-card">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold">Audio Analysis</h1>
            <p className="text-sm text-muted-foreground">
              Detect hidden messages in audio files - Morse code, DTMF, LSB steganography, and more
            </p>
          </div>
        </div>
      </div>

      {/* File Upload or Info */}
      <div className="flex-none px-6 py-4 bg-background">
        {!file ? (
          <div
            className="border-2 border-dashed border-border rounded-lg p-8 text-center hover:border-accent transition-colors cursor-pointer"
            onClick={() => fileInputRef.current?.click()}
          >
            <Upload className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
            <p className="text-lg font-medium mb-2">Drop audio file here or click to browse</p>
            <p className="text-sm text-muted-foreground">
              Supports MP3, WAV, OGG, M4A, FLAC - All audio formats supported
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
        ) : (
          <div className="flex items-center justify-between bg-card border border-border rounded-lg p-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded bg-accent/20 flex items-center justify-center">
                <Music className="w-5 h-5 text-accent" />
              </div>
              <div>
                <p className="font-medium">{file.name}</p>
                <p className="text-sm text-muted-foreground">{formatFileSize(file.size)}</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Button
                onClick={() => handleAnalyze()}
                disabled={isAnalyzing}
                variant="outline"
                className="hover:bg-accent hover:text-white hover:border-accent hover:scale-105 transition-all duration-200 tracking-wide"
              >
                {isAnalyzing ? (
                  <>
                    <Activity className="w-4 h-4 animate-spin mr-2" />
                    Analyzing...
                  </>
                ) : (
                  <>
                    <Zap className="w-4 h-4 mr-2" />
                    Analyze
                  </>
                )}
              </Button>
              <Button
                variant="outline"
                onClick={() => {
                  setFile(null)
                  resetAnalysis()
                }}
                disabled={isAnalyzing}
                className="hover:bg-red-500 hover:text-white hover:border-red-500 hover:scale-105 transition-all duration-200 tracking-wide"
              >
                Remove
              </Button>
            </div>
          </div>
        )}
      </div>

      {/* Analysis Section */}
      {file && (
        <div className="px-6 pb-6">
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

                {/* Waveform Visualizer */}
                <div className="mt-4">
                  <WaveformVisualizer
                    backendWaveform={backendWaveform}
                    audioBuffer={audioBuffer}
                    currentTime={currentTime}
                    isPlaying={isPlaying}
                    onSeek={seekTo}
                    regionA={regionA}
                    regionB={regionB}
                    onRegionChange={handleRegionChange}
                    selectionMode={selectionMode}
                  />
                </div>

                {/* A/B Comparison Panel */}
                {audioBuffer && (
                  <div className="mt-4">
                    <ABComparisonPanel
                      regionA={regionA}
                      regionB={regionB}
                      selectionMode={selectionMode}
                      onSelectionModeChange={setSelectionMode}
                      onClearRegion={handleClearRegion}
                      onPlayRegion={handlePlayRegion}
                      onCompareRegions={handleCompareRegions}
                      onSwapRegions={handleSwapRegions}
                      playbackSpeedA={playbackSpeedA}
                      playbackSpeedB={playbackSpeedB}
                      onSpeedChange={(label, speed) => {
                        if (label === 'A') setPlaybackSpeedA(speed)
                        else setPlaybackSpeedB(speed)
                      }}
                      isPlaying={isPlaying}
                    />
                  </div>
                )}

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
                                className="h-24"
                                style={{ writingMode: 'vertical-lr' as const, WebkitAppearance: 'slider-vertical', width: '20px' }}
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
              <TabsList className="grid grid-cols-5 w-full">
                <TabsTrigger value="overview">
                  <Eye className="w-4 h-4 mr-1" />
                  <span className="hidden md:inline">Overview</span>
                </TabsTrigger>
                <TabsTrigger value="morse">
                  <Radio className="w-4 h-4 mr-1" />
                  <span className="hidden md:inline">Morse</span>
                </TabsTrigger>
                <TabsTrigger value="spectrum">
                  <BarChart3 className="w-4 h-4 mr-1" />
                  <span className="hidden md:inline">Spectrum</span>
                </TabsTrigger>
                <TabsTrigger value="auto-decode">
                  <Zap className="w-4 h-4 mr-1" />
                  <span className="hidden md:inline">Auto-Decode</span>
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
                      <p><span className="text-muted-foreground">Frequency Peaks:</span> {frequencyResult ? 1 : 0}</p>
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

              {/* Spectrogram Tab */}
              <TabsContent value="spectrum">
                <Card className="p-4">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="font-semibold">Spectrogram Analysis</h3>
                    <div className="flex items-center gap-2">
                      {backendSpectrogram && (
                        <Button
                          size="sm"
                          variant="outline"
                          onClick={() => {
                            const link = document.createElement('a')
                            link.download = `${file?.name.replace(/\.[^.]+$/, '')}_spectrogram.png`
                            link.href = backendSpectrogram
                            link.click()
                          }}
                        >
                          <Download className="w-3 h-3 mr-1" />
                          PNG
                        </Button>
                      )}
                    </div>
                  </div>

                  <div className="bg-muted/20 p-2 rounded overflow-auto">
                    {backendSpectrogram ? (
                      <img 
                        src={backendSpectrogram} 
                        alt="Audio Spectrogram" 
                        className="w-full border border-border rounded"
                        style={{ display: 'block', width: '100%', height: 'auto' }}
                      />
                    ) : (
                      <div className="flex items-center justify-center h-64 text-muted-foreground">
                        {isAnalyzing || jobStatus?.status === 'processing' ? (
                          <div className="flex flex-col items-center gap-2">
                            <Activity className="w-8 h-8 animate-spin text-accent" />
                            <p>Generating spectrogram with FFmpeg...</p>
                          </div>
                        ) : (
                          <p>Upload and analyze an audio file to see the spectrogram</p>
                        )}
                      </div>
                    )}
                  </div>

                  <p className="text-xs text-muted-foreground mt-2">
                    🎨 High-quality spectrogram generated automatically using FFmpeg. Look for hidden images or patterns in the frequency spectrum.
                  </p>
                </Card>
              </TabsContent>

              {/* Auto-Decode Tab */}
              <TabsContent value="auto-decode">
                <Card className="p-4">
                  <div className="mb-4">
                    <h3 className="font-semibold flex items-center mb-2">
                      <Zap className="w-5 h-5 mr-2 text-accent" />
                      CTF Auto-Decode Results
                    </h3>
                    <p className="text-sm text-muted-foreground">
                      Automatic analysis results from: Morse, DTMF, Binary Encoding, LSB, Spectral Anomalies, and Pattern Detection
                    </p>
                  </div>

                  {isRunningComprehensiveAnalysis ? (
                    <div className="flex flex-col items-center justify-center py-12">
                      <Activity className="w-12 h-12 animate-spin text-accent mb-4" />
                      <p className="text-muted-foreground">Running comprehensive analysis...</p>
                    </div>
                  ) : analysisResults.length > 0 ? (
                    <AnalysisResultsPanel
                      results={analysisResults}
                      onJumpToTimestamp={seekTo}
                      onExportResults={handleExportResults}
                    />
                  ) : (
                    <div className="flex flex-col items-center justify-center py-12">
                      <AlertTriangle className="w-12 h-12 text-muted-foreground mb-4" />
                      <p className="text-muted-foreground">Analysis will run automatically when you upload a file</p>
                    </div>
                  )}
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
            </Tabs>
          )}

          </div>
        </div>
      )}
    </div>
  )
}

export default AudioAnalysis
