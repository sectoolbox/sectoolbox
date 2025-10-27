// Audio Analysis Library - CTF-focused steganography detection
// Detects hidden messages in audio files (Morse code, DTMF, LSB, spectrograms, etc.)

export interface AudioMetadata {
  duration: number
  sampleRate: number
  numberOfChannels: number
  bitDepth?: number
  codec?: string
  bitrate?: number
  format?: string
  size: number
}

export interface AudioAnalysisResult {
  metadata: AudioMetadata
  waveformData: Float32Array
  leftChannel?: Float32Array
  rightChannel?: Float32Array
  strings: string[]
  lsbData?: string
  detectedPatterns: {
    morse?: MorseResult
    dtmf?: DTMFResult
    frequencies?: FrequencyResult[]
    hiddenData?: string[]
  }
}

export interface MorseResult {
  detected: boolean
  message: string
  confidence: number
  positions: Array<{ start: number; end: number; symbol: string }>
}

export interface DTMFResult {
  detected: boolean
  sequence: string
  tones: Array<{ digit: string; timestamp: number; duration: number }>
}

export interface FrequencyResult {
  frequency: number
  amplitude: number
  timestamp: number
  suspicious: boolean
}

export interface SpectrogramData {
  data: number[][]
  width: number
  height: number
  minFreq: number
  maxFreq: number
  minTime: number
  maxTime: number
}

export interface SSTVResult {
  detected: boolean
  possibleFormat?: string
  confidence: number
  description: string
  spectrogramImageData?: ImageData
}

export interface FSKResult {
  detected: boolean
  baudRate: number
  markFrequency: number
  spaceFrequency: number
  decodedBits: string
  confidence: number
  decodedText?: string
}

export interface PSKResult {
  detected: boolean
  carrierFrequency: number
  baudRate: number
  pskType: 'BPSK' | 'QPSK' | 'Unknown'
  decodedBits: string
  confidence: number
  decodedText?: string
}

export interface EQBand {
  frequency: number
  gain: number  // -12 to +12 dB
}

// Re-export advanced features
export * from './audioAnalysisAdvanced'

export const EQ_PRESETS: Record<string, EQBand[]> = {
  'Flat': [
    { frequency: 31, gain: 0 }, { frequency: 62, gain: 0 }, { frequency: 125, gain: 0 },
    { frequency: 250, gain: 0 }, { frequency: 500, gain: 0 }, { frequency: 1000, gain: 0 },
    { frequency: 2000, gain: 0 }, { frequency: 4000, gain: 0 }, { frequency: 8000, gain: 0 },
    { frequency: 16000, gain: 0 }
  ],
  'Voice Enhance': [
    { frequency: 31, gain: -6 }, { frequency: 62, gain: -4 }, { frequency: 125, gain: -2 },
    { frequency: 250, gain: 2 }, { frequency: 500, gain: 4 }, { frequency: 1000, gain: 6 },
    { frequency: 2000, gain: 8 }, { frequency: 4000, gain: 6 }, { frequency: 8000, gain: 2 },
    { frequency: 16000, gain: -4 }
  ],
  'Bass Cut': [
    { frequency: 31, gain: -12 }, { frequency: 62, gain: -10 }, { frequency: 125, gain: -6 },
    { frequency: 250, gain: -3 }, { frequency: 500, gain: 0 }, { frequency: 1000, gain: 0 },
    { frequency: 2000, gain: 0 }, { frequency: 4000, gain: 0 }, { frequency: 8000, gain: 0 },
    { frequency: 16000, gain: 0 }
  ],
  'Treble Cut': [
    { frequency: 31, gain: 0 }, { frequency: 62, gain: 0 }, { frequency: 125, gain: 0 },
    { frequency: 250, gain: 0 }, { frequency: 500, gain: 0 }, { frequency: 1000, gain: 0 },
    { frequency: 2000, gain: -3 }, { frequency: 4000, gain: -6 }, { frequency: 8000, gain: -10 },
    { frequency: 16000, gain: -12 }
  ],
  'Hidden Signal': [
    { frequency: 31, gain: -8 }, { frequency: 62, gain: -6 }, { frequency: 125, gain: -3 },
    { frequency: 250, gain: 0 }, { frequency: 500, gain: 3 }, { frequency: 1000, gain: 6 },
    { frequency: 2000, gain: 8 }, { frequency: 4000, gain: 10 }, { frequency: 8000, gain: 8 },
    { frequency: 16000, gain: 4 }
  ]
}

// Load and decode audio file
export async function loadAudioFile(file: File): Promise<AudioBuffer> {
  const arrayBuffer = await file.arrayBuffer()
  const audioContext = new (window.AudioContext || (window as any).webkitAudioContext)()

  // For WAV files, try manual parsing first (more reliable)
  if (file.name.toLowerCase().endsWith('.wav') || file.type === 'audio/wav' || file.type === 'audio/x-wav') {
    console.log('Attempting manual WAV parsing first...')
    try {
      const wavBuffer = parseWAVFile(arrayBuffer, audioContext)
      if (wavBuffer) {
        console.log('Successfully parsed WAV file manually')
        return wavBuffer
      }
    } catch (wavError) {
      console.warn('Manual WAV parsing failed, trying browser decoder:', wavError)
    }
  }

  // Try browser's native decoder
  try {
    const audioBuffer = await audioContext.decodeAudioData(arrayBuffer.slice(0))
    console.log('Successfully decoded audio with browser decoder')
    return audioBuffer
  } catch (error) {
    console.error('Browser audio decode error:', error)

    // Log file details for debugging
    console.log('File details:', {
      name: file.name,
      type: file.type,
      size: file.size,
      firstBytes: Array.from(new Uint8Array(arrayBuffer.slice(0, 12))).map(b => b.toString(16).padStart(2, '0')).join(' ')
    })

    throw new Error(`Failed to decode audio file "${file.name}". The file may be corrupted or use an unsupported codec. Try converting to standard PCM WAV (16-bit) or MP3 format using a tool like FFmpeg or Audacity.`)
  }
}

// Manual WAV parser for files that fail standard decoding
function parseWAVFile(arrayBuffer: ArrayBuffer, audioContext: AudioContext): AudioBuffer | null {
  try {
    const view = new DataView(arrayBuffer)

    // Check RIFF header
    const riff = String.fromCharCode(view.getUint8(0), view.getUint8(1), view.getUint8(2), view.getUint8(3))
    if (riff !== 'RIFF') {
      console.warn('Not a valid RIFF file')
      return null
    }

    // Check WAVE format
    const wave = String.fromCharCode(view.getUint8(8), view.getUint8(9), view.getUint8(10), view.getUint8(11))
    if (wave !== 'WAVE') {
      console.warn('Not a valid WAVE file')
      return null
    }

    // Find fmt chunk
    let offset = 12
    let audioFormat = 0
    let numChannels = 0
    let sampleRate = 0
    let bitsPerSample = 0

    while (offset < view.byteLength - 8) {
      const chunkId = String.fromCharCode(
        view.getUint8(offset),
        view.getUint8(offset + 1),
        view.getUint8(offset + 2),
        view.getUint8(offset + 3)
      )
      const chunkSize = view.getUint32(offset + 4, true)

      if (chunkId === 'fmt ') {
        audioFormat = view.getUint16(offset + 8, true)
        numChannels = view.getUint16(offset + 10, true)
        sampleRate = view.getUint32(offset + 12, true)
        bitsPerSample = view.getUint16(offset + 22, true)
        console.log('WAV Format:', { audioFormat, numChannels, sampleRate, bitsPerSample })
      } else if (chunkId === 'data') {
        // Found data chunk
        const dataOffset = offset + 8
        const dataSize = chunkSize

        // Support PCM (1) and IEEE float (3) formats
        if (audioFormat !== 1 && audioFormat !== 3) {
          console.warn('Unsupported WAV format:', audioFormat, '(only PCM=1 and IEEE_FLOAT=3 supported)')
          return null
        }

        // Create audio buffer
        const numFrames = Math.floor(dataSize / (numChannels * (bitsPerSample / 8)))
        console.log('Creating buffer:', { numChannels, numFrames, sampleRate })
        const audioBuffer = audioContext.createBuffer(numChannels, numFrames, sampleRate)

        // Parse audio data based on bit depth
        const bytesPerSample = bitsPerSample / 8

        for (let channel = 0; channel < numChannels; channel++) {
          const channelData = audioBuffer.getChannelData(channel)

          for (let i = 0; i < numFrames; i++) {
            const sampleOffset = dataOffset + (i * numChannels * bytesPerSample) + (channel * bytesPerSample)
            let sample = 0

            if (bitsPerSample === 8) {
              // 8-bit is unsigned (0-255), convert to -1 to 1
              sample = (view.getUint8(sampleOffset) - 128) / 128
            } else if (bitsPerSample === 16) {
              // 16-bit is signed, convert to -1 to 1
              sample = view.getInt16(sampleOffset, true) / 32768
            } else if (bitsPerSample === 24) {
              // 24-bit signed
              const byte1 = view.getUint8(sampleOffset)
              const byte2 = view.getUint8(sampleOffset + 1)
              const byte3 = view.getUint8(sampleOffset + 2)
              let value = (byte3 << 16) | (byte2 << 8) | byte1
              if (value & 0x800000) value |= ~0xFFFFFF // Sign extend
              sample = value / 8388608
            } else if (bitsPerSample === 32) {
              // 32-bit float or int
              sample = view.getFloat32(sampleOffset, true)
            }

            channelData[i] = sample
          }
        }

        return audioBuffer
      }

      offset += 8 + chunkSize
      if (chunkSize % 2 === 1) offset++ // WAV chunks are word-aligned
    }

    return null
  } catch (error) {
    console.error('Error parsing WAV file:', error)
    return null
  }
}

// Extract comprehensive metadata
export function extractMetadata(audioBuffer: AudioBuffer, file: File): AudioMetadata {
  return {
    duration: audioBuffer.duration,
    sampleRate: audioBuffer.sampleRate,
    numberOfChannels: audioBuffer.numberOfChannels,
    format: file.type || 'unknown',
    size: file.size,
    bitrate: Math.round((file.size * 8) / audioBuffer.duration)
  }
}

// Get waveform data for visualization
export function getWaveformData(audioBuffer: AudioBuffer, samples: number = 2000): Float32Array {
  const channelData = audioBuffer.getChannelData(0)
  const blockSize = Math.floor(channelData.length / samples)
  const waveform = new Float32Array(samples)

  for (let i = 0; i < samples; i++) {
    const start = i * blockSize
    const end = start + blockSize
    let sum = 0

    for (let j = start; j < end && j < channelData.length; j++) {
      sum += Math.abs(channelData[j])
    }

    waveform[i] = sum / blockSize
  }

  return waveform
}

// Separate stereo channels
export function separateChannels(audioBuffer: AudioBuffer): { left: Float32Array; right: Float32Array } {
  const left = audioBuffer.getChannelData(0)
  const right = audioBuffer.numberOfChannels > 1 ? audioBuffer.getChannelData(1) : left

  return { left, right }
}

// Extract strings from audio file binary data
export async function extractStringsFromAudio(file: File): Promise<string[]> {
  const arrayBuffer = await file.arrayBuffer()
  const bytes = new Uint8Array(arrayBuffer)
  const strings: string[] = []
  let current: number[] = []

  for (let i = 0; i < bytes.length; i++) {
    const byte = bytes[i]
    if (byte >= 32 && byte <= 126) {
      current.push(byte)
    } else {
      if (current.length >= 4) {
        strings.push(String.fromCharCode(...current))
      }
      current = []
    }
  }

  if (current.length >= 4) {
    strings.push(String.fromCharCode(...current))
  }

  return strings
}

// Morse Code Detection in audio
export function detectMorseCode(audioBuffer: AudioBuffer, threshold: number = 0.1): MorseResult {
  const channelData = audioBuffer.getChannelData(0)
  const sampleRate = audioBuffer.sampleRate

  // Smooth the amplitude using a moving average to reduce noise
  const windowSize = Math.floor(sampleRate * 0.005) // 5ms window
  const smoothed = new Float32Array(channelData.length)

  for (let i = 0; i < channelData.length; i++) {
    let sum = 0
    let count = 0
    for (let j = Math.max(0, i - windowSize); j < Math.min(channelData.length, i + windowSize); j++) {
      sum += Math.abs(channelData[j])
      count++
    }
    smoothed[i] = sum / count
  }

  // Detect on/off events
  const events: Array<{ start: number; end: number; type: 'on' | 'off' }> = []
  let isOn = false
  let currentStart = 0

  for (let i = 0; i < smoothed.length; i++) {
    const amplitude = smoothed[i]

    if (!isOn && amplitude > threshold) {
      // Signal started - record the gap if there was one
      if (events.length > 0) {
        events.push({ start: currentStart, end: i, type: 'off' })
      }
      isOn = true
      currentStart = i
    } else if (isOn && amplitude <= threshold) {
      // Signal ended - record the tone
      events.push({ start: currentStart, end: i, type: 'on' })
      isOn = false
      currentStart = i
    }
  }

  // Filter events by minimum duration to remove noise
  const minDuration = Math.floor(sampleRate * 0.02) // 20ms minimum
  const filteredEvents = events.filter(e => (e.end - e.start) >= minDuration)

  if (filteredEvents.length < 3) {
    return { detected: false, message: '', confidence: 0, positions: [] }
  }

  // Calculate unit length (dit) from shortest ON events
  const onDurations = filteredEvents.filter(e => e.type === 'on').map(e => e.end - e.start)
  if (onDurations.length === 0) {
    return { detected: false, message: '', confidence: 0, positions: [] }
  }

  const sortedOnDurations = [...onDurations].sort((a, b) => a - b)
  const ditLength = sortedOnDurations[Math.floor(sortedOnDurations.length * 0.25)] // 25th percentile

  // Decode morse from events
  const morseChars: string[] = []
  const positions: Array<{ start: number; end: number; symbol: string }> = []
  let currentChar: string[] = []

  for (let i = 0; i < filteredEvents.length; i++) {
    const event = filteredEvents[i]
    const duration = event.end - event.start
    const ratio = duration / ditLength

    if (event.type === 'on') {
      // Tone event - determine if dit or dah
      let symbol = ''
      if (ratio < 1.8) {
        symbol = '.'
      } else {
        symbol = '-'
      }

      currentChar.push(symbol)
      positions.push({
        start: event.start / sampleRate,
        end: event.end / sampleRate,
        symbol
      })
    } else if (event.type === 'off') {
      // Gap event - determine character or word boundary
      if (ratio >= 5) {
        // Word space (7 units)
        if (currentChar.length > 0) {
          morseChars.push(currentChar.join(''))
          currentChar = []
        }
        morseChars.push(' ')
      } else if (ratio >= 2.5) {
        // Character space (3 units)
        if (currentChar.length > 0) {
          morseChars.push(currentChar.join(''))
          currentChar = []
        }
      }
      // Otherwise it's just inter-symbol space (1 unit) - continue building current character
    }
  }

  // Add final character if any
  if (currentChar.length > 0) {
    morseChars.push(currentChar.join(''))
  }

  const message = morseChars.map(char => {
    if (char === ' ') return ' '
    return morseDict[char] || ''
  }).join('')

  const confidence = filteredEvents.length > 10 ? 0.7 : 0.3

  return {
    detected: message.length > 0,
    message,
    confidence,
    positions
  }
}

// Morse code dictionary
const morseDict: Record<string, string> = {
  '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
  '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
  '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
  '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
  '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
  '--..': 'Z',
  '-----': '0', '.----': '1', '..---': '2', '...--': '3',
  '....-': '4', '.....': '5', '-....': '6', '--...': '7',
  '---..': '8', '----.': '9'
}


// DTMF (Dual-Tone Multi-Frequency) Detection
export async function detectDTMF(audioBuffer: AudioBuffer): Promise<DTMFResult> {
  const sampleRate = audioBuffer.sampleRate
  const channelData = audioBuffer.getChannelData(0)

  // Limit analysis to first 60 seconds for performance
  const maxSamples = Math.min(channelData.length, sampleRate * 60)
  const limitedData = channelData.slice(0, maxSamples)

  // DTMF frequency pairs
  const dtmfFreqs: Record<string, [number, number]> = {
    '1': [697, 1209], '2': [697, 1336], '3': [697, 1477],
    '4': [770, 1209], '5': [770, 1336], '6': [770, 1477],
    '7': [852, 1209], '8': [852, 1336], '9': [852, 1477],
    '*': [941, 1209], '0': [941, 1336], '#': [941, 1477]
  }

  const tones: Array<{ digit: string; timestamp: number; duration: number }> = []
  const windowSize = Math.floor(sampleRate * 0.1) // 100ms window

  // Process in chunks to avoid blocking
  for (let i = 0; i < limitedData.length - windowSize; i += windowSize) {
    const window = limitedData.slice(i, i + windowSize)
    const fft = await performFFT(window, sampleRate)

    // Check for DTMF frequency pairs
    for (const [digit, [f1, f2]] of Object.entries(dtmfFreqs)) {
      if (detectFrequency(fft, f1, sampleRate) && detectFrequency(fft, f2, sampleRate)) {
        tones.push({
          digit,
          timestamp: i / sampleRate,
          duration: windowSize / sampleRate
        })
        break
      }
    }
  }

  // Merge consecutive same tones
  const mergedTones: typeof tones = []
  for (let i = 0; i < tones.length; i++) {
    if (mergedTones.length === 0 || mergedTones[mergedTones.length - 1].digit !== tones[i].digit) {
      mergedTones.push(tones[i])
    } else {
      mergedTones[mergedTones.length - 1].duration += tones[i].duration
    }
  }

  const sequence = mergedTones.map(t => t.digit).join('')

  return {
    detected: mergedTones.length > 0,
    sequence,
    tones: mergedTones
  }
}

// Optimized FFT using native Web Audio API AnalyserNode
async function performFFT(signal: Float32Array, sampleRate: number = 44100): Promise<Float32Array> {
  // Find nearest power of 2 for FFT size (must be between 32 and 32768)
  const nearestPowerOf2 = (n: number) => {
    let power = 32
    while (power < n && power < 32768) {
      power *= 2
    }
    return Math.min(power, 8192) // Cap at 8192 for performance
  }

  const fftSize = nearestPowerOf2(signal.length)

  // Pad or truncate signal to match FFT size
  const paddedSignal = new Float32Array(fftSize)
  paddedSignal.set(signal.slice(0, fftSize))

  // For performance, use Web Audio API's native FFT
  const audioContext = new (window.AudioContext || (window as any).webkitAudioContext)({ sampleRate })
  const audioBuffer = audioContext.createBuffer(1, paddedSignal.length, sampleRate)
  audioBuffer.getChannelData(0).set(paddedSignal)

  const source = audioContext.createBufferSource()
  source.buffer = audioBuffer

  const analyser = audioContext.createAnalyser()
  analyser.fftSize = fftSize
  source.connect(analyser)

  const spectrum = new Float32Array(analyser.frequencyBinCount)
  analyser.getFloatFrequencyData(spectrum)

  // Convert from dB to magnitude
  const magnitude = new Float32Array(spectrum.length)
  for (let i = 0; i < spectrum.length; i++) {
    magnitude[i] = Math.pow(10, spectrum[i] / 20)
  }

  await audioContext.close()
  return magnitude
}

// Detect specific frequency in FFT result
function detectFrequency(fft: Float32Array, targetFreq: number, sampleRate: number, tolerance: number = 20): boolean {
  const freqPerBin = sampleRate / (fft.length * 2)
  const targetBin = Math.round(targetFreq / freqPerBin)
  const toleranceBins = Math.round(tolerance / freqPerBin)

  const startBin = Math.max(0, targetBin - toleranceBins)
  const endBin = Math.min(fft.length - 1, targetBin + toleranceBins)

  let maxAmplitude = 0
  for (let i = startBin; i <= endBin; i++) {
    maxAmplitude = Math.max(maxAmplitude, fft[i])
  }

  const avgAmplitude = fft.reduce((a, b) => a + b, 0) / fft.length
  return maxAmplitude > avgAmplitude * 3
}

// LSB (Least Significant Bit) Steganography Detection
export async function detectLSBSteganography(file: File): Promise<string> {
  const arrayBuffer = await file.arrayBuffer()
  const bytes = new Uint8Array(arrayBuffer)

  // Extract LSB from each byte
  let lsbBits = ''
  for (let i = 0; i < Math.min(bytes.length, 100000); i++) { // Limit to first 100KB
    lsbBits += (bytes[i] & 1).toString()
  }

  // Convert bits to text
  let extractedText = ''
  for (let i = 0; i < lsbBits.length - 8; i += 8) {
    const byte = parseInt(lsbBits.substr(i, 8), 2)
    if (byte >= 32 && byte <= 126) {
      extractedText += String.fromCharCode(byte)
    } else if (extractedText.length > 0) {
      break // Stop at first non-printable after getting some text
    }
  }

  return extractedText.length > 4 ? extractedText : ''
}

// Generate spectrogram data
export async function generateSpectrogram(
  audioBuffer: AudioBuffer,
  fftSize: number = 2048,
  maxFreq: number = 20000
): Promise<SpectrogramData> {
  const channelData = audioBuffer.getChannelData(0)
  const sampleRate = audioBuffer.sampleRate
  const hopSize = fftSize / 4

  // Limit to first 30 seconds for performance
  const maxSamples = Math.min(channelData.length, sampleRate * 30)
  const limitedData = channelData.slice(0, maxSamples)

  const numFrames = Math.min(Math.floor((limitedData.length - fftSize) / hopSize), 500) // Max 500 frames

  const spectrogram: number[][] = []
  const freqBins = fftSize / 2
  const maxFreqBin = Math.floor((maxFreq / sampleRate) * fftSize)

  for (let i = 0; i < numFrames; i++) {
    const start = i * hopSize
    const frame = limitedData.slice(start, start + fftSize)

    // Apply Hamming window
    const windowed = new Float32Array(fftSize)
    for (let j = 0; j < fftSize; j++) {
      windowed[j] = frame[j] * (0.54 - 0.46 * Math.cos((2 * Math.PI * j) / (fftSize - 1)))
    }

    const fft = await performFFT(windowed, sampleRate)
    const magnitudes: number[] = []

    for (let j = 0; j < Math.min(freqBins, maxFreqBin); j++) {
      magnitudes.push(20 * Math.log10(fft[j] + 1e-10)) // Convert to dB
    }

    spectrogram.push(magnitudes)
  }

  return {
    data: spectrogram,
    width: numFrames,
    height: Math.min(freqBins, maxFreqBin),
    minFreq: 0,
    maxFreq: Math.min(maxFreq, sampleRate / 2),
    minTime: 0,
    maxTime: audioBuffer.duration
  }
}

// Analyze frequency anomalies (suspicious frequencies)
export async function analyzeFrequencyAnomalies(audioBuffer: AudioBuffer): Promise<FrequencyResult[]> {
  const channelData = audioBuffer.getChannelData(0)
  const sampleRate = audioBuffer.sampleRate
  const windowSize = 4096
  const results: FrequencyResult[] = []

  for (let i = 0; i < channelData.length - windowSize; i += windowSize) {
    const window = channelData.slice(i, i + windowSize)
    const fft = await performFFT(window)

    // Find peaks
    for (let j = 1; j < fft.length - 1; j++) {
      if (fft[j] > fft[j - 1] && fft[j] > fft[j + 1]) {
        const frequency = (j * sampleRate) / (windowSize * 2)
        const amplitude = fft[j]

        // Suspicious if frequency is ultrasonic (>20kHz) or subsonic (<20Hz) with high amplitude
        const suspicious = (frequency < 20 || frequency > 20000) && amplitude > 0.1

        if (suspicious || amplitude > 0.5) {
          results.push({
            frequency,
            amplitude,
            timestamp: i / sampleRate,
            suspicious
          })
        }
      }
    }
  }

  return results.slice(0, 100) // Limit results
}

// Reverse audio buffer
export function reverseAudio(audioBuffer: AudioBuffer): AudioBuffer {
  const audioContext = new (window.AudioContext || (window as any).webkitAudioContext)()
  const reversedBuffer = audioContext.createBuffer(
    audioBuffer.numberOfChannels,
    audioBuffer.length,
    audioBuffer.sampleRate
  )

  for (let channel = 0; channel < audioBuffer.numberOfChannels; channel++) {
    const originalData = audioBuffer.getChannelData(channel)
    const reversedData = reversedBuffer.getChannelData(channel)

    for (let i = 0; i < originalData.length; i++) {
      reversedData[i] = originalData[originalData.length - 1 - i]
    }
  }

  return reversedBuffer
}

// Format duration for display
export function formatDuration(seconds: number): string {
  const mins = Math.floor(seconds / 60)
  const secs = Math.floor(seconds % 60)
  return `${mins}:${secs.toString().padStart(2, '0')}`
}

// Format file size
export function formatFileSize(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${(bytes / Math.pow(k, i)).toFixed(2)} ${sizes[i]}`
}

// SSTV (Slow-Scan Television) / Spectral Image Detection
export async function detectSSTVPattern(audioBuffer: AudioBuffer): Promise<SSTVResult> {
  const sampleRate = audioBuffer.sampleRate
  const channelData = audioBuffer.getChannelData(0)

  // Limit analysis to first 10 minutes (SSTV can be up to 9 minutes)
  const maxSamples = Math.min(channelData.length, sampleRate * 600)
  const limitedData = channelData.slice(0, maxSamples)

  // SSTV Key frequencies:
  // VIS header: 1900 Hz (leader), 1200 Hz (start bit), 1300/1100 Hz (data bits)
  // Sync pulse: 1200 Hz (5-30ms)
  // Image data: 1500 Hz (black) to 2300 Hz (white)

  const windowSize = Math.floor(sampleRate * 0.05) // 50ms windows
  const hopSize = Math.floor(windowSize / 2)
  const numWindows = Math.floor((limitedData.length - windowSize) / hopSize)

  let vis1900Count = 0  // 1900 Hz leader tone
  let sync1200Count = 0 // 1200 Hz sync
  let imageToneCount = 0 // 1500-2300 Hz range
  let totalWindows = 0

  // Analyze windows for SSTV characteristic frequencies
  for (let i = 0; i < Math.min(numWindows, 500); i++) {
    const start = i * hopSize
    const window = limitedData.slice(start, start + windowSize)

    // Use Goertzel algorithm for specific frequency detection
    const vis1900 = goertzelDetect(window, 1900, sampleRate)
    const sync1200 = goertzelDetect(window, 1200, sampleRate)
    const tone1500 = goertzelDetect(window, 1500, sampleRate)
    const tone1900 = goertzelDetect(window, 1900, sampleRate)
    const tone2300 = goertzelDetect(window, 2300, sampleRate)

    // Count windows with SSTV-like frequencies
    if (vis1900 > 0.1) vis1900Count++
    if (sync1200 > 0.1) sync1200Count++
    if (tone1500 > 0.05 || tone1900 > 0.05 || tone2300 > 0.05) imageToneCount++

    totalWindows++
  }

  // Calculate detection metrics
  const visRatio = vis1900Count / totalWindows
  const syncRatio = sync1200Count / totalWindows
  const imageRatio = imageToneCount / totalWindows

  let detected = false
  let possibleFormat = ''
  let confidence = 0
  let description = 'No SSTV pattern detected'

  // Detection logic based on SSTV characteristics
  if (visRatio > 0.01 && syncRatio > 0.02 && imageRatio > 0.1) {
    // Strong SSTV signature: VIS header + sync pulses + image tones
    detected = true
    confidence = Math.min(100, Math.floor((visRatio * 100 + syncRatio * 50 + imageRatio * 50)))
    possibleFormat = 'Robot36/Scottie/Martin (Auto-detect recommended)'
    description = 'Strong SSTV signal detected! Found VIS header (1900 Hz), sync pulses (1200 Hz), and image data (1500-2300 Hz). This audio contains an encoded image. Use SSTV decoder software like QSSTV, RX-SSTV, Robot36, or Black Cat SSTV to decode.'
  } else if (syncRatio > 0.03 && imageRatio > 0.15) {
    // SSTV without clear VIS header (might be partial or degraded)
    detected = true
    confidence = Math.min(100, Math.floor((syncRatio * 60 + imageRatio * 40)))
    possibleFormat = 'SSTV (degraded or partial signal)'
    description = 'SSTV-like pattern detected! Found sync pulses and image data tones, but VIS header is weak or missing. Try decoding with SSTV software in auto-detect mode.'
  } else if (imageRatio > 0.25) {
    // Lots of tones in SSTV frequency range
    detected = true
    confidence = Math.min(100, Math.floor(imageRatio * 60))
    possibleFormat = 'Possible SSTV or tonal data'
    description = 'Significant audio energy in SSTV frequency range (1500-2300 Hz). Could be SSTV image data, FAX, or other data transmission. Check spectrogram visually and try SSTV decoding.'
  } else if (sync1200Count > 10 || vis1900Count > 5) {
    // Some SSTV-characteristic tones present
    detected = true
    confidence = Math.min(100, Math.floor((visRatio * 100 + syncRatio * 100)))
    possibleFormat = 'Weak SSTV signature'
    description = 'Detected some SSTV-like tones (sync or VIS header). Signal may be very weak, partial, or distorted. Worth trying SSTV decoding software.'
  }

  return {
    detected,
    possibleFormat,
    confidence,
    description
  }
}

// Goertzel algorithm for single frequency detection (efficient for SSTV)
function goertzelDetect(samples: Float32Array, targetFreq: number, sampleRate: number): number {
  const k = Math.floor(0.5 + (samples.length * targetFreq) / sampleRate)
  const w = (2 * Math.PI * k) / samples.length
  const cosine = Math.cos(w)
  const coeff = 2 * cosine

  let s0 = 0, s1 = 0, s2 = 0

  for (let i = 0; i < samples.length; i++) {
    s0 = samples[i] + coeff * s1 - s2
    s2 = s1
    s1 = s0
  }

  const power = s1 * s1 + s2 * s2 - s1 * s2 * coeff
  return Math.sqrt(power) / samples.length
}
