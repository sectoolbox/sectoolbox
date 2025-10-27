// Advanced Audio Decoders for CTF Challenges
// DTMF, Binary Audio Encoding, Spectral Anomalies, and more

export interface DTMFResult {
  detected: boolean
  sequence: string
  confidence: number
  tones: Array<{ 
    digit: string
    timestamp: number
    duration: number
    lowFreq: number
    highFreq: number
  }>
}

export interface BinaryAudioResult {
  detected: boolean
  binaryString: string
  decodedText: string
  confidence: number
  encoding: 'frequency' | 'amplitude' | 'manchester' | 'unknown'
}

export interface SpectralAnomaly {
  type: 'frequency_spike' | 'hidden_tone' | 'pattern' | 'silence' | 'phase_shift'
  timestamp: number
  duration: number
  frequency?: number
  confidence: number
  description: string
  suspicious: boolean
}

export interface PatternMatch {
  startTime: number
  endTime: number
  pattern: string
  confidence: number
  repetitions: number
}

/**
 * Detect DTMF (Dual-Tone Multi-Frequency) tones - phone keypad sounds
 * Each digit is represented by two simultaneous frequencies
 */
export function detectDTMF(audioBuffer: AudioBuffer, minDuration = 0.05): DTMFResult {
  const sampleRate = audioBuffer.sampleRate
  const channelData = audioBuffer.getChannelData(0)
  
  // DTMF frequency pairs (row, column)
  const dtmfFreqs: Record<string, [number, number]> = {
    '1': [697, 1209], '2': [697, 1336], '3': [697, 1477], 'A': [697, 1633],
    '4': [770, 1209], '5': [770, 1336], '6': [770, 1477], 'B': [770, 1633],
    '7': [852, 1209], '8': [852, 1336], '9': [852, 1477], 'C': [852, 1633],
    '*': [941, 1209], '0': [941, 1336], '#': [941, 1477], 'D': [941, 1633],
  }
  
  const tones: DTMFResult['tones'] = []
  const windowSize = Math.floor(sampleRate * 0.05) // 50ms window
  const hopSize = Math.floor(windowSize / 2)
  
  for (let i = 0; i < channelData.length - windowSize; i += hopSize) {
    const window = channelData.slice(i, i + windowSize)
    
    // Compute FFT-like frequency detection (simplified)
    const frequencies = detectFrequencies(window, sampleRate)
    
    // Check for DTMF pairs
    for (const [digit, [lowF, highF]] of Object.entries(dtmfFreqs)) {
      const lowMatch = frequencies.some(f => Math.abs(f.freq - lowF) < 30 && f.magnitude > 0.1)
      const highMatch = frequencies.some(f => Math.abs(f.freq - highF) < 30 && f.magnitude > 0.1)
      
      if (lowMatch && highMatch) {
        const timestamp = i / sampleRate
        
        // Merge with previous tone if same digit
        if (tones.length > 0 && tones[tones.length - 1].digit === digit) {
          tones[tones.length - 1].duration += hopSize / sampleRate
        } else {
          tones.push({
            digit,
            timestamp,
            duration: hopSize / sampleRate,
            lowFreq: lowF,
            highFreq: highF
          })
        }
      }
    }
  }
  
  // Filter short tones and build sequence
  const validTones = tones.filter(t => t.duration >= minDuration)
  const sequence = validTones.map(t => t.digit).join('')
  
  const confidence = validTones.length > 0 ? 
    Math.min(0.95, 0.5 + (validTones.length * 0.1)) : 0
  
  return {
    detected: validTones.length > 0,
    sequence,
    confidence,
    tones: validTones
  }
}

/**
 * Detect binary data encoded in audio
 * Common CTF technique: 0 = low frequency, 1 = high frequency
 */
export function detectBinaryAudio(audioBuffer: AudioBuffer): BinaryAudioResult {
  const channelData = audioBuffer.getChannelData(0)
  const sampleRate = audioBuffer.sampleRate
  
  // Try frequency-based encoding (FSK-like)
  const freqResult = detectFrequencyShiftKeying(channelData, sampleRate)
  if (freqResult.confidence > 0.6) {
    return {
      detected: true,
      binaryString: freqResult.bits,
      decodedText: binaryToAscii(freqResult.bits),
      confidence: freqResult.confidence,
      encoding: 'frequency'
    }
  }
  
  // Try amplitude-based encoding
  const ampResult = detectAmplitudeEncoding(channelData, sampleRate)
  if (ampResult.confidence > 0.6) {
    return {
      detected: true,
      binaryString: ampResult.bits,
      decodedText: binaryToAscii(ampResult.bits),
      confidence: ampResult.confidence,
      encoding: 'amplitude'
    }
  }
  
  // Try Manchester encoding
  const manchResult = detectManchesterEncoding(channelData, sampleRate)
  if (manchResult.confidence > 0.6) {
    return {
      detected: true,
      binaryString: manchResult.bits,
      decodedText: binaryToAscii(manchResult.bits),
      confidence: manchResult.confidence,
      encoding: 'manchester'
    }
  }
  
  return {
    detected: false,
    binaryString: '',
    decodedText: '',
    confidence: 0,
    encoding: 'unknown'
  }
}

/**
 * Detect spectral anomalies that might indicate hidden data
 */
export function detectSpectralAnomalies(audioBuffer: AudioBuffer): SpectralAnomaly[] {
  const anomalies: SpectralAnomaly[] = []
  const channelData = audioBuffer.getChannelData(0)
  const sampleRate = audioBuffer.sampleRate
  
  const windowSize = 2048
  const hopSize = 512
  
  // Compute spectral statistics
  const spectralFrames = []
  for (let i = 0; i < channelData.length - windowSize; i += hopSize) {
    const window = channelData.slice(i, i + windowSize)
    const spectrum = computeSpectrum(window)
    spectralFrames.push({
      timestamp: i / sampleRate,
      spectrum,
      energy: computeEnergy(window),
      centroid: computeSpectralCentroid(spectrum)
    })
  }
  
  // Detect anomalies
  for (let i = 0; i < spectralFrames.length; i++) {
    const frame = spectralFrames[i]
    
    // 1. Detect frequency spikes (unusual sharp peaks)
    const peaks = findSpectralPeaks(frame.spectrum)
    for (const peak of peaks) {
      if (peak.magnitude > 0.7 && peak.sharpness > 0.8) {
        anomalies.push({
          type: 'frequency_spike',
          timestamp: frame.timestamp,
          duration: hopSize / sampleRate,
          frequency: peak.frequency,
          confidence: peak.sharpness,
          description: `Unusual frequency spike at ${peak.frequency.toFixed(0)}Hz`,
          suspicious: true
        })
      }
    }
    
    // 2. Detect hidden tones (sustained unusual frequencies)
    if (peaks.some(p => p.frequency > 18000 && p.magnitude > 0.3)) {
      anomalies.push({
        type: 'hidden_tone',
        timestamp: frame.timestamp,
        duration: hopSize / sampleRate,
        frequency: peaks.find(p => p.frequency > 18000)?.frequency,
        confidence: 0.85,
        description: 'Ultrasonic frequency detected (possible hidden data)',
        suspicious: true
      })
    }
    
    // 3. Detect unnatural silence (might be data)
    if (frame.energy < 0.001 && i > 10 && i < spectralFrames.length - 10) {
      anomalies.push({
        type: 'silence',
        timestamp: frame.timestamp,
        duration: hopSize / sampleRate,
        confidence: 0.6,
        description: 'Unusual silence period',
        suspicious: false
      })
    }
    
    // 4. Detect spectral centroid shifts (phase encoding indicator)
    if (i > 0) {
      const centroidDiff = Math.abs(frame.centroid - spectralFrames[i-1].centroid)
      if (centroidDiff > 2000) {
        anomalies.push({
          type: 'phase_shift',
          timestamp: frame.timestamp,
          duration: hopSize / sampleRate,
          confidence: 0.7,
          description: 'Sudden spectral change (possible phase encoding)',
          suspicious: true
        })
      }
    }
  }
  
  // Merge nearby anomalies
  return mergeAnomalies(anomalies)
}

/**
 * Find repeated patterns in audio (useful for finding hidden channels)
 */
export function detectRepeatedPatterns(audioBuffer: AudioBuffer, minLength = 0.1): PatternMatch[] {
  const channelData = audioBuffer.getChannelData(0)
  const sampleRate = audioBuffer.sampleRate
  const minSamples = Math.floor(minLength * sampleRate)
  
  const patterns: PatternMatch[] = []
  const windowSizes = [minSamples, minSamples * 2, minSamples * 4]
  
  for (const windowSize of windowSizes) {
    const correlations = []
    
    for (let i = 0; i < channelData.length - windowSize * 2; i += windowSize / 2) {
      const window1 = channelData.slice(i, i + windowSize)
      
      for (let j = i + windowSize; j < channelData.length - windowSize; j += windowSize / 2) {
        const window2 = channelData.slice(j, j + windowSize)
        const correlation = computeCorrelation(window1, window2)
        
        if (correlation > 0.85) {
          correlations.push({
            pos1: i,
            pos2: j,
            correlation,
            windowSize
          })
        }
      }
    }
    
    // Group correlations into patterns
    if (correlations.length >= 2) {
      patterns.push({
        startTime: correlations[0].pos1 / sampleRate,
        endTime: (correlations[correlations.length - 1].pos2 + windowSize) / sampleRate,
        pattern: `Repeated ${windowSize / sampleRate}s segment`,
        confidence: correlations[0].correlation,
        repetitions: correlations.length
      })
    }
  }
  
  return patterns
}

// Helper functions

function detectFrequencies(window: Float32Array, sampleRate: number) {
  const frequencies: Array<{freq: number, magnitude: number}> = []
  
  // Simplified frequency detection using Goertzel algorithm for common freqs
  const testFreqs = [697, 770, 852, 941, 1209, 1336, 1477, 1633, 440, 880]
  
  for (const freq of testFreqs) {
    const magnitude = goertzel(window, freq, sampleRate)
    if (magnitude > 0.05) {
      frequencies.push({ freq, magnitude })
    }
  }
  
  return frequencies
}

function goertzel(samples: Float32Array, targetFreq: number, sampleRate: number): number {
  const k = Math.round((samples.length * targetFreq) / sampleRate)
  const omega = (2 * Math.PI * k) / samples.length
  const cosine = Math.cos(omega)
  const sine = Math.sin(omega)
  const coeff = 2 * cosine
  
  let q0 = 0, q1 = 0, q2 = 0
  
  for (let i = 0; i < samples.length; i++) {
    q0 = coeff * q1 - q2 + samples[i]
    q2 = q1
    q1 = q0
  }
  
  const real = q1 - q2 * cosine
  const imag = q2 * sine
  const magnitude = Math.sqrt(real * real + imag * imag) / samples.length
  
  return magnitude
}

function detectFrequencyShiftKeying(data: Float32Array, sampleRate: number) {
  const bitDuration = 0.1 // 100ms per bit (10 baud)
  const samplesPerBit = Math.floor(sampleRate * bitDuration)
  const lowFreq = 440 // Hz (represents 0)
  const highFreq = 880 // Hz (represents 1)
  
  let bits = ''
  let totalConfidence = 0
  
  for (let i = 0; i < data.length - samplesPerBit; i += samplesPerBit) {
    const segment = data.slice(i, i + samplesPerBit)
    const lowMag = goertzel(segment, lowFreq, sampleRate)
    const highMag = goertzel(segment, highFreq, sampleRate)
    
    if (lowMag > 0.1 || highMag > 0.1) {
      bits += highMag > lowMag ? '1' : '0'
      totalConfidence += Math.abs(highMag - lowMag)
    }
  }
  
  return {
    bits,
    confidence: Math.min(0.95, totalConfidence / (bits.length || 1))
  }
}

function detectAmplitudeEncoding(data: Float32Array, sampleRate: number) {
  const bitDuration = 0.1
  const samplesPerBit = Math.floor(sampleRate * bitDuration)
  
  let bits = ''
  
  for (let i = 0; i < data.length - samplesPerBit; i += samplesPerBit) {
    const segment = data.slice(i, i + samplesPerBit)
    const avgAmplitude = segment.reduce((sum, val) => sum + Math.abs(val), 0) / segment.length
    bits += avgAmplitude > 0.1 ? '1' : '0'
  }
  
  return {
    bits,
    confidence: bits.length > 0 ? 0.5 : 0
  }
}

function detectManchesterEncoding(data: Float32Array, sampleRate: number) {
  // Manchester: 0 = low-high transition, 1 = high-low transition
  const bitDuration = 0.05
  const samplesPerHalfBit = Math.floor(sampleRate * bitDuration / 2)
  
  let bits = ''
  
  for (let i = 0; i < data.length - samplesPerHalfBit * 2; i += samplesPerHalfBit * 2) {
    const firstHalf = data.slice(i, i + samplesPerHalfBit)
    const secondHalf = data.slice(i + samplesPerHalfBit, i + samplesPerHalfBit * 2)
    
    const firstAvg = firstHalf.reduce((sum, val) => sum + val, 0) / firstHalf.length
    const secondAvg = secondHalf.reduce((sum, val) => sum + val, 0) / secondHalf.length
    
    if (Math.abs(firstAvg - secondAvg) > 0.05) {
      bits += firstAvg < secondAvg ? '0' : '1'
    }
  }
  
  return {
    bits,
    confidence: bits.length > 8 ? 0.6 : 0.3
  }
}

function binaryToAscii(binary: string): string {
  let text = ''
  
  for (let i = 0; i + 8 <= binary.length; i += 8) {
    const byte = binary.slice(i, i + 8)
    const charCode = parseInt(byte, 2)
    if (charCode >= 32 && charCode <= 126) {
      text += String.fromCharCode(charCode)
    }
  }
  
  return text
}

function computeSpectrum(window: Float32Array): Float32Array {
  // Simplified DFT
  const N = window.length
  const spectrum = new Float32Array(N / 2)
  
  for (let k = 0; k < N / 2; k++) {
    let real = 0, imag = 0
    for (let n = 0; n < N; n++) {
      const angle = -2 * Math.PI * k * n / N
      real += window[n] * Math.cos(angle)
      imag += window[n] * Math.sin(angle)
    }
    spectrum[k] = Math.sqrt(real * real + imag * imag) / N
  }
  
  return spectrum
}

function computeEnergy(window: Float32Array): number {
  return window.reduce((sum, val) => sum + val * val, 0) / window.length
}

function computeSpectralCentroid(spectrum: Float32Array): number {
  let weightedSum = 0
  let sum = 0
  
  for (let i = 0; i < spectrum.length; i++) {
    weightedSum += i * spectrum[i]
    sum += spectrum[i]
  }
  
  return sum > 0 ? weightedSum / sum : 0
}

function findSpectralPeaks(spectrum: Float32Array) {
  const peaks: Array<{frequency: number, magnitude: number, sharpness: number}> = []
  
  for (let i = 1; i < spectrum.length - 1; i++) {
    if (spectrum[i] > spectrum[i-1] && spectrum[i] > spectrum[i+1] && spectrum[i] > 0.1) {
      const sharpness = spectrum[i] / ((spectrum[i-1] + spectrum[i+1]) / 2)
      peaks.push({
        frequency: i * 22050 / spectrum.length, // Approximate frequency
        magnitude: spectrum[i],
        sharpness: Math.min(1, sharpness / 3)
      })
    }
  }
  
  return peaks.sort((a, b) => b.magnitude - a.magnitude).slice(0, 10)
}

function mergeAnomalies(anomalies: SpectralAnomaly[]): SpectralAnomaly[] {
  if (anomalies.length === 0) return []
  
  const merged: SpectralAnomaly[] = []
  let current = { ...anomalies[0] }
  
  for (let i = 1; i < anomalies.length; i++) {
    const next = anomalies[i]
    
    if (next.type === current.type && 
        next.timestamp - (current.timestamp + current.duration) < 0.1) {
      current.duration = next.timestamp + next.duration - current.timestamp
      current.confidence = Math.max(current.confidence, next.confidence)
    } else {
      merged.push(current)
      current = { ...next }
    }
  }
  
  merged.push(current)
  return merged
}

function computeCorrelation(a: Float32Array, b: Float32Array): number {
  if (a.length !== b.length) return 0
  
  let sum = 0
  let sumA = 0
  let sumB = 0
  
  for (let i = 0; i < a.length; i++) {
    sum += a[i] * b[i]
    sumA += a[i] * a[i]
    sumB += b[i] * b[i]
  }
  
  const denom = Math.sqrt(sumA * sumB)
  return denom > 0 ? sum / denom : 0
}
