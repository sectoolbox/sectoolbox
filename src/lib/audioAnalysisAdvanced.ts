// Advanced Audio Analysis - CTF-focused features
// Equalizer, Noise Reduction, FSK/PSK Detection, Export functions

import { EQBand, FSKResult, PSKResult } from './audioAnalysis'

// Apply 10-band equalizer to audio buffer
export async function applyEqualizer(
  audioBuffer: AudioBuffer,
  bands: EQBand[]
): Promise<AudioBuffer> {
  const audioContext = new (window.AudioContext || (window as any).webkitAudioContext)()
  const offline = new OfflineAudioContext(
    audioBuffer.numberOfChannels,
    audioBuffer.length,
    audioBuffer.sampleRate
  )

  const source = offline.createBufferSource()
  source.buffer = audioBuffer

  // Create filter chain for each band
  let previousNode: AudioNode = source

  for (const band of bands) {
    if (band.gain === 0) continue // Skip flat bands for performance

    const filter = offline.createBiquadFilter()
    filter.type = 'peaking'
    filter.frequency.value = band.frequency
    filter.Q.value = 1.0 // Bandwidth
    filter.gain.value = band.gain

    previousNode.connect(filter)
    previousNode = filter
  }

  previousNode.connect(offline.destination)
  source.start()

  const renderedBuffer = await offline.startRendering()
  await audioContext.close()
  return renderedBuffer
}

// Spectral subtraction noise reduction
export async function applyNoiseReduction(
  audioBuffer: AudioBuffer,
  noiseReductionAmount: number = 0.5 // 0-1
): Promise<AudioBuffer> {
  const sampleRate = audioBuffer.sampleRate
  const channelData = audioBuffer.getChannelData(0)

  // Estimate noise profile from first 0.5 seconds
  const noiseSamples = Math.min(Math.floor(sampleRate * 0.5), channelData.length)
  const noiseProfile = new Float32Array(2048)

  // Build noise profile using FFT of noise section
  const fftSize = 2048
  const audioContext = new (window.AudioContext || (window as any).webkitAudioContext)({ sampleRate })

  // Process audio in overlapping frames
  const hopSize = fftSize / 2
  const numFrames = Math.floor((channelData.length - fftSize) / hopSize)
  const outputData = new Float32Array(channelData.length)

  // Simple noise gate approach (faster than full spectral subtraction)
  const threshold = noiseReductionAmount * 0.02 // Amplitude threshold

  for (let i = 0; i < channelData.length; i++) {
    const sample = channelData[i]
    // Apply soft gate
    if (Math.abs(sample) < threshold) {
      outputData[i] = sample * (1 - noiseReductionAmount)
    } else {
      outputData[i] = sample
    }
  }

  // Create new buffer with processed data
  const newBuffer = audioContext.createBuffer(
    audioBuffer.numberOfChannels,
    audioBuffer.length,
    sampleRate
  )

  for (let channel = 0; channel < audioBuffer.numberOfChannels; channel++) {
    const channelOut = newBuffer.getChannelData(channel)
    if (channel === 0) {
      channelOut.set(outputData)
    } else {
      // Process other channels similarly
      const chData = audioBuffer.getChannelData(channel)
      for (let i = 0; i < chData.length; i++) {
        const sample = chData[i]
        if (Math.abs(sample) < threshold) {
          channelOut[i] = sample * (1 - noiseReductionAmount)
        } else {
          channelOut[i] = sample
        }
      }
    }
  }

  await audioContext.close()
  return newBuffer
}

// Normalize audio to peak at target level
export async function normalizeAudio(
  audioBuffer: AudioBuffer,
  targetLevel: number = 0.95
): Promise<AudioBuffer> {
  const audioContext = new (window.AudioContext || (window as any).webkitAudioContext)()

  // Find peak across all channels
  let maxPeak = 0
  for (let channel = 0; channel < audioBuffer.numberOfChannels; channel++) {
    const channelData = audioBuffer.getChannelData(channel)
    for (let i = 0; i < channelData.length; i++) {
      maxPeak = Math.max(maxPeak, Math.abs(channelData[i]))
    }
  }

  if (maxPeak === 0) return audioBuffer // Avoid division by zero

  const gain = targetLevel / maxPeak

  // Create new buffer with normalized audio
  const newBuffer = audioContext.createBuffer(
    audioBuffer.numberOfChannels,
    audioBuffer.length,
    audioBuffer.sampleRate
  )

  for (let channel = 0; channel < audioBuffer.numberOfChannels; channel++) {
    const inputData = audioBuffer.getChannelData(channel)
    const outputData = newBuffer.getChannelData(channel)
    for (let i = 0; i < inputData.length; i++) {
      outputData[i] = inputData[i] * gain
    }
  }

  await audioContext.close()
  return newBuffer
}

// Export audio buffer as WAV file
export async function exportAsWAV(audioBuffer: AudioBuffer, filename: string = 'audio.wav'): Promise<void> {
  const numChannels = audioBuffer.numberOfChannels
  const sampleRate = audioBuffer.sampleRate
  const format = 1 // PCM
  const bitDepth = 16

  const bytesPerSample = bitDepth / 8
  const blockAlign = numChannels * bytesPerSample

  const dataLength = audioBuffer.length * blockAlign
  const buffer = new ArrayBuffer(44 + dataLength)
  const view = new DataView(buffer)

  // Write WAV header
  const writeString = (offset: number, string: string) => {
    for (let i = 0; i < string.length; i++) {
      view.setUint8(offset + i, string.charCodeAt(i))
    }
  }

  writeString(0, 'RIFF')
  view.setUint32(4, 36 + dataLength, true)
  writeString(8, 'WAVE')
  writeString(12, 'fmt ')
  view.setUint32(16, 16, true) // fmt chunk size
  view.setUint16(20, format, true)
  view.setUint16(22, numChannels, true)
  view.setUint32(24, sampleRate, true)
  view.setUint32(28, sampleRate * blockAlign, true) // byte rate
  view.setUint16(32, blockAlign, true)
  view.setUint16(34, bitDepth, true)
  writeString(36, 'data')
  view.setUint32(40, dataLength, true)

  // Write audio data (interleaved)
  let offset = 44
  for (let i = 0; i < audioBuffer.length; i++) {
    for (let channel = 0; channel < numChannels; channel++) {
      const sample = audioBuffer.getChannelData(channel)[i]
      const int16 = Math.max(-1, Math.min(1, sample)) * 0x7FFF
      view.setInt16(offset, int16, true)
      offset += 2
    }
  }

  // Download file
  const blob = new Blob([buffer], { type: 'audio/wav' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  a.click()
  URL.revokeObjectURL(url)
}

// Export spectrogram as PNG image
export function exportSpectrogramImage(canvas: HTMLCanvasElement, filename: string = 'spectrogram.png'): void {
  canvas.toBlob((blob) => {
    if (!blob) return
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    a.click()
    URL.revokeObjectURL(url)
  })
}

// FSK (Frequency-Shift Keying) Detection
export async function detectFSK(audioBuffer: AudioBuffer): Promise<FSKResult> {
  const sampleRate = audioBuffer.sampleRate
  const channelData = audioBuffer.getChannelData(0)

  // Limit to first 60 seconds
  const maxSamples = Math.min(channelData.length, sampleRate * 60)
  const limitedData = channelData.slice(0, maxSamples)

  // Common FSK frequencies for Bell 103/202 modems
  const commonPairs = [
    { mark: 1270, space: 1070, baud: 300 },   // Bell 103
    { mark: 2225, space: 2025, baud: 300 },   // Bell 103
    { mark: 1200, space: 2200, baud: 1200 },  // Bell 202
    { mark: 2100, space: 1300, baud: 1200 }   // V.23
  ]

  let bestMatch: FSKResult = {
    detected: false,
    baudRate: 0,
    markFrequency: 0,
    spaceFrequency: 0,
    decodedBits: '',
    confidence: 0
  }

  // Analyze for each frequency pair
  for (const pair of commonPairs) {
    const windowSize = Math.floor(sampleRate / pair.baud)
    let markCount = 0
    let spaceCount = 0
    let bits = ''

    for (let i = 0; i < limitedData.length - windowSize; i += windowSize) {
      const window = limitedData.slice(i, i + windowSize)

      // Simple Goertzel algorithm for specific frequency detection
      const markEnergy = goertzelEnergy(window, pair.mark, sampleRate)
      const spaceEnergy = goertzelEnergy(window, pair.space, sampleRate)

      if (markEnergy > spaceEnergy && markEnergy > 0.01) {
        markCount++
        bits += '1'
      } else if (spaceEnergy > 0.01) {
        spaceCount++
        bits += '0'
      }
    }

    const totalBits = markCount + spaceCount
    const confidence = totalBits > 10 ? Math.min(100, (totalBits / 100) * 100) : 0

    if (confidence > bestMatch.confidence) {
      bestMatch = {
        detected: confidence > 20,
        baudRate: pair.baud,
        markFrequency: pair.mark,
        spaceFrequency: pair.space,
        decodedBits: bits,
        confidence,
        decodedText: bitsToASCII(bits)
      }
    }
  }

  return bestMatch
}

// PSK (Phase-Shift Keying) Detection
export async function detectPSK(audioBuffer: AudioBuffer): Promise<PSKResult> {
  const sampleRate = audioBuffer.sampleRate
  const channelData = audioBuffer.getChannelData(0)

  // Limit to first 60 seconds
  const maxSamples = Math.min(channelData.length, sampleRate * 60)
  const limitedData = channelData.slice(0, maxSamples)

  // Common PSK31 carrier frequency
  const carrierFreq = 1000
  const baudRate = 31.25 // PSK31

  // Detect phase shifts
  const windowSize = Math.floor(sampleRate / baudRate)
  let bits = ''
  let phaseShifts = 0

  let prevPhase = 0

  for (let i = 0; i < limitedData.length - windowSize; i += windowSize) {
    const window = limitedData.slice(i, i + windowSize)
    const phase = calculatePhase(window, carrierFreq, sampleRate)

    const phaseDiff = Math.abs(phase - prevPhase)

    if (phaseDiff > Math.PI / 2) {
      phaseShifts++
      bits += '1'
    } else {
      bits += '0'
    }

    prevPhase = phase
  }

  const confidence = Math.min(100, (phaseShifts / 10) * 100)

  return {
    detected: confidence > 15,
    carrierFrequency: carrierFreq,
    baudRate,
    pskType: 'BPSK',
    decodedBits: bits,
    confidence,
    decodedText: bitsToASCII(bits)
  }
}

// Goertzel algorithm for single frequency detection
function goertzelEnergy(samples: Float32Array, targetFreq: number, sampleRate: number): number {
  const k = Math.floor(0.5 + (samples.length * targetFreq) / sampleRate)
  const w = (2 * Math.PI * k) / samples.length
  const cosine = Math.cos(w)
  const sine = Math.sin(w)
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

// Calculate phase of signal at specific frequency
function calculatePhase(samples: Float32Array, freq: number, sampleRate: number): number {
  let real = 0, imag = 0

  for (let i = 0; i < samples.length; i++) {
    const angle = (2 * Math.PI * freq * i) / sampleRate
    real += samples[i] * Math.cos(angle)
    imag += samples[i] * Math.sin(angle)
  }

  return Math.atan2(imag, real)
}

// Convert bit string to ASCII text
function bitsToASCII(bits: string): string {
  let text = ''
  for (let i = 0; i < bits.length - 7; i += 8) {
    const byte = bits.substring(i, i + 8)
    const charCode = parseInt(byte, 2)
    if (charCode >= 32 && charCode <= 126) {
      text += String.fromCharCode(charCode)
    }
  }
  return text || 'No readable text decoded'
}
