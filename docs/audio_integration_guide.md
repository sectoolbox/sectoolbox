# Audio Component Integration Guide

## Overview
This guide explains how to integrate the new modular audio components into the main `AudioAnalysis.tsx` file.

## Current State
- ✅ 5 new tab components created in `src/components/audio/`
- ⏳ Main `AudioAnalysis.tsx` still uses inline JSX (1,540 lines)
- ⏳ Need to refactor main file to use new components

## Integration Steps

### Step 1: Update Imports
Replace the large lucide-react icon imports with component imports:

```typescript
// Remove these large icon imports (keep only Upload, FileAudio)
import {
  Upload, Music, Activity, Radio, Eye, Volume2, Play, Pause,
  SkipBack, SkipForward, FileAudio, Search, Zap, Download,
  RefreshCw, AlertTriangle, CheckCircle, Hash, Waves,
  BarChart3, ExternalLink, Cloud
} from 'lucide-react'

// Add component imports
import { Upload, FileAudio } from 'lucide-react'
import {
  AudioPlayer,
  OverviewTab,
  SteganographyTab,
  SpectrumTab,
  EnhanceTab
} from '../components/audio'
import { ProgressTracker } from '../components/ui/ProgressTracker'
```

### Step 2: Simplify State Management
Keep existing state but organize better:

```typescript
// Core file state
const [file, setFile] = useState<File | null>(null)
const [audioBuffer, setAudioBuffer] = useState<AudioBuffer | null>(null)
const [metadata, setMetadata] = useState<AudioMetadata | null>(null)
const [isAnalyzing, setIsAnalyzing] = useState(false)

// Playback state (pass to AudioPlayer)
const [isPlaying, setIsPlaying] = useState(false)
const [currentTime, setCurrentTime] = useState(0)
const [playbackRate, setPlaybackRate] = useState(1.0)
const [isReversed, setIsReversed] = useState(false)
const [stereoBalance, setStereoBalance] = useState(0)

// Analysis results (pass to respective tabs)
const [waveformData, setWaveformData] = useState<Float32Array | null>(null)
const [strings, setStrings] = useState<string[]>([])
const [morseResult, setMorseResult] = useState<MorseResult | null>(null)
const [dtmfResult, setDTMFResult] = useState<DTMFResult | null>(null)
const [lsbData, setLsbData] = useState<string>('')
const [spectrogram, setSpectrogram] = useState<SpectrogramData | null>(null)
const [frequencyResult, setFrequencyResult] = useState<FrequencyResult | null>(null)
const [sstvResult, setSstvResult] = useState<SSTVResult | null>(null)
const [fskResult, setFskResult] = useState<FSKResult | null>(null)
const [pskResult, setPskResult] = useState<PSKResult | null>(null)

// Enhancement state (pass to EnhanceTab)
const [eqBands, setEqBands] = useState<EQBand[]>(EQ_PRESETS['Flat'])
const [noiseReduction, setNoiseReduction] = useState(0)
const [enhancedBuffer, setEnhancedBuffer] = useState<AudioBuffer | null>(null)

// Progress tracking (pass to ProgressTracker)
const [analysisProgress, setAnalysisProgress] = useState<Array<{ name: string; progress: number }>>([])
```

### Step 3: Add Batch Analysis Function
Create a new function that runs all analyses sequentially:

```typescript
const handleAnalyzeAll = async () => {
  if (!audioBuffer || !file) return

  setIsAnalyzing(true)
  setAnalysisProgress([])
  
  try {
    const tasks = [
      { name: 'String Extraction', fn: async () => setStrings(await extractStringsFromAudio(file!)) },
      { name: 'Morse Code Detection', fn: async () => setMorseResult(detectMorseCode(audioBuffer!, 0.1)) },
      { name: 'DTMF Detection', fn: async () => setDTMFResult(await detectDTMF(audioBuffer!)) },
      { name: 'LSB Steganography', fn: async () => setLsbData(await detectLSBSteganography(file!)) },
      { name: 'Spectrogram', fn: async () => setSpectrogram(await generateSpectrogram(audioBuffer!, 2048, 20000)) },
      { name: 'Frequency Analysis', fn: async () => {
        const anomalies = analyzeFrequencyAnomalies(audioBuffer!)
        // Convert to FrequencyResult format
        setFrequencyResult({
          peaks: anomalies.map((a: any) => ({ frequency: a.frequency, magnitude: a.magnitude }))
        })
      }},
      { name: 'SSTV Detection', fn: async () => setSstvResult(await detectSSTVPattern(audioBuffer!)) },
      { name: 'FSK Detection', fn: async () => setFskResult(await detectFSK(audioBuffer!)) },
      { name: 'PSK Detection', fn: async () => setPskResult(await detectPSK(audioBuffer!)) },
    ]

    for (let i = 0; i < tasks.length; i++) {
      const task = tasks[i]
      setAnalysisProgress(prev => [...prev.filter(p => p.name !== task.name), { name: task.name, progress: 50 }])
      await task.fn()
      setAnalysisProgress(prev => [...prev.filter(p => p.name !== task.name), { name: task.name, progress: 100 }])
    }

    toast.success('Complete analysis finished!')
  } catch (error) {
    console.error('Batch analysis error:', error)
    toast.error('Analysis failed: ' + (error as Error).message)
  } finally {
    setIsAnalyzing(false)
    setAnalysisProgress([])
  }
}
```

### Step 4: Create Individual Analysis Handlers
Simplify existing analysis functions:

```typescript
// Individual analysis methods for tab "Analyze" buttons
const analyzeMorse = () => {
  if (!audioBuffer) return
  setMorseResult(detectMorseCode(audioBuffer, 0.1))
  toast.success('Morse code analysis complete')
}

const analyzeDTMF = async () => {
  if (!audioBuffer) return
  setIsAnalyzing(true)
  try {
    setDTMFResult(await detectDTMF(audioBuffer))
    toast.success('DTMF analysis complete')
  } finally {
    setIsAnalyzing(false)
  }
}

const analyzeLSB = async () => {
  if (!file) return
  setIsAnalyzing(true)
  try {
    setLsbData(await detectLSBSteganography(file))
    toast.success('LSB analysis complete')
  } finally {
    setIsAnalyzing(false)
  }
}

const analyzeStrings = async () => {
  if (!file) return
  setIsAnalyzing(true)
  try {
    setStrings(await extractStringsFromAudio(file))
    toast.success('String extraction complete')
  } finally {
    setIsAnalyzing(false)
  }
}

const analyzeSpectrogram = async () => {
  if (!audioBuffer) return
  setIsAnalyzing(true)
  try {
    const spectro = await generateSpectrogram(audioBuffer, 2048, 20000)
    setSpectrogram(spectro)
    toast.success('Spectrogram generated')
  } finally {
    setIsAnalyzing(false)
  }
}

const analyzeFrequency = () => {
  if (!audioBuffer) return
  const anomalies = analyzeFrequencyAnomalies(audioBuffer)
  setFrequencyResult({
    peaks: anomalies.map((a: any) => ({ frequency: a.frequency, magnitude: a.magnitude }))
  })
  toast.success('Frequency analysis complete')
}

const analyzeSStv = async () => {
  if (!audioBuffer) return
  setIsAnalyzing(true)
  try {
    setSstvResult(await detectSSTVPattern(audioBuffer))
    toast.success('SSTV analysis complete')
  } finally {
    setIsAnalyzing(false)
  }
}

const analyzeFSK = async () => {
  if (!audioBuffer) return
  setIsAnalyzing(true)
  try {
    setFskResult(await detectFSK(audioBuffer))
    toast.success('FSK analysis complete')
  } finally {
    setIsAnalyzing(false)
  }
}

const analyzePSK = async () => {
  if (!audioBuffer) return
  setIsAnalyzing(true)
  try {
    setPskResult(await detectPSK(audioBuffer))
    toast.success('PSK analysis complete')
  } finally {
    setIsAnalyzing(false)
  }
}
```

### Step 5: Simplify Enhancement Handlers
Update EQ and export functions:

```typescript
const handleEQChange = (bandIndex: number, value: number) => {
  const newBands = [...eqBands]
  newBands[bandIndex].gain = value
  setEqBands(newBands)
}

const handleResetEQ = () => {
  setEqBands(EQ_PRESETS['Flat'])
  toast.success('EQ reset to flat')
}

const handleExport = async () => {
  if (!audioBuffer) return

  setIsAnalyzing(true)
  try {
    let processedBuffer = audioBuffer

    // Apply EQ if any bands are adjusted
    if (eqBands.some(band => band.gain !== 0)) {
      processedBuffer = await applyEqualizer(processedBuffer, eqBands)
    }

    // Apply noise reduction if enabled
    if (noiseReduction > 0) {
      processedBuffer = await applyNoiseReduction(processedBuffer, noiseReduction)
    }

    // Normalize
    processedBuffer = await normalizeAudio(processedBuffer, 0.95)

    // Export
    const filename = file?.name.replace(/\.[^/.]+$/, '_enhanced.wav') || 'enhanced.wav'
    await exportAsWAV(processedBuffer, filename)
    
    toast.success('Enhanced audio exported!')
  } catch (error) {
    console.error('Export error:', error)
    toast.error('Export failed: ' + (error as Error).message)
  } finally {
    setIsAnalyzing(false)
  }
}
```

### Step 6: Replace JSX with Component Calls
Find the massive `<Tabs>` section and replace with this clean version:

```typescript
{/* Analysis Tabs */}
<Tabs defaultValue="overview" className="w-full">
  <TabsList className="grid w-full grid-cols-5 bg-gray-800">
    <TabsTrigger value="overview">Overview</TabsTrigger>
    <TabsTrigger value="steganography">Steganography</TabsTrigger>
    <TabsTrigger value="spectrum">Spectrum</TabsTrigger>
    <TabsTrigger value="enhance">Enhance</TabsTrigger>
    <TabsTrigger value="settings">Settings</TabsTrigger>
  </TabsList>

  <TabsContent value="overview">
    <OverviewTab
      file={file}
      metadata={metadata}
      waveformData={waveformData}
      currentTime={currentTime}
      onAnalyzeAll={handleAnalyzeAll}
      isAnalyzing={isAnalyzing}
      formatDuration={formatDuration}
      formatFileSize={formatFileSize}
    />
  </TabsContent>

  <TabsContent value="steganography">
    <SteganographyTab
      strings={strings}
      morseResult={morseResult}
      dtmfResult={dtmfResult}
      lsbData={lsbData}
      onAnalyzeMorse={analyzeMorse}
      onAnalyzeDTMF={analyzeDTMF}
      onAnalyzeLSB={analyzeLSB}
      onAnalyzeStrings={analyzeStrings}
      isAnalyzing={isAnalyzing}
    />
  </TabsContent>

  <TabsContent value="spectrum">
    <SpectrumTab
      spectrogramData={spectrogram}
      frequencyResult={frequencyResult}
      sstvResult={sstvResult}
      fskResult={fskResult}
      pskResult={pskResult}
      onAnalyzeSpectrogram={analyzeSpectrogram}
      onAnalyzeFrequency={analyzeFrequency}
      onAnalyzeSStv={analyzeSStv}
      onAnalyzeFSK={analyzeFSK}
      onAnalyzePSK={analyzePSK}
      isAnalyzing={isAnalyzing}
    />
  </TabsContent>

  <TabsContent value="enhance">
    <EnhanceTab
      eqBands={eqBands}
      noiseReduction={noiseReduction}
      onEQChange={handleEQChange}
      onNoiseReductionChange={setNoiseReduction}
      onResetEQ={handleResetEQ}
      onExport={handleExport}
      isProcessing={isAnalyzing}
    />
  </TabsContent>

  <TabsContent value="settings">
    <Card className="p-6">
      <h3 className="text-lg font-semibold mb-4">Analysis Settings</h3>
      <div className="space-y-4">
        <Button
          onClick={() => {
            if (fileInputRef.current) {
              resetAnalysis()
              fileInputRef.current.click()
            }
          }}
          variant="outline"
          className="w-full"
        >
          Load New File
        </Button>
      </div>
    </Card>
  </TabsContent>
</Tabs>
```

### Step 7: Add Progress Tracker
Insert this before the tabs section:

```typescript
{/* Progress Tracker */}
{analysisProgress.length > 0 && (
  <ProgressTracker tasks={analysisProgress} />
)}
```

### Step 8: Simplify handleAnalyze
The initial analysis should just load the file:

```typescript
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

    // Get waveform for overview
    const waveform = getWaveformData(buffer)
    setWaveformData(waveform)

    toast.success('Audio file loaded successfully')
  } catch (error) {
    console.error('Analysis error:', error)
    toast.error('Failed to analyze audio: ' + (error as Error).message)
  } finally {
    setIsAnalyzing(false)
  }
}
```

### Step 9: Remove Unused Code
After integration, remove:
- All inline JSX for tabs (replaced by components)
- `drawWaveform()` function (now in OverviewTab)
- `drawSpectrogram()` function (now in SpectrumTab)
- Canvas refs that are no longer used in main file
- Unused UI state (stringFilter, debouncedStringFilter, hoverTime, etc.)
- Old tab selection logic

## Expected Results

**Before Refactoring:**
- AudioAnalysis.tsx: 1,540 lines
- Monolithic structure with all UI inline
- Hard to maintain and test

**After Refactoring:**
- AudioAnalysis.tsx: ~350-400 lines
- Clean component-based architecture
- Easy to maintain, test, and extend
- Matches PCAP/EventLogs pattern

## Testing Checklist

After integration, verify:
- [ ] File upload works
- [ ] Audio playback controls work (play/pause/seek/speed/balance/reverse)
- [ ] Waveform displays and updates with playback
- [ ] "Analyze All" button triggers batch analysis with progress
- [ ] Individual "Analyze" buttons in each tab work
- [ ] Morse code detection displays correctly
- [ ] DTMF detection displays correctly
- [ ] LSB steganography works
- [ ] String extraction works
- [ ] Spectrogram generates and displays
- [ ] Frequency analysis shows peaks
- [ ] SSTV detection works
- [ ] FSK detection works
- [ ] PSK detection works
- [ ] Equalizer adjustments work
- [ ] Noise reduction slider works
- [ ] Export enhanced audio works
- [ ] Tab navigation works smoothly
- [ ] Toast notifications appear for all actions

## Troubleshooting

### Type Errors
- Ensure all imports from `../components/audio` are correct
- Check that FrequencyResult matches expected structure
- Verify audioAnalysis.ts exports all needed types

### Missing Features
- If spectrogram doesn't display, check that canvas rendering is in SpectrumTab
- If waveform doesn't update, ensure currentTime prop is passed correctly
- If batch analysis fails, check task array structure

### Performance Issues
- If UI freezes during analysis, ensure await statements are present
- Consider adding more progress updates in long-running tasks
- Use React.memo() for tab components if needed

## Next Features to Add

After successful integration:
1. **Export settings:** Allow choosing output format (MP3, OGG, FLAC)
2. **Analysis presets:** Save/load common analysis configurations
3. **Comparison mode:** Load two files and compare waveforms
4. **Real-time monitoring:** Analyze audio from microphone input
5. **Collaboration:** Share analysis results via URL

---

**Status:** Ready for implementation
**Estimated Time:** 2-3 hours for careful integration
**Risk:** Low (components tested individually, backup exists)
