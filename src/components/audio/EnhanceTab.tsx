import { Card } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Settings, Filter, Download } from "lucide-react"
import type { EQBand } from "@/lib/audioAnalysis"

interface EnhanceTabProps {
  eqBands: EQBand[]
  noiseReduction: number
  onEQChange: (bandIndex: number, value: number) => void
  onNoiseReductionChange: (value: number) => void
  onResetEQ: () => void
  onExport: () => void
  isProcessing: boolean
}

export function EnhanceTab({
  eqBands,
  noiseReduction,
  onEQChange,
  onNoiseReductionChange,
  onResetEQ,
  onExport,
  isProcessing,
}: EnhanceTabProps) {
  return (
    <div className="space-y-4">
      {/* Equalizer */}
      <Card className="p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Settings className="w-5 h-5 text-blue-400" />
            <h3 className="text-lg font-semibold">Equalizer</h3>
          </div>
          <Button onClick={onResetEQ} variant="outline" size="sm">
            Reset
          </Button>
        </div>
        
        <div className="space-y-6">
          <div className="flex items-end gap-4 justify-center">
            {eqBands.map((band, i) => (
              <div key={i} className="flex flex-col items-center gap-2">
                <div className="h-32 flex items-end">
                  <input
                    type="range"
                    min="-12"
                    max="12"
                    step="0.5"
                    value={band.gain}
                    onChange={(e) => onEQChange(i, parseFloat(e.target.value))}
                    className="w-24 transform -rotate-90 origin-center"
                    style={{ marginBottom: '48px' }}
                  />
                </div>
                <div className="text-center">
                  <p className="text-xs font-mono text-muted-foreground">
                    {band.frequency >= 1000
                      ? `${(band.frequency / 1000).toFixed(1)}k`
                      : band.frequency}Hz
                  </p>
                  <p className="text-xs font-semibold">
                    {band.gain > 0 ? '+' : ''}{band.gain.toFixed(1)} dB
                  </p>
                </div>
              </div>
            ))}
          </div>
          
          <p className="text-xs text-muted-foreground text-center">
            Adjust frequency bands to enhance or reduce specific audio ranges
          </p>
        </div>
      </Card>

      {/* Noise Reduction */}
      <Card className="p-6">
        <div className="flex items-center gap-2 mb-4">
          <Filter className="w-5 h-5 text-purple-400" />
          <h3 className="text-lg font-semibold">Noise Reduction</h3>
        </div>
        
        <div className="space-y-4">
          <div>
            <div className="flex justify-between mb-2">
              <label htmlFor="noise-reduction" className="text-sm font-medium">Reduction Amount</label>
              <span className="text-sm font-mono text-muted-foreground">
                {noiseReduction.toFixed(1)} dB
              </span>
            </div>
            <input
              id="noise-reduction"
              type="range"
              min={0}
              max={30}
              step={0.5}
              value={noiseReduction}
              onChange={(e) => onNoiseReductionChange(parseFloat(e.target.value))}
              className="w-full h-2 bg-gray-800 rounded-lg appearance-none cursor-pointer"
            />
          </div>
          
          <div className="grid grid-cols-3 gap-2 text-xs">
            <Button
              onClick={() => onNoiseReductionChange(0)}
              variant="outline"
              size="sm"
              className="text-xs"
            >
              None (0 dB)
            </Button>
            <Button
              onClick={() => onNoiseReductionChange(10)}
              variant="outline"
              size="sm"
              className="text-xs"
            >
              Light (10 dB)
            </Button>
            <Button
              onClick={() => onNoiseReductionChange(20)}
              variant="outline"
              size="sm"
              className="text-xs"
            >
              Heavy (20 dB)
            </Button>
          </div>
          
          <p className="text-xs text-muted-foreground">
            Apply noise gate to reduce background noise and hiss
          </p>
        </div>
      </Card>

      {/* Export */}
      <Card className="p-6">
        <div className="flex items-center gap-2 mb-4">
          <Download className="w-5 h-5 text-green-400" />
          <h3 className="text-lg font-semibold">Export Enhanced Audio</h3>
        </div>
        
        <div className="space-y-4">
          <p className="text-sm text-muted-foreground">
            Export the audio with applied enhancements (EQ, noise reduction, effects)
          </p>
          
          <Button
            onClick={onExport}
            disabled={isProcessing}
            className="w-full"
          >
            {isProcessing ? "Processing..." : "Export Audio"}
          </Button>
          
          <div className="text-xs text-muted-foreground space-y-1">
            <p>• Format: WAV (uncompressed)</p>
            <p>• Sample Rate: Original</p>
            <p>• All enhancements will be permanently applied</p>
          </div>
        </div>
      </Card>

      {/* Audio Effects */}
      <Card className="p-6">
        <div className="flex items-center gap-2 mb-4">
          <Settings className="w-5 h-5 text-orange-400" />
          <h3 className="text-lg font-semibold">Additional Effects</h3>
        </div>
        
        <div className="space-y-4">
          <p className="text-sm text-muted-foreground">
            Additional audio enhancement features coming soon:
          </p>
          <ul className="text-sm text-muted-foreground space-y-2 list-disc list-inside">
            <li>Compressor/Limiter for dynamic range control</li>
            <li>Reverb and delay effects</li>
            <li>Pitch shifting and time stretching</li>
            <li>Spectral noise reduction</li>
            <li>High-pass/Low-pass filters</li>
          </ul>
        </div>
      </Card>
    </div>
  )
}
