import { Card } from "@/components/ui/card"
import { Button } from "@/components/ui/button"
import { Activity, Image, Radio } from "lucide-react"
import type { SpectrogramData, FrequencyResult, SSTVResult, FSKResult, PSKResult } from "@/lib/audioAnalysis"

interface SpectrumTabProps {
  spectrogramData: SpectrogramData | null
  frequencyResult: FrequencyResult | null
  sstvResult: SSTVResult | null
  fskResult: FSKResult | null
  pskResult: PSKResult | null
  onAnalyzeSpectrogram: () => void
  onAnalyzeFrequency: () => void
  onAnalyzeSStv: () => void
  onAnalyzeFSK: () => void
  onAnalyzePSK: () => void
  isAnalyzing: boolean
}

export function SpectrumTab({
  spectrogramData,
  frequencyResult,
  sstvResult,
  fskResult,
  pskResult,
  onAnalyzeSpectrogram,
  onAnalyzeFrequency,
  onAnalyzeSStv,
  onAnalyzeFSK,
  onAnalyzePSK,
  isAnalyzing,
}: SpectrumTabProps) {
  return (
    <div className="space-y-4">
      {/* Spectrogram */}
      <Card className="p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Activity className="w-5 h-5 text-blue-400" />
            <h3 className="text-lg font-semibold">Spectrogram</h3>
          </div>
          <Button onClick={onAnalyzeSpectrogram} disabled={isAnalyzing} size="sm">
            {isAnalyzing ? "Analyzing..." : "Generate"}
          </Button>
        </div>
        
        {spectrogramData ? (
          <div className="space-y-4">
            <div className="relative border border-border rounded overflow-hidden">
              <img
                src={(spectrogramData as any).imageUrl}
                alt="Spectrogram"
                className="w-full"
                style={{ imageRendering: "crisp-edges" }}
              />
            </div>
            <div className="text-xs text-muted-foreground">
              <p>Frequency range: 0 Hz - {((spectrogramData as any).sampleRate / 2).toLocaleString()} Hz</p>
              <p>Time resolution: {((spectrogramData as any).duration / spectrogramData.width).toFixed(3)}s per pixel</p>
            </div>
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">Click "Generate" to create a spectrogram visualization</p>
        )}
      </Card>

      {/* Frequency Analysis */}
      <Card className="p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Activity className="w-5 h-5 text-purple-400" />
            <h3 className="text-lg font-semibold">Frequency Analysis</h3>
          </div>
          <Button onClick={onAnalyzeFrequency} disabled={isAnalyzing} size="sm">
            {isAnalyzing ? "Analyzing..." : "Analyze"}
          </Button>
        </div>
        
        {frequencyResult ? (
          <div className="space-y-4">
            <div>
              <p className="text-xs text-muted-foreground mb-2">Dominant Frequencies:</p>
              <div className="space-y-1">
                {((frequencyResult as any).peaks || []).slice(0, 10).map((peak: any, i: number) => (
                  <div
                    key={i}
                    className="flex items-center gap-2 text-sm font-mono p-2 bg-gray-900 rounded"
                  >
                    <span className="text-purple-400">{peak.frequency.toFixed(2)} Hz</span>
                    <div className="flex-1 bg-gray-800 h-2 rounded overflow-hidden">
                      <div
                        className="bg-purple-500 h-full"
                        style={{ width: `${(peak.magnitude / (frequencyResult as any).peaks[0].magnitude) * 100}%` }}
                      />
                    </div>
                    <span className="text-xs text-muted-foreground">
                      {peak.magnitude.toFixed(2)} dB
                    </span>
                  </div>
                ))}
              </div>
            </div>
            <div className="text-xs text-muted-foreground">
              <p>Total peaks analyzed: {((frequencyResult as any).peaks || []).length}</p>
            </div>
          </div>
        ) : (
          <p className="text-sm text-muted-foreground">Click "Analyze" to detect dominant frequencies</p>
        )}
      </Card>

      {/* SSTV Detection */}
      <Card className="p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Image className="w-5 h-5 text-pink-400" />
            <h3 className="text-lg font-semibold">SSTV Detection</h3>
          </div>
          <Button onClick={onAnalyzeSStv} disabled={isAnalyzing} size="sm">
            {isAnalyzing ? "Analyzing..." : "Analyze"}
          </Button>
        </div>
        
        {sstvResult ? (
          sstvResult.detected ? (
            <div className="space-y-4">
              <div className="flex items-center gap-2 text-green-500">
                <Activity className="w-4 h-4" />
                <span className="font-semibold">SSTV Signal Detected!</span>
              </div>
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <p className="text-muted-foreground">Mode:</p>
                  <p className="font-semibold">{(sstvResult as any).mode}</p>
                </div>
                <div>
                  <p className="text-muted-foreground">Confidence:</p>
                  <p className="font-semibold">{(sstvResult.confidence * 100).toFixed(1)}%</p>
                </div>
              </div>
              {(sstvResult as any).imageData && (
                <div className="border border-border rounded overflow-hidden">
                  <img src={(sstvResult as any).imageData} alt="Decoded SSTV" className="w-full" />
                </div>
              )}
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No SSTV signal detected</p>
          )
        ) : (
          <p className="text-sm text-muted-foreground">
            Click "Analyze" to detect Slow-Scan Television signals
          </p>
        )}
      </Card>

      {/* FSK Detection */}
      <Card className="p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Radio className="w-5 h-5 text-orange-400" />
            <h3 className="text-lg font-semibold">FSK Detection</h3>
          </div>
          <Button onClick={onAnalyzeFSK} disabled={isAnalyzing} size="sm">
            {isAnalyzing ? "Analyzing..." : "Analyze"}
          </Button>
        </div>
        
        {fskResult ? (
          fskResult.detected ? (
            <div className="space-y-4">
              <div className="flex items-center gap-2 text-green-500">
                <Activity className="w-4 h-4" />
                <span className="font-semibold">FSK Data Detected!</span>
              </div>
              <div>
                <p className="text-xs text-muted-foreground mb-2">Decoded Data:</p>
                <div className="p-3 bg-gray-900 rounded border border-border">
                  <code className="font-mono text-sm break-all">{(fskResult as any).data}</code>
                </div>
              </div>
              <div className="grid grid-cols-3 gap-4 text-sm">
                <div>
                  <p className="text-muted-foreground">Baud Rate:</p>
                  <p className="font-semibold">{fskResult.baudRate}</p>
                </div>
                <div>
                  <p className="text-muted-foreground">Shift:</p>
                  <p className="font-semibold">{(fskResult as any).shift} Hz</p>
                </div>
                <div>
                  <p className="text-muted-foreground">Confidence:</p>
                  <p className="font-semibold">{(fskResult.confidence * 100).toFixed(1)}%</p>
                </div>
              </div>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No FSK data detected</p>
          )
        ) : (
          <p className="text-sm text-muted-foreground">
            Click "Analyze" to detect Frequency-Shift Keying data
          </p>
        )}
      </Card>

      {/* PSK Detection */}
      <Card className="p-6">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Radio className="w-5 h-5 text-cyan-400" />
            <h3 className="text-lg font-semibold">PSK Detection</h3>
          </div>
          <Button onClick={onAnalyzePSK} disabled={isAnalyzing} size="sm">
            {isAnalyzing ? "Analyzing..." : "Analyze"}
          </Button>
        </div>
        
        {pskResult ? (
          pskResult.detected ? (
            <div className="space-y-4">
              <div className="flex items-center gap-2 text-green-500">
                <Activity className="w-4 h-4" />
                <span className="font-semibold">PSK Data Detected!</span>
              </div>
              <div>
                <p className="text-xs text-muted-foreground mb-2">Decoded Data:</p>
                <div className="p-3 bg-gray-900 rounded border border-border">
                  <code className="font-mono text-sm break-all">{(pskResult as any).data}</code>
                </div>
              </div>
              <div className="grid grid-cols-3 gap-4 text-sm">
                <div>
                  <p className="text-muted-foreground">Mode:</p>
                  <p className="font-semibold">{(pskResult as any).mode}</p>
                </div>
                <div>
                  <p className="text-muted-foreground">Baud Rate:</p>
                  <p className="font-semibold">{pskResult.baudRate}</p>
                </div>
                <div>
                  <p className="text-muted-foreground">Confidence:</p>
                  <p className="font-semibold">{(pskResult.confidence * 100).toFixed(1)}%</p>
                </div>
              </div>
            </div>
          ) : (
            <p className="text-sm text-muted-foreground">No PSK data detected</p>
          )
        ) : (
          <p className="text-sm text-muted-foreground">
            Click "Analyze" to detect Phase-Shift Keying data
          </p>
        )}
      </Card>
    </div>
  )
}
