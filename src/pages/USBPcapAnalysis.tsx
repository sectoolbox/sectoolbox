import React, { useState, useRef, useCallback } from 'react'
import { useNavigate, useLocation } from 'react-router-dom'
import {
  Upload,
  Download,
  Keyboard,
  Activity,
  FileText,
  ArrowLeft,
  Copy,
  CheckCircle
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Card } from '../components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs'
import {
  analyzeUSBPcap,
  USBAnalysisResult,
  formatTimestamp,
  bytesToHex
} from '../lib/usbPcap'

const USBPcapAnalysis: React.FC = () => {
  const navigate = useNavigate()
  const location = useLocation()
  const [file, setFile] = useState<File | null>(null)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [result, setResult] = useState<USBAnalysisResult | null>(null)
  const [activeTab, setActiveTab] = useState<'keystrokes' | 'text' | 'packets' | 'leftover'>('text')
  const [copiedText, setCopiedText] = useState(false)
  const fileInputRef = useRef<HTMLInputElement>(null)

  // Handle quick upload from PCAP page
  React.useEffect(() => {
    if (location.state?.pcapFile) {
      const uploadedFile = location.state.pcapFile as File
      setFile(uploadedFile)
      analyzeUSB(uploadedFile)
    }
  }, [location.state])

  const analyzeUSB = useCallback(async (fileParam?: File) => {
    const fileToAnalyze = fileParam || file
    if (!fileToAnalyze) return

    setIsAnalyzing(true)
    try {
      const buffer = await fileToAnalyze.arrayBuffer()
      const analysisResult = analyzeUSBPcap(buffer)
      setResult(analysisResult)
    } catch (error) {
      console.error('USB Analysis error:', error)
      alert('Failed to analyze USB PCAP file: ' + (error as Error).message)
    } finally {
      setIsAnalyzing(false)
    }
  }, [file])

  const handleFileSelect = (event: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = event.target.files?.[0]
    if (selectedFile) {
      setFile(selectedFile)
      analyzeUSB(selectedFile)
    }
  }

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    setCopiedText(true)
    setTimeout(() => setCopiedText(false), 2000)
  }

  const downloadText = () => {
    if (!result) return
    const blob = new Blob([result.reconstructedText], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `${file?.name.replace(/\.[^.]+$/, '')}_keystrokes.txt`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-4">
          <Button variant="ghost" size="sm" onClick={() => navigate('/pcap')}>
            <ArrowLeft className="w-4 h-4 mr-2" />
            Back to PCAP
          </Button>
          <div>
            <h1 className="text-3xl font-bold flex items-center gap-3">
              <Keyboard className="w-8 h-8 text-accent" />
              USB PCAP Analysis
            </h1>
            <p className="text-muted-foreground mt-1">
              Analyze USB packet captures and decode HID keyboard data
            </p>
          </div>
        </div>
      </div>

      {/* File Upload */}
      {!file ? (
        <Card className="p-6">
          <h2 className="text-lg font-semibold mb-4">Upload USB PCAP File</h2>
          <div className="border-2 border-dashed border-border rounded-lg p-8 text-center hover:border-accent transition-colors cursor-pointer"
            onClick={() => fileInputRef.current?.click()}>
            <Upload className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
            <p className="text-lg font-medium mb-2">
              Drop your USB PCAP file here or click to browse
            </p>
            <p className="text-sm text-muted-foreground">
              Supports .pcap, .pcapng, .cap files
            </p>
            <input
              ref={fileInputRef}
              type="file"
              accept=".pcap,.pcapng,.cap"
              onChange={handleFileSelect}
              className="hidden"
            />
          </div>
        </Card>
      ) : (
        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Keyboard className="w-5 h-5 text-accent" />
              <div>
                <p className="font-medium">{file.name}</p>
                <p className="text-sm text-muted-foreground">
                  {(file.size / 1024).toFixed(2)} KB
                  {result && ` • ${result.statistics.totalPackets} packets • ${result.statistics.totalKeystrokes} keystrokes`}
                </p>
              </div>
            </div>
            <Button
              variant="destructive"
              size="sm"
              onClick={() => {
                setFile(null)
                setResult(null)
              }}
            >
              Remove File
            </Button>
          </div>
        </Card>
      )}

      {isAnalyzing && (
        <Card className="p-8 text-center">
          <Activity className="w-12 h-12 mx-auto mb-4 text-accent animate-pulse" />
          <p className="text-lg font-medium">Analyzing USB PCAP...</p>
          <p className="text-sm text-muted-foreground mt-2">
            Parsing USB packets and decoding HID keyboard data
          </p>
        </Card>
      )}

      {result && !isAnalyzing && (
        <>
          {/* Statistics */}
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <Card className="p-4">
              <div className="text-sm text-muted-foreground mb-1">Total Packets</div>
              <div className="text-2xl font-bold">{result.statistics.totalPackets}</div>
            </Card>
            <Card className="p-4">
              <div className="text-sm text-muted-foreground mb-1">Keystrokes Detected</div>
              <div className="text-2xl font-bold text-accent">{result.statistics.totalKeystrokes}</div>
            </Card>
            <Card className="p-4">
              <div className="text-sm text-muted-foreground mb-1">USB Devices</div>
              <div className="text-2xl font-bold">{result.statistics.totalDevices}</div>
            </Card>
            <Card className="p-4">
              <div className="text-sm text-muted-foreground mb-1">Capture Duration</div>
              <div className="text-2xl font-bold">{result.statistics.duration.toFixed(3)}s</div>
            </Card>
          </div>

          {/* Analysis Tabs */}
          <Card className="p-6">
            <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as any)}>
              <TabsList className="grid grid-cols-2 md:grid-cols-4 w-full">
                <TabsTrigger value="text">
                  <FileText className="w-4 h-4 mr-2" />
                  Reconstructed Text
                </TabsTrigger>
                <TabsTrigger value="keystrokes">
                  <Keyboard className="w-4 h-4 mr-2" />
                  Keystrokes
                </TabsTrigger>
                <TabsTrigger value="packets">
                  <Activity className="w-4 h-4 mr-2" />
                  Packets
                </TabsTrigger>
                <TabsTrigger value="leftover">
                  <FileText className="w-4 h-4 mr-2" />
                  Leftover Data
                </TabsTrigger>
              </TabsList>

              {/* Reconstructed Text Tab */}
              <TabsContent value="text">
                <div className="space-y-4">
                  <div className="flex items-center justify-between">
                    <h3 className="font-semibold">Reconstructed Keyboard Input</h3>
                    <div className="flex gap-2">
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => copyToClipboard(result.reconstructedText)}
                      >
                        {copiedText ? (
                          <><CheckCircle className="w-4 h-4 mr-2 text-green-400" /> Copied!</>
                        ) : (
                          <><Copy className="w-4 h-4 mr-2" /> Copy Text</>
                        )}
                      </Button>
                      <Button size="sm" variant="outline" onClick={downloadText}>
                        <Download className="w-4 h-4 mr-2" />
                        Download
                      </Button>
                    </div>
                  </div>
                  <div className="bg-muted/20 p-4 rounded border border-border font-mono text-sm whitespace-pre-wrap break-all max-h-96 overflow-auto">
                    {result.reconstructedText || '(No text reconstructed)'}
                  </div>
                  {result.reconstructedText.length > 0 && (
                    <p className="text-xs text-muted-foreground">
                      Text reconstructed from {result.statistics.totalKeystrokes} keystrokes. Special keys are shown in [brackets].
                    </p>
                  )}
                </div>
              </TabsContent>

              {/* Keystrokes Tab */}
              <TabsContent value="keystrokes">
                <div className="space-y-2 max-h-96 overflow-auto">
                  {result.keystrokes.length > 0 ? (
                    result.keystrokes.map((keystroke, idx) => (
                      <div key={idx} className="bg-muted/20 p-3 rounded border border-border text-sm">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-4">
                            <span className="font-mono text-lg text-accent font-bold min-w-[60px]">
                              {keystroke.key}
                            </span>
                            <div className="text-xs text-muted-foreground">
                              <div>Packet #{keystroke.packetNumber}</div>
                              <div>{formatTimestamp(keystroke.timestamp)}</div>
                            </div>
                          </div>
                          <div className="flex gap-2 text-xs">
                            {keystroke.modifiers.leftShift && <span className="px-2 py-1 bg-blue-500/20 rounded">Shift</span>}
                            {keystroke.modifiers.leftCtrl && <span className="px-2 py-1 bg-red-500/20 rounded">Ctrl</span>}
                            {keystroke.modifiers.leftAlt && <span className="px-2 py-1 bg-green-500/20 rounded">Alt</span>}
                            {keystroke.modifiers.leftGUI && <span className="px-2 py-1 bg-purple-500/20 rounded">Win</span>}
                          </div>
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="text-center py-8 text-muted-foreground">
                      No keyboard data detected in this capture
                    </div>
                  )}
                </div>
              </TabsContent>

              {/* Packets Tab */}
              <TabsContent value="packets">
                <div className="space-y-2 max-h-96 overflow-auto">
                  {result.packets.slice(0, 100).map((packet, idx) => (
                    <div key={idx} className="bg-muted/20 p-3 rounded border border-border text-xs font-mono">
                      <div className="flex items-center justify-between mb-2">
                        <div className="flex items-center gap-4">
                          <span className="text-muted-foreground">#{packet.number}</span>
                          <span className="text-accent">{formatTimestamp(packet.timestamp)}</span>
                          <span>{packet.source} → {packet.destination}</span>
                        </div>
                        <div className="flex gap-2">
                          <span className={`px-2 py-1 rounded ${packet.direction === 'IN' ? 'bg-green-500/20' : 'bg-blue-500/20'}`}>
                            {packet.direction}
                          </span>
                          <span className="px-2 py-1 bg-muted rounded">{packet.transferType}</span>
                        </div>
                      </div>
                      {packet.capdata && packet.capdata.length > 0 && (
                        <div className="text-muted-foreground mt-2">
                          Data: {bytesToHex(packet.capdata.slice(0, 16))}
                          {packet.capdata.length > 16 && '...'}
                        </div>
                      )}
                    </div>
                  ))}
                  {result.packets.length > 100 && (
                    <div className="text-center text-muted-foreground text-sm py-2">
                      Showing first 100 of {result.packets.length} packets
                    </div>
                  )}
                </div>
              </TabsContent>

              {/* Leftover Data Tab */}
              <TabsContent value="leftover">
                <div className="space-y-2 max-h-96 overflow-auto">
                  {result.leftoverData.length > 0 ? (
                    result.leftoverData.slice(0, 50).map((data, idx) => (
                      <div key={idx} className="bg-muted/20 p-3 rounded border border-border">
                        <div className="text-xs text-muted-foreground mb-1">Packet #{idx + 1} - {data.length} bytes</div>
                        <div className="font-mono text-xs break-all">
                          {bytesToHex(data)}
                        </div>
                      </div>
                    ))
                  ) : (
                    <div className="text-center py-8 text-muted-foreground">
                      No leftover data found in packets
                    </div>
                  )}
                  {result.leftoverData.length > 50 && (
                    <div className="text-center text-muted-foreground text-sm py-2">
                      Showing first 50 of {result.leftoverData.length} data chunks
                    </div>
                  )}
                </div>
              </TabsContent>
            </Tabs>
          </Card>
        </>
      )}

      {!result && !isAnalyzing && (
        <Card className="p-12 text-center">
          <Keyboard className="w-16 h-16 mx-auto mb-4 text-muted-foreground opacity-50" />
          <h3 className="text-xl font-semibold mb-2">Upload a USB PCAP File</h3>
          <p className="text-muted-foreground mb-4">
            Analyze USB packet captures to decode HID keyboard input, extract leftover data, and more
          </p>
          <Button onClick={() => fileInputRef.current?.click()}>
            <Upload className="w-4 h-4 mr-2" />
            Select USB PCAP File
          </Button>
        </Card>
      )}
    </div>
  )
}

export default USBPcapAnalysis
