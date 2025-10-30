import React, { useState, useRef, useEffect, useCallback } from 'react'
import { useLocation } from 'react-router-dom'
import { Upload, Image as ImageIcon, Search, Eye, Layers, FileText, AlertTriangle, CheckCircle, XCircle, QrCode, Copy, Download, ExternalLink, Activity, MapPin, Camera, Clock, ChevronDown, AlertCircle, Key, FileArchive } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Input } from '../components/ui/input'
import { ShowFullToggle } from '../components/ShowFullToggle'
import { performComprehensiveImageAnalysis, ImageAnalysisResult, extractBitPlaneFromCanvas, analyzeLSBWithDepth, extractPrintableStringsFromBuffer, applyEdgeDetection, analyzeNoise, applyAutoGammaCorrection, applyHistogramEqualization } from '../lib/imageAnalysis'
import { carveFiles } from '../lib/forensics'
import { scanImageData } from '@undecaf/zbar-wasm'
import { apiClient } from '../services/api'
import { useBackendJob } from '../hooks/useBackendJob'

type StringsResult = { 
  all: string[]; 
  interesting: string[]; 
  base64: string[]; 
  urls: string[]; 
  ips?: string[]; 
  emails?: string[];
  patterns?: Record<string, string[]>;
  counts?: {
    ascii: number;
    unicode: number;
    total: number;
    unique: number;
  };
}

interface ImageAdjustments {
  brightness: number
  contrast: number
  saturation: number
  hue: number
  exposure: number
  shadows: number
  highlights: number
  temperature: number
  vibrance: number
  clarity: number
  vignette: number
}

type ColorChannel = 'normal' | 'red' | 'green' | 'blue' | 'grayscale' | 'invert'

function formatExifValue(v: any) {
  if (v === null || v === undefined) return '-'
  if (typeof v === 'object') {
    // common shapes from exif libraries
    if ('description' in v && typeof v.description === 'string') return v.description
    if ('value' in v) return String(v.value)
    if ('text' in v) return String(v.text)
    try {
      return JSON.stringify(v)
    } catch (e) {
      return String(v)
    }
  }
  return String(v)
}

export default function ImageAnalysis() {
  const [file, setFile] = useState<File | null>(null)
  const [imageUrl, setImageUrl] = useState<string | null>(null)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [analysisProgress, setAnalysisProgress] = useState<{
    stage: number
    total: number
    currentTask: string
    completedTasks: string[]
    subTask?: string
  }>({
    stage: 0,
    total: 7,
    currentTask: '',
    completedTasks: [],
    subTask: undefined
  })
  const [metadata, setMetadata] = useState<any | null>(null)
  const [structuredResults, setStructuredResults] = useState<ImageAnalysisResult | null>(null)
  const [activeTab, setActiveTab] = useState<'metadata' | 'forensics' | 'stego' | 'strings' | 'hex' | 'bitplane' | 'barcode'>('metadata')
  const [extractedStrings, setExtractedStrings] = useState<StringsResult | null>(null)
  const [stringFilter, setStringFilter] = useState('')
  const [imageList, setImageList] = useState<string[]>([])
  const [currentImageIndex, setCurrentImageIndex] = useState(0)
  const [imageAdjustments, setImageAdjustments] = useState<ImageAdjustments>({
    brightness: 100,
    contrast: 100,
    saturation: 100,
    hue: 0,
    exposure: 0,
    shadows: 0,
    highlights: 0,
    temperature: 0,
    vibrance: 0,
    clarity: 0,
    vignette: 0
  })
  const [colorChannel, setColorChannel] = useState<ColorChannel>('normal')
  const [showAdjustedImage, setShowAdjustedImage] = useState(false)
  const [lsbDepth, setLsbDepth] = useState<number>(1)
  const [bitPlane, setBitPlane] = useState<number>(0)
  const [bitPlaneUrl, setBitPlaneUrl] = useState<string | null>(null)
  const [lsbDepthResult, setLsbDepthResult] = useState<any | null>(null)
  const [hexData, setHexData] = useState<{offset: string, hex: string, ascii: string}[] | null>(null)
  const [hexFilter, setHexFilter] = useState('')
  const [zoomLevel, setZoomLevel] = useState(1)
  const [panPosition, setPanPosition] = useState({ x: 0, y: 0 })
  const [isPanning, setIsPanning] = useState(false)
  const [lastPanPoint, setLastPanPoint] = useState({ x: 0, y: 0 })
  const [mousePosition, setMousePosition] = useState<{x: number, y: number, color?: string} | null>(null)
  const [showPixelInfo, setShowPixelInfo] = useState(false)
  const [showFullStrings, setShowFullStrings] = useState(false)
  const [colorChannelType, setColorChannelType] = useState<'rgb' | 'red' | 'green' | 'blue' | 'alpha' | 'grayscale' | 'hsv'>('rgb')
  const [bitPlanePanPosition, setBitPlanePanPosition] = useState({ x: 0, y: 0 })
  const [bitPlaneZoomLevel, setBitPlaneZoomLevel] = useState(1)
  const [isBitPlanePanning, setIsBitPlanePanning] = useState(false)
  const [bitPlaneLastPanPoint, setBitPlaneLastPanPoint] = useState({ x: 0, y: 0 })
  const [barcodeResults, setBarcodeResults] = useState<Array<{
    format: string,
    text: string,
    raw?: string,
    rawBytes?: Uint8Array,
    quality?: number,
    position?: {x: number, y: number, width: number, height: number},
    decoded?: any,
    binary?: string,
    qrMetadata?: {
      version?: number,
      errorCorrectionLevel?: string,
      maskPattern?: number,
      encoding?: string
    },
    reconstructedImage?: string
  }>>([])
  const [isScanningBarcode, setIsScanningBarcode] = useState(false)
  const [barcodeImage, setBarcodeImage] = useState<string | null>(null)
  const [barcodeTryHarder, setBarcodeTryHarder] = useState(false)
  const [barcodeFormats, setBarcodeFormats] = useState<string[]>(['ALL'])
  const [reconstructedScanResults, setReconstructedScanResults] = useState<Record<number, {text: string, format: string} | null>>({})
  const [barcodeSubPage, setBarcodeSubPage] = useState<'original' | 'reconstructed'>('original')
  const [editableBytes, setEditableBytes] = useState<Record<number, string>>({})

  // Backend analysis state
  const [backendResults, setBackendResults] = useState<any>(null)
  const [backendJobId, setBackendJobId] = useState<string | null>(null)
  const [isBackendProcessing, setIsBackendProcessing] = useState(false)
  const { jobStatus, startJob } = useBackendJob()

  // EXIF display state
  const [exifSearchQuery, setExifSearchQuery] = useState('')
  const [expandedExifCategories, setExpandedExifCategories] = useState<string[]>(['File', 'EXIF'])

  // Performance optimization state
  const [bitplaneCache, setBitplaneCache] = useState<Record<number, string>>({})
  const [isProcessingImage, setIsProcessingImage] = useState(false)

  // Bitplane gallery state
  const [bitplaneGallery, setBitplaneGallery] = useState<Record<number, {url: string, histogram: {zeros: number, ones: number, percentage: number}}>>({})
  const [bitplaneViewMode, setBitplaneViewMode] = useState<'normal' | 'difference' | 'xor'>('normal')
  const [selectedGalleryPlane, setSelectedGalleryPlane] = useState<number | null>(null)
  const [bitplaneStats, setBitplaneStats] = useState<{chiSquare: number, entropy: number[], suspicious: number[]}>({ chiSquare: 0, entropy: [], suspicious: [] })
  const [isGeneratingGallery, setIsGeneratingGallery] = useState(false)
  const [galleryProgress, setGalleryProgress] = useState<{current: number, total: number, status: string}>({current: 0, total: 8, status: 'Initializing...'})

  const fileRef = useRef<HTMLInputElement | null>(null)
  const canvasRef = useRef<HTMLCanvasElement | null>(null)
  const imageRef = useRef<HTMLImageElement | null>(null)
  const autoExtractTimerRef = useRef<number | null>(null)
  const userHasChangedBitplaneRef = useRef<boolean>(false)

  // Quick-upload handling from Dashboard (navigate state)
  const location = useLocation()
  const shouldAutoAnalyzeRef = useRef(false)

  useEffect(() => {
    const state: any = (location && (location as any).state) || {}
    if (state?.quickUploadFile) {
      try {
        onFile(state.quickUploadFile)
        shouldAutoAnalyzeRef.current = !!state.quickUploadAutoAnalyze
        // Clear history state to avoid re-trigger on refresh
        try { window.history.replaceState({}, '', window.location.pathname) } catch (e) { void e }
      } catch (e) {
        console.warn('Quick upload to ImageAnalysis failed', e)
      }
    }
  }, [location])

  useEffect(() => {
    if (file && shouldAutoAnalyzeRef.current) {
      analyze()
      shouldAutoAnalyzeRef.current = false
    }
    // analyze function is stable in this component; disable exhaustive-deps warning
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [file])

  // Auto-trigger backend analysis when file is uploaded
  useEffect(() => {
    if (file && !backendJobId && !isBackendProcessing) {
      triggerBackendAnalysis()
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [file])

  // Listen for backend job updates
  useEffect(() => {
    if (jobStatus && jobStatus.jobId === backendJobId) {
      if (jobStatus.status === 'completed' && jobStatus.results) {
        setBackendResults(jobStatus.results)
        setIsBackendProcessing(false)
      } else if (jobStatus.status === 'failed') {
        console.error('Backend analysis failed:', jobStatus.error)
        setIsBackendProcessing(false)
      }
    }
  }, [jobStatus, backendJobId])

  const triggerBackendAnalysis = async () => {
    if (!file) return
    
    setIsBackendProcessing(true)
    try {
      const response = await apiClient.analyzeImageAdvanced(file, {
        performELA: true,
        elaQuality: 90,
        performSteganography: true,
        performFileCarving: true
      })
      
      const { jobId } = response
      setBackendJobId(jobId)
      startJob(jobId)
    } catch (error) {
      console.error('Failed to start backend analysis:', error)
      setIsBackendProcessing(false)
    }
  }

  const onFile = (f?: File) => {
    if (!f) return
    setFile(f)
    const newImageUrl = URL.createObjectURL(f)
    setImageUrl(newImageUrl)
    
    // Add to image list for navigation
    setImageList(prev => {
      const newList = [...prev, newImageUrl]
      setCurrentImageIndex(newList.length - 1)
      return newList
    })
    
    setMetadata(null)
    setStructuredResults(null)
    setExtractedStrings(null)
    setBitPlaneUrl(null)
    setLsbDepthResult(null)
    setHexData(null)
    setBarcodeResults([])
    setBitplaneCache({}) // Clear bitplane cache for new image
    // Reset backend analysis state
    setBackendResults(null)
    setBackendJobId(null)
    setIsBackendProcessing(false)
    // reset user manual selection so auto-extract runs for new images
    userHasChangedBitplaneRef.current = false
  }

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    const f = e.dataTransfer.files?.[0]
    if (f && f.type.startsWith('image/')) onFile(f)
  }

  // Advanced forensic processing functions
  const applyAdvancedProcessing = (processingType: 'edge' | 'noise' | 'gamma' | 'histogram') => {
    if (!canvasRef.current) {
      alert('No image loaded')
      return
    }

    const ctx = canvasRef.current.getContext('2d')
    if (!ctx) return

    const width = canvasRef.current.width
    const height = canvasRef.current.height

    setIsProcessingImage(true)

    // Use setTimeout to allow UI to update with processing indicator
    setTimeout(() => {
      try {
        let processedImageData: ImageData
        let resultMessage = ''

        switch (processingType) {
          case 'edge':
            processedImageData = applyEdgeDetection(ctx, width, height)
            resultMessage = 'Edge detection applied - highlights object boundaries and texture details'
            break
          case 'noise':
            const noiseResult = analyzeNoise(ctx, width, height)
            processedImageData = noiseResult.visualData
            resultMessage = `Noise analysis complete - Level: ${noiseResult.noiseLevel}% (${noiseResult.analysis})`
            break
          case 'gamma':
            processedImageData = applyAutoGammaCorrection(ctx, width, height)
            resultMessage = 'Auto gamma correction applied - enhanced luminance distribution'
            break
          case 'histogram':
            processedImageData = applyHistogramEqualization(ctx, width, height)
            resultMessage = 'Histogram equalization applied - improved contrast and detail visibility'
            break
          default:
            setIsProcessingImage(false)
            return
        }

        // Apply the processed image data to canvas
        ctx.putImageData(processedImageData, 0, 0)
        setShowAdjustedImage(true)
      
        // Display result message
        alert(resultMessage)
        setIsProcessingImage(false)
      } catch (error) {
        console.error(`${processingType} processing failed:`, error)
        alert(`${processingType} processing failed - check console`)
        setIsProcessingImage(false)
      }
    }, 50)
  }

  // Helper: Convert text to binary representation
  const textToBinary = (text: string): string => {
    return Array.from(text)
      .map(char => char.charCodeAt(0).toString(2).padStart(8, '0'))
      .join(' ')
  }

  // Helper: Parse Python-style escape sequences (\x89, \r, \n, etc.) to actual bytes
  const parseEscapeSequences = (text: string): Uint8Array => {
    const bytes: number[] = []
    let i = 0

    while (i < text.length) {
      if (text[i] === '\\' && i + 1 < text.length) {
        const next = text[i + 1]

        // Hex escape: \xNN
        if (next === 'x' && i + 3 < text.length) {
          const hexStr = text.substring(i + 2, i + 4)
          const byte = parseInt(hexStr, 16)
          if (!isNaN(byte)) {
            bytes.push(byte)
            i += 4
            continue
          }
        }

        // Common escape sequences
        switch (next) {
          case 'n': bytes.push(0x0A); i += 2; continue // \n -> LF
          case 'r': bytes.push(0x0D); i += 2; continue // \r -> CR
          case 't': bytes.push(0x09); i += 2; continue // \t -> TAB
          case '0': bytes.push(0x00); i += 2; continue // \0 -> NULL
          case '\\': bytes.push(0x5C); i += 2; continue // \\ -> \
          case '\'': bytes.push(0x27); i += 2; continue // \' -> '
          case '\"': bytes.push(0x22); i += 2; continue // \" -> "
        }
      }

      // Regular character
      bytes.push(text.charCodeAt(i))
      i++
    }

    return new Uint8Array(bytes)
  }

  // Helper: Reconstruct from binary blob (like Python: with open('flag.png', 'wb') as f: f.write(png_data))
  const reconstructQRCode = async (rawBytes: Uint8Array, format: string, customBytes?: Uint8Array): Promise<string | undefined> => {
    try {
      if (!format.includes('QR')) return undefined

      // Use custom bytes if provided, otherwise use original raw bytes
      let bytes = customBytes || rawBytes

      // Check if the data contains escape sequences (like \x89PNG instead of actual bytes)
      const text = new TextDecoder('utf-8', { fatal: false }).decode(bytes)
      if (text.includes('\\x') || text.includes('\\r') || text.includes('\\n')) {
        console.log('Detected escape sequences in QR data, parsing...')
        bytes = parseEscapeSequences(text)
        console.log('Parsed bytes first 4:', bytes[0], bytes[1], bytes[2], bytes[3])
      }

      // Detect file type from magic bytes
      let mimeType = 'application/octet-stream'
      if (bytes.length >= 4) {
        // PNG: \x89PNG
        if (bytes[0] === 0x89 && bytes[1] === 0x50 && bytes[2] === 0x4E && bytes[3] === 0x47) {
          mimeType = 'image/png'
        }
        // JPEG: \xFF\xD8\xFF
        else if (bytes[0] === 0xFF && bytes[1] === 0xD8 && bytes[2] === 0xFF) {
          mimeType = 'image/jpeg'
        }
        // GIF: GIF8
        else if (bytes[0] === 0x47 && bytes[1] === 0x49 && bytes[2] === 0x46 && bytes[3] === 0x38) {
          mimeType = 'image/gif'
        }
        // PDF: %PDF
        else if (bytes[0] === 0x25 && bytes[1] === 0x50 && bytes[2] === 0x44 && bytes[3] === 0x46) {
          mimeType = 'application/pdf'
        }
      }

      // Create data URL from blob (like Python write to file)
      const blobWithType = new Blob([bytes.buffer as ArrayBuffer], { type: mimeType })
      const dataUrl = URL.createObjectURL(blobWithType)

      return dataUrl
    } catch (e) {
      console.error('Failed to reconstruct from binary:', e)
      return undefined
    }
  }

  // Regenerate QR from edited bytes
  const regenerateQRFromBytes = async (resultIndex: number, customBytesString: string) => {
    const result = barcodeResults[resultIndex]
    if (!result || !result.rawBytes) return

    // Convert string back to bytes
    const customBytes = new Uint8Array(Array.from(customBytesString).map(c => c.charCodeAt(0)))

    const reconstructedImage = await reconstructQRCode(result.rawBytes, result.format, customBytes)
    if (reconstructedImage) {
      // Update the result with new reconstructed image
      const updatedResults = [...barcodeResults]
      updatedResults[resultIndex] = { ...result, reconstructedImage }
      setBarcodeResults(updatedResults)
    }
  }

  // Scan reconstructed QR code image
  const scanReconstructedQR = async (imageDataUrl: string, resultIndex: number) => {
    try {
      // Create image element from data URL (blob URLs don't need CORS)
      const img = new Image()
      // Only set crossOrigin for external URLs, not blob: or data: URLs
      if (!imageDataUrl.startsWith('blob:') && !imageDataUrl.startsWith('data:')) {
        img.crossOrigin = 'anonymous'
      }

      await new Promise<void>((resolve, reject) => {
        img.onload = () => resolve()
        img.onerror = () => reject(new Error('Failed to load reconstructed image'))
        img.src = imageDataUrl
      })

      // Create canvas and get imageData for ZBar WASM
      const canvas = document.createElement('canvas')
      const ctx = canvas.getContext('2d')
      if (!ctx) throw new Error('Canvas context not available')

      canvas.width = img.width
      canvas.height = img.height
      ctx.drawImage(img, 0, 0)
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height)

      // Scan with ZBar WASM (real zbarimg algorithm!)
      const zbarResults = await scanImageData(imageData)

      if (zbarResults.length > 0) {
        const symbol = zbarResults[0]
        setReconstructedScanResults(prev => ({
          ...prev,
          [resultIndex]: {
            text: symbol.decode(),
            format: symbol.typeName
          }
        }))
      } else {
        setReconstructedScanResults(prev => ({
          ...prev,
          [resultIndex]: null
        }))
      }
    } catch (error) {
      console.warn('Failed to scan reconstructed QR:', error)
      setReconstructedScanResults(prev => ({
        ...prev,
        [resultIndex]: null
      }))
    }
  }

  // ZBar WASM barcode scanning (real zbarimg in browser!)
  const scanBarcodes = async () => {
    if (!imageUrl) {
      console.error('No image loaded for barcode scanning')
      setIsScanningBarcode(false)
      return
    }

    setIsScanningBarcode(true)
    setBarcodeResults([])
    setBarcodeImage(null)

    try {
      // Create a temporary image element with the current image
      const img = new Image()
      img.crossOrigin = 'anonymous'

      // Wait for image to load with timeout
      await Promise.race([
        new Promise<void>((resolve, reject) => {
          img.onload = () => resolve()
          img.onerror = () => reject(new Error('Failed to load image'))
          img.src = imageUrl
        }),
        new Promise<void>((_, reject) =>
          setTimeout(() => reject(new Error('Image load timeout')), 10000)
        )
      ])

      // Create canvas for image processing and visualization
      const canvas = document.createElement('canvas')
      const ctx = canvas.getContext('2d')
      if (!ctx) throw new Error('Canvas context not available')

      canvas.width = img.width
      canvas.height = img.height
      ctx.drawImage(img, 0, 0)

      // Get ImageData for ZBar WASM
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height)

      // Scan with ZBar WASM (real zbarimg algorithm!)
      console.log('Scanning with ZBar WASM...')
      const zbarResults = await scanImageData(imageData)

      const results: Array<{format: string, text: string, raw?: string, rawBytes?: Uint8Array, quality?: number, position?: {x: number, y: number, width: number, height: number}, decoded?: any, binary?: string, qrMetadata?: any, reconstructedImage?: string}> = []

      for (const symbol of zbarResults) {
        console.log(`Found: ${symbol.typeName} - ${symbol.decode()}`)

        // Use raw binary data instead of decoded string (for binary files like PNG)
        const rawBytes = new Uint8Array(symbol.data.buffer, symbol.data.byteOffset, symbol.data.byteLength)
        const text = symbol.decode()

        // === DEBUG: Option 6 - Show first 20 bytes in multiple formats ===
        // Byte analysis
        // Total length

        const first20 = rawBytes.slice(0, 20)
        console.log('Hex:', Array.from(first20).map(b => b.toString(16).padStart(2, '0')).join(' '))
        console.log('Decimal:', Array.from(first20).join(' '))
        console.log('ASCII:', Array.from(first20).map(b => b >= 32 && b <= 126 ? String.fromCharCode(b) : '.').join(''))
        console.log('Raw bytes[0-3]:', rawBytes[0], rawBytes[1], rawBytes[2], rawBytes[3])

        // Check PNG signature
        const isPNG = rawBytes[0] === 0x89 && rawBytes[1] === 0x50 && rawBytes[2] === 0x4E && rawBytes[3] === 0x47
        console.log('PNG signature detected:', isPNG)

        // Check if it looks like Base64
        const isBase64 = /^[A-Za-z0-9+/=]+$/.test(text.substring(0, 100))
        console.log('Looks like Base64:', isBase64)

        // Check if it looks like Hex
        const isHex = /^[0-9a-fA-F]+$/.test(text.substring(0, 100))
        console.log('Looks like Hex:', isHex)

        // Try Base64 decode if it looks like Base64
        if (isBase64 && text.length > 20) {
          try {
            const base64Decoded = atob(text)
            const base64Bytes = new Uint8Array(Array.from(base64Decoded).map(c => c.charCodeAt(0)))
            console.log('Base64 decoded first 4 bytes:', base64Bytes[0], base64Bytes[1], base64Bytes[2], base64Bytes[3])
            const isPNGAfterBase64 = base64Bytes[0] === 0x89 && base64Bytes[1] === 0x50 && base64Bytes[2] === 0x4E && base64Bytes[3] === 0x47
            console.log('PNG signature after Base64 decode:', isPNGAfterBase64)
          } catch (e) {
            console.log('Base64 decode failed:', e)
          }
        }

        // Try Hex decode if it looks like Hex
        if (isHex && text.length > 8) {
          try {
            const hexBytes = new Uint8Array(text.match(/.{2}/g)?.slice(0, 4).map(byte => parseInt(byte, 16)) || [])
            console.log('Hex decoded first 4 bytes:', hexBytes[0], hexBytes[1], hexBytes[2], hexBytes[3])
            const isPNGAfterHex = hexBytes[0] === 0x89 && hexBytes[1] === 0x50 && hexBytes[2] === 0x4E && hexBytes[3] === 0x47
            console.log('PNG signature after Hex decode:', isPNGAfterHex)
          } catch (e) {
            console.log('Hex decode failed:', e)
          }
        }
        console.log('=== END BYTE ANALYSIS ===')
        // === END DEBUG ===

        let position = undefined

        // Get symbol position from points
        if (symbol.points && symbol.points.length >= 2) {
          const xs = symbol.points.map(p => p.x)
          const ys = symbol.points.map(p => p.y)
          const minX = Math.min(...xs)
          const minY = Math.min(...ys)
          const maxX = Math.max(...xs)
          const maxY = Math.max(...ys)

          position = {
            x: minX,
            y: minY,
            width: maxX - minX,
            height: maxY - minY
          }

          // Draw bounding box on canvas
          ctx.strokeStyle = '#10b981'
          ctx.lineWidth = 3
          ctx.strokeRect(minX, minY, maxX - minX, maxY - minY)

          // Draw corner points
          ctx.fillStyle = '#10b981'
          symbol.points.forEach(p => {
            ctx.beginPath()
            ctx.arc(p.x, p.y, 5, 0, 2 * Math.PI)
            ctx.fill()
          })
        }

        // Auto-decode Base64, Hex, URL encoding
        let decoded = undefined

        // Try Base64 decode
        if (text.match(/^[A-Za-z0-9+/=]{20,}$/)) {
          try {
            const decodedText = atob(text)
            if (decodedText.match(/[\x20-\x7E]/)) {
              decoded = { type: 'base64', value: decodedText }
            }
          } catch (e) {}
        }

        // Try Hex decode
        if (!decoded && text.match(/^[0-9a-fA-F]+$/) && text.length % 2 === 0) {
          try {
            const hexDecoded = text.match(/.{2}/g)?.map(byte => String.fromCharCode(parseInt(byte, 16))).join('')
            if (hexDecoded && hexDecoded.match(/[\x20-\x7E]/)) {
              decoded = { type: 'hex', value: hexDecoded }
            }
          } catch (e) {}
        }

        // Try URL decode
        if (!decoded && text.includes('%')) {
          try {
            const urlDecoded = decodeURIComponent(text)
            if (urlDecoded !== text) {
              decoded = { type: 'url', value: urlDecoded }
            }
          } catch (e) {}
        }

        // Extract binary representation
        const binary = textToBinary(text)

        // Parse QR metadata (basic - ZBar doesn't expose as much as ZXing)
        const qrMetadata = symbol.typeName.includes('QR') ? {
          encoding: 'Detected by ZBar',
          quality: symbol.quality
        } : undefined

        // Reconstruct QR code from raw binary data
        const reconstructedImage = await reconstructQRCode(rawBytes, symbol.typeName)

        results.push({
          format: symbol.typeName,
          text: text,
          raw: text,
          rawBytes: rawBytes, // Store raw binary data for reconstruction
          position,
          quality: symbol.quality,
          decoded,
          binary,
          qrMetadata,
          reconstructedImage
        })
      }

      if (results.length === 0) {
        console.log('No barcodes/QR codes found with ZBar WASM')
      }

      // If we found codes and drew on canvas, save the visualization
      if (results.length > 0) {
        setBarcodeImage(canvas.toDataURL())
        console.log(`Found ${results.length} barcode(s)/QR code(s)`)
      } else {
        console.log('No barcodes or QR codes detected in the image')
      }

      setBarcodeResults(results)
    } catch (error) {
      console.error('Barcode scanning failed:', error)
      setBarcodeResults([])
    } finally {
      setIsScanningBarcode(false)
    }
  }

  // Generate hex dump of file
  const generateHexData = async (buffer: ArrayBuffer) => {
    try {
      const bytes = new Uint8Array(buffer)
      const maxBytes = Math.min(bytes.length, 65536) // Limit to 64KB for display (matching Forensics)
      const hexLines: {offset: string, hex: string, ascii: string}[] = []

      for (let i = 0; i < maxBytes; i += 16) {
        // Offset
        const offset = '0x' + i.toString(16).padStart(8, '0').toUpperCase()

        // Hex bytes and ASCII
        const hexBytes = []
        const asciiChars = []

        for (let j = 0; j < 16 && (i + j) < maxBytes; j++) {
          const byte = bytes[i + j]
          hexBytes.push(byte.toString(16).padStart(2, '0').toUpperCase())
          asciiChars.push(byte >= 32 && byte <= 126 ? String.fromCharCode(byte) : '.')
        }

        // Pad hex bytes to maintain alignment
        while (hexBytes.length < 16) {
          hexBytes.push('  ')
        }

        // Format hex part with spacing
        const hexPart = hexBytes.slice(0, 8).join(' ') + '  ' + hexBytes.slice(8).join(' ')
        const asciiPart = asciiChars.join('')

        hexLines.push({
          offset,
          hex: hexPart,
          ascii: asciiPart
        })
      }

      setHexData(hexLines)
    } catch (error) {
      console.error('Hex generation failed:', error)
      setHexData([])
    }
  }

  const extractStrings = (buf: ArrayBuffer): StringsResult => {
    try {
      // Use the enhanced extraction function from imageAnalysis
      const enhanced = extractPrintableStringsFromBuffer(buf, 4, 500)
      const allStrings = enhanced.all
      const patterns = enhanced.patterns
      
      // Legacy compatibility format
      const base64 = patterns.base64 || []
      const urls = patterns.urls || []
      const ips = patterns.ipAddresses || []
      const emails = patterns.emails || []
      
      // Enhanced interesting strings detection
      const interesting = allStrings.filter(s => {
        const sl = String(s).toLowerCase()
        return (
          sl.includes('flag') || sl.includes('password') || sl.includes('key') || 
          sl.includes('secret') || sl.includes('token') || sl.includes('admin') || 
          sl.includes('ctf') || sl.includes('config') || sl.includes('credential') ||
          sl.includes('api') || sl.includes('auth') || sl.includes('login') ||
          s.length > 50 || /^[A-Za-z0-9+/=]{20,}$/.test(s) ||
          /[A-Za-z]:[\\\/]/.test(s) || // File paths
          /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(s) || // IP addresses
          /@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}/.test(s) // Email domains
        )
      })

      return { 
        all: allStrings, 
        interesting, 
        base64, 
        urls, 
        ips, 
        emails,
        patterns,
        counts: enhanced.counts
      }
    } catch (error) {
      console.warn('Enhanced string extraction failed, falling back to basic:', error)
      
      // Fallback to original logic
      const data = new Uint8Array(buf)
      const strings: string[] = []
      let cur: number[] = []
      const minLen = 4
      for (let i = 0; i < data.length; i++) {
        const b = data[i]
        if (b >= 32 && b <= 126) cur.push(b)
        else {
          if (cur.length >= minLen) strings.push(String.fromCharCode(...cur))
          cur = []
        }
      }
      if (cur.length >= minLen) strings.push(String.fromCharCode(...cur))

      const base64 = strings.filter(s => /^[A-Za-z0-9+/=]{20,}$/.test(s))
      const urls = strings.filter(s => /https?:\/\//i.test(s))
      const ips = strings.filter(s => /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/.test(s))
      const emails = strings.filter(s => /[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/.test(s))
      const interesting = strings.filter(s => {
        const sl = String(s).toLowerCase()
        return (
          sl.includes('flag') || sl.includes('password') || sl.includes('key') || 
          sl.includes('secret') || sl.includes('token') || sl.includes('admin') || 
          sl.includes('ctf') || s.length > 50 || /^[A-Za-z0-9+/=]{20,}$/.test(s)
        )
      })

      return { all: strings, interesting, base64, urls, ips, emails }
    }
  }

  const analyze = async () => {
    if (!file) return
    setIsAnalyzing(true)
    setAnalysisProgress({
      stage: 0,
      total: 7,
      currentTask: 'Reading file data...',
      completedTasks: [],
      subTask: undefined
    })
    
    try {
      const buf = await file.arrayBuffer()

      // Stage 1: File Information
      setAnalysisProgress({
        stage: 1,
        total: 7,
        currentTask: 'Extracting file information',
        completedTasks: ['Reading file data'],
        subTask: 'Analyzing file structure'
      })
      await new Promise(resolve => setTimeout(resolve, 100))

      // Stage 2: Image Dimensions & Format
      setAnalysisProgress({
        stage: 2,
        total: 7,
        currentTask: 'Analyzing image properties',
        completedTasks: ['Reading file data', 'File information extracted'],
        subTask: 'Detecting format and dimensions'
      })
      await new Promise(resolve => setTimeout(resolve, 100))

      // Stage 3: Comprehensive Analysis with ExifTool
      setAnalysisProgress({
        stage: 3,
        total: 7,
        currentTask: 'Running ExifTool analysis',
        completedTasks: ['Reading file data', 'File information', 'Image properties'],
        subTask: 'Extracting metadata fields...'
      })
      
      // Handle image file analysis
      const res = await performComprehensiveImageAnalysis(file)
      setStructuredResults(res)

      const meta = res?.metadata || {}
      setMetadata({
        filename: meta.filename || file.name,
        fileSize: meta.fileSize ?? file.size,
        dimensions: meta.dimensions ?? { width: 0, height: 0 },
        format: meta.format || ''
      })

      // Stage 4: Steganography Detection
      setAnalysisProgress({
        stage: 4,
        total: 7,
        currentTask: 'Analyzing steganography',
        completedTasks: ['Reading file data', 'File information', 'Image properties', 'ExifTool analysis'],
        subTask: 'Checking LSB patterns and hidden data'
      })
      await new Promise(resolve => setTimeout(resolve, 150))

      // Stage 5: String Extraction
      setAnalysisProgress({
        stage: 5,
        total: 7,
        currentTask: 'Extracting strings',
        completedTasks: ['Reading file data', 'File information', 'Image properties', 'ExifTool analysis', 'Steganography scan'],
        subTask: 'Finding ASCII and Unicode strings'
      })
      setExtractedStrings(extractStrings(buf))
      await new Promise(resolve => setTimeout(resolve, 100))

      // Stage 6: Hidden File Scanning
      setAnalysisProgress({
        stage: 6,
        total: 7,
        currentTask: 'Scanning for hidden files',
        completedTasks: ['Reading file data', 'File information', 'Image properties', 'ExifTool analysis', 'Steganography scan', 'String extraction'],
        subTask: 'Detecting embedded archives and files'
      })
      await new Promise(resolve => setTimeout(resolve, 100))

      // Stage 7: Hex Dump Generation
      setAnalysisProgress({
        stage: 7,
        total: 7,
        currentTask: 'Generating hex dump',
        completedTasks: ['Reading file data', 'File information', 'Image properties', 'ExifTool analysis', 'Steganography scan', 'String extraction', 'Hidden file scan'],
        subTask: 'Creating hexadecimal view'
      })
      
      // Generate hex data
      await generateHexData(buf)

      // Complete
      setAnalysisProgress({
        stage: 7,
        total: 7,
        currentTask: 'Analysis complete',
        completedTasks: ['Reading file data', 'File information', 'Image properties', 'ExifTool analysis', 'Steganography scan', 'String extraction', 'Hidden file scan', 'Hex dump generated'],
        subTask: undefined
      })
    } catch (err) {
      console.error('analysis failed', err)
      alert('Analysis failed – check console')
    } finally {
      setIsAnalyzing(false)
    }
  }

  const navigateImage = (direction: 'prev' | 'next') => {
    if (imageList.length <= 1) return
    
    let newIndex = currentImageIndex
    if (direction === 'prev') {
      newIndex = currentImageIndex > 0 ? currentImageIndex - 1 : imageList.length - 1
    } else {
      newIndex = currentImageIndex < imageList.length - 1 ? currentImageIndex + 1 : 0
    }
    
    setCurrentImageIndex(newIndex)
    // consider this a new image load — reset manual-selection flag so auto-extract can run
    userHasChangedBitplaneRef.current = false
    setImageUrl(imageList[newIndex])
  }

  const updateAdjustment = (key: keyof ImageAdjustments, value: number) => {
    setImageAdjustments(prev => ({ ...prev, [key]: value }))
    setShowAdjustedImage(true)
    // Auto-update bitplane preview when forensic processing changes
    if (bitPlaneUrl) {
      setTimeout(() => extractBitPlane(), 100) // Small delay to ensure canvas is updated
    }
  }

  const resetAdjustments = () => {
    setImageAdjustments({
      brightness: 100,
      contrast: 100,
      saturation: 100,
      hue: 0,
      exposure: 0,
      shadows: 0,
      highlights: 0,
      temperature: 0,
      vibrance: 0,
      clarity: 0,
      vignette: 0
    })
    setColorChannel('normal')
    setShowAdjustedImage(false)
    setBitPlaneUrl(null)
    setLsbDepthResult(null)
  }

  const extractBitPlane = useCallback((plane?: number) => {
    if (!canvasRef.current) return
    const ctx = canvasRef.current.getContext('2d')
    if (!ctx) return
    const currentPlane = plane !== undefined ? plane : bitPlane
    
    // Check cache first for instant switching (but verify canvas has data)
    if (bitplaneCache[currentPlane] && canvasRef.current.width > 0 && canvasRef.current.height > 0) {
      setBitPlaneUrl(bitplaneCache[currentPlane])
      return
    }
    
    // Process and cache (only if canvas has valid dimensions)
    if (canvasRef.current.width === 0 || canvasRef.current.height === 0) {
      console.warn('Canvas not ready for bitplane extraction')
      return
    }
    
    const planeCanvas = extractBitPlaneFromCanvas(ctx, canvasRef.current.width, canvasRef.current.height, currentPlane)
    try {
      const url = planeCanvas.toDataURL('image/png')
      setBitPlaneUrl(url)
      // Cache this bitplane for instant future access
      setBitplaneCache(prev => ({ ...prev, [currentPlane]: url }))
    } catch (e) {
      console.error('bitplane export failed', e)
    }
  }, [bitPlane, bitplaneCache])

  const handleImageLoad = useCallback(() => {
    if (!imageRef.current || !canvasRef.current) return
    
    const canvas = canvasRef.current
    const ctx = canvas.getContext('2d')
    const img = imageRef.current
    
    if (!ctx) return
    
    canvas.width = img.naturalWidth
    canvas.height = img.naturalHeight
    
    // Apply color channel effects
    ctx.drawImage(img, 0, 0)
    
    if (colorChannel !== 'normal') {
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height)
      const data = imageData.data
      
      for (let i = 0; i < data.length; i += 4) {
        const r = data[i]
        const g = data[i + 1]
        const b = data[i + 2]
        
        switch (colorChannel) {
          case 'red':
            data[i + 1] = 0 // green
            data[i + 2] = 0 // blue
            break
          case 'green':
            data[i] = 0     // red
            data[i + 2] = 0 // blue
            break
          case 'blue':
            data[i] = 0     // red
            data[i + 1] = 0 // green
            break
          case 'grayscale': {
            const gray = Math.round(0.299 * r + 0.587 * g + 0.114 * b)
            data[i] = gray
            data[i + 1] = gray
            data[i + 2] = gray
            break
          }
          case 'invert':
            data[i] = 255 - r
            data[i + 1] = 255 - g
            data[i + 2] = 255 - b
            break
        }
      }
      
      ctx.putImageData(imageData, 0, 0)
    }

    // Auto-extract bitplane 0 after canvas is ready
    // Clear any previously scheduled auto-extract so it doesn't override user actions
    if (autoExtractTimerRef.current) {
      clearTimeout(autoExtractTimerRef.current)
      autoExtractTimerRef.current = null
    }

    // Only schedule auto-extract if user hasn't manually changed the bitplane
    if (!userHasChangedBitplaneRef.current) {
      autoExtractTimerRef.current = window.setTimeout(() => {
        extractBitPlane(0)
        autoExtractTimerRef.current = null
      }, 100)
    }
  }, [colorChannel, extractBitPlane])

  // Trigger canvas update when color channel changes
  const handleColorChannelChange = (newChannel: ColorChannel) => {
    setColorChannel(newChannel)
    // Force canvas to show when color channel is applied
    if (newChannel !== 'normal') {
      setShowAdjustedImage(true)
    }
  }

  useEffect(() => {
    if (showAdjustedImage || colorChannel !== 'normal' || imageUrl) {
      handleImageLoad()
    }
  }, [colorChannel, showAdjustedImage, imageUrl, handleImageLoad])

  useEffect(() => {
    // cleanup auto-extract timer on unmount
    return () => {
      if (autoExtractTimerRef.current) {
        clearTimeout(autoExtractTimerRef.current)
        autoExtractTimerRef.current = null
      }
    }
  }, [])

  // Auto-update bitplane when colorChannelType changes in bitplane tab
  useEffect(() => {
    if (canvasRef.current && bitPlaneUrl && userHasChangedBitplaneRef.current) {
      setTimeout(() => extractBitPlane(), 100)
    }
  }, [colorChannelType, extractBitPlane])


  const changeBitPlane = (direction: 'prev' | 'next') => {
    // Mark that user has manually changed bitplane to prevent auto-extract
    userHasChangedBitplaneRef.current = true
    
    // Cancel any pending auto-extract so user selection isn't overridden
    if (autoExtractTimerRef.current) {
      clearTimeout(autoExtractTimerRef.current)
      autoExtractTimerRef.current = null
    }

    let newPlane = bitPlane
    if (direction === 'prev' && bitPlane > 0) {
      newPlane = bitPlane - 1
    } else if (direction === 'next' && bitPlane < 7) {
      newPlane = bitPlane + 1
    }
    setBitPlane(newPlane)
    extractBitPlane(newPlane)
  }

  const exportAllBitPlanes = async () => {
    if (!canvasRef.current) return
    const ctx = canvasRef.current.getContext('2d')
    if (!ctx) return
    try {
      // Simple export without external dependencies - download each bitplane individually
      const width = canvasRef.current.width
      const height = canvasRef.current.height
      
      for (let p = 0; p < 8; p++) {
        const c = extractBitPlaneFromCanvas(ctx, width, height, p)
        const dataUrl = c.toDataURL('image/png')
        const a = document.createElement('a')
        a.href = dataUrl
        a.download = `${metadata?.filename || 'image'}_bitplane_${p}.png`
        a.click()
        // Small delay between downloads
        await new Promise(resolve => setTimeout(resolve, 200))
      }
    } catch (e) {
      console.error('export all bitplanes failed', e)
      alert('Export failed – check console')
    }
  }

  const computeLsbDepth = () => {
    if (!canvasRef.current) return
    const ctx = canvasRef.current.getContext('2d')
    if (!ctx) return
    const res = analyzeLSBWithDepth(ctx, canvasRef.current.width, canvasRef.current.height, lsbDepth, 20000)
    setLsbDepthResult(res)
  }

  // Group EXIF data by category
  const groupExifByCategory = (exifData: Record<string, any>) => {
    const grouped: Record<string, Array<{key: string, value: any}>> = {}
    
    Object.keys(exifData).forEach(key => {
      // Extract category from key (e.g., "EXIF:Make" -> "EXIF", "GPS:Latitude" -> "GPS")
      const parts = key.split(':')
      const category = parts.length > 1 ? parts[0] : 'File'
      
      if (!grouped[category]) {
        grouped[category] = []
      }
      
      grouped[category].push({ key, value: exifData[key] })
    })
    
    // Sort categories: prioritize common ones
    const priorityOrder = ['File', 'EXIF', 'GPS', 'XMP', 'ICC_Profile', 'Composite', 'MakerNotes']
    const sortedCategories = Object.keys(grouped).sort((a, b) => {
      const aIndex = priorityOrder.indexOf(a)
      const bIndex = priorityOrder.indexOf(b)
      if (aIndex !== -1 && bIndex !== -1) return aIndex - bIndex
      if (aIndex !== -1) return -1
      if (bIndex !== -1) return 1
      return a.localeCompare(b)
    })
    
    const result: Record<string, Array<{key: string, value: any}>> = {}
    sortedCategories.forEach(cat => {
      result[cat] = grouped[cat].sort((a, b) => a.key.localeCompare(b.key))
    })
    
    return result
  }

  const toggleExifCategory = (category: string) => {
    setExpandedExifCategories(prev => 
      prev.includes(category) 
        ? prev.filter(c => c !== category)
        : [...prev, category]
    )
  }

  const downloadDataUrl = (url: string | null, filename = 'download.png') => {
    if (!url) return
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    a.click()
  }

  const downloadModifiedImage = async (format: 'png' | 'jpeg' | 'webp' = 'png') => {
    if (!canvasRef.current) {
      alert('No image to download')
      return
    }

    try {
      const mimeType = format === 'jpeg' ? 'image/jpeg' : format === 'webp' ? 'image/webp' : 'image/png'
      const quality = format === 'jpeg' ? 0.95 : format === 'webp' ? 0.90 : undefined
      const dataUrl = canvasRef.current.toDataURL(mimeType, quality)
      
      const filename = metadata?.filename 
        ? `${metadata.filename.replace(/\.[^.]+$/, '')}_modified.${format}`
        : `modified_image.${format}`
      
      downloadDataUrl(dataUrl, filename)
    } catch (error) {
      console.error('Failed to download image:', error)
      alert('Failed to download image - check console')
    }
  }

  const copyModifiedImageToClipboard = async () => {
    if (!canvasRef.current) {
      alert('No image to copy')
      return
    }

    try {
      const blob = await new Promise<Blob>((resolve, reject) => {
        canvasRef.current!.toBlob((b) => {
          if (b) resolve(b)
          else reject(new Error('Failed to create blob'))
        }, 'image/png')
      })

      await navigator.clipboard.write([
        new ClipboardItem({ 'image/png': blob })
      ])
      
      alert('✓ Image copied to clipboard!')
    } catch (error) {
      console.error('Failed to copy image:', error)
      alert('Failed to copy image - your browser may not support this feature')
    }
  }

  // Bitplane analysis functions
  const calculateBitplaneHistogram = (imageData: ImageData, bitPlane: number): {zeros: number, ones: number, percentage: number} => {
    let zeros = 0
    let ones = 0
    
    for (let i = 0; i < imageData.data.length; i += 4) {
      // Check each RGB channel
      for (let ch = 0; ch < 3; ch++) {
        const pixel = imageData.data[i + ch]
        const bit = (pixel >> bitPlane) & 1
        if (bit === 0) zeros++
        else ones++
      }
    }
    
    const total = zeros + ones
    const percentage = total > 0 ? (ones / total) * 100 : 50
    return { zeros, ones, percentage }
  }

  const calculateChiSquare = (histograms: Record<number, {zeros: number, ones: number}>): number => {
    // Chi-square test for LSB plane randomness
    const lsb = histograms[0]
    if (!lsb) return 0
    
    const total = lsb.zeros + lsb.ones
    const expected = total / 2
    
    const chiSquare = 
      Math.pow(lsb.zeros - expected, 2) / expected +
      Math.pow(lsb.ones - expected, 2) / expected
    
    // Normalize to 0-1 range (divide by critical value at p=0.05)
    return chiSquare / 3.841
  }

  const calculateBitplaneEntropy = (imageData: ImageData, bitPlane: number): number => {
    const frequencies: Record<number, number> = {}
    let count = 0
    
    for (let i = 0; i < imageData.data.length; i += 4) {
      for (let ch = 0; ch < 3; ch++) {
        const pixel = imageData.data[i + ch]
        const bit = (pixel >> bitPlane) & 1
        frequencies[bit] = (frequencies[bit] || 0) + 1
        count++
      }
    }
    
    let entropy = 0
    for (const freq of Object.values(frequencies)) {
      const p = freq / count
      if (p > 0) {
        entropy -= p * Math.log2(p)
      }
    }
    
    return entropy
  }

  const generateBitplaneGallery = async () => {
    if (!canvasRef.current) return
    const ctx = canvasRef.current.getContext('2d')
    if (!ctx) return
    
    setIsGeneratingGallery(true)
    setGalleryProgress({current: 0, total: 8, status: 'Preparing image data...'})
    
    try {
      const width = canvasRef.current.width
      const height = canvasRef.current.height
      const imageData = ctx.getImageData(0, 0, width, height)
      
      const gallery: Record<number, {url: string, histogram: {zeros: number, ones: number, percentage: number}}> = {}
      const histograms: Record<number, {zeros: number, ones: number}> = {}
      const entropyValues: number[] = []
      const suspicious: number[] = []
      
      // Generate all 8 bitplanes based on view mode
      for (let plane = 0; plane < 8; plane++) {
        // Update progress
        setGalleryProgress({
          current: plane, 
          total: 8, 
          status: `Extracting bitplane ${plane} (${plane === 0 ? 'LSB' : plane === 7 ? 'MSB' : `Bit ${plane}`})...`
        })
        
        // Small delay to allow UI to update
        await new Promise(resolve => setTimeout(resolve, 50))
        
        let planeCanvas: HTMLCanvasElement
        
        if (bitplaneViewMode === 'difference' && plane < 7) {
          // Difference mode: Show (Plane N - Plane N+1)
          const canvas1 = extractBitPlaneFromCanvas(ctx, width, height, plane)
          const canvas2 = extractBitPlaneFromCanvas(ctx, width, height, plane + 1)
          planeCanvas = createDifferenceImage(canvas1, canvas2)
        } else if (bitplaneViewMode === 'xor') {
          // XOR mode: Show (Plane N XOR Plane 7-N)
          const oppositeIndex = 7 - plane
          const canvas1 = extractBitPlaneFromCanvas(ctx, width, height, plane)
          const canvas2 = extractBitPlaneFromCanvas(ctx, width, height, oppositeIndex)
          planeCanvas = createXORImage(canvas1, canvas2)
        } else {
          // Normal mode: Standard bitplane extraction
          planeCanvas = extractBitPlaneFromCanvas(ctx, width, height, plane)
        }
        
        const url = planeCanvas.toDataURL('image/png')
        
        // Update progress for analysis
        setGalleryProgress({
          current: plane, 
          total: 8, 
          status: `Analyzing bitplane ${plane} (histogram & entropy)...`
        })
        
        const histogram = calculateBitplaneHistogram(imageData, plane)
        const entropy = calculateBitplaneEntropy(imageData, plane)
        
        histograms[plane] = { zeros: histogram.zeros, ones: histogram.ones }
        gallery[plane] = { url, histogram }
        entropyValues.push(entropy)
        
        // Flag suspicious planes (far from 50/50 distribution)
        if (plane <= 2 && (histogram.percentage < 45 || histogram.percentage > 55)) {
          suspicious.push(plane)
        }
      }
      
      // Final statistics
      setGalleryProgress({current: 8, total: 8, status: 'Calculating Chi-Square test...'})
      await new Promise(resolve => setTimeout(resolve, 100))
      
      const chiSquare = calculateChiSquare(histograms)
      
      setBitplaneGallery(gallery)
      setBitplaneStats({ chiSquare, entropy: entropyValues, suspicious })
    } catch (error) {
      console.error('Failed to generate bitplane gallery:', error)
      alert('Failed to generate bitplane gallery - check console')
    } finally {
      setIsGeneratingGallery(false)
      setGalleryProgress({current: 0, total: 8, status: 'Complete'})
    }
  }

  // Helper function for difference mode
  const createDifferenceImage = (canvas1: HTMLCanvasElement, canvas2: HTMLCanvasElement): HTMLCanvasElement => {
    const width = canvas1.width
    const height = canvas1.height
    const resultCanvas = document.createElement('canvas')
    resultCanvas.width = width
    resultCanvas.height = height
    
    const ctx1 = canvas1.getContext('2d')
    const ctx2 = canvas2.getContext('2d')
    const resultCtx = resultCanvas.getContext('2d')
    
    if (!ctx1 || !ctx2 || !resultCtx) return canvas1
    
    const data1 = ctx1.getImageData(0, 0, width, height)
    const data2 = ctx2.getImageData(0, 0, width, height)
    const resultData = resultCtx.createImageData(width, height)
    
    for (let i = 0; i < data1.data.length; i += 4) {
      // Calculate absolute difference
      const diff = Math.abs(data1.data[i] - data2.data[i])
      resultData.data[i] = diff
      resultData.data[i + 1] = diff
      resultData.data[i + 2] = diff
      resultData.data[i + 3] = 255
    }
    
    resultCtx.putImageData(resultData, 0, 0)
    return resultCanvas
  }

  // Helper function for XOR mode
  const createXORImage = (canvas1: HTMLCanvasElement, canvas2: HTMLCanvasElement): HTMLCanvasElement => {
    const width = canvas1.width
    const height = canvas1.height
    const resultCanvas = document.createElement('canvas')
    resultCanvas.width = width
    resultCanvas.height = height
    
    const ctx1 = canvas1.getContext('2d')
    const ctx2 = canvas2.getContext('2d')
    const resultCtx = resultCanvas.getContext('2d')
    
    if (!ctx1 || !ctx2 || !resultCtx) return canvas1
    
    const data1 = ctx1.getImageData(0, 0, width, height)
    const data2 = ctx2.getImageData(0, 0, width, height)
    const resultData = resultCtx.createImageData(width, height)
    
    for (let i = 0; i < data1.data.length; i += 4) {
      // XOR the pixel values
      const xor = data1.data[i] ^ data2.data[i]
      resultData.data[i] = xor
      resultData.data[i + 1] = xor
      resultData.data[i + 2] = xor
      resultData.data[i + 3] = 255
    }
    
    resultCtx.putImageData(resultData, 0, 0)
    return resultCanvas
  }


  const extractRawLSBBits = (): string => {
    if (!canvasRef.current) return ''
    const ctx = canvasRef.current.getContext('2d')
    if (!ctx) return ''
    
    const width = canvasRef.current.width
    const height = canvasRef.current.height
    const imageData = ctx.getImageData(0, 0, width, height)
    
    let bits = ''
    for (let i = 0; i < imageData.data.length; i += 4) {
      // Extract LSB from RGB channels
      for (let ch = 0; ch < 3; ch++) {
        const pixel = imageData.data[i + ch]
        const bit = pixel & 1
        bits += bit
      }
    }
    
    return bits
  }

  const decodeLSBBits = (bits: string, format: 'ascii' | 'hex' | 'base64' = 'ascii'): string => {
    const bytes: number[] = []
    
    // Convert bits to bytes
    for (let i = 0; i < bits.length; i += 8) {
      const byte = bits.slice(i, i + 8)
      if (byte.length === 8) {
        bytes.push(parseInt(byte, 2))
      }
    }
    
    if (format === 'hex') {
      return bytes.map(b => b.toString(16).padStart(2, '0')).join(' ')
    } else if (format === 'base64') {
      const binary = String.fromCharCode(...bytes)
      return btoa(binary)
    } else {
      // ASCII - only printable characters
      return bytes
        .filter(b => b >= 32 && b <= 126)
        .map(b => String.fromCharCode(b))
        .join('')
    }
  }

  const scanForEmbeddedFiles = async () => {
    if (!file) return alert('No file loaded')
    const existing = structuredResults?.steganography?.embeddedFiles || []
    if (existing.length > 0) return alert(`Found ${existing.length} embedded file(s)`)

    try {
      const buf = await file.arrayBuffer()
      const carved = carveFiles(new Uint8Array(buf), 64)
      const mapped = carved.map(c => ({ 
        type: c.type, 
        offset: c.offset, 
        size: c.size,
        id: c.id,
        filename: c.filename || `extracted_${c.offset.toString(16)}.${c.type.toLowerCase()}`,
        recovered: c.recovered || true
      }))
      setStructuredResults(prev => prev ? ({ 
        ...prev, 
        steganography: { 
          ...prev.steganography, 
          embeddedFiles: mapped, 
          detected: (prev.steganography.detected || mapped.length > 0) 
        } 
      }) : prev)
      if (mapped.length === 0) alert('No embedded files found')
    } catch (e) {
      console.error('embedded scan failed', e)
      alert('Embedded file scan failed – check console')
    }
  }

  const downloadHiddenFile = async (embeddedFile: any) => {
    if (!file) return
    
    try {
      const buf = await file.arrayBuffer()
      const view = new Uint8Array(buf)
      
      // Extract the embedded file data
      const startOffset = embeddedFile.offset
      const endOffset = Math.min(startOffset + embeddedFile.size, view.length)
      const extractedData = view.slice(startOffset, endOffset)
      
      // Create blob and download
      const blob = new Blob([extractedData], { 
        type: getFileTypeForExtension(embeddedFile.type) 
      })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = embeddedFile.filename || `hidden_file_${embeddedFile.offset.toString(16)}.${getExtensionForType(embeddedFile.type)}`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    } catch (error) {
      console.error('Failed to download hidden file:', error)
      alert('Failed to download hidden file')
    }
  }

  const getFileTypeForExtension = (type: string): string => {
    const types: Record<string, string> = {
      'JPEG': 'image/jpeg',
      'PNG': 'image/png', 
      'GIF': 'image/gif',
      'PDF': 'application/pdf',
      'ZIP': 'application/zip',
      'RAR': 'application/x-rar-compressed',
      'EXE': 'application/octet-stream',
      'DOC': 'application/msword'
    }
    return types[type] || 'application/octet-stream'
  }

  const getExtensionForType = (type: string): string => {
    const extensions: Record<string, string> = {
      'JPEG': 'jpg',
      'PNG': 'png',
      'GIF': 'gif', 
      'PDF': 'pdf',
      'ZIP': 'zip',
      'RAR': 'rar',
      'EXE': 'exe',
      'DOC': 'doc'
    }
    return extensions[type] || 'bin'
  }

  const extractLSBData = () => {
    if (!canvasRef.current) return
    const ctx = canvasRef.current.getContext('2d')
    if (!ctx) return
    
    const lsbData = analyzeLSBWithDepth(ctx, canvasRef.current.width, canvasRef.current.height, lsbDepth, 50000)
    
    // Create downloadable files for each channel if they contain meaningful data
    const channels = ['red', 'green', 'blue'] as const
    channels.forEach(channel => {
      const channelData = lsbData[channel[0] as 'r' | 'g' | 'b']
      if (channelData.ratio > 0.5) {
        const blob = new Blob([channelData.text], { type: 'text/plain' })
        const url = URL.createObjectURL(blob)
        const a = document.createElement('a')
        a.href = url
        a.download = `lsb_${channel}_channel.txt`
        document.body.appendChild(a)
        a.click()
        document.body.removeChild(a)
        URL.revokeObjectURL(url)
      }
    })
    
    // Also create a composite file
    const compositeBlob = new Blob([lsbData.composite], { type: 'text/plain' })
    const compositeUrl = URL.createObjectURL(compositeBlob)
    const compositeLink = document.createElement('a')
    compositeLink.href = compositeUrl
    compositeLink.download = 'lsb_composite_data.txt'
    document.body.appendChild(compositeLink)
    compositeLink.click()
    document.body.removeChild(compositeLink)
    URL.revokeObjectURL(compositeUrl)
  }

  return (
    <div className="flex flex-col min-h-full">
      {/* Multi-Stage Analysis Pipeline Loading Overlay */}
      {isAnalyzing && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-md z-50 flex items-center justify-center">
          <div className="bg-background border-2 border-accent rounded-lg p-8 shadow-2xl max-w-xl w-full mx-4">
            <div className="flex flex-col gap-6">
              {/* Title */}
              <div className="text-center">
                <h3 className="text-xl font-bold text-accent mb-2 flex items-center justify-center gap-2">
                  <Search className="w-6 h-6 animate-pulse" />
                  Comprehensive Image Analysis
                </h3>
                <p className="text-sm text-muted-foreground">
                  Stage {analysisProgress.stage} of {analysisProgress.total}: {analysisProgress.currentTask}
                </p>
              </div>

              {/* Task List with Status */}
              <div className="space-y-2">
                {[
                  'File Information',
                  'Image Properties',
                  'ExifTool Analysis',
                  'Steganography Detection',
                  'String Extraction',
                  'Hidden File Scanning',
                  'Hex Dump Generation'
                ].map((task, index) => {
                  const taskNumber = index + 1
                  const isComplete = analysisProgress.completedTasks.length > index
                  const isCurrent = analysisProgress.stage === taskNumber
                  
                  return (
                    <div
                      key={task}
                      className={`flex items-start gap-3 p-3 rounded-lg transition-all duration-300 ${
                        isComplete 
                          ? 'bg-accent/10 border border-accent/30' 
                          : isCurrent
                          ? 'bg-accent/20 border-2 border-accent shadow-md'
                          : 'bg-background/50 border border-border opacity-50'
                      }`}
                    >
                      {/* Status Icon */}
                      <div className="flex-shrink-0 mt-0.5">
                        {isComplete ? (
                          <CheckCircle className="w-5 h-5 text-accent" />
                        ) : isCurrent ? (
                          <Activity className="w-5 h-5 text-accent animate-spin" />
                        ) : (
                          <div className="w-5 h-5 rounded-full border-2 border-border" />
                        )}
                      </div>
                      
                      {/* Task Info */}
                      <div className="flex-1 min-w-0">
                        <div className={`text-sm font-medium ${
                          isComplete || isCurrent ? 'text-foreground' : 'text-muted-foreground'
                        }`}>
                          {task}
                        </div>
                        
                        {/* Sub-task for current stage */}
                        {isCurrent && analysisProgress.subTask && (
                          <div className="text-xs text-muted-foreground mt-1 flex items-center gap-1">
                            <span className="inline-block w-1 h-1 bg-accent rounded-full animate-pulse"></span>
                            {analysisProgress.subTask}
                          </div>
                        )}
                      </div>
                      
                      {/* Task Number Badge */}
                      <div className={`flex-shrink-0 text-xs font-mono px-2 py-0.5 rounded ${
                        isComplete 
                          ? 'bg-accent text-background' 
                          : isCurrent
                          ? 'bg-accent/30 text-accent font-bold'
                          : 'bg-muted text-muted-foreground'
                      }`}>
                        {taskNumber}
                      </div>
                    </div>
                  )
                })}
              </div>

              {/* Progress Bar */}
              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs text-muted-foreground">
                  <span>Overall Progress</span>
                  <span className="font-mono font-bold text-accent">
                    {Math.round((analysisProgress.stage / analysisProgress.total) * 100)}%
                  </span>
                </div>
                <div className="w-full h-2 bg-background/50 rounded-full overflow-hidden border border-border">
                  <div 
                    className="h-full bg-gradient-to-r from-accent to-accent/80 transition-all duration-500 ease-out"
                    style={{ width: `${(analysisProgress.stage / analysisProgress.total) * 100}%` }}
                  />
                </div>
              </div>

              {/* Animation Dots */}
              <div className="flex items-center justify-center gap-1">
                <div className="w-2 h-2 bg-accent rounded-full animate-bounce" style={{animationDelay: '0ms'}}></div>
                <div className="w-2 h-2 bg-accent rounded-full animate-bounce" style={{animationDelay: '150ms'}}></div>
                <div className="w-2 h-2 bg-accent rounded-full animate-bounce" style={{animationDelay: '300ms'}}></div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Header */}
      <div className="flex-none px-6 py-4 border-b border-border bg-card">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold">Image Analysis</h1>
            <p className="text-sm text-muted-foreground">
              Deep image forensics: metadata, steganography, and embedded file detection
            </p>
          </div>
        </div>
      </div>

      {/* File Upload or Info */}
      <div className="flex-none px-6 py-4 bg-background">
        {!file ? (
          <div
            className="border-2 border-dashed border-border rounded-lg p-8 text-center hover:border-accent transition-colors cursor-pointer"
            onDragOver={e=>e.preventDefault()}
            onDrop={handleDrop}
            onClick={()=>fileRef.current?.click()}
          >
            <Upload className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
            <p className="text-lg font-medium mb-2">Drop image file here or click to browse</p>
            <p className="text-sm text-muted-foreground">Supports JPEG, PNG, GIF, BMP, TIFF files up to 500MB</p>
            <input ref={fileRef} type="file" accept="image/*" className="hidden" onChange={e=>{ const f=e.target.files?.[0]; if(f) onFile(f) }} />
          </div>
        ) : (
          <div className="flex items-center justify-between bg-card border border-border rounded-lg p-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded bg-accent/20 flex items-center justify-center">
                <ImageIcon className="w-5 h-5 text-accent" />
              </div>
              <div>
                <p className="font-medium">{file.name}</p>
                <p className="text-sm text-muted-foreground">{(file.size/1024/1024).toFixed(2)} MB</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Button
                onClick={analyze}
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
                    <Search className="w-4 h-4 mr-2" />
                    Analyze
                  </>
                )}
              </Button>
              <Button
                variant="outline"
                onClick={() => {
                  setFile(null)
                  setImageUrl(null)
                  setMetadata(null)
                  setStructuredResults(null)
                  setExtractedStrings(null)
                  setBitPlaneUrl(null)
                  setLsbDepthResult(null)
                  setHexData(null)
                  setBarcodeResults([])
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

      {/* Content Area */}
      {imageUrl && metadata && (
        <div className="px-6 pb-6">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-card border border-border rounded-lg p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-lg font-semibold flex items-center"><Eye className="w-5 h-5 text-accent mr-2"/> Image Preview</h3>
              <div className="flex items-center gap-2">
                {imageList.length > 1 && (
                  <div className="flex items-center space-x-2 text-sm text-muted-foreground mr-2">
                    <span>{currentImageIndex + 1} of {imageList.length}</span>
                  </div>
                )}
                
                {/* Quick Download Actions */}
                {imageUrl && (
                  <div className="flex items-center gap-1">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => downloadModifiedImage('png')}
                      className="h-8 px-3"
                      title="Download as PNG (lossless)"
                    >
                      <Download className="w-4 h-4 mr-1" />
                      PNG
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => downloadModifiedImage('jpeg')}
                      className="h-8 px-3"
                      title="Download as JPEG (compressed)"
                    >
                      <Download className="w-4 h-4 mr-1" />
                      JPEG
                    </Button>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={copyModifiedImageToClipboard}
                      className="h-8 px-3"
                      title="Copy to clipboard"
                    >
                      <Copy className="w-4 h-4 mr-1" />
                      Copy
                    </Button>
                  </div>
                )}
              </div>
            </div>
            
            <div className="relative group">
              {/* Processing Indicator Overlay */}
              {isProcessingImage && (
                <div className="absolute inset-0 z-50 flex items-center justify-center bg-background/80 backdrop-blur-sm rounded">
                  <div className="flex flex-col items-center space-y-3">
                    <Activity className="w-8 h-8 text-accent animate-spin" />
                    <span className="text-sm font-medium">Processing image...</span>
                  </div>
                </div>
              )}

              {/* Enhanced Image Display with Zoom and Pixel Inspector */}
              <div className="relative overflow-hidden rounded border border-border bg-background/50">
                <canvas 
                  ref={canvasRef}
                  className={`object-contain ${zoomLevel > 1 ? 'cursor-move' : showPixelInfo ? 'cursor-crosshair' : 'cursor-default'}`}
                  style={{
                    filter: `brightness(${imageAdjustments.brightness}%) contrast(${imageAdjustments.contrast}%) saturate(${imageAdjustments.saturation}%) hue-rotate(${imageAdjustments.hue}deg) ${imageAdjustments.exposure !== 0 ? `brightness(${100 + imageAdjustments.exposure}%)` : ''} ${imageAdjustments.temperature !== 0 ? `sepia(${Math.abs(imageAdjustments.temperature) / 2}%) ${imageAdjustments.temperature > 0 ? 'hue-rotate(10deg)' : 'hue-rotate(-10deg)'}` : ''} ${imageAdjustments.clarity !== 0 ? `contrast(${100 + imageAdjustments.clarity}%)` : ''} ${imageAdjustments.vignette !== 0 ? `drop-shadow(inset 0 0 ${Math.abs(imageAdjustments.vignette)}px rgba(0,0,0,0.5))` : ''}`,
                    display: showAdjustedImage ? 'block' : 'none',
                    transform: `scale(${zoomLevel}) translate(${panPosition.x}px, ${panPosition.y}px)`,
                    transformOrigin: '0 0',
                    transition: isPanning ? 'none' : 'transform 0.1s ease',
                    width: '100%',
                    height: 'auto',
                    userSelect: 'none'
                  }}
                  draggable={false}
                  onMouseDown={(e) => {
                    e.preventDefault()
                    if (zoomLevel > 1) {
                      setIsPanning(true)
                      setLastPanPoint({ x: e.clientX, y: e.clientY })
                    }
                  }}
                  onMouseMove={(e) => {
                    e.preventDefault()
                    if (isPanning && zoomLevel > 1) {
                      const dx = (e.clientX - lastPanPoint.x) / zoomLevel
                      const dy = (e.clientY - lastPanPoint.y) / zoomLevel
                      setPanPosition(prev => ({ 
                        x: Math.max(-500, Math.min(500, prev.x + dx)), 
                        y: Math.max(-500, Math.min(500, prev.y + dy))
                      }))
                      setLastPanPoint({ x: e.clientX, y: e.clientY })
                    } else if (showPixelInfo && canvasRef.current) {
                      const rect = canvasRef.current.getBoundingClientRect()
                      const x = Math.floor(((e.clientX - rect.left) / rect.width) * canvasRef.current.width)
                      const y = Math.floor(((e.clientY - rect.top) / rect.height) * canvasRef.current.height)
                      
                      // Get pixel color if available
                      const ctx = canvasRef.current.getContext('2d')
                      if (ctx && x >= 0 && y >= 0 && x < canvasRef.current.width && y < canvasRef.current.height) {
                        const imageData = ctx.getImageData(x, y, 1, 1)
                        const [r, g, b, a] = imageData.data
                        setMousePosition({ x, y, color: `rgba(${r}, ${g}, ${b}, ${a/255})` })
                      }
                    }
                  }}
                  onMouseUp={(e) => {
                    e.preventDefault()
                    setIsPanning(false)
                  }}
                  onMouseLeave={() => {
                    setIsPanning(false)
                    setMousePosition(null)
                  }}
                />
                <img 
                  ref={imageRef}
                  src={imageUrl} 
                  alt="preview" 
                  className={`object-contain ${zoomLevel > 1 ? 'cursor-move' : showPixelInfo ? 'cursor-crosshair' : 'cursor-default'}`}
                  style={{ 
                    display: showAdjustedImage ? 'none' : 'block',
                    transform: `scale(${zoomLevel}) translate(${panPosition.x}px, ${panPosition.y}px)`,
                    transformOrigin: '0 0',
                    transition: isPanning ? 'none' : 'transform 0.1s ease',
                    width: '100%',
                    height: 'auto',
                    userSelect: 'none'
                  }}
                  draggable={false}
                  onLoad={handleImageLoad}
                  onMouseDown={(e) => {
                    e.preventDefault()
                    if (zoomLevel > 1) {
                      setIsPanning(true)
                      setLastPanPoint({ x: e.clientX, y: e.clientY })
                    }
                  }}
                  onMouseMove={(e) => {
                    e.preventDefault()
                    if (isPanning && zoomLevel > 1) {
                      const dx = (e.clientX - lastPanPoint.x) / zoomLevel
                      const dy = (e.clientY - lastPanPoint.y) / zoomLevel
                      setPanPosition(prev => ({ 
                        x: Math.max(-500, Math.min(500, prev.x + dx)), 
                        y: Math.max(-500, Math.min(500, prev.y + dy))
                      }))
                      setLastPanPoint({ x: e.clientX, y: e.clientY })
                    } else if (showPixelInfo && imageRef.current && canvasRef.current) {
                      const rect = imageRef.current.getBoundingClientRect()
                      const x = Math.floor(((e.clientX - rect.left) / rect.width) * imageRef.current.naturalWidth)
                      const y = Math.floor(((e.clientY - rect.top) / rect.height) * imageRef.current.naturalHeight)
                      setMousePosition({ x, y })
                    }
                  }}
                  onMouseUp={(e) => {
                    e.preventDefault()
                    setIsPanning(false)
                  }}
                  onMouseLeave={() => {
                    setIsPanning(false)
                    setMousePosition(null)
                  }}
                />
                
                {/* Pixel Info Overlay */}
                {showPixelInfo && mousePosition && (
                  <div className="absolute top-2 left-2 bg-background/90 backdrop-blur-sm border border-border rounded px-3 py-2 text-xs font-mono">
                    <div>X: {mousePosition.x}, Y: {mousePosition.y}</div>
                    {mousePosition.color && (
                      <div className="flex items-center gap-2 mt-1">
                        <div 
                          className="w-4 h-4 rounded border border-border" 
                          style={{backgroundColor: mousePosition.color}}
                        />
                        <span>{mousePosition.color}</span>
                      </div>
                    )}
                  </div>
                )}
                
              </div>

              {imageList.length > 1 && (
                <>
                  <button
                    onClick={() => navigateImage('prev')}
                    className="absolute left-2 top-1/2 transform -translate-y-1/2 bg-accent/80 hover:bg-accent text-background p-2 rounded-full opacity-0 group-hover:opacity-100 transition-all duration-200 hover:scale-110"
                    title="Previous image"
                  >
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 19l-7-7 7-7" />
                    </svg>
                  </button>
                  
                  <button
                    onClick={() => navigateImage('next')}
                    className="absolute right-2 top-1/2 transform -translate-y-1/2 bg-accent/80 hover:bg-accent text-background p-2 rounded-full opacity-0 group-hover:opacity-100 transition-all duration-200 hover:scale-110"
                    title="Next image"
                  >
                    <svg className="w-5 h-5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                    </svg>
                  </button>
                </>
              )}
            </div>
            
            {/* Image Zoom and Pan Controls - Matching Bitplane style */}
            <div className="mb-4 bg-background/50 p-3 rounded border border-border">
              <div className="text-xs font-medium text-center text-muted-foreground mb-2">Image Zoom & Pan Controls</div>
              
              <div className="flex items-center justify-between gap-4">
                <div className="flex items-center gap-2 flex-1">
                  <label className="text-xs text-muted-foreground min-w-max">Zoom:</label>
                  <input
                    type="range"
                    min="50"
                    max="500"
                    step="5"
                    value={zoomLevel * 100}
                    onChange={(e) => {
                      const newZoom = Number(e.target.value) / 100
                      setZoomLevel(newZoom)
                      if (Math.abs(newZoom - zoomLevel) > 0.5) {
                        setPanPosition({ x: 0, y: 0 })
                      }
                    }}
                    className="flex-1 h-2 bg-muted rounded-lg appearance-none cursor-pointer"
                    style={{
                      background: `linear-gradient(to right, #6366f1 0%, #6366f1 ${((zoomLevel * 100 - 50) / (500 - 50)) * 100}%, #e5e7eb ${((zoomLevel * 100 - 50) / (500 - 50)) * 100}%, #e5e7eb 100%)`
                    }}
                  />
                  <span className="text-xs font-mono text-foreground min-w-max">
                    {Math.round(zoomLevel * 100)}%
                  </span>
                </div>
                
                <div className="flex items-center gap-2">
                  <button
                    onClick={() => {
                      setZoomLevel(1)
                      setPanPosition({ x: 0, y: 0 })
                    }}
                    className="px-2 py-1 bg-accent/10 hover:bg-accent text-accent hover:text-background rounded text-xs font-mono transition-colors"
                  >
                    Reset
                  </button>
                  {zoomLevel > 1 && (
                    <button
                      onClick={() => setPanPosition({ x: 0, y: 0 })}
                      className="px-2 py-1 bg-muted hover:bg-accent text-foreground hover:text-background rounded text-xs font-mono transition-colors"
                    >
                      Center
                    </button>
                  )}
                </div>
              </div>
              
              {zoomLevel > 1 && (
                <div className="text-xs text-muted-foreground text-center mt-2">
                  🔍 Click and drag on the image to pan around
                </div>
              )}
            </div>

            {/* Enhanced Professional Image Analysis Tools */}
            <div className="mt-4 space-y-4">
              <div className="bg-background/50 p-4 rounded-lg border border-border space-y-4">
                <div className="flex items-center justify-between">
                  <h4 className="text-sm font-medium text-accent">Forensic Image Processing</h4>
                  <div className="flex space-x-2">
                    <Button 
                      variant="outline" 
                      size="sm" 
                      onClick={() => setShowPixelInfo(!showPixelInfo)}
                      className={`p-1 text-sm ${showPixelInfo ? 'bg-accent text-background' : ''}`}
                    >
                      Pixel Inspector
                    </Button>
                    <Button 
                      variant="outline" 
                      size="sm" 
                      onClick={() => setShowAdjustedImage(!showAdjustedImage)}
                      className="p-1 text-sm"
                    >
                      {showAdjustedImage ? 'Show Original' : 'Show Processed'}
                    </Button>
                    <Button 
                      variant="outline" 
                      size="sm" 
                      onClick={resetAdjustments}
                      className="p-1 text-sm"
                    >
                      Reset All
                    </Button>
                  </div>
                </div>

                {/* Basic Adjustments */}
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <label className="text-xs text-muted-foreground flex justify-between">
                      <span>Brightness</span>
                      <span className="font-mono">{imageAdjustments.brightness}%</span>
                    </label>
                    <input type="range" min={25} max={300} value={imageAdjustments.brightness} onChange={e=>updateAdjustment('brightness', Number(e.target.value))} className="w-full" />
                  </div>
                  <div>
                    <label className="text-xs text-muted-foreground flex justify-between">
                      <span>Contrast</span>
                      <span className="font-mono">{imageAdjustments.contrast}%</span>
                    </label>
                    <input type="range" min={25} max={300} value={imageAdjustments.contrast} onChange={e=>updateAdjustment('contrast', Number(e.target.value))} className="w-full" />
                  </div>
                  <div>
                    <label className="text-xs text-muted-foreground flex justify-between">
                      <span>Saturation</span>
                      <span className="font-mono">{imageAdjustments.saturation}%</span>
                    </label>
                    <input type="range" min={0} max={300} value={imageAdjustments.saturation} onChange={e=>updateAdjustment('saturation', Number(e.target.value))} className="w-full" />
                  </div>
                  <div>
                    <label className="text-xs text-muted-foreground flex justify-between">
                      <span>Hue Shift</span>
                      <span className="font-mono">{imageAdjustments.hue}°</span>
                    </label>
                    <input type="range" min={-180} max={180} value={imageAdjustments.hue} onChange={e=>updateAdjustment('hue', Number(e.target.value))} className="w-full" />
                  </div>
                </div>
                
                {/* Extended Professional Controls */}
                <div className="grid grid-cols-2 md:grid-cols-3 gap-3 border-t pt-3">
                  <div>
                    <label className="text-xs text-muted-foreground flex justify-between">
                      <span>Exposure</span>
                      <span className="font-mono">{imageAdjustments.exposure > 0 ? '+' : ''}{imageAdjustments.exposure}</span>
                    </label>
                    <input type="range" min={-100} max={100} value={imageAdjustments.exposure} onChange={e=>updateAdjustment('exposure', Number(e.target.value))} className="w-full" />
                  </div>
                  <div>
                    <label className="text-xs text-muted-foreground flex justify-between">
                      <span>Shadows</span>
                      <span className="font-mono">{imageAdjustments.shadows > 0 ? '+' : ''}{imageAdjustments.shadows}</span>
                    </label>
                    <input type="range" min={-100} max={100} value={imageAdjustments.shadows} onChange={e=>updateAdjustment('shadows', Number(e.target.value))} className="w-full" />
                  </div>
                  <div>
                    <label className="text-xs text-muted-foreground flex justify-between">
                      <span>Highlights</span>
                      <span className="font-mono">{imageAdjustments.highlights > 0 ? '+' : ''}{imageAdjustments.highlights}</span>
                    </label>
                    <input type="range" min={-100} max={100} value={imageAdjustments.highlights} onChange={e=>updateAdjustment('highlights', Number(e.target.value))} className="w-full" />
                  </div>
                  <div>
                    <label className="text-xs text-muted-foreground flex justify-between">
                      <span>Temperature</span>
                      <span className="font-mono">{imageAdjustments.temperature > 0 ? '+' : ''}{imageAdjustments.temperature}K</span>
                    </label>
                    <input type="range" min={-100} max={100} value={imageAdjustments.temperature} onChange={e=>updateAdjustment('temperature', Number(e.target.value))} className="w-full" />
                  </div>
                  <div>
                    <label className="text-xs text-muted-foreground flex justify-between">
                      <span>Vibrance</span>
                      <span className="font-mono">{imageAdjustments.vibrance > 0 ? '+' : ''}{imageAdjustments.vibrance}</span>
                    </label>
                    <input type="range" min={-100} max={100} value={imageAdjustments.vibrance} onChange={e=>updateAdjustment('vibrance', Number(e.target.value))} className="w-full" />
                  </div>
                  <div>
                    <label className="text-xs text-muted-foreground flex justify-between">
                      <span>Clarity</span>
                      <span className="font-mono">{imageAdjustments.clarity > 0 ? '+' : ''}{imageAdjustments.clarity}</span>
                    </label>
                    <input type="range" min={-100} max={100} value={imageAdjustments.clarity} onChange={e=>updateAdjustment('clarity', Number(e.target.value))} className="w-full" />
                  </div>
                </div>
                  
                {/* Enhanced Color Channel Analysis */}
                <div>
                  <label className="text-xs text-muted-foreground mb-2 block">Forensic Color Channel Analysis</label>
                  <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                    {[
                      { value: 'normal', label: 'Original' },
                      { value: 'red', label: 'Red' },
                      { value: 'green', label: 'Green' },
                      { value: 'blue', label: 'Blue' },
                      { value: 'grayscale', label: 'Grayscale' },
                      { value: 'invert', label: 'Invert' }
                    ].map((channel) => (
                      <button
                        key={channel.value}
                        onClick={() => handleColorChannelChange(channel.value as ColorChannel)}
                        className={`p-2 text-xs rounded border transition-colors text-center ${
                          colorChannel === channel.value
                            ? 'bg-accent text-background border-accent'
                            : 'bg-background border-border hover:border-accent/50'
                        }`}
                      >
                        <div className="font-medium">{channel.label}</div>
                      </button>
                    ))}
                  </div>
                </div>

                {/* Forensic Quick Presets */}
                <div className="border-t pt-3">
                  <label className="text-xs text-muted-foreground mb-2 block">Forensic Quick Presets</label>
                  <div className="grid grid-cols-2 gap-2">
                    <Button size="sm" variant="outline" onClick={() => {
                      setImageAdjustments({...imageAdjustments, brightness: 150, contrast: 200})
                      setShowAdjustedImage(true)
                    }}>
                      Enhance Dark
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => {
                      setImageAdjustments({...imageAdjustments, brightness: 80, contrast: 150, saturation: 50})
                      setShowAdjustedImage(true)
                    }}>
                      High Contrast
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => {
                      handleColorChannelChange('grayscale')
                      setImageAdjustments({...imageAdjustments, contrast: 180})
                    }}>
                      Forensic Gray
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => {
                      handleColorChannelChange('invert')
                      setImageAdjustments({...imageAdjustments, contrast: 120})
                    }}>
                      Negative
                    </Button>
                  </div>
                  <div className="text-xs text-muted-foreground mt-2">
                    Common forensic enhancement presets for revealing hidden details.
                  </div>
                </div>

                {/* Advanced Processing Options */}
                <div className="border-t pt-3">
                  <label className="text-xs text-muted-foreground mb-2 block">Advanced Forensic Processing</label>
                  <div className="grid grid-cols-2 gap-2">
                    <Button size="sm" variant="outline" onClick={() => applyAdvancedProcessing('edge')}>
                      Edge Detection
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => applyAdvancedProcessing('noise')}>
                      Noise Analysis
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => applyAdvancedProcessing('gamma')}>
                      Auto Gamma
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => applyAdvancedProcessing('histogram')}>
                      Histogram EQ
                    </Button>
                  </div>
                  <div className="text-xs text-muted-foreground mt-2">
                    Advanced processing tools for forensic image enhancement and analysis.
                  </div>
                </div>
              </div>
            </div>

            
            <div className="mt-3 flex items-center justify-between">
              <div className="font-mono text-xs text-muted-foreground">
                {metadata.dimensions?.width} x {metadata.dimensions?.height} • {(Number(metadata.fileSize||0)/1024/1024).toFixed(2)} MB
              </div>
            </div>
          </div>

          <div className="bg-card border border-border rounded-lg p-6">
            <div className="flex space-x-2 border-b border-border pb-3 mb-4 overflow-x-auto">
              <button onClick={()=>setActiveTab('metadata')} className={`px-3 py-2 whitespace-nowrap ${activeTab==='metadata'?'text-accent border-b-2 border-accent':''}`}>
                EXIF Fields
              </button>
              <button onClick={()=>setActiveTab('forensics')} className={`px-3 py-2 whitespace-nowrap ${activeTab==='forensics'?'text-accent border-b-2 border-accent':''}`}>
                Forensics
              </button>
              <button onClick={()=>setActiveTab('bitplane')} className={`px-3 py-2 whitespace-nowrap ${activeTab==='bitplane'?'text-accent border-b-2 border-accent':''}`}>Bitplane</button>
              <button onClick={()=>setActiveTab('strings')} className={`px-3 py-2 whitespace-nowrap ${activeTab==='strings'?'text-accent border-b-2 border-accent':''}`}>Strings</button>
              <button onClick={()=>setActiveTab('hex')} className={`px-3 py-2 whitespace-nowrap ${activeTab==='hex'?'text-accent border-b-2 border-accent':''}`}>Hex</button>
              <button onClick={()=>{setActiveTab('barcode'); if(barcodeResults.length === 0 && !isScanningBarcode) scanBarcodes()}} className={`px-3 py-2 whitespace-nowrap ${activeTab==='barcode'?'text-accent border-b-2 border-accent':''}`}>Barcode</button>
            </div>

            {activeTab==='metadata' && (
              <div>
                <h4 className="font-medium mb-2">File Information</h4>
                <div className="text-sm font-mono space-y-2">
                  <div className="flex justify-between"><span className="text-muted-foreground">Filename:</span><span>{metadata.filename}</span></div>
                  <div className="flex justify-between"><span className="text-muted-foreground">Format:</span><span>{metadata.format}</span></div>
                </div>

                {/* ExifTool Advanced Analysis from Backend */}
                {backendResults?.exif && (
                  <div className="mt-6 space-y-4">
                    {/* Anomalies Warning */}
                    {backendResults.exif.anomalies && backendResults.exif.anomalies.length > 0 && (
                      <div className="bg-yellow-500/10 border border-yellow-500/30 rounded-lg p-4">
                        <div className="flex items-center space-x-2 mb-2">
                          <AlertTriangle className="w-5 h-5 text-yellow-500" />
                          <h5 className="font-medium text-yellow-500">EXIF Anomalies Detected</h5>
                        </div>
                        <div className="space-y-2">
                          {backendResults.exif.anomalies.map((anomaly: any, i: number) => (
                            <div key={i} className="text-sm p-2 bg-background rounded border-l-2 border-yellow-500">
                              <div className="flex items-center justify-between mb-1">
                                <span className="font-mono text-xs text-muted-foreground">{anomaly.type}</span>
                                <span className={`text-xs px-2 py-0.5 rounded ${
                                  anomaly.severity === 'high' ? 'bg-red-500/20 text-red-400' :
                                  anomaly.severity === 'medium' ? 'bg-yellow-500/20 text-yellow-400' :
                                  'bg-blue-500/20 text-blue-400'
                                }`}>{anomaly.severity}</span>
                              </div>
                              <p className="text-xs">{anomaly.description}</p>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* GPS Location */}
                    {backendResults.exif.hasGPS && backendResults.exif.gps && (
                      <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4">
                        <div className="flex items-center space-x-2 mb-3">
                          <MapPin className="w-5 h-5 text-blue-400" />
                          <h5 className="font-medium text-blue-400">GPS Location Found</h5>
                        </div>
                        <div className="space-y-2 text-sm">
                          {backendResults.exif.gps.location && (
                            <div className="flex justify-between">
                              <span className="text-muted-foreground">Coordinates:</span>
                              <span className="font-mono">{backendResults.exif.gps.location}</span>
                            </div>
                          )}
                          {backendResults.exif.gps.altitude && (
                            <div className="flex justify-between">
                              <span className="text-muted-foreground">Altitude:</span>
                              <span className="font-mono">{backendResults.exif.gps.altitude}</span>
                            </div>
                          )}
                          {backendResults.exif.gps.timestamp && (
                            <div className="flex justify-between">
                              <span className="text-muted-foreground">GPS Time:</span>
                              <span className="font-mono">{backendResults.exif.gps.timestamp}</span>
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Camera Information */}
                    {backendResults.exif.camera && (backendResults.exif.camera.make || backendResults.exif.camera.model) && (
                      <div className="bg-purple-500/10 border border-purple-500/30 rounded-lg p-4">
                        <div className="flex items-center space-x-2 mb-3">
                          <Camera className="w-5 h-5 text-purple-400" />
                          <h5 className="font-medium text-purple-400">Camera Information</h5>
                        </div>
                        <div className="space-y-2 text-sm">
                          {backendResults.exif.camera.make && (
                            <div className="flex justify-between">
                              <span className="text-muted-foreground">Make:</span>
                              <span>{backendResults.exif.camera.make}</span>
                            </div>
                          )}
                          {backendResults.exif.camera.model && (
                            <div className="flex justify-between">
                              <span className="text-muted-foreground">Model:</span>
                              <span>{backendResults.exif.camera.model}</span>
                            </div>
                          )}
                          {backendResults.exif.camera.lens && (
                            <div className="flex justify-between">
                              <span className="text-muted-foreground">Lens:</span>
                              <span>{backendResults.exif.camera.lens}</span>
                            </div>
                          )}
                          {backendResults.exif.camera.settings && Object.keys(backendResults.exif.camera.settings).some(k => backendResults.exif.camera.settings[k]) && (
                            <div className="mt-3 pt-3 border-t border-border">
                              <h6 className="text-xs font-medium text-muted-foreground mb-2">Settings</h6>
                              <div className="grid grid-cols-2 gap-2 text-xs">
                                {backendResults.exif.camera.settings.iso && (
                                  <div><span className="text-muted-foreground">ISO:</span> <span className="font-mono">{backendResults.exif.camera.settings.iso}</span></div>
                                )}
                                {backendResults.exif.camera.settings.aperture && (
                                  <div><span className="text-muted-foreground">Aperture:</span> <span className="font-mono">{backendResults.exif.camera.settings.aperture}</span></div>
                                )}
                                {backendResults.exif.camera.settings.shutterSpeed && (
                                  <div><span className="text-muted-foreground">Shutter:</span> <span className="font-mono">{backendResults.exif.camera.settings.shutterSpeed}</span></div>
                                )}
                                {backendResults.exif.camera.settings.focalLength && (
                                  <div><span className="text-muted-foreground">Focal Length:</span> <span className="font-mono">{backendResults.exif.camera.settings.focalLength}</span></div>
                                )}
                              </div>
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Timeline Analysis */}
                    {backendResults.exif.timeline && (backendResults.exif.timeline.created || backendResults.exif.timeline.modified) && (
                      <div className={`rounded-lg p-4 ${backendResults.exif.timeline.possiblyEdited ? 'bg-orange-500/10 border border-orange-500/30' : 'bg-green-500/10 border border-green-500/30'}`}>
                        <div className="flex items-center space-x-2 mb-3">
                          <Clock className={`w-5 h-5 ${backendResults.exif.timeline.possiblyEdited ? 'text-orange-400' : 'text-green-400'}`} />
                          <h5 className={`font-medium ${backendResults.exif.timeline.possiblyEdited ? 'text-orange-400' : 'text-green-400'}`}>
                            Timeline {backendResults.exif.timeline.possiblyEdited ? '(Modified)' : ''}
                          </h5>
                        </div>
                        <div className="space-y-2 text-sm">
                          {backendResults.exif.timeline.created && (
                            <div className="flex justify-between">
                              <span className="text-muted-foreground">Created:</span>
                              <span className="font-mono">{backendResults.exif.timeline.created}</span>
                            </div>
                          )}
                          {backendResults.exif.timeline.modified && (
                            <div className="flex justify-between">
                              <span className="text-muted-foreground">Modified:</span>
                              <span className="font-mono">{backendResults.exif.timeline.modified}</span>
                            </div>
                          )}
                          {backendResults.exif.timeline.possiblyEdited && backendResults.exif.timeline.timeDifference && (
                            <div className="mt-2 p-2 bg-background rounded text-xs">
                              <AlertTriangle className="w-3 h-3 inline mr-1 text-orange-400" />
                              Image was modified {backendResults.exif.timeline.timeDifference} after capture
                            </div>
                          )}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* EXIF Data with Search and Grouped Categories */}
                {backendResults?.exif?.raw && Object.keys(backendResults.exif.raw).length > 0 && (
                  <div className="mt-6">
                    <div className="flex items-center justify-between mb-3">
                      <h5 className="text-sm font-medium">EXIF Data</h5>
                      <span className="text-xs text-muted-foreground">{Object.keys(backendResults.exif.raw).length} fields</span>
                    </div>

                    {/* Search Bar */}
                    <div className="mb-3">
                      <div className="relative">
                        <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                        <Input
                          type="text"
                          placeholder="Search EXIF fields..."
                          value={exifSearchQuery}
                          onChange={(e) => setExifSearchQuery(e.target.value)}
                          className="pl-10 h-9 text-sm"
                        />
                      </div>
                    </div>

                    {/* Grouped Accordion */}
                    <div className="space-y-2 max-h-[600px] overflow-y-auto">
                      {Object.entries(groupExifByCategory(backendResults.exif.raw))
                        .filter(([, fields]) => {
                          if (!exifSearchQuery) return true
                          // Show category if any field matches search
                          return fields.some(field => 
                            field.key.toLowerCase().includes(exifSearchQuery.toLowerCase()) ||
                            String(field.value).toLowerCase().includes(exifSearchQuery.toLowerCase())
                          )
                        })
                        .map(([category, fields]) => {
                          const filteredFields = exifSearchQuery
                            ? fields.filter(field => 
                                field.key.toLowerCase().includes(exifSearchQuery.toLowerCase()) ||
                                String(field.value).toLowerCase().includes(exifSearchQuery.toLowerCase())
                              )
                            : fields
                          
                          const isExpanded = expandedExifCategories.includes(category)
                          
                          return (
                            <div key={category} className="border border-border rounded-lg overflow-hidden">
                              {/* Category Header */}
                              <button
                                onClick={() => toggleExifCategory(category)}
                                className="w-full flex items-center justify-between p-3 bg-background/50 hover:bg-background/80 transition-colors"
                              >
                                <div className="flex items-center space-x-2">
                                  <ChevronDown className={`w-4 h-4 transition-transform ${isExpanded ? 'rotate-0' : '-rotate-90'}`} />
                                  <span className="font-medium text-sm">{category}</span>
                                  <span className="text-xs text-muted-foreground">({filteredFields.length})</span>
                                </div>
                              </button>
                              
                              {/* Category Content */}
                              {isExpanded && (
                                <div className="border-t border-border">
                                  {filteredFields.map((field, idx) => (
                                    <div 
                                      key={idx} 
                                      className="flex flex-col md:flex-row md:justify-between md:items-start p-2 hover:bg-background/30 border-b border-border/50 last:border-b-0"
                                    >
                                      <div className="text-xs text-muted-foreground md:w-1/3 font-mono break-all">
                                        {field.key.split(':').slice(1).join(':') || field.key}
                                      </div>
                                      <div className="break-all md:w-2/3 text-sm font-mono">
                                        {formatExifValue(field.value)}
                                      </div>
                                    </div>
                                  ))}
                                </div>
                              )}
                            </div>
                          )
                        })}
                    </div>
                  </div>
                )}

                {/* Show processing message if backend hasn't completed yet */}
                {!backendResults?.exif && (
                  <div className="mt-4 bg-blue-500/10 border border-blue-500/30 rounded-lg p-4">
                    <div className="flex items-center space-x-3">
                      <Activity className="w-4 h-4 text-blue-400 animate-spin" />
                      <span className="text-sm text-muted-foreground">Processing EXIF data with ExifTool...</span>
                    </div>
                  </div>
                )}
              </div>
            )}

            {activeTab==='forensics' && (
              <div className="space-y-6">
                {/* Backend Processing Status */}
                {isBackendProcessing && !backendResults && (
                  <div className="bg-blue-500/10 border border-blue-500/30 rounded-lg p-4">
                    <div className="flex items-center space-x-3">
                      <Activity className="w-5 h-5 text-blue-400 animate-spin" />
                      <div>
                        <h5 className="font-medium text-blue-400">Running Forensic Analysis...</h5>
                        {jobStatus?.message && (
                          <p className="text-sm text-muted-foreground mt-1">{jobStatus.message}</p>
                        )}
                        {jobStatus?.progress !== undefined && (
                          <div className="mt-2 bg-background rounded-full h-2 overflow-hidden">
                            <div className="bg-blue-500 h-full transition-all" style={{ width: `${jobStatus.progress}%` }}></div>
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                )}

                {/* ELA Results */}
                {backendResults?.ela && (
                  <div className="bg-card border border-border rounded-lg p-4">
                    <div className="flex items-center space-x-2 mb-3">
                      <Eye className="w-5 h-5 text-accent" />
                      <h5 className="font-medium">Error Level Analysis (ELA)</h5>
                    </div>
                    
                    {backendResults.ela.elaImageUrl && (
                      <div className="mb-4">
                        <img 
                          src={backendResults.ela.elaImageUrl} 
                          alt="ELA Analysis" 
                          className="max-w-full rounded border border-border"
                        />
                      </div>
                    )}

                    <div className="space-y-3">
                      <div className="p-3 bg-background rounded-lg">
                        <p className="text-sm mb-2">{backendResults.ela.analysis?.interpretation}</p>
                        <div className="grid grid-cols-2 gap-3 text-sm">
                          <div>
                            <span className="text-muted-foreground">Max Difference:</span>
                            <span className="ml-2 font-mono text-accent">{backendResults.ela.analysis?.maxDifference?.toFixed(2)}</span>
                          </div>
                          <div>
                            <span className="text-muted-foreground">Avg Difference:</span>
                            <span className="ml-2 font-mono text-accent">{backendResults.ela.analysis?.avgDifference?.toFixed(2)}</span>
                          </div>
                        </div>
                      </div>

                      {backendResults.ela.analysis?.suspiciousRegions && backendResults.ela.analysis.suspiciousRegions.length > 0 && (
                        <div className="bg-red-500/10 border border-red-500/30 rounded-lg p-3">
                          <div className="flex items-center space-x-2 mb-2">
                            <AlertTriangle className="w-4 h-4 text-red-400" />
                            <h6 className="text-sm font-medium text-red-400">Suspicious Regions Detected</h6>
                          </div>
                          <div className="space-y-1 text-xs">
                            {backendResults.ela.analysis.suspiciousRegions.slice(0, 5).map((region: any, i: number) => (
                              <div key={i} className="flex justify-between p-2 bg-background rounded">
                                <span>Region {i + 1}</span>
                                <span className="font-mono">
                                  x:{region.x} y:{region.y} ({region.width}x{region.height})
                                </span>
                                <span className="text-red-400">Err: {region.avgError.toFixed(1)}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* Steganography Detection */}
                {backendResults?.steganography && (
                  <div className="bg-card border border-border rounded-lg p-4">
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center space-x-2">
                        <Layers className="w-5 h-5 text-accent" />
                        <h5 className="font-medium">Professional Steganography Analysis</h5>
                      </div>
                      {backendResults.steganography.summary?.suspicious && (
                        <div className="flex items-center space-x-1 text-xs">
                          <AlertTriangle className="w-4 h-4 text-yellow-500" />
                          <span className="text-yellow-500 font-medium">HIDDEN DATA DETECTED</span>
                        </div>
                      )}
                    </div>

                    {/* Summary Findings */}
                    {backendResults.steganography.summary?.findings && backendResults.steganography.summary.findings.length > 0 && (
                      <div className="mb-4 p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg">
                        <h6 className="text-sm font-medium mb-2 flex items-center">
                          <AlertTriangle className="w-4 h-4 mr-1" />
                          Key Findings
                        </h6>
                        <ul className="text-xs space-y-1">
                          {backendResults.steganography.summary.findings.map((finding: string, i: number) => (
                            <li key={i} className="flex items-start">
                              <span className="text-yellow-500 mr-2">•</span>
                              <span>{finding}</span>
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}

                    <div className="space-y-3">
                      {/* ZSteg Results (PNG/BMP LSB Analysis) */}
                      {backendResults.steganography.tools?.zsteg && !backendResults.steganography.tools.zsteg.skipped && (
                        <div className={`p-3 rounded-lg ${backendResults.steganography.tools.zsteg.foundData ? 'bg-red-500/10 border border-red-500/30' : 'bg-green-500/10 border border-green-500/30'}`}>
                          <h6 className="text-sm font-medium mb-2 flex items-center">
                            <Search className="w-4 h-4 mr-1" />
                            ZSteg Analysis (LSB Detection)
                          </h6>
                          {backendResults.steganography.tools.zsteg.foundData ? (
                            <div className="space-y-2">
                              <div className="text-xs text-yellow-500 font-medium">⚠ Hidden data found in LSB bits!</div>
                              {backendResults.steganography.tools.zsteg.extractedData?.map((data: any, i: number) => (
                                <div key={i} className="p-2 bg-background rounded border border-border">
                                  <div className="text-xs text-muted-foreground mb-1">Method: {data.method}</div>
                                  <div className="text-xs font-mono break-all">{data.content}</div>
                                </div>
                              ))}
                            </div>
                          ) : (
                            <div className="text-xs text-green-500">✓ No LSB steganography detected</div>
                          )}
                        </div>
                      )}

                      {/* Steghide Results */}
                      {backendResults.steganography.tools?.steghide && (
                        <div className={`p-3 rounded-lg ${backendResults.steganography.tools.steghide.detected ? 'bg-red-500/10 border border-red-500/30' : 'bg-green-500/10 border border-green-500/30'}`}>
                          <h6 className="text-sm font-medium mb-2 flex items-center">
                            <Key className="w-4 h-4 mr-1" />
                            Steghide Detection
                          </h6>
                          {backendResults.steganography.tools.steghide.detected ? (
                            <div className="space-y-2">
                              <div className="text-xs text-yellow-500 font-medium">⚠ Steghide embedded data detected!</div>
                              {backendResults.steganography.tools.steghide.extracted ? (
                                <>
                                  <div className="text-xs">
                                    <span className="text-muted-foreground">Password: </span>
                                    <span className="font-mono">{backendResults.steganography.tools.steghide.passwordUsed}</span>
                                  </div>
                                  {backendResults.steganography.tools.steghide.data && (
                                    <div className="p-2 bg-background rounded border border-border">
                                      <div className="text-xs text-muted-foreground mb-1">Extracted Content:</div>
                                      <div className="text-xs font-mono break-all max-h-32 overflow-y-auto">
                                        {backendResults.steganography.tools.steghide.data.content}
                                      </div>
                                    </div>
                                  )}
                                </>
                              ) : (
                                <div className="text-xs text-yellow-500">Data detected but extraction failed (password protected)</div>
                              )}
                            </div>
                          ) : (
                            <div className="text-xs text-green-500">✓ No Steghide embedding detected</div>
                          )}
                        </div>
                      )}

                      {/* Binwalk Results */}
                      {backendResults.steganography.tools?.binwalk && (
                        <div className={`p-3 rounded-lg ${backendResults.steganography.tools.binwalk.filesFound > 0 ? 'bg-red-500/10 border border-red-500/30' : 'bg-green-500/10 border border-green-500/30'}`}>
                          <h6 className="text-sm font-medium mb-2 flex items-center">
                            <FileArchive className="w-4 h-4 mr-1" />
                            Binwalk File Carving
                          </h6>
                          {backendResults.steganography.tools.binwalk.filesFound > 0 ? (
                            <div className="space-y-2">
                              <div className="text-xs text-yellow-500 font-medium">
                                ⚠ Found {backendResults.steganography.tools.binwalk.filesFound} embedded file signature(s)!
                              </div>
                              {backendResults.steganography.tools.binwalk.files?.map((file: any, i: number) => (
                                <div key={i} className="p-2 bg-background rounded border border-border text-xs">
                                  <div className="flex items-center justify-between">
                                    <div className="flex-1">
                                      <div className="font-medium">{file.description}</div>
                                      <div className="text-muted-foreground">Offset: 0x{file.offset.toString(16).toUpperCase()}</div>
                                    </div>
                                  </div>
                                </div>
                              ))}
                              {backendResults.steganography.tools.binwalk.extractedFiles?.length > 0 && (
                                <div className="text-xs text-muted-foreground mt-2">
                                  Extracted {backendResults.steganography.tools.binwalk.extractedFiles.length} file(s) to temp directory
                                </div>
                              )}
                            </div>
                          ) : (
                            <div className="text-xs text-green-500">✓ No embedded files detected</div>
                          )}
                        </div>
                      )}

                      {/* No tools ran or all skipped */}
                      {(!backendResults.steganography.tools || Object.keys(backendResults.steganography.tools).length === 0) && (
                        <div className="text-xs text-muted-foreground text-center py-4">
                          No steganography tools were executed
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* Carved Files */}
                {backendResults?.carvedFiles && backendResults.carvedFiles.length > 0 && (
                  <div className="bg-card border border-border rounded-lg p-4">
                    <div className="flex items-center space-x-2 mb-3">
                      <FileText className="w-5 h-5 text-accent" />
                      <h5 className="font-medium">Embedded Files Found ({backendResults.carvedFiles.length})</h5>
                    </div>
                    <div className="space-y-3">
                      {backendResults.carvedFiles.map((file: any, i: number) => {
                        const isImage = ['JPEG', 'PNG', 'GIF'].includes(file.type);
                        const dataUrl = `data:${file.mimeType};base64,${file.data}`;
                        
                        const handleDownload = () => {
                          try {
                            const byteCharacters = atob(file.data);
                            const byteNumbers = new Array(byteCharacters.length);
                            for (let i = 0; i < byteCharacters.length; i++) {
                              byteNumbers[i] = byteCharacters.charCodeAt(i);
                            }
                            const byteArray = new Uint8Array(byteNumbers);
                            const blob = new Blob([byteArray], { type: file.mimeType });
                            const url = window.URL.createObjectURL(blob);
                            const link = document.createElement('a');
                            link.href = url;
                            link.download = `carved_${i + 1}_${file.hash}${file.extension}`;
                            document.body.appendChild(link);
                            link.click();
                            document.body.removeChild(link);
                            window.URL.revokeObjectURL(url);
                          } catch (error) {
                            console.error('Download failed:', error);
                            alert('Failed to download file');
                          }
                        };
                        
                        return (
                          <div key={i} className="p-3 bg-background rounded-lg border border-border">
                            <div className="flex items-start space-x-3">
                              {isImage ? (
                                <div className="flex-shrink-0">
                                  <img 
                                    src={dataUrl} 
                                    alt={`Carved ${file.type}`}
                                    className="w-24 h-24 object-cover rounded border border-border"
                                    onError={(e) => {
                                      (e.target as HTMLImageElement).style.display = 'none';
                                    }}
                                  />
                                </div>
                              ) : (
                                <div className="flex-shrink-0 w-24 h-24 flex items-center justify-center bg-muted rounded border border-border">
                                  <FileText className="w-10 h-10 text-muted-foreground" />
                                </div>
                              )}
                              <div className="flex-1 min-w-0">
                                <div className="flex items-center justify-between mb-2">
                                  <div className="text-sm font-medium">{file.type}</div>
                                  <Button size="sm" variant="outline" onClick={handleDownload}>
                                    <Download className="w-3 h-3 mr-1" />
                                    Save
                                  </Button>
                                </div>
                                <div className="text-xs text-muted-foreground space-y-1">
                                  <div>Offset: 0x{file.offset.toString(16).toUpperCase()}</div>
                                  <div>Size: {(file.size / 1024).toFixed(2)} KB</div>
                                  <div>Hash: {file.hash}</div>
                                </div>
                              </div>
                            </div>
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}

                {!backendResults && !isBackendProcessing && (
                  <div className="text-center text-muted-foreground py-8">
                    <Activity className="w-12 h-12 mx-auto mb-3 opacity-50" />
                    <p>Forensic analysis will run automatically when you upload an image</p>
                  </div>
                )}
              </div>
            )}

            {activeTab==='strings' && (
              <div>
                <div className="flex justify-between items-center mb-3">
                  <h4 className="font-medium">Extracted Strings</h4>
                  <div className="flex items-center space-x-2">
                    <input 
                      className="px-3 py-2 border border-border rounded-lg text-sm bg-background focus:border-accent focus:outline-none" 
                      placeholder="Filter strings..." 
                      value={stringFilter} 
                      onChange={e => setStringFilter(e.target.value)}
                    />
                  </div>
                </div>
                {extractedStrings ? (
                  <div className="space-y-4">
                    {/* Enhanced string statistics */}
                    {extractedStrings.counts && (
                      <div className="bg-card border border-border rounded-lg p-4">
                        <h6 className="text-sm font-medium text-accent mb-3">String Analysis Statistics</h6>
                        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-xs">
                          <div className="text-center">
                            <div className="font-mono text-lg">{extractedStrings.counts.total}</div>
                            <div className="text-muted-foreground">Total</div>
                          </div>
                          <div className="text-center">
                            <div className="font-mono text-lg">{extractedStrings.counts.unique}</div>
                            <div className="text-muted-foreground">Unique</div>
                          </div>
                          <div className="text-center">
                            <div className="font-mono text-lg">{extractedStrings.counts.ascii}</div>
                            <div className="text-muted-foreground">ASCII</div>
                          </div>
                          <div className="text-center">
                            <div className="font-mono text-lg">{extractedStrings.counts.unicode}</div>
                            <div className="text-muted-foreground">Unicode</div>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* All Strings Display Box */}
                    <div className="bg-card border border-border rounded-lg p-4">
                      <div className="flex items-center justify-between mb-3">
                        <h6 className="text-sm font-medium text-accent flex items-center">
                          <FileText className="w-4 h-4 mr-2"/>
                          All Strings ({extractedStrings.all.length} total, {extractedStrings.counts?.unique || new Set(extractedStrings.all).size} unique)
                        </h6>
                        <ShowFullToggle
                          isShowingFull={showFullStrings}
                          onToggle={() => setShowFullStrings(!showFullStrings)}
                          totalCount={extractedStrings.all.filter(s=>!stringFilter||String(s).toLowerCase().includes(stringFilter.toLowerCase())).length}
                          displayedCount={500}
                        />
                      </div>
                      <div className="max-h-64 overflow-auto bg-background border border-border rounded-lg">
                        <div className="font-mono text-sm p-3 space-y-1">
                          {extractedStrings.all
                            .filter(s=>!stringFilter||String(s).toLowerCase().includes(stringFilter.toLowerCase()))
                            .slice(0, showFullStrings ? undefined : 500)
                            .map((s,i)=>(
                              <div key={i} className="py-1 break-all hover:bg-accent/10 px-2 rounded cursor-default border-b border-border/20 last:border-b-0">
                                {s}
                              </div>
                            ))
                          }
                        </div>
                        {!showFullStrings && extractedStrings.all.filter(s=>!stringFilter||String(s).toLowerCase().includes(stringFilter.toLowerCase())).length > 500 && (
                          <div className="p-3 text-center text-muted-foreground text-xs border-t">
                            Showing first 500 strings. Use "Show Full" to see all {extractedStrings.all.filter(s=>!stringFilter||String(s).toLowerCase().includes(stringFilter.toLowerCase())).length} strings.
                          </div>
                        )}
                      </div>
                    </div>

                    <div className="bg-card border border-border rounded-lg p-4">
                      <h6 className="text-sm font-medium text-accent mb-3 flex items-center"><Search className="w-4 h-4 mr-2"/>Interesting Strings ({extractedStrings.interesting.length})</h6>
                      <div className="max-h-40 overflow-auto space-y-2">
                        {extractedStrings.interesting.filter(s=>!stringFilter||String(s).toLowerCase().includes(stringFilter.toLowerCase())).slice(0,100).map((s,i)=>(<div key={i} className="p-3 bg-background border border-border/50 rounded font-mono text-sm break-all hover:border-accent/50 transition-colors">{s}</div>))}
                      </div>
                    </div>

                      {/* Enhanced pattern-based results */}
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <div className="bg-card border border-border rounded-lg p-4">
                          <h6 className="text-sm font-medium text-accent mb-3">URLs ({extractedStrings.urls.length})</h6>
                          <div className="max-h-32 overflow-auto space-y-1 font-mono text-sm">
                            {extractedStrings.urls.filter(s=>!stringFilter||String(s).toLowerCase().includes(stringFilter.toLowerCase())).map((s,i)=>(<div key={i} className="break-all p-2 bg-background rounded hover:bg-accent/10">{s}</div>))}
                          </div>
                        </div>

                        <div className="bg-card border border-border rounded-lg p-4">
                          <h6 className="text-sm font-medium text-accent mb-3">Email Addresses ({extractedStrings.emails?.length || 0})</h6>
                          <div className="max-h-32 overflow-auto font-mono text-sm space-y-1">
                            {extractedStrings.emails?.filter(s=>!stringFilter||String(s).toLowerCase().includes(stringFilter.toLowerCase())).map((s,i)=>(<div key={i} className="break-all p-2 bg-background rounded hover:bg-accent/10">{s}</div>))}
                          </div>
                        </div>

                        <div className="bg-card border border-border rounded-lg p-4">
                          <h6 className="text-sm font-medium text-accent mb-3">IP Addresses ({extractedStrings.ips?.length || 0})</h6>
                          <div className="max-h-32 overflow-auto font-mono text-sm space-y-1">
                            {extractedStrings.ips?.filter(s=>!stringFilter||String(s).toLowerCase().includes(stringFilter.toLowerCase())).map((s,i)=>(<div key={i} className="break-all p-2 bg-background rounded hover:bg-accent/10">{s}</div>))}
                          </div>
                        </div>

                        <div className="bg-card border border-border rounded-lg p-4">
                          <h6 className="text-sm font-medium text-accent mb-3">Base64 Candidates ({extractedStrings.base64.length})</h6>
                          <div className="max-h-32 overflow-auto font-mono text-sm space-y-1">
                            {extractedStrings.base64.filter(s=>!stringFilter||String(s).toLowerCase().includes(stringFilter.toLowerCase())).map((s,i)=>(<div key={i} className="break-all p-2 bg-background rounded hover:bg-accent/10">{s.length > 50 ? s.substring(0, 50) + '...' : s}</div>))}
                          </div>
                        </div>
                      </div>

                      {/* Additional pattern categories if available */}
                      {extractedStrings.patterns && Object.keys(extractedStrings.patterns).length > 4 && (
                        <div className="bg-card border border-border rounded-lg p-4">
                          <h6 className="text-sm font-medium text-accent mb-3">Additional Patterns</h6>
                          <div className="grid grid-cols-2 md:grid-cols-3 gap-4 text-xs">
                            {Object.entries(extractedStrings.patterns)
                              .filter(([key]) => !['urls', 'emails', 'ipAddresses', 'base64'].includes(key))
                              .map(([pattern, values]) => (
                                <div key={pattern} className="bg-background rounded p-2 border border-border/50">
                                  <div className="font-medium capitalize">{pattern.replace(/([A-Z])/g, ' $1')}</div>
                                  <div className="text-muted-foreground">{values.length} found</div>
                                  {values.length > 0 && (
                                    <div className="mt-1 font-mono text-xs truncate">{values[0]}</div>
                                  )}
                                </div>
                              ))}
                          </div>
                        </div>
                      )}
                  </div>
                ) : (
                  <div className="text-sm text-muted-foreground">Run analysis to extract printable strings</div>
                )}
              </div>
            )}

            {activeTab==='bitplane' && (
              <div className="space-y-4">
                {/* Header with Generate Button */}
                <div className="flex justify-between items-center mb-3">
                  <h4 className="font-medium">Bitplane Gallery & Analysis</h4>
                  <div className="flex items-center gap-3">
                    {/* Settings Changed Indicator */}
                    {Object.keys(bitplaneGallery).length > 0 && (
                      <div className="text-xs text-yellow-500 flex items-center gap-1 animate-pulse">
                        <AlertCircle className="w-3 h-3" />
                        <span>Settings changed - regenerate to see updates</span>
                      </div>
                    )}
                    
                    {/* Generate Button - More Prominent */}
                    <Button 
                      onClick={generateBitplaneGallery}
                      disabled={isGeneratingGallery || !canvasRef.current}
                      size="default"
                      className="bg-accent hover:bg-accent/90 text-background font-semibold px-6 shadow-lg"
                    >
                      {isGeneratingGallery ? (
                        <>
                          <Activity className="w-4 h-4 mr-2 animate-spin" />
                          Generating Gallery...
                        </>
                      ) : (
                        <>
                          <Eye className="w-4 h-4 mr-2" />
                          Generate Gallery
                        </>
                      )}
                    </Button>
                  </div>
                </div>

                {/* Fancy Bitplane Scanning Animation Overlay */}
                {isGeneratingGallery && (
                  <div className="fixed inset-0 bg-black/60 backdrop-blur-md z-50 flex items-center justify-center">
                    <div className="bg-background border-2 border-accent rounded-lg p-8 shadow-2xl max-w-lg w-full mx-4">
                      <div className="flex flex-col items-center gap-6">
                        {/* Title */}
                        <div className="text-center">
                          <h3 className="text-xl font-bold text-accent mb-2 flex items-center justify-center gap-2">
                            <Layers className="w-6 h-6 animate-pulse" />
                            Generating Bitplane Gallery
                          </h3>
                          <p className="text-sm text-muted-foreground">
                            {galleryProgress.status}
                          </p>
                        </div>

                        {/* 2x4 Bitplane Grid Progress Visualization */}
                        <div className="grid grid-cols-4 gap-3 w-full max-w-sm">
                          {Array.from({length: 8}, (_, i) => {
                            const isComplete = i < galleryProgress.current
                            const isCurrent = i === galleryProgress.current
                            
                            return (
                              <div
                                key={i}
                                className={`relative aspect-square rounded-lg border-2 transition-all duration-300 ${
                                  isComplete 
                                    ? 'bg-accent border-accent' 
                                    : isCurrent
                                    ? 'bg-accent/30 border-accent animate-pulse shadow-lg shadow-accent/50'
                                    : 'bg-background/50 border-border'
                                }`}
                              >
                                {/* Bitplane Label */}
                                <div className={`absolute inset-0 flex items-center justify-center font-mono text-xs font-bold ${
                                  isComplete ? 'text-background' : 'text-muted-foreground'
                                }`}>
                                  {isComplete ? (
                                    <CheckCircle className="w-6 h-6" />
                                  ) : isCurrent ? (
                                    <Activity className="w-6 h-6 animate-spin text-accent" />
                                  ) : (
                                    <span>{i === 0 ? 'LSB' : i === 7 ? 'MSB' : i}</span>
                                  )}
                                </div>
                                
                                {/* Plane Number Badge */}
                                <div className={`absolute top-0.5 left-0.5 text-[8px] font-mono px-1 rounded ${
                                  isComplete 
                                    ? 'bg-background/90 text-accent' 
                                    : 'bg-accent/20 text-muted-foreground'
                                }`}>
                                  {i}
                                </div>
                              </div>
                            )
                          })}
                        </div>

                        {/* Progress Bar */}
                        <div className="w-full">
                          <div className="flex items-center justify-between text-xs text-muted-foreground mb-2">
                            <span>Progress</span>
                            <span className="font-mono font-bold text-accent">
                              {galleryProgress.current}/{galleryProgress.total}
                            </span>
                          </div>
                          <div className="w-full h-2 bg-background/50 rounded-full overflow-hidden border border-border">
                            <div 
                              className="h-full bg-gradient-to-r from-accent to-accent/80 transition-all duration-500 ease-out"
                              style={{ width: `${(galleryProgress.current / galleryProgress.total) * 100}%` }}
                            />
                          </div>
                        </div>

                        {/* Animation Dots */}
                        <div className="flex items-center justify-center gap-1">
                          <div className="w-2 h-2 bg-accent rounded-full animate-bounce" style={{animationDelay: '0ms'}}></div>
                          <div className="w-2 h-2 bg-accent rounded-full animate-bounce" style={{animationDelay: '150ms'}}></div>
                          <div className="w-2 h-2 bg-accent rounded-full animate-bounce" style={{animationDelay: '300ms'}}></div>
                        </div>
                      </div>
                    </div>
                  </div>
                )}

                {/* Gallery View or Empty State */}
                {Object.keys(bitplaneGallery).length > 0 ? (
                  <div className="grid grid-cols-1 lg:grid-cols-4 gap-4">
                    {/* Bitplane Gallery Grid */}
                    <div className="lg:col-span-3 space-y-4">
                      {/* Color Channel & View Mode Controls */}
                      <div className="bg-background/50 p-4 rounded-lg border border-border">
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          {/* Color Channel Selection */}
                          <div>
                            <label className="text-xs text-muted-foreground mb-2 block flex items-center gap-2">
                              Color Channel
                              {colorChannelType !== 'rgb' && (
                                <span className="text-yellow-500 text-[10px] flex items-center gap-1">
                                  <AlertCircle className="w-3 h-3" />
                                  Click "Generate Gallery" to apply
                                </span>
                              )}
                            </label>
                            <div className="grid grid-cols-4 gap-1">
                              {[
                                { value: 'rgb', label: 'RGB' },
                                { value: 'red', label: 'Red' },
                                { value: 'green', label: 'Green' },
                                { value: 'blue', label: 'Blue' }
                              ].map((channel) => (
                                <button
                                  key={channel.value}
                                  onClick={() => {
                                    setColorChannelType(channel.value as any)
                                    // Don't auto-regenerate - let user click button
                                  }}
                                  disabled={isGeneratingGallery}
                                  className={`px-2 py-1.5 text-xs rounded transition-colors ${
                                    colorChannelType === channel.value
                                      ? 'bg-accent text-background'
                                      : 'bg-background border border-border hover:border-accent/50'
                                  } disabled:opacity-50 disabled:cursor-not-allowed`}
                                >
                                  {channel.label}
                                </button>
                              ))}
                            </div>
                          </div>

                          {/* View Mode Selection */}
                          <div>
                            <label className="text-xs text-muted-foreground mb-2 block flex items-center gap-2">
                              View Mode
                              {bitplaneViewMode !== 'normal' && (
                                <span className="text-yellow-500 text-[10px] flex items-center gap-1">
                                  <AlertCircle className="w-3 h-3" />
                                  Click "Generate Gallery" to apply
                                </span>
                              )}
                            </label>
                            <div className="grid grid-cols-3 gap-1">
                              {[
                                { value: 'normal', label: 'Normal', desc: 'Standard extraction' },
                                { value: 'difference', label: 'Difference', desc: 'Plane N - N+1' },
                                { value: 'xor', label: 'XOR', desc: 'Plane N ⊕ (7-N)' }
                              ].map((mode) => (
                                <button
                                  key={mode.value}
                                  onClick={() => {
                                    setBitplaneViewMode(mode.value as any)
                                    // Don't auto-regenerate - let user click button
                                  }}
                                  disabled={isGeneratingGallery}
                                  title={mode.desc}
                                  className={`px-2 py-1.5 text-xs rounded transition-colors ${
                                    bitplaneViewMode === mode.value
                                      ? 'bg-accent text-background'
                                      : 'bg-background border border-border hover:border-accent/50'
                                  } disabled:opacity-50 disabled:cursor-not-allowed`}
                                >
                                  {mode.label}
                                </button>
                              ))}
                            </div>
                          </div>
                        </div>
                      </div>

                      {/* 8-Plane Gallery Grid (2x4) */}
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                        {Array.from({length: 8}, (_, i) => {
                          const plane = bitplaneGallery[i]
                          if (!plane) return null
                          
                          const isSuspicious = bitplaneStats.suspicious.includes(i)
                          const isSelected = selectedGalleryPlane === i
                          
                          return (
                            <div
                              key={i}
                              onClick={() => setSelectedGalleryPlane(isSelected ? null : i)}
                              className={`relative group cursor-pointer rounded-lg border-2 overflow-hidden transition-all ${
                                isSelected 
                                  ? 'border-accent ring-2 ring-accent/50' 
                                  : isSuspicious
                                  ? 'border-yellow-500/50 hover:border-yellow-500'
                                  : 'border-border hover:border-accent/50'
                              }`}
                            >
                              {/* Bitplane Image */}
                              <img 
                                src={plane.url} 
                                alt={`Bitplane ${i}`}
                                className="w-full h-auto"
                              />
                              
                              {/* Overlay Info */}
                              <div className="absolute inset-0 bg-gradient-to-t from-black/80 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-opacity">
                                <div className="absolute bottom-0 left-0 right-0 p-2">
                                  <div className="text-xs font-mono text-white">
                                    <div className="font-bold">Bit {i} {i === 0 ? '(LSB)' : i === 7 ? '(MSB)' : ''}</div>
                                    <div>{plane.histogram.percentage.toFixed(1)}% ones</div>
                                    <div className="text-[10px] opacity-75">
                                      Entropy: {bitplaneStats.entropy[i]?.toFixed(2) || 'N/A'}
                                    </div>
                                  </div>
                                </div>
                              </div>
                              
                              {/* Label Badge */}
                              <div className={`absolute top-1 left-1 px-2 py-0.5 rounded text-[10px] font-mono font-bold ${
                                i === 0 ? 'bg-red-500 text-white' :
                                i === 7 ? 'bg-blue-500 text-white' :
                                'bg-black/60 text-white'
                              }`}>
                                {i === 0 ? 'LSB' : i === 7 ? 'MSB' : `B${i}`}
                              </div>
                              
                              {/* Suspicious Flag */}
                              {isSuspicious && (
                                <div className="absolute top-1 right-1 bg-yellow-500 text-black px-1.5 py-0.5 rounded text-[10px] font-bold">
                                  ⚠️
                                </div>
                              )}
                              
                              {/* Histogram Bar */}
                              <div className="absolute bottom-0 left-0 right-0 h-1 bg-gray-700">
                                <div 
                                  className={`h-full ${
                                    plane.histogram.percentage < 45 || plane.histogram.percentage > 55
                                      ? 'bg-yellow-500'
                                      : 'bg-green-500'
                                  }`}
                                  style={{ width: `${plane.histogram.percentage}%` }}
                                />
                              </div>
                            </div>
                          )
                        })}
                      </div>

                      {/* Selected Plane Preview */}
                      {selectedGalleryPlane !== null && bitplaneGallery[selectedGalleryPlane] && (
                        <div className="bg-background/50 p-4 rounded-lg border border-border">
                          <div className="flex items-center justify-between mb-3">
                            <h5 className="text-sm font-medium">
                              Bitplane {selectedGalleryPlane} Preview 
                              {selectedGalleryPlane === 0 ? ' (LSB)' : selectedGalleryPlane === 7 ? ' (MSB)' : ''}
                            </h5>
                            <div className="flex items-center gap-2">
                              <Button 
                                size="sm" 
                                variant="outline"
                                onClick={() => downloadDataUrl(
                                  bitplaneGallery[selectedGalleryPlane].url,
                                  `${metadata?.filename||'image'}_bitplane_${selectedGalleryPlane}.png`
                                )}
                              >
                                <Download className="w-4 h-4 mr-1" />
                                Download
                              </Button>
                              <Button 
                                size="sm" 
                                variant="outline"
                                onClick={() => setSelectedGalleryPlane(null)}
                              >
                                Close
                              </Button>
                            </div>
                          </div>
                          
                          <div className="border border-border rounded overflow-hidden">
                            <img 
                              src={bitplaneGallery[selectedGalleryPlane].url}
                              alt={`Bitplane ${selectedGalleryPlane} enlarged`}
                              className="w-full h-auto"
                            />
                          </div>
                        </div>
                      )}

                      {/* LSB Extraction Tool */}
                      <div className="bg-background/50 p-4 rounded-lg border border-border">
                        <div className="flex items-center justify-between mb-3">
                          <h5 className="text-sm font-medium">LSB Data Extraction</h5>
                          <Button 
                            size="sm" 
                            variant="outline"
                            onClick={() => {
                              const bits = extractRawLSBBits()
                              const ascii = decodeLSBBits(bits, 'ascii')
                              const hex = decodeLSBBits(bits, 'hex')
                              alert(`LSB Data Preview:\n\nASCII (first 200 chars):\n${ascii.slice(0, 200)}\n\nHex (first 100 bytes):\n${hex.split(' ').slice(0, 100).join(' ')}`)
                            }}
                          >
                            Extract & Decode LSB
                          </Button>
                        </div>
                        <div className="text-xs text-muted-foreground">
                          Extract the least significant bits from all pixels and decode to ASCII/Hex/Base64 format.
                        </div>
                      </div>
                    </div>

                    {/* Statistics Sidebar */}
                    <div className="space-y-4">
                      <div className="bg-background/50 p-4 rounded-lg border border-border">
                        <h5 className="text-sm font-medium mb-3">Statistical Analysis</h5>
                        
                        <div className="space-y-4">
                          {/* Chi-Square Test */}
                          <div>
                            <div className="text-xs text-muted-foreground mb-1">Chi-Square Test (LSB)</div>
                            <div className="text-2xl font-mono font-bold">
                              {bitplaneStats.chiSquare.toFixed(3)}
                            </div>
                            <div className={`text-xs mt-1 ${
                              bitplaneStats.chiSquare > 0.05 
                                ? 'text-yellow-500' 
                                : 'text-green-500'
                            }`}>
                              {bitplaneStats.chiSquare > 0.05 
                                ? '⚠️ Suspicious (>0.05)'
                                : '✓ Normal randomness'
                              }
                            </div>
                          </div>

                          {/* Entropy Summary */}
                          <div>
                            <div className="text-xs text-muted-foreground mb-2">Entropy per Plane</div>
                            <div className="space-y-1">
                              {bitplaneStats.entropy.map((e, i) => (
                                <div key={i} className="flex items-center justify-between text-xs">
                                  <span className="font-mono">Bit {i}:</span>
                                  <span className="font-mono font-bold">{e.toFixed(3)}</span>
                                </div>
                              ))}
                            </div>
                          </div>

                          {/* Suspicious Planes */}
                          {bitplaneStats.suspicious.length > 0 && (
                            <div className="bg-yellow-500/10 border border-yellow-500/30 rounded p-3">
                              <div className="text-xs font-medium text-yellow-500 mb-1">
                                ⚠️ Suspicious Planes
                              </div>
                              <div className="text-xs text-muted-foreground">
                                Bitplanes {bitplaneStats.suspicious.join(', ')} have unusual distributions
                              </div>
                            </div>
                          )}

                          {/* Quick Actions */}
                          <div className="space-y-2">
                            <Button 
                              size="sm" 
                              variant="outline"
                              className="w-full"
                              onClick={exportAllBitPlanes}
                            >
                              Export All Planes
                            </Button>
                            <Button 
                              size="sm" 
                              variant="outline"
                              className="w-full"
                              onClick={generateBitplaneGallery}
                            >
                              Regenerate Gallery
                            </Button>
                          </div>
                        </div>
                      </div>

                      {/* Analysis Tips */}
                      <div className="bg-accent/5 border border-accent/20 rounded-lg p-3">
                        <div className="text-xs font-medium text-accent mb-2">💡 Analysis Tips</div>
                        <div className="text-[10px] text-muted-foreground space-y-1">
                          <div>• <strong>LSB (0):</strong> Most common hiding spot</div>
                          <div>• <strong>50% ones:</strong> Expected for random data</div>
                          <div>• <strong>Chi² &gt;0.05:</strong> May indicate steganography</div>
                          <div>• <strong>Entropy ~1.0:</strong> High randomness (suspicious)</div>
                          <div>• <strong>Yellow flags:</strong> Unusual bit distributions</div>
                        </div>
                      </div>
                    </div>
                  </div>
                ) : (
                  <div className="bg-background/50 p-12 rounded-lg border-2 border-accent/30 border-dashed text-center">
                    <Eye className="w-16 h-16 text-accent mx-auto mb-4 opacity-80" />
                    <h5 className="text-lg font-bold text-accent mb-2">Ready to Analyze Bitplanes</h5>
                    <p className="text-sm text-muted-foreground mb-6 max-w-md mx-auto">
                      Generate a comprehensive gallery of all 8 bitplanes with histogram analysis, 
                      Chi-Square testing, and entropy calculations
                    </p>
                    <Button 
                      onClick={generateBitplaneGallery} 
                      disabled={!canvasRef.current}
                      size="lg"
                      className="bg-accent hover:bg-accent/90 text-background font-bold px-8 shadow-lg"
                    >
                      <Eye className="w-5 h-5 mr-2" />
                      Generate Bitplane Gallery
                    </Button>
                    {!canvasRef.current && (
                      <p className="text-xs text-red-500 mt-3">
                        ⚠️ Please upload an image first
                      </p>
                    )}
                  </div>
                )}
              </div>
            )}

            {activeTab==='hex' && (
              <div className="space-y-4">
                <div className="flex items-center gap-2">
                  <Input
                    type="text"
                    placeholder="Filter hex dump (hex, ASCII, or offset)..."
                    value={hexFilter}
                    onChange={(e) => setHexFilter(e.target.value)}
                    className="flex-1"
                  />
                  <span className="text-sm text-muted-foreground whitespace-nowrap">
                    ({hexData ? hexData.filter(line => {
                      if (!hexFilter) return true
                      const searchTerm = hexFilter.toLowerCase()
                      return line.offset.toLowerCase().includes(searchTerm) ||
                             line.hex.toLowerCase().includes(searchTerm) ||
                             line.ascii.toLowerCase().includes(searchTerm)
                    }).length : 0} lines)
                  </span>
                </div>

                <div className="bg-muted/20 rounded-lg p-3">
                  <div className="flex justify-between items-center mb-2">
                    <h4 className="font-medium">
                      Binary Content ({hexData ? hexData.filter(line => {
                        if (!hexFilter) return true
                        const searchTerm = hexFilter.toLowerCase()
                        return line.offset.toLowerCase().includes(searchTerm) ||
                               line.hex.toLowerCase().includes(searchTerm) ||
                               line.ascii.toLowerCase().includes(searchTerm)
                      }).length * 16 : 0} bytes shown)
                      {hexFilter && ` (filtered)`}
                    </h4>
                    <div className="text-xs text-muted-foreground">
                      First 64KB • Offset | Hex | ASCII
                    </div>
                  </div>
                  {hexData && hexData.length > 0 ? (
                    <div className="bg-background rounded border max-h-96 overflow-y-auto font-mono text-xs">
                      <div className="sticky top-0 bg-muted px-3 py-2 border-b flex">
                        <div className="w-24 text-muted-foreground">Offset</div>
                        <div className="flex-1 text-muted-foreground ml-4">Hex</div>
                        <div className="w-32 text-muted-foreground ml-4">ASCII</div>
                      </div>
                      <div className="divide-y">
                        {hexData
                          .filter(line => {
                            if (!hexFilter) return true
                            const searchTerm = hexFilter.toLowerCase()
                            return line.offset.toLowerCase().includes(searchTerm) ||
                                   line.hex.toLowerCase().includes(searchTerm) ||
                                   line.ascii.toLowerCase().includes(searchTerm)
                          })
                          .map((line, index) => (
                            <div key={index} className="px-3 py-1 hover:bg-muted/50 flex items-center">
                              <div className="w-24 text-accent font-bold">{line.offset}</div>
                              <div className="flex-1 ml-4 tracking-wider">{line.hex}</div>
                              <div className="w-32 ml-4 text-muted-foreground bg-muted/30 px-2 rounded">
                                {line.ascii}
                              </div>
                            </div>
                          ))}
                      </div>
                    </div>
                  ) : (
                    <div className="text-center text-muted-foreground py-8">
                      <FileText className="w-12 h-12 mx-auto mb-4 opacity-50" />
                      <p>{hexFilter ? "No hex dump lines match the filter" : "No hex dump available"}</p>
                      <p className="text-sm mt-2">{hexFilter ? "Try a different search term" : "Upload and analyze an image to see hex dump"}</p>
                    </div>
                  )}
                </div>
              </div>
            )}

            {activeTab==='barcode' && (
              <div className="space-y-4">
                <div className="flex items-center justify-between mb-4">
                  <h4 className="font-medium flex items-center">
                    <QrCode className="w-4 h-4 mr-2 text-accent" />
                    Barcode & QR Code Scanner
                  </h4>
                  <div className="flex items-center space-x-2">
                    {barcodeResults.length > 0 && (
                      <Button
                        size="sm"
                        variant="outline"
                        onClick={() => {
                          const data = JSON.stringify(barcodeResults, null, 2)
                          const blob = new Blob([data], { type: 'application/json' })
                          const url = URL.createObjectURL(blob)
                          const a = document.createElement('a')
                          a.href = url
                          a.download = 'barcode_results.json'
                          a.click()
                          URL.revokeObjectURL(url)
                        }}
                      >
                        <Download className="w-3 h-3 mr-1" />
                        Export
                      </Button>
                    )}
                    <Button
                      size="sm"
                      onClick={scanBarcodes}
                      disabled={isScanningBarcode}
                    >
                      {isScanningBarcode ? 'Scanning...' : 'Scan Image'}
                    </Button>
                  </div>
                </div>

                {/* Scanner Options */}
                <div className="bg-muted/20 border border-border rounded-lg p-4">
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <label className="flex items-center space-x-2 cursor-pointer">
                        <input
                          type="checkbox"
                          checked={barcodeTryHarder}
                          onChange={(e) => setBarcodeTryHarder(e.target.checked)}
                          className="rounded border-border"
                        />
                        <span className="text-sm font-medium">Try Harder Mode</span>
                      </label>
                      <span className="text-xs text-muted-foreground">
                        {barcodeTryHarder ? 'Slower, more accurate' : 'Faster scan'}
                      </span>
                    </div>

                    <div className="space-y-2">
                      <div className="text-sm font-medium">Barcode Formats</div>
                      <div className="grid grid-cols-2 md:grid-cols-3 gap-2 text-xs">
                        {['ALL', 'QR_CODE', 'DATA_MATRIX', 'EAN_13', 'EAN_8', 'UPC_A', 'UPC_E', 'CODE_128', 'CODE_39'].map(format => (
                          <label key={format} className="flex items-center space-x-1 cursor-pointer">
                            <input
                              type="checkbox"
                              checked={barcodeFormats.includes(format)}
                              onChange={(e) => {
                                if (format === 'ALL') {
                                  setBarcodeFormats(e.target.checked ? ['ALL'] : [])
                                } else {
                                  if (e.target.checked) {
                                    setBarcodeFormats(prev => [...prev.filter(f => f !== 'ALL'), format])
                                  } else {
                                    setBarcodeFormats(prev => prev.filter(f => f !== format))
                                  }
                                }
                              }}
                              className="rounded border-border"
                            />
                            <span className="text-xs">{format.replace('_', ' ')}</span>
                          </label>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>

                {isScanningBarcode && (
                  <div className="bg-accent/5 border border-accent/20 rounded-lg p-6 text-center">
                    <div className="flex items-center justify-center space-x-2">
                      <div className="animate-spin rounded-full h-6 w-6 border-b-2 border-accent"></div>
                      <span className="text-sm text-muted-foreground">Scanning for barcodes and QR codes...</span>
                    </div>
                  </div>
                )}

                {!isScanningBarcode && barcodeResults.length > 0 && (
                  <div className="space-y-4">
                    {/* Page Navigation */}
                    <div className="flex items-center space-x-2 border-b border-border pb-2">
                      <button
                        onClick={() => setBarcodeSubPage('original')}
                        className={`px-4 py-2 text-sm font-medium rounded-t transition-colors ${
                          barcodeSubPage === 'original'
                            ? 'bg-accent text-background border-b-2 border-accent'
                            : 'text-muted-foreground hover:text-foreground'
                        }`}
                      >
                        Original Scan
                      </button>
                      <button
                        onClick={() => setBarcodeSubPage('reconstructed')}
                        className={`px-4 py-2 text-sm font-medium rounded-t transition-colors ${
                          barcodeSubPage === 'reconstructed'
                            ? 'bg-accent text-background border-b-2 border-accent'
                            : 'text-muted-foreground hover:text-foreground'
                        }`}
                      >
                        Reconstructed Analysis
                      </button>
                    </div>

                    {/* Original Scan Page */}
                    {barcodeSubPage === 'original' && (
                      <div className="space-y-4">
                        {/* Visualization Image */}
                        {barcodeImage && (
                      <div className="bg-background border border-border rounded-lg p-4">
                        <div className="flex items-center justify-between mb-3">
                          <h5 className="text-sm font-medium">Detection Visualization</h5>
                          <div className="text-xs text-muted-foreground">
                            Green boxes indicate detected codes
                          </div>
                        </div>
                        <div className="relative bg-muted/10 rounded overflow-hidden">
                          <img
                            src={barcodeImage}
                            alt="Barcode detection visualization"
                            className="w-full h-auto"
                            style={{ imageRendering: 'pixelated' }}
                          />
                        </div>
                      </div>
                    )}

                    {/* Detection Results */}
                    <div className="bg-accent/5 border border-accent/20 rounded-lg p-4">
                      <div className="flex items-center justify-between mb-3">
                        <div className="flex items-center space-x-2">
                          <CheckCircle className="w-5 h-5 text-green-400" />
                          <span className="text-sm font-medium text-green-400">
                            {barcodeResults.length} Code{barcodeResults.length !== 1 ? 's' : ''} Detected
                          </span>
                        </div>
                      </div>

                      <div className="space-y-3">
                        {barcodeResults.map((result, index) => (
                          <div key={index} className="bg-background rounded-lg border border-border p-4">
                            <div className="flex items-start justify-between mb-2">
                              <div className="space-y-1">
                                <div className="flex items-center space-x-2">
                                  <QrCode className="w-4 h-4 text-accent" />
                                  <span className="text-xs font-medium text-accent">{result.format}</span>
                                </div>
                                {result.position && (
                                  <div className="text-xs text-muted-foreground">
                                    Position: ({Math.round(result.position.x)}, {Math.round(result.position.y)}) •
                                    Size: {Math.round(result.position.width)}×{Math.round(result.position.height)}px
                                  </div>
                                )}
                              </div>
                              <div className="flex items-center space-x-2">
                                {result.text.match(/^https?:\/\//i) && (
                                  <Button
                                    size="sm"
                                    variant="outline"
                                    onClick={() => window.open(result.text, '_blank')}
                                    className="h-6 px-2"
                                  >
                                    <ExternalLink className="w-3 h-3 mr-1" />
                                    Open
                                  </Button>
                                )}
                                <Button
                                  size="sm"
                                  variant="outline"
                                  onClick={() => {
                                    navigator.clipboard.writeText(result.text)
                                    alert('Copied to clipboard!')
                                  }}
                                  className="h-6 px-2"
                                >
                                  <Copy className="w-3 h-3 mr-1" />
                                  Copy
                                </Button>
                              </div>
                            </div>

                            <div className="bg-muted/30 rounded p-3 font-mono text-sm break-all">
                              {/* Make URLs clickable */}
                              {result.text.match(/^https?:\/\//i) ? (
                                <a
                                  href={result.text}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="text-accent hover:underline"
                                >
                                  {result.text}
                                </a>
                              ) : (
                                result.text
                              )}
                            </div>

                            {/* Auto-decoded content */}
                            {result.decoded && (
                              <div className="mt-3 p-3 bg-green-500/10 border border-green-500/20 rounded">
                                <div className="text-xs font-medium text-green-400 mb-1">
                                  🔓 Auto-decoded ({result.decoded.type.toUpperCase()})
                                </div>
                                <div className="font-mono text-sm break-all text-green-300">
                                  {result.decoded.value}
                                </div>
                              </div>
                            )}

                            {/* Binary representation */}
                            {result.binary && (
                              <div className="mt-3 p-3 bg-blue-500/10 border border-blue-500/20 rounded">
                                <div className="text-xs font-medium text-blue-400 mb-2">
                                  🔢 Binary Representation
                                </div>
                                <div className="font-mono text-xs break-all text-blue-300 max-h-32 overflow-y-auto">
                                  {result.binary}
                                </div>
                              </div>
                            )}

                            {/* QR Metadata */}
                            {result.qrMetadata && (
                              <div className="mt-3 p-3 bg-purple-500/10 border border-purple-500/20 rounded">
                                <div className="text-xs font-medium text-purple-400 mb-2">
                                  📊 QR Code Structure
                                </div>
                                <div className="space-y-1 text-xs">
                                  {result.qrMetadata.version && (
                                    <div className="flex justify-between items-center gap-2">
                                      <span className="text-muted-foreground flex-shrink-0">Version:</span>
                                      <span className="font-mono text-purple-300 break-all text-right">{result.qrMetadata.version}</span>
                                    </div>
                                  )}
                                  {result.qrMetadata.errorCorrectionLevel && (
                                    <div className="flex justify-between items-center gap-2">
                                      <span className="text-muted-foreground flex-shrink-0">Error Correction:</span>
                                      <span className="font-mono text-purple-300 break-all text-right">{result.qrMetadata.errorCorrectionLevel}</span>
                                    </div>
                                  )}
                                  {result.qrMetadata.maskPattern !== undefined && (
                                    <div className="flex justify-between items-center gap-2">
                                      <span className="text-muted-foreground flex-shrink-0">Mask Pattern:</span>
                                      <span className="font-mono text-purple-300 break-all text-right">{result.qrMetadata.maskPattern}</span>
                                    </div>
                                  )}
                                  {result.qrMetadata.encoding && (
                                    <div className="flex justify-between items-center gap-2">
                                      <span className="text-muted-foreground flex-shrink-0">Encoding Mode:</span>
                                      <span className="font-mono text-purple-300 break-all text-right">{result.qrMetadata.encoding}</span>
                                    </div>
                                  )}
                                </div>
                              </div>
                            )}

                            <div className="mt-2 flex items-center justify-between text-xs text-muted-foreground">
                              <span>{result.text.length} characters</span>
                              {result.text.length > 0 && (
                                <span>
                                  {result.text.match(/^https?:\/\//i) ? '🔗 URL' :
                                   result.text.match(/^[0-9]+$/) ? '🔢 Numeric' :
                                   result.text.match(/^[A-Z0-9]+$/) ? '🔤 Alphanumeric' : '📝 Text'}
                                </span>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                      </div>
                    )}

                    {/* Reconstructed Analysis Page */}
                    {barcodeSubPage === 'reconstructed' && (
                      <div className="space-y-4">
                        {barcodeResults.map((result, index) => (
                          <div key={`reconstructed-${index}`} className="bg-background border border-border rounded-lg p-4">
                            <div className="flex items-center justify-between mb-4">
                              <h5 className="text-sm font-medium text-accent">
                                Result #{index + 1} - {result.format}
                              </h5>
                            </div>

                            {/* Editable Byte String */}
                            <div className="space-y-3">
                              <div>
                                <label className="text-xs font-medium text-muted-foreground mb-2 block">
                                  Edit Byte String
                                </label>
                                <textarea
                                  value={editableBytes[index] !== undefined ? editableBytes[index] : result.text}
                                  onChange={(e) => {
                                    setEditableBytes(prev => ({
                                      ...prev,
                                      [index]: e.target.value
                                    }))
                                  }}
                                  className="w-full p-3 bg-muted/20 border border-border rounded font-mono text-sm min-h-[100px]"
                                  placeholder="Enter custom byte string..."
                                />
                                <div className="flex items-center justify-between mt-2">
                                  <span className="text-xs text-muted-foreground">
                                    {(editableBytes[index] || result.text).length} characters
                                  </span>
                                  <div className="flex items-center gap-2">
                                    <Button
                                      size="sm"
                                      variant="outline"
                                      onClick={() => {
                                        setEditableBytes(prev => ({
                                          ...prev,
                                          [index]: result.text
                                        }))
                                      }}
                                    >
                                      Reset
                                    </Button>
                                    <Button
                                      size="sm"
                                      onClick={() => {
                                        const customBytes = editableBytes[index] || result.text
                                        regenerateQRFromBytes(index, customBytes)
                                      }}
                                    >
                                      Regenerate QR
                                    </Button>
                                  </div>
                                </div>
                              </div>

                              {/* Reconstructed Image Display */}
                              {result.reconstructedImage && (
                                <div className="space-y-3">
                                  <div className="flex items-center justify-between">
                                    <div className="text-sm font-medium">Reconstructed QR Code</div>
                                    <Button
                                      size="sm"
                                      variant="outline"
                                      onClick={() => scanReconstructedQR(result.reconstructedImage!, index)}
                                    >
                                      <QrCode className="w-3 h-3 mr-1" />
                                      Scan
                                    </Button>
                                  </div>

                                  <div className="grid grid-cols-2 gap-4">
                                    <div>
                                      <div className="text-xs text-muted-foreground mb-1">Original</div>
                                      <img
                                        src={imageUrl || ''}
                                        alt="Original"
                                        className="w-full border border-border rounded"
                                        style={{ imageRendering: 'pixelated' }}
                                      />
                                    </div>
                                    <div>
                                      <div className="text-xs text-muted-foreground mb-1">Reconstructed</div>
                                      <img
                                        src={result.reconstructedImage}
                                        alt="Reconstructed"
                                        className="w-full border border-border rounded"
                                        style={{ imageRendering: 'pixelated' }}
                                      />
                                    </div>
                                  </div>

                                  {/* Scan Results */}
                                  {reconstructedScanResults[index] && (
                                    <div className="p-3 bg-green-500/10 border border-green-500/20 rounded">
                                      <div className="text-xs font-medium text-green-400 mb-2">
                                        ✅ Scan Result
                                      </div>
                                      <div className="space-y-2 text-xs">
                                        <div className="flex justify-between items-center gap-2">
                                          <span className="text-muted-foreground flex-shrink-0">Format:</span>
                                          <span className="font-mono text-green-300">{reconstructedScanResults[index]?.format}</span>
                                        </div>
                                        <div className="flex flex-col gap-1">
                                          <span className="text-muted-foreground">Decoded:</span>
                                          <div className="font-mono text-green-300 bg-muted/20 p-2 rounded break-all max-h-32 overflow-y-auto">
                                            {reconstructedScanResults[index]?.text}
                                          </div>
                                        </div>
                                        <div className="pt-2 border-t border-green-500/20">
                                          <div className="flex items-center gap-2 text-green-400">
                                            <CheckCircle className="w-4 h-4" />
                                            <span>
                                              {reconstructedScanResults[index]?.text === result.text
                                                ? 'Perfect Match!'
                                                : reconstructedScanResults[index]?.text === (editableBytes[index] || result.text)
                                                ? 'Matches Edited Version!'
                                                : 'Difference Detected'}
                                            </span>
                                          </div>
                                        </div>
                                      </div>
                                    </div>
                                  )}

                                  {reconstructedScanResults[index] === null && (
                                    <div className="p-3 bg-red-500/10 border border-red-500/20 rounded text-center text-xs text-red-400">
                                      ⚠️ Could not scan reconstructed QR
                                    </div>
                                  )}
                                </div>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    )}

                  </div>
                )}

                {!isScanningBarcode && barcodeResults.length === 0 && metadata && (
                  <div className="bg-muted/10 border border-border rounded-lg p-8 text-center">
                    <QrCode className="w-16 h-16 mx-auto mb-4 opacity-30" />
                    <h5 className="text-lg font-medium mb-2">No Codes Detected</h5>
                    <p className="text-sm text-muted-foreground mb-4">
                      No barcodes or QR codes were found in this image.
                    </p>
                    <div className="text-xs text-muted-foreground space-y-1 text-left max-w-md mx-auto">
                      <div className="font-medium mb-2">Supported Formats:</div>
                      <div className="grid grid-cols-2 gap-2">
                        <div>• QR Code</div>
                        <div>• Data Matrix</div>
                        <div>• EAN-13 / EAN-8</div>
                        <div>• UPC-A / UPC-E</div>
                        <div>• Code 128</div>
                        <div>• Code 39</div>
                        <div>• Code 93</div>
                        <div>• ITF</div>
                        <div>• Codabar</div>
                        <div>• PDF417</div>
                        <div>• Aztec</div>
                        <div>• RSS-14</div>
                      </div>
                    </div>
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={scanBarcodes}
                      className="mt-4"
                    >
                      Scan Again
                    </Button>
                  </div>
                )}

                {!isScanningBarcode && !metadata && (
                  <div className="text-center text-muted-foreground py-8">
                    <QrCode className="w-12 h-12 mx-auto mb-4 opacity-50" />
                    <p>Upload and analyze an image to scan for barcodes</p>
                    <p className="text-sm mt-2">Supports QR codes, EAN, UPC, Code 128, and more</p>
                  </div>
                )}
              </div>
            )}

          </div>
        </div>
        </div>
      )}
    </div>
  )
}
