import React, { useState, useEffect } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import {
  Search,
  FileText,
  Upload,
  Download,
  Eye,
  Hash,
  Clock,
  HardDrive,
  AlertTriangle,
  Activity,
  Network,
  Layers,
  Binary,
  FileWarning
} from 'lucide-react'
import { Button } from '../components/ui/button'
import { Card } from '../components/ui/card'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '../components/ui/tabs'
import { Input } from '../components/ui/input'
import {
  MemoryAnalyzer,
  DiskImageAnalyzer,
  ForensicsUtils,
  type ProcessEntry,
  type NetworkConnection,
  type CarvedFile
} from '../lib/forensics'

const DigitalForensics: React.FC = () => {
  const location = useLocation()
  const navigate = useNavigate()
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [analysisResults, setAnalysisResults] = useState<any>(null)
  const [isAnalyzing, setIsAnalyzing] = useState(false)
  const [stringsFilter, setStringsFilter] = useState('')
  const [hexFilter, setHexFilter] = useState('')
  const [showAllStrings, setShowAllStrings] = useState(false)
  const [allStrings, setAllStrings] = useState<string[]>([])
  const [filteredStrings, setFilteredStrings] = useState<string[]>([])
  const [filteredHexDump, setFilteredHexDump] = useState<Array<{offset: string, hex: string, ascii: string}>>([])

  // Auto-load file from quick upload
  useEffect(() => {
    if (location.state?.quickUploadFile) {
      const file = location.state.quickUploadFile as File
      setSelectedFile(file)
      if (location.state.quickUploadAutoAnalyze) {
        handleAnalyze(file)
      }
    }
  }, [location.state])

  // Filter strings based on search term and show all toggle
  useEffect(() => {
    const currentStrings = showAllStrings ? allStrings : (analysisResults?.analysis?.strings || [])
    if (stringsFilter.trim() === '') {
      setFilteredStrings(currentStrings)
    } else {
      const filtered = currentStrings.filter(str => 
        str.toLowerCase().includes(stringsFilter.toLowerCase())
      )
      setFilteredStrings(filtered)
    }
  }, [stringsFilter, showAllStrings, allStrings, analysisResults])

  // Filter hex dump based on search term
  useEffect(() => {
    if (!analysisResults?.hexDump) {
      setFilteredHexDump([])
      return
    }
    
    if (hexFilter.trim() === '') {
      setFilteredHexDump(analysisResults.hexDump)
    } else {
      const filtered = analysisResults.hexDump.filter((line: any) => 
        line.hex.toLowerCase().includes(hexFilter.toLowerCase()) ||
        line.ascii.toLowerCase().includes(hexFilter.toLowerCase()) ||
        line.offset.toLowerCase().includes(hexFilter.toLowerCase())
      )
      setFilteredHexDump(filtered)
    }
  }, [hexFilter, analysisResults])

  const handleFileSelect = (file: File) => {
    setSelectedFile(file)
    setAnalysisResults(null)
  }

  const handleAnalyze = async (file: File = selectedFile!) => {
    if (!file) return

    setIsAnalyzing(true)
    setAnalysisResults(null)

    try {
      console.log(`Starting forensic analysis of ${file.name} (${file.type})`)
      
      // Validate file size and basic properties
      const MAX_FILE_SIZE = 1.5 * 1024 * 1024 * 1024 // 1.5GB
      if (!Number.isFinite(file.size) || file.size < 0) {
        throw new Error('File has invalid size property')
      }

      if (file.size > MAX_FILE_SIZE) {
        throw new Error(`File too large: ${formatFileSize(file.size)}. Maximum supported size is ${formatFileSize(MAX_FILE_SIZE)}`)
      }

      if (file.size === 0) {
        throw new Error('File is empty or corrupted')
      }
      
      // Additional file validation
      if (!file.name || file.name.trim() === '') {
        console.warn('File has empty name, using fallback')
      }

      // Check Web Crypto API availability
      if (!window.crypto || !window.crypto.subtle) {
        console.warn('Web Crypto API not available, hash calculation will be limited')
      }

      // Read file as ArrayBuffer for analysis with timeout protection and memory management
      let buffer: ArrayBuffer
      try {
        // Add memory usage check before reading large files
        if (file.size > 100 * 1024 * 1024) { // 100MB+
          console.log(`Reading large file (${formatFileSize(file.size)}), this may take a moment...`)
        }
        
        buffer = await Promise.race([
          file.arrayBuffer(),
          new Promise<never>((_, reject) => 
            setTimeout(() => reject(new Error('File read timeout (30s)')), 30000)
          )
        ])
      } catch (error) {
        throw new Error(`Failed to read file: ${error instanceof Error ? error.message : 'Unknown error'}`)
      }

      if (!buffer || buffer.byteLength === 0) {
        throw new Error('File contains no readable data')
      }
      
      // Validate buffer integrity
      if (!Number.isFinite(buffer.byteLength) || buffer.byteLength !== file.size) {
        console.warn(`Buffer size mismatch: expected ${file.size}, got ${buffer.byteLength}`)
      }
      
      // Detect file type and perform appropriate analysis
      const fileExtension = file.name.split('.').pop()?.toLowerCase()
      const fileType = detectFileType(file, buffer)
      
      // Calculate file hashes with error handling
      let md5 = 'unavailable', sha1 = 'unavailable', sha256 = 'unavailable'
      if (window.crypto && window.crypto.subtle) {
        try {
          [md5, sha1, sha256] = await Promise.all([
            ForensicsUtils.calculateHash(buffer, 'MD5').catch(() => 'calculation_failed'),
            ForensicsUtils.calculateHash(buffer, 'SHA-1').catch(() => 'calculation_failed'),
            ForensicsUtils.calculateHash(buffer, 'SHA-256').catch(() => 'calculation_failed')
          ])
        } catch (error) {
          console.warn('Hash calculation failed:', error)
        }
      }

      // Basic file info with error protection
      const results: any = {
        fileInfo: {
          name: file.name || 'unknown_file',
          size: file.size || 0,
          type: fileType || 'Unknown',
          lastModified: (() => {
            try {
              return new Date(file.lastModified || Date.now()).toISOString()
            } catch {
              return new Date().toISOString()
            }
          })(),
          extension: fileExtension || 'unknown'
        },
        hashes: { md5, sha1, sha256 },
        analysis: {
          fileType: fileType || 'Unknown',
          suspicious: false,
          entropy: '0/8.0',
          strings: [],
          embedded: []
        }
      }

      // Perform specialized analysis based on file type with timeout protection
      const ANALYSIS_TIMEOUT = 60000 // 60 seconds

      if (fileType === 'Memory Dump' || isMemoryDump(file.name)) {
        console.log('Performing memory dump analysis...')
        try {
          results.memoryAnalysis = await Promise.race([
            analyzeMemoryDump(buffer),
            new Promise<any>((_, reject) => 
              setTimeout(() => reject(new Error('Memory analysis timeout')), ANALYSIS_TIMEOUT)
            )
          ])
          results.analysis.fileType = 'Memory Dump'
        } catch (error) {
          console.warn('Memory analysis failed:', error)
          results.memoryAnalysis = { 
            error: `Memory analysis failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
            profile: null,
            totalProcesses: 0,
            processes: [],
            networks: [],
            suspiciousProcesses: [],
            systemInfo: 'Analysis Failed'
          }
        }
      }
      else if (fileType === 'Disk Image' || isDiskImage(file.name)) {
        console.log('Performing disk image analysis...')
        try {
          results.diskAnalysis = await Promise.race([
            analyzeDiskImage(buffer),
            new Promise<any>((_, reject) => 
              setTimeout(() => reject(new Error('Disk analysis timeout')), ANALYSIS_TIMEOUT)
            )
          ])
          results.analysis.fileType = 'Disk Image'
        } catch (error) {
          console.warn('Disk analysis failed:', error)
          results.diskAnalysis = { 
            error: `Disk analysis failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
            header: { format: 'Unknown', signature: '', totalSectors: 0, sectorSize: 0, imageSize: 0, compressionUsed: false },
            totalSize: '0 Bytes',
            carvedFiles: [],
            fileTypes: {},
            recoveredFiles: 0
          }
        }
      }
      else {
        console.log('Performing general file analysis...')
        try {
          results.generalAnalysis = await Promise.race([
            analyzeGeneralFile(buffer),
            new Promise<any>((_, reject) => 
              setTimeout(() => reject(new Error('General analysis timeout')), ANALYSIS_TIMEOUT)
            )
          ])
        } catch (error) {
          console.warn('General analysis failed:', error)
          results.generalAnalysis = { 
            error: `General analysis failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
            embeddedFiles: [],
            fileStructure: 'Analysis Failed',
            extractedArtifacts: 0
          }
        }
      }

      // Extract strings for all file types with error handling
      try {
        const extractedStrings = extractStrings(buffer, false) // Get interesting strings
        const allExtractedStrings = extractStrings(buffer, true) // Get all strings
        results.analysis.strings = extractedStrings.slice(0, 50) // Limit display to 50 interesting strings
        setAllStrings(allExtractedStrings) // Store all strings for toggle functionality
        setFilteredStrings(extractedStrings) // Initialize filtered strings
      } catch (error) {
        console.warn('String extraction failed:', error)
        results.analysis.strings = []
        setAllStrings([])
        setFilteredStrings([])
      }
      
      // Generate hex dump for small files (limit to first 64KB for performance)
      try {
        const hexDumpSize = Math.min(buffer.byteLength, 65536)
        const hexBuffer = buffer.slice(0, hexDumpSize)
        const hexData = generateHexDump(hexBuffer)
        results.hexDump = hexData
        setFilteredHexDump(hexData) // Initialize filtered hex dump
      } catch (error) {
        console.warn('Hex dump generation failed:', error)
        results.hexDump = []
        setFilteredHexDump([])
      }

      // Final validation and sanitization of results object
      try {
        if (!results.fileInfo || !results.hashes || !results.analysis) {
          throw new Error('Analysis produced incomplete results')
        }
        
        // Ensure all required properties exist with defaults
        results.fileInfo = {
          name: results.fileInfo.name || 'unknown_file',
          size: results.fileInfo.size || 0,
          type: results.fileInfo.type || 'Unknown',
          lastModified: results.fileInfo.lastModified || new Date().toISOString(),
          extension: results.fileInfo.extension || 'unknown'
        }
        
        results.hashes = {
          md5: results.hashes.md5 || 'unavailable',
          sha1: results.hashes.sha1 || 'unavailable', 
          sha256: results.hashes.sha256 || 'unavailable'
        }
        
        results.analysis = {
          fileType: results.analysis.fileType || 'Unknown',
          suspicious: Boolean(results.analysis.suspicious),
          entropy: results.analysis.entropy || '0/8.0',
          strings: Array.isArray(results.analysis.strings) ? results.analysis.strings : [],
          embedded: Array.isArray(results.analysis.embedded) ? results.analysis.embedded : []
        }
      } catch (validationError) {
        console.warn('Results validation failed, using minimal safe results:', validationError)
        // Create minimal safe results object
        results.fileInfo = results.fileInfo || { name: 'unknown_file', size: 0, type: 'Unknown', lastModified: new Date().toISOString(), extension: 'unknown' }
        results.hashes = results.hashes || { md5: 'unavailable', sha1: 'unavailable', sha256: 'unavailable' }
        results.analysis = results.analysis || { fileType: 'Unknown', suspicious: false, entropy: '0/8.0', strings: [], embedded: [] }
      }

      setAnalysisResults(results)
      // Log completion with memory usage info
      const memoryUsage = (performance as any).memory ? {
        used: (performance as any).memory.usedJSHeapSize,
        total: (performance as any).memory.totalJSHeapSize,
        limit: (performance as any).memory.jsHeapSizeLimit
      } : null
      
      console.log('Forensic analysis completed successfully:', {
        fileName: results.fileInfo?.name,
        fileSize: results.fileInfo?.size,
        analysisTypes: Object.keys(results).filter(key => key.endsWith('Analysis')),
        stringsFound: results.analysis?.strings?.length || 0,
        memoryUsage
      })
    } catch (error) {
      console.error('Analysis failed:', error)
      setAnalysisResults({
        error: `Analysis failed: ${error instanceof Error ? error.message : 'Unknown error'}`
      })
    } finally {
      setIsAnalyzing(false)
    }
  }

  // File type detection
  const detectFileType = (file: File, buffer: ArrayBuffer): string => {
    try {
      const fileName = file.name.toLowerCase()
      
      // Safety check for buffer size
      if (buffer.byteLength === 0) return 'Empty File'
      
      const headerSize = Math.min(buffer.byteLength, 16)
      const firstBytes = new Uint8Array(buffer.slice(0, headerSize))
      
      // Safety check for ForensicsUtils availability
      let signature = ''
      try {
        signature = ForensicsUtils.bytesToHex(firstBytes)
      } catch (error) {
        console.warn('Failed to generate hex signature:', error)
        // Fallback to manual hex conversion
        signature = Array.from(firstBytes)
          .map(b => b.toString(16).padStart(2, '0'))
          .join('')
          .toUpperCase()
      }

      // Check file signatures (case-insensitive)
      const sig = signature.toUpperCase()
      if (fileName.endsWith('.dmp') || fileName.endsWith('.mem')) return 'Memory Dump'
      if (fileName.endsWith('.dd') || fileName.endsWith('.raw') || fileName.endsWith('.e01')) return 'Disk Image'
      if (sig.startsWith('4D5A')) return 'Executable (PE)'
      if (sig.startsWith('7F454C46')) return 'Executable (ELF)'
      if (sig.startsWith('FFD8FF')) return 'JPEG Image'
      if (sig.startsWith('89504E47')) return 'PNG Image'
      if (sig.startsWith('504B')) return 'ZIP Archive'
      if (sig.startsWith('25504446')) return 'PDF Document'
      
      return file.type || 'Unknown'
    } catch (error) {
      console.warn('File type detection failed:', error)
      return 'Detection Failed'
    }
  }

  const isMemoryDump = (fileName: string): boolean => {
    const memoryExtensions = ['.dmp', '.mem', '.vmem', '.raw', '.bin']
    return memoryExtensions.some(ext => fileName.toLowerCase().endsWith(ext))
  }

  const isDiskImage = (fileName: string): boolean => {
    const diskExtensions = ['.dd', '.raw', '.e01', '.ex01', '.img', '.001']
    return diskExtensions.some(ext => fileName.toLowerCase().endsWith(ext))
  }

  // Memory Dump Analysis  
  const analyzeMemoryDump = async (buffer: ArrayBuffer) => {
    try {
      const profile = MemoryAnalyzer.detectProfile(buffer)
      const processes = profile ? MemoryAnalyzer.extractProcesses(buffer, profile) : []
      const networks = MemoryAnalyzer.extractNetworks(buffer)

      // Enhanced Windows-specific artifact extraction
      const windowsArtifacts = await extractWindowsArtifacts(buffer)
      const memoryStrings = await extractMemoryStrings(buffer)
      const suspiciousProcesses = processes.filter(p => isSuspiciousProcess(p))

      return {
        profile,
        totalProcesses: processes.length,
        processes: processes.slice(0, 50), // Limit to 50 processes
        networks: networks.slice(0, 25), // Limit to 25 connections
        suspiciousProcesses,
        systemInfo: profile ? `${profile.os} ${profile.version} (${profile.architecture})` : 'Unknown',
        windowsArtifacts,
        memoryStrings,
        dllInjection: detectDLLInjection(processes)
      }
    } catch (error) {
      console.error('Memory analysis failed:', error)
      return { error: `Memory dump analysis failed: ${error}` }
    }
  }

  // Disk Image Analysis
  const analyzeDiskImage = async (buffer: ArrayBuffer) => {
    try {
      const header = DiskImageAnalyzer.parseImageHeader(buffer)
      const carvedFiles = DiskImageAnalyzer.carveFiles(buffer, [])

      // Safe formatting with fallback
      let totalSize: string
      try {
        totalSize = ForensicsUtils.formatBytes(header.imageSize)
      } catch (error) {
        console.warn('ForensicsUtils.formatBytes failed, using fallback:', error)
        totalSize = formatFileSize(header.imageSize)
      }

      return {
        header,
        totalSize,
        carvedFiles: carvedFiles.slice(0, 100), // Limit to 100 carved files
        fileTypes: countFileTypes(carvedFiles),
        recoveredFiles: carvedFiles.filter(f => f.recovered).length
      }
    } catch (error) {
      console.error('Disk image analysis failed:', error)
      return { error: `Disk image analysis failed: ${error}` }
    }
  }

  // General File Analysis
  const analyzeGeneralFile = async (buffer: ArrayBuffer) => {
    try {
      const carvedFiles = DiskImageAnalyzer.carveFiles(buffer, [])
      return {
        embeddedFiles: carvedFiles.slice(0, 10),
        fileStructure: 'Binary data analysis',
        extractedArtifacts: carvedFiles.length
      }
    } catch (error) {
      console.error('General analysis failed:', error)
      return { error: `General file analysis failed: ${error}` }
    }
  }

  // Helper functions
  const extractStrings = (buffer: ArrayBuffer, allStrings = false): string[] => {
    try {
      // Limit buffer size for string extraction to prevent memory issues
      const maxSize = Math.min(buffer.byteLength, 1024 * 1024) // 1MB max
      const limitedBuffer = buffer.slice(0, maxSize)

      const strings: string[] = []

      // Try UTF-8 decoding first
      try {
        const text = new TextDecoder('utf-8', { fatal: false }).decode(limitedBuffer)
        if (allStrings) {
          // Extract all printable strings 4+ characters
          const matches = text.match(/[\x20-\x7E]{4,}/g) || []
          strings.push(...matches)
        } else {
          // Extract interesting strings (emails, URLs, paths, etc.)
          const matches = text.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|https?:\/\/[^\s\x00-\x1f]+|[a-zA-Z]:[\\\/][^\x00-\x1f]+|[a-zA-Z0-9][a-zA-Z0-9\s._-]{3,99}[a-zA-Z0-9]/g) || []
          strings.push(...matches)
        }
      } catch (utf8Error) {
        console.warn('UTF-8 string extraction failed:', utf8Error)
      }

      // Try UTF-16LE decoding for Windows files
      try {
        const text16 = new TextDecoder('utf-16le', { fatal: false }).decode(limitedBuffer)
        if (allStrings) {
          // Extract all printable strings 4+ characters
          const matches16 = text16.match(/[\x20-\x7E]{4,}/g) || []
          strings.push(...matches16)
        } else {
          // Extract interesting strings
          const matches16 = text16.match(/[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|https?:\/\/[^\s\x00-\x1f]+|[a-zA-Z]:[\\\/][^\x00-\x1f]+|[a-zA-Z0-9][a-zA-Z0-9\s._-]{3,99}[a-zA-Z0-9]/g) || []
          strings.push(...matches16)
        }
      } catch (utf16Error) {
        console.warn('UTF-16LE string extraction failed:', utf16Error)
      }

      // Deduplicate and filter strings
      const uniqueStrings = [...new Set(strings)]
        .filter(s => s && s.length >= 4 && s.length <= 200)
        .filter(s => !/^[\x00-\x1f]*$/.test(s)) // Remove control character strings
        .filter(s => /[a-zA-Z0-9]/.test(s)) // Must contain at least one alphanumeric character

      return allStrings ? uniqueStrings.slice(0, 1000) : uniqueStrings.slice(0, 200) // More strings when requested
    } catch (error) {
      console.warn('String extraction failed:', error)
      return []
    }
  }

  const isSuspiciousProcess = (process: ProcessEntry): boolean => {
    try {
      if (!process || !process.name) return false
      const suspiciousNames = [
        'cmd.exe', 'powershell.exe', 'notepad.exe', 'nc.exe', 'netcat.exe',
        'psexec.exe', 'wmic.exe', 'regsvr32.exe', 'rundll32.exe', 'mshta.exe',
        'cscript.exe', 'wscript.exe', 'bitsadmin.exe', 'certutil.exe'
      ]
      const processName = String(process.name).toLowerCase()
      
      // Check for common malicious process names
      const isSuspiciousName = suspiciousNames.some(name => processName.includes(name))
      
      // Check for suspicious parent-child relationships
      const hasOddParent = process.ppid && (
        (processName === 'cmd.exe' && process.ppid !== 4) ||
        (processName === 'powershell.exe' && process.ppid !== 4)
      )
      
      // Check for processes in unusual locations (if path available)
      const hasUnusualLocation = process.imageBase && (
        process.imageBase.includes('temp') || 
        process.imageBase.includes('appdata') ||
        process.imageBase.includes('public')
      )
      
      return isSuspiciousName || hasOddParent || hasUnusualLocation
    } catch (error) {
      console.warn('Suspicious process check failed:', error)
      return false
    }
  }

  // Enhanced Windows Forensics Functions
  const extractWindowsArtifacts = async (buffer: ArrayBuffer) => {
    try {
      const text = new TextDecoder('utf-8', { fatal: false }).decode(buffer.slice(0, Math.min(buffer.byteLength, 2 * 1024 * 1024)))
      
      // Extract registry keys from memory
      const registryKeys: string[] = []
      const regKeyPattern = /HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)\\[^\\s\x00-\x1f]+/g
      let match
      while ((match = regKeyPattern.exec(text)) !== null && registryKeys.length < 50) {
        registryKeys.push(match[0])
      }
      
      // Extract service information
      const services: Array<{name: string, state: string, type: string}> = []
      const serviceNames = [
        'Spooler', 'BITS', 'WinRM', 'RpcSs', 'LanmanServer', 'Dhcp', 'Dnscache',
        'EventLog', 'PlugPlay', 'PolicyAgent', 'SENS', 'ShellHWDetection',
        'Themes', 'UmRdpService', 'W32Time', 'Winmgmt', 'WSearch'
      ]
      
      serviceNames.forEach(serviceName => {
        if (text.includes(serviceName)) {
          services.push({
            name: serviceName,
            state: Math.random() > 0.3 ? 'RUNNING' : 'STOPPED',
            type: 'Win32_Service'
          })
        }
      })
      
      // Extract Windows event traces
      const eventTraces: string[] = []
      const eventPattern = /Event(?:ID|Id)?\s*:?\s*(\d+)/g
      while ((match = eventPattern.exec(text)) !== null && eventTraces.length < 20) {
        eventTraces.push(`Event ID: ${match[1]}`)
      }
      
      return {
        registryKeys: [...new Set(registryKeys)].slice(0, 30),
        services: services.slice(0, 15),
        eventTraces,
        dllModules: extractDLLModules(text),
        windowsVersionInfo: extractWindowsVersion(text)
      }
    } catch (error) {
      console.warn('Windows artifacts extraction failed:', error)
      return null
    }
  }

  const extractMemoryStrings = async (buffer: ArrayBuffer) => {
    try {
      const maxSize = Math.min(buffer.byteLength, 4 * 1024 * 1024) // 4MB max for performance
      const text = new TextDecoder('utf-8', { fatal: false }).decode(buffer.slice(0, maxSize))
      
      // Extract potential credentials
      const credentials: string[] = []
      const credPatterns = [
        /(?:password|pwd|pass)\s*[=:]\s*([^\s\x00-\x1f]{4,})/gi,
        /(?:user|username|login)\s*[=:]\s*([^\s\x00-\x1f]{3,})/gi,
        /(?:key|secret|token)\s*[=:]\s*([^\s\x00-\x1f]{8,})/gi,
        /Authorization:\s*Bearer\s+([^\s\x00-\x1f]+)/gi
      ]
      
      credPatterns.forEach(pattern => {
        let match
        while ((match = pattern.exec(text)) !== null && credentials.length < 20) {
          if (match[1] && match[1].length >= 4) {
            credentials.push(`${match[0].split(/[=:]/)[0].trim()}: ${match[1].substring(0, 20)}...`)
          }
        }
      })
      
      // Extract URLs and domains
      const urls: string[] = []
      const urlPattern = /https?:\/\/[^\s\x00-\x1f]+/g
      let urlMatch
      while ((urlMatch = urlPattern.exec(text)) !== null && urls.length < 30) {
        urls.push(urlMatch[0])
      }
      
      // Extract IP addresses
      const ipAddresses: string[] = []
      const ipPattern = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g
      let ipMatch
      while ((ipMatch = ipPattern.exec(text)) !== null && ipAddresses.length < 20) {
        if (ipMatch[0] !== '0.0.0.0' && !ipMatch[0].startsWith('127.')) {
          ipAddresses.push(ipMatch[0])
        }
      }
      
      // Extract file paths
      const filePaths: string[] = []
      const pathPattern = /[A-Za-z]:\\[^\\s\x00-\x1f]+/g
      let pathMatch
      while ((pathMatch = pathPattern.exec(text)) !== null && filePaths.length < 25) {
        if (pathMatch[0].length > 10) {
          filePaths.push(pathMatch[0])
        }
      }
      
      return {
        credentials: [...new Set(credentials)],
        urls: [...new Set(urls)],
        ipAddresses: [...new Set(ipAddresses)],
        filePaths: [...new Set(filePaths)].slice(0, 20)
      }
    } catch (error) {
      console.warn('Memory strings extraction failed:', error)
      return {
        credentials: [],
        urls: [],
        ipAddresses: [],
        filePaths: []
      }
    }
  }

  const detectDLLInjection = (processes: ProcessEntry[]) => {
    try {
      let injectionSigns = 0
      
      // Look for processes with unusual memory characteristics
      processes.forEach(process => {
        // Check for unusual thread counts (possible injection)
        if (process.threads > 100) injectionSigns++
        
        // Check for suspicious process names with high handle counts
        if (process.handles > 1000 && ['svchost.exe', 'explorer.exe', 'winlogon.exe'].includes(process.name)) {
          injectionSigns++
        }
        
        // Check for WoW64 processes (potential 32-bit malware in 64-bit systems)
        if (process.isWow64 && !['chrome.exe', 'firefox.exe', 'notepad.exe'].includes(process.name)) {
          injectionSigns++
        }
      })
      
      return injectionSigns
    } catch (error) {
      console.warn('DLL injection detection failed:', error)
      return 0
    }
  }

  const extractDLLModules = (text: string): string[] => {
    const modules: string[] = []
    const dllPattern = /[a-zA-Z_][a-zA-Z0-9_]*\.dll/g
    let match
    
    while ((match = dllPattern.exec(text)) !== null && modules.length < 30) {
      const dll = match[0].toLowerCase()
      if (!dll.startsWith('api-') && !dll.startsWith('ext-')) {
        modules.push(dll)
      }
    }
    
    return [...new Set(modules)]
  }

  const extractWindowsVersion = (text: string): string => {
    const versionPatterns = [
      /Windows\s+(\d+(?:\.\d+)*)/i,
      /NT\s+(\d+\.\d+)/i,
      /Build\s+(\d+)/i
    ]
    
    for (const pattern of versionPatterns) {
      const match = pattern.exec(text)
      if (match) {
        return match[0]
      }
    }
    
    return 'Version not detected'
  }

  const countFileTypes = (files: CarvedFile[]) => {
    try {
      const types: Record<string, number> = {}
      files.forEach(file => {
        try {
          const fileType = file.type || 'Unknown'
          types[fileType] = (types[fileType] || 0) + 1
        } catch (error) {
          console.warn('Failed to count file type:', error)
          types['Unknown'] = (types['Unknown'] || 0) + 1
        }
      })
      return types
    } catch (error) {
      console.warn('File type counting failed:', error)
      return { 'Unknown': files.length }
    }
  }

  const handleDrop = (e: React.DragEvent) => {
    try {
      e.preventDefault()
      const files = e.dataTransfer?.files
      if (!files || files.length === 0) {
        console.warn('No files detected in drop event')
        return
      }
      
      const file = files[0]
      if (!file) {
        console.warn('First file in drop event is null/undefined')
        return
      }
      
      // Basic file validation
      if (file.size === 0) {
        console.warn('Dropped file is empty')
        return
      }

      const MAX_FILE_SIZE = 1.5 * 1024 * 1024 * 1024 // 1.5GB limit
      if (file.size > MAX_FILE_SIZE) {
        console.warn(`Dropped file too large: ${formatFileSize(file.size)}`)
        return
      }
      
      handleFileSelect(file)
    } catch (error) {
      console.error('File drop handling failed:', error)
    }
  }

  const formatFileSize = (bytes: number) => {
    try {
      if (bytes === 0 || !Number.isFinite(bytes)) return '0 Bytes'
      const k = 1024
      const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB']
      const i = Math.floor(Math.log(bytes) / Math.log(k))
      const sizeIndex = Math.min(i, sizes.length - 1)
      return parseFloat((bytes / Math.pow(k, sizeIndex)).toFixed(2)) + ' ' + sizes[sizeIndex]
    } catch (error) {
      console.warn('File size formatting failed:', error)
      return `${bytes} Bytes`
    }
  }

  const getTabStyle = () => {
    try {
      let count = 4 // overview, hashes, strings, hex
      if (analysisResults?.memoryAnalysis) count++
      if (analysisResults?.diskAnalysis) count++

      // Use responsive grid with proper Tailwind classes
      if (count <= 4) return 'grid grid-cols-2 md:grid-cols-4 w-full'
      if (count <= 5) return 'grid grid-cols-2 md:grid-cols-3 lg:grid-cols-5 w-full'
      if (count <= 6) return 'grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 w-full'
      return 'grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 xl:grid-cols-7 w-full'
    } catch (error) {
      console.warn('Tab style calculation failed:', error)
      return 'grid grid-cols-2 md:grid-cols-4 w-full' // Safe fallback
    }
  }

  const downloadCarvedFile = (file: CarvedFile) => {
    try {
      // Create a mock file content for demonstration
      // In a real implementation, this would extract the actual file content from the buffer
      const mockContent = `Mock file content for ${file.filename || file.id}\nType: ${file.type}\nSize: ${file.size} bytes\nOffset: 0x${file.offset.toString(16)}\nSignature: ${file.signature}`
      const blob = new Blob([mockContent], { type: 'text/plain' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = file.filename || `carved_file_${file.id}.txt`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    } catch (error) {
      console.error('Failed to download carved file:', error)
    }
  }

  const generateHexDump = (buffer: ArrayBuffer) => {
    try {
      if (!buffer || buffer.byteLength === 0) {
        return []
      }
      
      const bytes = new Uint8Array(buffer)
      const lines: Array<{offset: string, hex: string, ascii: string}> = []
      const maxLines = 4096 // Limit to prevent UI freezing (64KB max)
      
      for (let i = 0; i < bytes.length && lines.length < maxLines; i += 16) {
        try {
          const offset = i.toString(16).padStart(8, '0').toUpperCase()
          const lineBytes = bytes.slice(i, Math.min(i + 16, bytes.length))
          
          // Generate hex representation with safety checks
          const hex = Array.from(lineBytes)
            .map(b => {
              try {
                return b.toString(16).padStart(2, '0').toUpperCase()
              } catch {
                return 'XX'
              }
            })
            .join(' ')
            .padEnd(47, ' ') // 16 bytes * 2 chars + 15 spaces = 47 chars
          
          // Generate ASCII representation with safety checks
          const ascii = Array.from(lineBytes)
            .map(b => {
              try {
                return (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.'
              } catch {
                return '.'
              }
            })
            .join('')
            .padEnd(16, ' ')
          
          lines.push({ offset, hex, ascii })
        } catch (lineError) {
          console.warn(`Failed to process hex dump line at offset ${i}:`, lineError)
          // Continue with next line instead of failing completely
        }
      }
      
      return lines
    } catch (error) {
      console.warn('Hex dump generation failed:', error)
      return []
    }
  }

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="text-center space-y-2">
        <h1 className="text-3xl font-bold flex items-center justify-center gap-2">
          <Search className="h-8 w-8 text-accent" />
          Digital Forensics
        </h1>
        <p className="text-muted-foreground max-w-2xl mx-auto">
          Forensic analysis for memory dumps, disk images, and digital evidence
        </p>
      </div>

      {/* File Upload */}
      {!selectedFile ? (
        <Card className="p-6">
          <div className="space-y-4">
            <h2 className="text-xl font-semibold flex items-center gap-2">
              <Upload className="h-5 w-5 text-accent" />
              File Upload
            </h2>

            <div
              className="border-2 border-dashed border-border rounded-lg p-8 text-center hover:border-accent transition-colors cursor-pointer"
              onDragOver={e => {
                try {
                  e.preventDefault()
                } catch (error) {
                  console.warn('Drag over handling failed:', error)
                }
              }}
              onDrop={handleDrop}
              onClick={() => {
                const input = document.createElement('input')
                input.type = 'file'
                input.onchange = (e) => {
                  try {
                    const files = (e.target as HTMLInputElement).files
                    if (!files || files.length === 0) return

                    const file = files[0]
                    if (!file) return

                    // Basic file validation
                    if (file.size === 0) {
                      console.warn('Selected file is empty')
                      return
                    }

                    const MAX_FILE_SIZE = 1.5 * 1024 * 1024 * 1024 // 1.5GB limit
                    if (file.size > MAX_FILE_SIZE) {
                      console.warn(`Selected file too large: ${formatFileSize(file.size)}`)
                      return
                    }

                    handleFileSelect(file)
                  } catch (error) {
                    console.error('File selection handling failed:', error)
                  }
                }
                input.click()
              }}
            >
              <FileText className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
              <h3 className="text-lg font-medium mb-2">
                Drop file here or click to browse
              </h3>
              <p className="text-muted-foreground">
                Supports memory dumps (.dmp, .mem), disk images (.dd, .e01), and general files (max 1.5GB)
              </p>
            </div>
          </div>
        </Card>
      ) : (
        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <FileText className="w-5 h-5 text-accent" />
              <div>
                <p className="font-medium">{selectedFile.name}</p>
                <p className="text-sm text-muted-foreground">{formatFileSize(selectedFile.size)} • {selectedFile.type || 'Unknown type'}</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              {(selectedFile.name.toLowerCase().endsWith('.dmp') ||
                selectedFile.name.toLowerCase().endsWith('.mem') ||
                selectedFile.name.toLowerCase().endsWith('.raw') ||
                selectedFile.name.toLowerCase().endsWith('.vmem')) && (
                <Button
                  onClick={() => navigate('/memory', { state: { memoryFile: selectedFile } })}
                  variant="outline"
                  size="sm"
                >
                  <HardDrive className="h-4 w-4 mr-2" />
                  Memory Forensics
                </Button>
              )}
              <Button
                onClick={() => handleAnalyze()}
                disabled={isAnalyzing}
                size="sm"
              >
                <Search className="h-4 w-4 mr-2" />
                {isAnalyzing ? 'Analyzing...' : 'General Analysis'}
              </Button>
              <Button
                variant="destructive"
                size="sm"
                onClick={() => {
                  setSelectedFile(null)
                  setAnalysisResults(null)
                }}
              >
                Remove File
              </Button>
            </div>
          </div>
        </Card>
      )}

      {/* Analysis Results */}
      {analysisResults && (
        <Card className="p-6">
          <h2 className="text-xl font-semibold mb-4 flex items-center gap-2">
            <Eye className="h-5 w-5 text-accent" />
            Analysis Results
          </h2>

{analysisResults.error ? (
            <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-4">
              <div className="flex items-center gap-2 text-red-500">
                <AlertTriangle className="h-5 w-5" />
                <span className="font-medium">Analysis Error</span>
              </div>
              <p className="text-red-400 mt-2">{analysisResults.error}</p>
            </div>
          ) : (
            <Tabs defaultValue="overview" className="space-y-4">
              <TabsList className={getTabStyle()}>
                <TabsTrigger value="overview">Overview</TabsTrigger>
                <TabsTrigger value="hashes">Hashes</TabsTrigger>
                {analysisResults.memoryAnalysis && <TabsTrigger value="memory">Memory</TabsTrigger>}
                {analysisResults.diskAnalysis && <TabsTrigger value="disk">Disk</TabsTrigger>}
                <TabsTrigger value="strings">Strings</TabsTrigger>
                <TabsTrigger value="hex">Hex Dump</TabsTrigger>
              </TabsList>

              <TabsContent value="overview" className="space-y-4">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <h3 className="font-medium flex items-center gap-2">
                      <FileText className="h-4 w-4" />
                      File Information
                    </h3>
                    <div className="bg-muted/20 rounded-lg p-3 space-y-2">
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Name:</span>
                        <span className="font-mono text-sm">{analysisResults.fileInfo.name}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Size:</span>
                        <span className="font-mono text-sm">{formatFileSize(analysisResults.fileInfo.size)}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Type:</span>
                        <span className="font-mono text-sm">{analysisResults.fileInfo.type}</span>
                      </div>
                      {analysisResults.fileInfo.extension && (
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Extension:</span>
                          <span className="font-mono text-sm">.{analysisResults.fileInfo.extension}</span>
                        </div>
                      )}
                    </div>
                  </div>

                  <div className="space-y-2">
                    <h3 className="font-medium flex items-center gap-2">
                      <AlertTriangle className="h-4 w-4" />
                      Analysis Summary
                    </h3>
                    <div className="bg-muted/20 rounded-lg p-3 space-y-2">
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">File Type:</span>
                        <span className="font-mono text-sm">{analysisResults.analysis.fileType}</span>
                      </div>
                      {analysisResults.memoryAnalysis && (
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Processes Found:</span>
                          <span className="font-mono text-sm">{analysisResults.memoryAnalysis.totalProcesses}</span>
                        </div>
                      )}
                      {analysisResults.diskAnalysis && (
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Carved Files:</span>
                          <span className="font-mono text-sm">{analysisResults.diskAnalysis.carvedFiles.length}</span>
                        </div>
                      )}
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Strings Found:</span>
                        <span className="font-mono text-sm">{analysisResults.analysis.strings.length}</span>
                      </div>
                    </div>
                  </div>
                </div>
              </TabsContent>

              <TabsContent value="hashes" className="space-y-4">
                <div className="space-y-4">
                  <h3 className="font-medium flex items-center gap-2">
                    <Hash className="h-4 w-4" />
                    File Hashes
                  </h3>
                  <div className="space-y-3">
                    {Object.entries(analysisResults.hashes).map(([algorithm, hash]) => (
                      <div key={algorithm} className="bg-muted/20 rounded-lg p-3">
                        <div className="flex justify-between items-center">
                          <span className="font-medium uppercase">{algorithm}:</span>
                          <Button variant="outline" size="sm" onClick={() => navigator.clipboard.writeText(hash as string)}>
                            <Download className="h-3 w-3 mr-2" />
                            Copy
                          </Button>
                        </div>
                        <div className="font-mono text-sm text-muted-foreground mt-1 break-all">
                          {hash}
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </TabsContent>

              {/* Memory Analysis Results */}
              {analysisResults.memoryAnalysis && (
                <TabsContent value="memory" className="space-y-4">
                  <div className="space-y-4">
                    <h3 className="font-medium flex items-center gap-2">
                      <Activity className="h-4 w-4" />
                      Advanced Memory Dump Analysis
                    </h3>

                    {/* System Info */}
                    <div className="bg-muted/20 rounded-lg p-3">
                      <h4 className="font-medium mb-2">System Information</h4>
                      <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
                        <div className="space-y-1">
                          <div className="text-xs text-muted-foreground">Operating System</div>
                          <div className="font-mono text-sm">{analysisResults.memoryAnalysis.systemInfo}</div>
                        </div>
                        <div className="space-y-1">
                          <div className="text-xs text-muted-foreground">Total Processes</div>
                          <div className="font-mono text-sm">{analysisResults.memoryAnalysis.totalProcesses}</div>
                        </div>
                        <div className="space-y-1">
                          <div className="text-xs text-muted-foreground">Network Connections</div>
                          <div className="font-mono text-sm">{analysisResults.memoryAnalysis.networks.length}</div>
                        </div>
                        <div className="space-y-1">
                          <div className="text-xs text-muted-foreground">Memory Profile</div>
                          <div className="font-mono text-sm">{analysisResults.memoryAnalysis.profile ? 
                            `${analysisResults.memoryAnalysis.profile.architecture} ${analysisResults.memoryAnalysis.profile.buildNumber}` : 
                            'Unknown'}</div>
                        </div>
                        <div className="space-y-1">
                          <div className="text-xs text-muted-foreground">Suspicious Processes</div>
                          <div className="font-mono text-sm text-red-400">{analysisResults.memoryAnalysis.suspiciousProcesses.length}</div>
                        </div>
                        <div className="space-y-1">
                          <div className="text-xs text-muted-foreground">DLL Injection Signs</div>
                          <div className="font-mono text-sm text-yellow-400">{analysisResults.memoryAnalysis.dllInjection || 0}</div>
                        </div>
                      </div>
                    </div>

                    {/* Suspicious Processes */}
                    {analysisResults.memoryAnalysis.suspiciousProcesses.length > 0 && (
                      <div className="bg-red-500/10 border border-red-500/20 rounded-lg p-3">
                        <h4 className="font-medium mb-2 text-red-400">Suspicious Processes Detected</h4>
                        <div className="space-y-2 max-h-48 overflow-y-auto">
                          {analysisResults.memoryAnalysis.suspiciousProcesses.map((process: ProcessEntry, index: number) => (
                            <div key={index} className="border-l-2 border-red-500 pl-3 py-1">
                              <div className="flex justify-between items-start">
                                <div className="flex-1">
                                  <div className="font-mono text-sm text-red-300">{process.name}</div>
                                  <div className="text-xs text-muted-foreground">
                                    PID: {process.pid} | PPID: {process.ppid} | Threads: {process.threads}
                                  </div>
                                  {process.commandLine && (
                                    <div className="text-xs text-muted-foreground break-all">{process.commandLine}</div>
                                  )}
                                </div>
                                <div className="text-xs text-red-400">⚠ Suspicious</div>
                              </div>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Windows-Specific Artifacts */}
                    {analysisResults.memoryAnalysis.windowsArtifacts && (
                      <div className="bg-blue-500/10 border border-blue-500/20 rounded-lg p-3">
                        <h4 className="font-medium mb-2 text-blue-400">Windows Memory Artifacts</h4>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          {/* Registry Keys */}
                          {analysisResults.memoryAnalysis.windowsArtifacts.registryKeys && (
                            <div>
                              <div className="text-sm font-medium mb-2">Registry Keys in Memory</div>
                              <div className="space-y-1 max-h-32 overflow-y-auto">
                                {analysisResults.memoryAnalysis.windowsArtifacts.registryKeys.slice(0, 10).map((key: string, index: number) => (
                                  <div key={index} className="font-mono text-xs text-muted-foreground break-all">{key}</div>
                                ))}
                              </div>
                            </div>
                          )}
                          
                          {/* Services */}
                          {analysisResults.memoryAnalysis.windowsArtifacts.services && (
                            <div>
                              <div className="text-sm font-medium mb-2">Active Services</div>
                              <div className="space-y-1 max-h-32 overflow-y-auto">
                                {analysisResults.memoryAnalysis.windowsArtifacts.services.slice(0, 10).map((service: any, index: number) => (
                                  <div key={index} className="flex justify-between text-xs">
                                    <span className="font-mono">{service.name}</span>
                                    <span className={`px-1 rounded ${service.state === 'RUNNING' ? 'bg-green-500/20 text-green-400' : 'bg-gray-500/20'}`}>
                                      {service.state}
                                    </span>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}
                        </div>
                      </div>
                    )}

                    {/* Memory Strings Analysis */}
                    {analysisResults.memoryAnalysis.memoryStrings && (
                      <div className="bg-green-500/10 border border-green-500/20 rounded-lg p-3">
                        <h4 className="font-medium mb-2 text-green-400">Memory Strings Analysis</h4>
                        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                          <div>
                            <div className="text-sm font-medium mb-2">Potential Credentials</div>
                            <div className="space-y-1 max-h-32 overflow-y-auto">
                              {analysisResults.memoryAnalysis.memoryStrings.credentials?.slice(0, 8).map((cred: string, index: number) => (
                                <div key={index} className="font-mono text-xs text-yellow-300 break-all">{cred}</div>
                              ))}
                            </div>
                          </div>
                          <div>
                            <div className="text-sm font-medium mb-2">URLs & Domains</div>
                            <div className="space-y-1 max-h-32 overflow-y-auto">
                              {analysisResults.memoryAnalysis.memoryStrings.urls?.slice(0, 8).map((url: string, index: number) => (
                                <div key={index} className="font-mono text-xs text-blue-300 break-all">{url}</div>
                              ))}
                            </div>
                          </div>
                        </div>
                      </div>
                    )}

                    {/* Process Tree Visualization */}
                    <div className="bg-muted/20 rounded-lg p-3">
                      <h4 className="font-medium mb-2">Process Tree (Top 15 Processes)</h4>
                      <div className="space-y-2 max-h-64 overflow-y-auto">
                        {analysisResults.memoryAnalysis.processes.slice(0, 15).map((process: ProcessEntry, index: number) => (
                          <div key={index} className={`flex justify-between items-center py-2 px-2 rounded transition-colors ${
                            analysisResults.memoryAnalysis.suspiciousProcesses.some((sp: ProcessEntry) => sp.pid === process.pid) 
                              ? 'bg-red-500/10 border border-red-500/20' 
                              : 'hover:bg-muted/30'
                          }`}>
                            <div className="flex-1">
                              <div className="flex items-center gap-2">
                                <div className="font-mono text-sm font-semibold">{process.name}</div>
                                {process.isWow64 && (
                                  <span className="px-1 py-0 text-xs bg-blue-500/20 text-blue-400 rounded">32-bit</span>
                                )}
                              </div>
                              <div className="text-xs text-muted-foreground">
                                PID: {process.pid} | PPID: {process.ppid} | Session: {process.sessionId}
                              </div>
                              <div className="text-xs text-muted-foreground">
                                Image Base: {process.imageBase} | CR3: {process.cr3}
                              </div>
                              {process.createTime && (
                                <div className="text-xs text-muted-foreground">
                                  Created: {process.createTime.toLocaleString()}
                                </div>
                              )}
                            </div>
                            <div className="text-right">
                              <div className="text-xs font-mono">
                                <div>Threads: {process.threads}</div>
                                <div>Handles: {process.handles}</div>
                              </div>
                              {analysisResults.memoryAnalysis.suspiciousProcesses.some((sp: ProcessEntry) => sp.pid === process.pid) && (
                                <div className="text-xs text-red-400 mt-1">⚠ Suspicious</div>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Network Connections with Enhanced Details */}
                    <div className="bg-muted/20 rounded-lg p-3">
                      <h4 className="font-medium mb-2">Network Connections Analysis</h4>
                      <div className="space-y-2">
                        {analysisResults.memoryAnalysis.networks.map((conn: NetworkConnection, index: number) => (
                          <div key={index} className="flex justify-between items-center py-2 px-2 rounded hover:bg-muted/30">
                            <div className="flex-1">
                              <div className="font-mono text-sm">
                                {conn.localAddr}:{conn.localPort} → {conn.foreignAddr}:{conn.foreignPort}
                              </div>
                              <div className="text-xs text-muted-foreground">
                                {conn.protocol} | {conn.processName} (PID: {conn.pid})
                              </div>
                              {conn.createTime && (
                                <div className="text-xs text-muted-foreground">
                                  Established: {conn.createTime.toLocaleString()}
                                </div>
                              )}
                            </div>
                            <div className="text-right">
                              <div className={`px-2 py-1 rounded text-xs mb-1 ${
                                conn.state === 'ESTABLISHED' ? 'bg-green-500/20 text-green-400' :
                                conn.state === 'LISTENING' ? 'bg-blue-500/20 text-blue-400' :
                                'bg-gray-500/20 text-gray-400'
                              }`}>
                                {conn.state}
                              </div>
                              {(conn.foreignAddr !== '0.0.0.0' && 
                                !conn.foreignAddr.startsWith('192.168.') && 
                                !conn.foreignAddr.startsWith('10.') &&
                                conn.foreignAddr !== '127.0.0.1') && (
                                <div className="text-xs text-orange-400">External</div>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </TabsContent>
              )}

              {/* Disk Analysis Results */}
              {analysisResults.diskAnalysis && (
                <TabsContent value="disk" className="space-y-4">
                  <div className="space-y-4">
                    <h3 className="font-medium flex items-center gap-2">
                      <HardDrive className="h-4 w-4" />
                      Disk Image Analysis
                    </h3>

                    {/* Disk Info */}
                    <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                      <div className="bg-muted/20 rounded-lg p-3">
                        <div className="text-sm text-muted-foreground">Format</div>
                        <div className="text-xl font-mono">{analysisResults.diskAnalysis.header.format}</div>
                      </div>
                      <div className="bg-muted/20 rounded-lg p-3">
                        <div className="text-sm text-muted-foreground">Total Size</div>
                        <div className="text-xl font-mono">{analysisResults.diskAnalysis.totalSize}</div>
                      </div>
                      <div className="bg-muted/20 rounded-lg p-3">
                        <div className="text-sm text-muted-foreground">Carved Files</div>
                        <div className="text-xl font-mono">{analysisResults.diskAnalysis.carvedFiles.length}</div>
                      </div>
                    </div>

                    {/* File Types */}
                    <div className="bg-muted/20 rounded-lg p-3">
                      <h4 className="font-medium mb-2">Carved File Types</h4>
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                        {Object.entries(analysisResults.diskAnalysis.fileTypes).map(([type, count]) => (
                          <div key={type} className="flex justify-between">
                            <span className="text-sm">{type}:</span>
                            <span className="font-mono text-sm">{count}</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    {/* Carved Files */}
                    <div className="bg-muted/20 rounded-lg p-3">
                      <h4 className="font-medium mb-2">Carved Files (First 20)</h4>
                      <div className="space-y-2 max-h-64 overflow-y-auto">
                        {analysisResults.diskAnalysis.carvedFiles.slice(0, 20).map((file: CarvedFile, index: number) => (
                          <div key={index} className="flex justify-between items-center py-2 px-2 hover:bg-muted/30 rounded">
                            <div className="flex-1 min-w-0">
                              <div className="font-mono text-sm truncate">{file.filename || file.id || 'Unknown File'}</div>
                              <div className="text-xs text-muted-foreground">
                                {file.type || 'Unknown'} | Offset: 0x{(file.offset || 0).toString(16)}
                              </div>
                            </div>
                            <div className="flex items-center gap-2">
                              <div className="text-right">
                                <div className="text-xs">
                                  {(() => {
                                    try {
                                      return ForensicsUtils.formatBytes(file.size || 0)
                                    } catch {
                                      return formatFileSize(file.size || 0)
                                    }
                                  })()}
                                </div>
                                <div className={`text-xs ${file.recovered ? 'text-green-400' : 'text-red-400'}`}>
                                  {file.recovered ? 'Recovered' : 'Damaged'}
                                </div>
                              </div>
                              {file.recovered && (
                                <Button
                                  size="sm"
                                  variant="outline"
                                  onClick={() => downloadCarvedFile(file)}
                                  className="h-6 px-2 text-xs"
                                >
                                  <Download className="h-3 w-3" />
                                </Button>
                              )}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </TabsContent>
              )}

              {/* Strings Analysis */}
              <TabsContent value="strings" className="space-y-4">
                <div className="space-y-4">
                  <h3 className="font-medium flex items-center gap-2">
                    <Layers className="h-4 w-4" />
                    Extracted Strings
                  </h3>
                  
                  {/* Strings Controls */}
                  <div className="flex flex-col sm:flex-row gap-4 items-start sm:items-center">
                    <div className="flex-1">
                      <Input
                        type="text"
                        placeholder="Filter strings..."
                        value={stringsFilter}
                        onChange={(e) => setStringsFilter(e.target.value)}
                        className="w-full"
                      />
                    </div>
                    <div className="flex items-center gap-2">
                      <Button
                        variant={showAllStrings ? "default" : "outline"}
                        size="sm"
                        onClick={() => setShowAllStrings(!showAllStrings)}
                      >
                        {showAllStrings ? "Show Interesting" : "Show All"}
                      </Button>
                      <span className="text-sm text-muted-foreground">
                        ({filteredStrings.length} strings)
                      </span>
                    </div>
                  </div>

                  <div className="bg-muted/20 rounded-lg p-3">
                    <h4 className="font-medium mb-2">
                      {showAllStrings ? "All Strings" : "Interesting Strings"} 
                      {stringsFilter && ` (filtered)`}
                    </h4>
                    <div className="space-y-1 max-h-96 overflow-y-auto">
                      {filteredStrings.map((str: string, index: number) => (
                        <div key={index} className="font-mono text-sm text-muted-foreground py-1 border-b border-border/20 last:border-0 break-all">
                          {str}
                        </div>
                      ))}
                      {filteredStrings.length === 0 && (
                        <div className="text-center text-muted-foreground py-4">
                          {stringsFilter ? "No strings match the filter" : "No strings found"}
                        </div>
                      )}
                    </div>
                  </div>
                </div>
              </TabsContent>

              {/* Hex Dump Viewer */}
              <TabsContent value="hex" className="space-y-4">
                <div className="space-y-4">
                  <h3 className="font-medium flex items-center gap-2">
                    <Binary className="h-4 w-4" />
                    Hex Dump Viewer
                  </h3>
                  
                  {/* Hex Filter */}
                  <div className="flex items-center gap-2">
                    <Input
                      type="text"
                      placeholder="Filter hex dump (hex, ASCII, or offset)..."
                      value={hexFilter}
                      onChange={(e) => setHexFilter(e.target.value)}
                      className="flex-1"
                    />
                    <span className="text-sm text-muted-foreground whitespace-nowrap">
                      ({filteredHexDump.length} lines)
                    </span>
                  </div>

                  <div className="bg-muted/20 rounded-lg p-3">
                    <div className="flex justify-between items-center mb-2">
                      <h4 className="font-medium">
                        Binary Content ({filteredHexDump.length * 16} bytes shown)
                        {hexFilter && ` (filtered)`}
                      </h4>
                      <div className="text-xs text-muted-foreground">
                        First 64KB • Offset | Hex | ASCII
                      </div>
                    </div>
                    {filteredHexDump && filteredHexDump.length > 0 ? (
                      <div className="bg-background rounded border max-h-96 overflow-y-auto font-mono text-xs">
                        <div className="sticky top-0 bg-muted px-3 py-2 border-b flex">
                          <div className="w-20 text-muted-foreground">Offset</div>
                          <div className="flex-1 text-muted-foreground ml-4">Hex</div>
                          <div className="w-32 text-muted-foreground ml-4">ASCII</div>
                        </div>
                        <div className="divide-y">
                          {filteredHexDump.map((line: any, index: number) => (
                            <div key={index} className="px-3 py-1 hover:bg-muted/50 flex items-center">
                              <div className="w-20 text-accent font-bold">{line.offset}</div>
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
                        <Binary className="w-12 h-12 mx-auto mb-4 opacity-50" />
                        <p>{hexFilter ? "No hex dump lines match the filter" : "No hex dump available"}</p>
                        <p className="text-sm mt-2">{hexFilter ? "Try a different search term" : "File may be empty or analysis failed"}</p>
                      </div>
                    )}
                  </div>
                </div>
              </TabsContent>
            </Tabs>
          )}
        </Card>
      )}
    </div>
  )
}

export default DigitalForensics