import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  Network,
  Image,
  Lock,
  Globe,
  Search,
  ArrowRight,
  Activity,
  Upload,
  FileImage,
  FileText,
  ChevronDown,
  Clock,
  FolderOpen,
  Headphones,
  Shield
} from 'lucide-react'
import { Button } from '../components/ui/button'
// Removed unused changelog functionality
import { searchTools } from '../lib/toolsDatabase'

const Dashboard: React.FC = () => {
  // Changelogs state (loading + items)
  const [changelogs, setChangelogs] = useState<any[]>([])
  const [clLoading, setClLoading] = useState(false)

  const [searchQuery, setSearchQuery] = useState('')
  const [showDropdown, setShowDropdown] = useState(false)
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const navigate = useNavigate()

  // Removed unused changelog loading

  const tools = [
    { name: 'PCAP', path: '/pcap', description: 'Deep packet inspection and network traffic analysis', icon: Network },
    { name: 'Image', path: '/image', description: 'Steganography detection and metadata extraction', icon: Image },
    { name: 'Cryptography Tools', path: '/crypto', description: 'Encoding, decoding, and cryptographic operations', icon: Lock },
    { name: 'Web', path: '/web', description: 'Web application security and exploitation utilities', icon: Globe },
    { name: 'Network', path: '/network', description: 'Network analysis and security tools', icon: Network },
    { name: 'Memory Analysis', path: '/memory', description: 'Memory dump analysis and artifact extraction', icon: Search },
    { name: 'Folder', path: '/folder-scanner', description: 'Bulk scan folders and filter files by content', icon: FolderOpen },
    { name: 'Audio', path: '/audio', description: 'Detect hidden messages in audio files', icon: Headphones },
    { name: 'Threat Intel', path: '/threat-intel', description: 'Threat intelligence and security monitoring', icon: Activity }
  ]

  // Use the tools database search to find actual tools/operations
  const toolResults = searchQuery.trim() ? searchTools(searchQuery) : []

  const handleToolSelect = (tool: any) => {
    // Navigate to the tool's page and include the tool id as query so the page can open the specific tool UI
    navigate(`${tool.path}?tool=${encodeURIComponent(tool.id)}`)
    setSearchQuery('')
    setShowDropdown(false)
  }

  const handleFileUpload = (file: File) => {
    setSelectedFile(file)
    const fileType = file.type

    // Pass the uploaded File object via location state so the target page can auto-load and scan
    const state = { quickUploadFile: file, quickUploadAutoAnalyze: true }

    if (fileType.startsWith('image/')) {
      navigate('/image', { state })
    } else if (file.name.endsWith('.pcap') || file.name.endsWith('.pcapng') || file.name.endsWith('.cap')) {
      navigate('/pcap', { state })
    } else if (fileType.startsWith('audio/') || file.name.match(/\.(mp3|wav|ogg|m4a|flac|aac|wma)$/i)) {
      navigate('/audio', { state })
    } else {
      navigate('/memory', { state })
    }
  }

  const handleDrop = (e: React.DragEvent, type: string) => {
    e.preventDefault()
    const file = e.dataTransfer.files?.[0]
    if (file) {
      handleFileUpload(file)
    }
  }

  useEffect(() => {
    let mounted = true
    const fetchChangelogs = async () => {
      setClLoading(true)
      try {
        const res = await fetch('https://raw.githubusercontent.com/sectoolbox/sectoolbox/main/changelogs.json')
        if (!res.ok) throw new Error('Failed to fetch changelogs')
        const data = await res.json()
        const items = Array.isArray(data) ? data : (data.changelogs || [])
        const sorted = items
          .slice()
          .sort((a: any, b: any) => new Date(b.date).getTime() - new Date(a.date).getTime())
          .slice(0, 8)
        if (mounted) setChangelogs(sorted)
      } catch (err) {
        console.error('Changelogs fetch error', err)
      } finally {
        if (mounted) setClLoading(false)
      }
    }

    fetchChangelogs()
    const id = setInterval(fetchChangelogs, 10 * 60 * 1000)
    return () => {
      mounted = false
      clearInterval(id)
    }
  }, [])


  return (
    <div className="p-6">
      {/* Welcome Section */}
      <div className="mb-8">
        <div className="text-center space-y-2">
          <h1 className="text-4xl font-bold glow-text">Sectoolbox</h1>
          <p className="text-lg text-muted-foreground max-w-3xl mx-auto">
            Cybersecurity analysis tools for CTF competitions and security research
          </p>
        </div>
      </div>

      {/* Main Content Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Left: Quick Upload */}
        <div className="lg:col-span-1 space-y-4">
          <h2 className="text-xl font-semibold flex items-center gap-2">
            <Upload className="h-5 w-5 text-accent" />
            Quick Upload
          </h2>
          
          <div className="space-y-2">
            {/* Image Upload */}
            <div
              className="bg-card border-2 border-dashed border-border rounded-lg p-3 text-center hover:border-accent transition-colors cursor-pointer group"
              onDragOver={e => e.preventDefault()}
              onDrop={e => handleDrop(e, 'image')}
              onClick={() => {
                const input = document.createElement('input')
                input.type = 'file'
                input.accept = 'image/*'
                input.onchange = (e) => {
                  const file = (e.target as HTMLInputElement).files?.[0]
                  if (file) handleFileUpload(file)
                }
                input.click()
              }}
            >
              <FileImage className="w-6 h-6 text-muted-foreground group-hover:text-accent mx-auto mb-1" />
              <p className="text-xs font-medium">Image Analysis</p>
              <p className="text-xs text-muted-foreground">JPG, PNG, GIF</p>
            </div>

            {/* PCAP Upload */}
            <div
              className="bg-card border-2 border-dashed border-border rounded-lg p-3 text-center hover:border-accent transition-colors cursor-pointer group"
              onDragOver={e => e.preventDefault()}
              onDrop={e => handleDrop(e, 'pcap')}
              onClick={() => {
                const input = document.createElement('input')
                input.type = 'file'
                input.accept = '.pcap,.pcapng,.cap'
                input.onchange = (e) => {
                  const file = (e.target as HTMLInputElement).files?.[0]
                  if (file) handleFileUpload(file)
                }
                input.click()
              }}
            >
              <Network className="w-6 h-6 text-muted-foreground group-hover:text-accent mx-auto mb-1" />
              <p className="text-xs font-medium">PCAP Analysis</p>
              <p className="text-xs text-muted-foreground">PCAP, PCAPNG</p>
            </div>

            {/* Audio Upload */}
            <div
              className="bg-card border-2 border-dashed border-border rounded-lg p-3 text-center hover:border-accent transition-colors cursor-pointer group"
              onDragOver={e => e.preventDefault()}
              onDrop={e => handleDrop(e, 'audio')}
              onClick={() => {
                const input = document.createElement('input')
                input.type = 'file'
                input.accept = 'audio/*,.mp3,.wav,.ogg,.m4a,.flac,.aac,.wma'
                input.onchange = (e) => {
                  const file = (e.target as HTMLInputElement).files?.[0]
                  if (file) handleFileUpload(file)
                }
                input.click()
              }}
            >
              <Headphones className="w-6 h-6 text-muted-foreground group-hover:text-accent mx-auto mb-1" />
              <p className="text-xs font-medium">Audio Analysis</p>
              <p className="text-xs text-muted-foreground">MP3, WAV, OGG</p>
            </div>

            {/* Memory Analysis Upload */}
            <div
              className="bg-card border-2 border-dashed border-border rounded-lg p-3 text-center hover:border-accent transition-colors cursor-pointer group"
              onDragOver={e => e.preventDefault()}
              onDrop={e => handleDrop(e, 'memory')}
              onClick={() => {
                const input = document.createElement('input')
                input.type = 'file'
                input.accept = '*'
                input.onchange = (e) => {
                  const file = (e.target as HTMLInputElement).files?.[0]
                  if (file) handleFileUpload(file)
                }
                input.click()
              }}
            >
              <Shield className="w-6 h-6 text-muted-foreground group-hover:text-accent mx-auto mb-1" />
              <p className="text-xs font-medium">Memory Analysis</p>
              <p className="text-xs text-muted-foreground">Memory dumps</p>
            </div>

            {/* Folder Scanner Upload */}
            <div
              className="bg-card border-2 border-dashed border-border rounded-lg p-3 text-center hover:border-accent transition-colors cursor-pointer group"
              onClick={() => navigate('/folder-scanner')}
            >
              <FolderOpen className="w-6 h-6 text-muted-foreground group-hover:text-accent mx-auto mb-1" />
              <p className="text-xs font-medium">Folder Scanner</p>
              <p className="text-xs text-muted-foreground">Scan directories</p>
            </div>
          </div>
        </div>

        {/* Center: Search Bar */}
        <div className="lg:col-span-2 flex flex-col justify-center items-center space-y-6">
          <div className="w-full max-w-2xl relative">
            <div className="relative">
              <div className="absolute inset-0 bg-gradient-to-r from-accent/20 to-blue-500/20 rounded-lg blur-xl"></div>
              <div className="relative bg-card border border-border rounded-lg p-1">
                <div className="flex items-center space-x-3 px-4 py-3">
                  <Search className="w-5 h-5 text-muted-foreground" />
                  <input
                    type="text"
                    placeholder="Search for tools... e.g. 'base64 decode'"
                    value={searchQuery}
                    onChange={(e) => {
                      setSearchQuery(e.target.value)
                      setShowDropdown(e.target.value.length > 0)
                    }}
                    onFocus={() => setShowDropdown(searchQuery.length > 0)}
                    className="flex-1 bg-transparent text-foreground placeholder:text-muted-foreground focus:outline-none"
                  />
                  <ChevronDown className="w-4 h-4 text-muted-foreground" />
                </div>
              </div>
            </div>

            {/* Search Dropdown */}
            {showDropdown && (
              <div className="absolute top-full left-0 right-0 mt-2 bg-card border border-border rounded-lg shadow-lg z-50 max-h-80 overflow-auto">
                {toolResults.length > 0 ? (
                  toolResults.map((tool, index) => {
                    return (
                      <div
                        key={tool.id}
                        className="flex flex-col p-3 hover:bg-accent/10 cursor-pointer border-b border-border/50 last:border-b-0"
                        onClick={() => handleToolSelect(tool)}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center space-x-3">
                            <div className="bg-muted rounded px-2 py-1 text-xs font-mono text-muted-foreground">{tool.category}</div>
                            <p className="font-medium text-foreground">{tool.name}</p>
                          </div>
                          <div className="flex items-center space-x-2">
                            {tool.operations.slice(0,2).map((op) => (
                              <span key={op} className="text-xs px-2 py-1 bg-accent/10 text-accent rounded">{op}</span>
                            ))}
                            <ArrowRight className="w-4 h-4 text-muted-foreground" />
                          </div>
                        </div>
                        <p className="text-sm text-muted-foreground mt-1">{tool.description}</p>
                      </div>
                    )
                  })
                ) : (
                  <div className="p-4 text-center text-muted-foreground">
                    No tools found matching "{searchQuery}"
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Quick Access Buttons */}
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3 w-full max-w-2xl">
            {tools.map((tool, index) => {
              const Icon = tool.icon
              return (
                <Button
                  key={index}
                  variant="outline"
                  className="h-auto p-3 flex flex-col items-center space-y-2 hover:bg-accent/10 hover:border-accent"
                  onClick={() => navigate(tool.path)}
                >
                  <Icon className="w-5 h-5" />
                  <span className="text-xs font-medium">{tool.name.split(' ')[0]}</span>
                </Button>
              )
            })}
          </div>
        </div>

        {/* Right: Changelogs */}
        <div className="lg:col-span-1 space-y-4">
          <h2 className="text-xl font-semibold flex items-center gap-2">
            <Clock className="h-5 w-5 text-accent" />
            Changelogs
          </h2>

          <div className="bg-card border border-border rounded-lg p-3 max-h-[400px]">
            {clLoading ? (
              <div className="text-sm text-muted-foreground">Loading changelogs...</div>
            ) : changelogs.length === 0 ? (
              <div className="text-sm text-muted-foreground">No changelogs available</div>
            ) : (
              <div className="space-y-2 h-full max-h-80 overflow-auto">
                {changelogs.map((c: any, i: number) => (
                  <div key={i} className="p-2 bg-muted/20 rounded">
                    <div className="flex items-center justify-between">
                      <div className="text-xs text-muted-foreground">{new Date(c.date).toLocaleDateString()}</div>
                      <div className="text-xs font-mono text-accent">{c.version || c.tag || ''}</div>
                    </div>
                    <div className="mt-1 text-sm font-medium text-foreground">{c.title || c.summary || c.message || 'Update'}</div>
                    {c.description && (
                      <div className="mt-1 text-xs text-muted-foreground overflow-hidden">{c.description}</div>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

export default Dashboard