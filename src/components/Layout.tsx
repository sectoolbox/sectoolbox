import React, { useState, useEffect, useRef } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import {
  Zap,
  Home,
  Network,
  Image,
  Lock,
  Globe,
  Search as SearchIcon,
  Menu,
  X,
  FolderOpen,
  Headphones,
  Wifi,
  ChevronDown,
  BarChart3,
  Shield,
  Music,
  FileImage,
  HardDrive,
  XCircle,
  Code
} from 'lucide-react'
import Footer from './Footer'
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from '@/components/ui/dropdown-menu'
import { Input } from '@/components/ui/input'
import { searchTools, Tool } from '@/lib/toolsDatabase'

interface LayoutProps {
  children: React.ReactNode
}

interface NavItem {
  path: string
  label: string
  icon: React.ElementType
  description?: string
  keywords?: string[]
}

interface NavGroup {
  label: string
  items: NavItem[]
}

const Layout: React.FC<LayoutProps> = ({ children }) => {
  const location = useLocation()
  const navigate = useNavigate()
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false)
  const [currentTime, setCurrentTime] = useState(new Date().toLocaleTimeString())
  const [searchQuery, setSearchQuery] = useState('')
  const [searchResults, setSearchResults] = useState<Tool[]>([])
  const [isSearchFocused, setIsSearchFocused] = useState(false)
  const searchRef = useRef<HTMLDivElement>(null)

  // Update time every second
  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(new Date().toLocaleTimeString())
    }, 1000)

    return () => clearInterval(timer)
  }, [])

  // Close mobile menu on route change
  useEffect(() => {
    setIsMobileMenuOpen(false)
  }, [location.pathname])

  // Close search on ESC key
  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        setIsSearchFocused(false)
        setSearchQuery('')
      }
    }

    document.addEventListener('keydown', handleEscape)
    return () => document.removeEventListener('keydown', handleEscape)
  }, [])

  // Close search when clicking outside
  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (searchRef.current && !searchRef.current.contains(e.target as Node)) {
        setIsSearchFocused(false)
      }
    }

    document.addEventListener('mousedown', handleClickOutside)
    return () => document.removeEventListener('mousedown', handleClickOutside)
  }, [])

  // Navigation groups
  const analysisTools: NavItem[] = [
    {
      path: '/pcap',
      label: 'PCAP Analysis',
      icon: BarChart3,
      description: 'Analyze network packet captures',
      keywords: ['network', 'packet', 'traffic', 'wireshark', 'tcpdump']
    },
    {
      path: '/image',
      label: 'Image Analysis',
      icon: FileImage,
      description: 'Analyze and extract data from images',
      keywords: ['steganography', 'metadata', 'exif', 'forensics', 'picture']
    },
    {
      path: '/audio',
      label: 'Audio Analysis',
      icon: Music,
      description: 'Analyze audio files and spectrograms',
      keywords: ['sound', 'spectrogram', 'waveform', 'frequency']
    },
    {
      path: '/folder-scanner',
      label: 'Folder Scanner',
      icon: FolderOpen,
      description: 'Scan and analyze directory structures',
      keywords: ['directory', 'files', 'scan', 'bulk']
    },
    {
      path: '/memory',
      label: 'Memory Analysis',
      icon: HardDrive,
      description: 'Memory dump analysis and artifact extraction',
      keywords: ['memory', 'dump', 'volatility', 'ram', 'forensics', 'process']
    },
  ]

  const securityTools: NavItem[] = [
    {
      path: '/network',
      label: 'Network',
      icon: Wifi,
      description: 'Network utilities and tools',
      keywords: ['ping', 'port', 'scan', 'connectivity']
    },
    {
      path: '/threat-intel',
      label: 'Threat Intel',
      icon: Shield,
      description: 'Threat intelligence and malware analysis',
      keywords: ['virustotal', 'hibp', 'malware', 'phishing', 'abuse', 'threat']
    },
    {
      path: '/crypto',
      label: 'Cryptography',
      icon: Lock,
      description: 'Encryption, decryption, and cipher tools',
      keywords: ['encryption', 'decryption', 'cipher', 'hash', 'base64', 'rsa', 'aes']
    },
  ]

  const standaloneItems: NavItem[] = [
    {
      path: '/python',
      label: 'Python',
      icon: Code,
      description: 'Browser-based Python for forensics scripting',
      keywords: ['python', 'script', 'code', 'analysis', 'programming', 'pyodide']
    },
  ]

  const allItems = [...analysisTools, ...securityTools, ...standaloneItems]

  // Search functionality with debouncing - using comprehensive toolsDatabase
  useEffect(() => {
    const debounceTimer = setTimeout(() => {
      if (searchQuery.trim()) {
        const results = searchTools(searchQuery)
        // Limit to top 10 results
        setSearchResults(results.slice(0, 10))
      } else {
        setSearchResults([])
      }
    }, 300)

    return () => clearTimeout(debounceTimer)
  }, [searchQuery])

  const handleNavigation = (path: string) => {
    navigate(path)
    setIsMobileMenuOpen(false)
    setSearchQuery('')
    setIsSearchFocused(false)
  }

  const isItemActive = (path: string) => location.pathname === path

  const isGroupActive = (items: NavItem[]) => {
    return items.some(item => location.pathname === item.path)
  }

  const getCurrentPageLabel = () => {
    const currentItem = allItems.find(item => item.path === location.pathname)
    return currentItem?.label || 'Sectoolbox'
  }

  const renderDropdownTrigger = (label: string, items: NavItem[]) => {
    const isActive = isGroupActive(items)
    return (
      <button
        className={`flex items-center space-x-1 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
          isActive
            ? 'bg-accent/10 text-accent border border-accent/20'
            : 'text-muted-foreground hover:text-foreground hover:bg-muted/50'
        }`}
      >
        <span>{label}</span>
        <ChevronDown className="w-3 h-3" />
      </button>
    )
  }

  return (
    <div className="min-h-screen flex flex-col">
      {/* Top Bar */}
      <header className="h-16 bg-card border-b border-border flex items-center px-4 lg:px-6 relative z-50">
        {/* Logo - Left Side (Desktop Only) */}
        <div className="hidden lg:flex items-center space-x-2 absolute left-6">
          <Zap className="w-5 h-5 text-accent" />
          <span className="text-lg font-bold">Sectoolbox</span>
        </div>

        {/* Desktop Navigation - Centered */}
        <nav className="hidden lg:flex items-center space-x-1 mx-auto">
          {/* Home */}
          <button
            onClick={() => navigate('/')}
            className={`flex items-center space-x-2 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
              location.pathname === '/'
                ? 'bg-accent/10 text-accent border border-accent/20'
                : 'text-muted-foreground hover:text-foreground hover:bg-muted/50'
            }`}
          >
            <Home className="w-4 h-4" />
            <span>Home</span>
          </button>

          {/* Analysis Tools Dropdown */}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              {renderDropdownTrigger('Analysis Tools', analysisTools)}
            </DropdownMenuTrigger>
            <DropdownMenuContent align="center" className="w-56">
              {analysisTools.map((item) => {
                const Icon = item.icon
                const isActive = isItemActive(item.path)
                return (
                  <DropdownMenuItem
                    key={item.path}
                    onClick={() => handleNavigation(item.path)}
                    className={`flex items-center space-x-2 cursor-pointer ${
                      isActive ? 'bg-accent/10 text-accent' : ''
                    }`}
                  >
                    <Icon className="w-4 h-4" />
                    <div className="flex flex-col">
                      <span className="font-medium">{item.label}</span>
                      <span className="text-xs text-muted-foreground">{item.description}</span>
                    </div>
                  </DropdownMenuItem>
                )
              })}
            </DropdownMenuContent>
          </DropdownMenu>

          {/* Security Tools Dropdown */}
          <DropdownMenu>
            <DropdownMenuTrigger asChild>
              {renderDropdownTrigger('Security Tools', securityTools)}
            </DropdownMenuTrigger>
            <DropdownMenuContent align="center" className="w-56">
              {securityTools.map((item) => {
                const Icon = item.icon
                const isActive = isItemActive(item.path)
                return (
                  <DropdownMenuItem
                    key={item.path}
                    onClick={() => handleNavigation(item.path)}
                    className={`flex items-center space-x-2 cursor-pointer ${
                      isActive ? 'bg-accent/10 text-accent' : ''
                    }`}
                  >
                    <Icon className="w-4 h-4" />
                    <div className="flex flex-col">
                      <span className="font-medium">{item.label}</span>
                      <span className="text-xs text-muted-foreground">{item.description}</span>
                    </div>
                  </DropdownMenuItem>
                )
              })}
            </DropdownMenuContent>
          </DropdownMenu>

          {/* Standalone Items */}
          {standaloneItems.map((item) => {
            const Icon = item.icon
            const isActive = isItemActive(item.path)
            return (
              <button
                key={item.path}
                onClick={() => navigate(item.path)}
                className={`flex items-center space-x-2 px-3 py-2 rounded-md text-sm font-medium transition-colors ${
                  isActive
                    ? 'bg-accent/10 text-accent border border-accent/20'
                    : 'text-muted-foreground hover:text-foreground hover:bg-muted/50'
                }`}
              >
                <Icon className="w-4 h-4" />
                <span>{item.label}</span>
              </button>
            )
          })}
        </nav>

        {/* Search + Status - Right Side (Desktop Only) */}
        <div className="hidden lg:flex items-center space-x-4 absolute right-6">
          {/* Search Bar */}
          <div ref={searchRef} className="relative">
            <div className="relative">
              <SearchIcon className="absolute left-2 top-1/2 transform -translate-y-1/2 w-3.5 h-3.5 text-muted-foreground" />
              <Input
                type="text"
                placeholder="Search tools..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onFocus={() => setIsSearchFocused(true)}
                className="pl-8 pr-7 w-40 focus:w-56 transition-all duration-200 h-8 text-sm"
              />
              {searchQuery && (
                <button
                  onClick={() => {
                    setSearchQuery('')
                    setSearchResults([])
                  }}
                  className="absolute right-1.5 top-1/2 transform -translate-y-1/2 text-muted-foreground hover:text-foreground"
                >
                  <XCircle className="w-3.5 h-3.5" />
                </button>
              )}
            </div>

            {/* Search Results Dropdown */}
            {isSearchFocused && searchResults.length > 0 && (
              <div className="absolute top-full mt-2 w-96 bg-popover border border-border rounded-md shadow-lg overflow-hidden z-50 animate-in slide-in-from-top-2">
                <div className="max-h-96 overflow-y-auto">
                  {searchResults.map((tool) => {
                    return (
                      <button
                        key={tool.id}
                        onClick={() => handleNavigation(tool.path)}
                        className="w-full flex items-start space-x-3 px-4 py-3 hover:bg-accent/10 transition-colors text-left border-b border-border/50 last:border-0"
                      >
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1">
                            <span className="font-semibold text-sm">{tool.name}</span>
                            <span className="px-2 py-0.5 bg-accent/20 text-accent rounded text-xs font-medium">
                              {tool.category}
                            </span>
                          </div>
                          <div className="text-xs text-muted-foreground line-clamp-2 mb-1">
                            {tool.description}
                          </div>
                          {tool.operations.length > 0 && (
                            <div className="flex gap-1 flex-wrap">
                              {tool.operations.slice(0, 3).map((op) => (
                                <span key={op} className="px-1.5 py-0.5 bg-muted text-muted-foreground rounded text-xs">
                                  {op}
                                </span>
                              ))}
                            </div>
                          )}
                        </div>
                      </button>
                    )
                  })}
                </div>
              </div>
            )}
          </div>

          <div className="text-xs font-mono text-muted-foreground">
            {currentTime}
          </div>
          <div className="w-2 h-2 bg-accent rounded-full animate-pulse"></div>
        </div>

        {/* Mobile Navigation - Hamburger Menu + Centered Title */}
        <div className="lg:hidden flex items-center w-full">
          <h1 className="absolute left-1/2 transform -translate-x-1/2 text-lg font-semibold pointer-events-none">
            {getCurrentPageLabel()}
          </h1>
          <button
            onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
            className="ml-auto p-2 rounded-md hover:bg-muted/50 transition-colors z-50"
            aria-label="Toggle navigation menu"
          >
            {isMobileMenuOpen ? (
              <X className="w-5 h-5 text-foreground" />
            ) : (
              <Menu className="w-5 h-5 text-foreground" />
            )}
          </button>
        </div>
      </header>

      {/* Mobile Menu */}
      {isMobileMenuOpen && (
        <>
          {/* Overlay */}
          <div
            className="fixed inset-0 bg-black/50 z-40 lg:hidden backdrop-blur-sm"
            onClick={() => setIsMobileMenuOpen(false)}
          />

          {/* Slide-in Menu */}
          <div className="fixed top-16 left-0 right-0 bottom-0 bg-card z-50 lg:hidden transform transition-transform duration-300 ease-out overflow-y-auto">
            <nav className="flex flex-col p-4 space-y-6" role="menu" aria-label="Mobile navigation">
              {/* Search Bar */}
              <div className="relative">
                <SearchIcon className="absolute left-3 top-1/2 transform -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <Input
                  type="text"
                  placeholder="Search tools..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-10 pr-10"
                />
                {searchQuery && (
                  <button
                    onClick={() => setSearchQuery('')}
                    className="absolute right-3 top-1/2 transform -translate-y-1/2 text-muted-foreground"
                  >
                    <XCircle className="w-4 h-4" />
                  </button>
                )}
              </div>

              {/* Search Results */}
              {searchQuery && searchResults.length > 0 && (
                <div className="space-y-1 pb-4 border-b border-border">
                  <div className="text-xs text-muted-foreground font-medium px-2 mb-2">
                    Search Results ({searchResults.length})
                  </div>
                  {searchResults.map((tool) => {
                    return (
                      <button
                        key={tool.id}
                        onClick={() => handleNavigation(tool.path)}
                        className="w-full flex flex-col items-start px-4 py-3 rounded-lg text-sm transition-all text-left bg-muted/30 hover:bg-accent/10 border border-border"
                      >
                        <div className="flex items-center gap-2 mb-1">
                          <span className="font-semibold">{tool.name}</span>
                          <span className="px-2 py-0.5 bg-accent/20 text-accent rounded text-xs font-medium">
                            {tool.category}
                          </span>
                        </div>
                        <div className="text-xs text-muted-foreground line-clamp-2">
                          {tool.description}
                        </div>
                      </button>
                    )
                  })}
                </div>
              )}

              {/* Home */}
              {!searchQuery && (
                <button
                  onClick={() => handleNavigation('/')}
                  className={`flex items-center space-x-3 px-4 py-3 rounded-lg text-sm font-medium transition-all ${
                    location.pathname === '/'
                      ? 'bg-accent/15 text-accent border border-accent/30'
                      : 'text-muted-foreground hover:text-foreground hover:bg-muted/60 border border-transparent'
                  }`}
                >
                  <Home className="w-5 h-5" />
                  <span>Home</span>
                </button>
              )}

              {/* Analysis Tools Section */}
              {!searchQuery && (
                <>
                  <div>
                    <div className="text-xs text-muted-foreground font-medium px-2 mb-2">
                      Analysis Tools
                    </div>
                    <div className="space-y-1">
                      {analysisTools.map((item) => {
                        const Icon = item.icon
                        const isActive = isItemActive(item.path)
                        return (
                          <button
                            key={item.path}
                            onClick={() => handleNavigation(item.path)}
                            className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg text-sm font-medium transition-all text-left ${
                              isActive
                                ? 'bg-accent/15 text-accent border border-accent/30'
                                : 'text-muted-foreground hover:text-foreground hover:bg-muted/60 border border-transparent'
                            }`}
                          >
                            <Icon className="w-5 h-5" />
                            <span>{item.label}</span>
                          </button>
                        )
                      })}
                    </div>
                  </div>

                  {/* Security Tools Section */}
                  <div>
                    <div className="text-xs text-muted-foreground font-medium px-2 mb-2">
                      Security Tools
                    </div>
                    <div className="space-y-1">
                      {securityTools.map((item) => {
                        const Icon = item.icon
                        const isActive = isItemActive(item.path)
                        return (
                          <button
                            key={item.path}
                            onClick={() => handleNavigation(item.path)}
                            className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg text-sm font-medium transition-all text-left ${
                              isActive
                                ? 'bg-accent/15 text-accent border border-accent/30'
                                : 'text-muted-foreground hover:text-foreground hover:bg-muted/60 border border-transparent'
                            }`}
                          >
                            <Icon className="w-5 h-5" />
                            <span>{item.label}</span>
                          </button>
                        )
                      })}
                    </div>
                  </div>

                  {/* Other Section */}
                  <div>
                    <div className="text-xs text-muted-foreground font-medium px-2 mb-2">
                      Other
                    </div>
                    <div className="space-y-1">
                      {standaloneItems.map((item) => {
                        const Icon = item.icon
                        const isActive = isItemActive(item.path)
                        return (
                          <button
                            key={item.path}
                            onClick={() => handleNavigation(item.path)}
                            className={`w-full flex items-center space-x-3 px-4 py-3 rounded-lg text-sm font-medium transition-all text-left ${
                              isActive
                                ? 'bg-accent/15 text-accent border border-accent/30'
                                : 'text-muted-foreground hover:text-foreground hover:bg-muted/60 border border-transparent'
                            }`}
                          >
                            <Icon className="w-5 h-5" />
                            <span>{item.label}</span>
                          </button>
                        )
                      })}
                    </div>
                  </div>
                </>
              )}

              {/* Mobile Status */}
              <div className="flex items-center justify-between pt-4 mt-4 border-t border-border/50">
                <div className="text-xs font-mono text-muted-foreground bg-background/50 px-2 py-1 rounded">
                  {currentTime}
                </div>
                <div className="flex items-center space-x-2">
                  <div className="w-2 h-2 bg-accent rounded-full animate-pulse shadow-sm"></div>
                  <span className="text-xs text-muted-foreground font-medium">Online</span>
                </div>
              </div>

              {/* Mobile Footer */}
              <div className="pt-3 mt-3 border-t border-border/30">
                <div className="text-xs text-center text-muted-foreground/70">
                  <span className="font-mono">Sectoolbox</span> • Professional CTF Tools
                </div>
              </div>
            </nav>
          </div>
        </>
      )}

      {/* Page Content */}
      <main className="flex-1 flex flex-col" id="main-content">
        <div className="flex-1">
          {children}
        </div>
        <div className="mt-auto pt-24">
          <Footer />
        </div>
      </main>
    </div>
  )
}

export default Layout
