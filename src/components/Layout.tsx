import React, { useState, useEffect } from 'react'
import { useLocation, useNavigate } from 'react-router-dom'
import { Zap, Home, Network, Image, Lock, Globe, Search, Menu, X, FolderOpen, Headphones, Wifi } from 'lucide-react'
import Footer from './Footer'

interface LayoutProps {
  children: React.ReactNode
}

const Layout: React.FC<LayoutProps> = ({ children }) => {
  const location = useLocation()
  const navigate = useNavigate()
  const [isMobileMenuOpen, setIsMobileMenuOpen] = useState(false)
  const [currentTime, setCurrentTime] = useState(new Date().toLocaleTimeString())

  // Update time every second
  useEffect(() => {
    const timer = setInterval(() => {
      setCurrentTime(new Date().toLocaleTimeString())
    }, 1000)

    return () => clearInterval(timer)
  }, [])

  const navItems = [
    { path: '/', label: 'Home', icon: Home },
    { path: '/pcap', label: 'PCAP', icon: Network },
    { path: '/image', label: 'Image', icon: Image },
    { path: '/crypto', label: 'Cryptography', icon: Lock },
    { path: '/web', label: 'Web', icon: Globe },
    { path: '/forensics', label: 'Forensics', icon: Search },
    { path: '/folder-scanner', label: 'Folder', icon: FolderOpen },
    { path: '/audio', label: 'Audio', icon: Headphones },
    { path: '/network', label: 'Network', icon: Wifi },
  ]

  const handleNavigation = (path: string) => {
    navigate(path)
    setIsMobileMenuOpen(false)
  }

  return (
    <div className="min-h-screen flex flex-col">
      {/* Top Bar */}
      <header className="h-16 bg-card border-b border-border flex items-center px-4 lg:px-6 relative">
        {/* Logo - Left Side (Desktop Only) */}
        <div className="hidden lg:flex items-center space-x-2 absolute left-6">
          <Zap className="w-5 h-5 text-accent" />
          <span className="text-lg font-bold">Sectoolbox</span>
        </div>

        {/* Desktop Navigation - Centered */}
        <nav className="hidden lg:flex items-center space-x-1 mx-auto">
          {navItems.map((item) => {
          const Icon = item.icon
          const isActive = location.pathname === item.path
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

        {/* Status Indicator - Right Side (Desktop Only) */}
        <div className="hidden lg:flex items-center space-x-2 lg:space-x-4 absolute right-6">
          <div className="text-xs font-mono text-muted-foreground hidden sm:block">
            {currentTime}
          </div>
          <div className="w-2 h-2 bg-accent rounded-full animate-pulse"></div>
        </div>

        {/* Mobile Navigation - Hamburger Menu + Centered Title */}
        <div className="lg:hidden flex items-center space-x-3 ml-auto">
          <h1 className="absolute left-1/2 transform -translate-x-1/2 lg:static text-lg font-semibold pointer-events-none">
            {navItems.find(item => item.path === location.pathname)?.label || 'Home'}
          </h1>
          <button
            onClick={() => setIsMobileMenuOpen(!isMobileMenuOpen)}
            className="p-2 rounded-md hover:bg-muted/50 transition-colors z-50"
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

      {/* Mobile Dropdown Menu */}
      {isMobileMenuOpen && (
        <>
          {/* Overlay */}
          <div
            className="fixed inset-0 bg-black/50 z-40 lg:hidden backdrop-blur-sm"
            onClick={() => setIsMobileMenuOpen(false)}
          />

          {/* Dropdown Menu */}
          <div className="absolute top-16 left-0 right-0 bg-card/95 backdrop-blur-md border-b border-border shadow-2xl z-50 lg:hidden transform transition-all duration-200 ease-out">
            <nav className="flex flex-col p-4 space-y-2 max-h-[calc(100vh-4rem)] overflow-y-auto" role="menu" aria-label="Mobile navigation">
              {navItems.map((item) => {
                const Icon = item.icon
                const isActive = location.pathname === item.path
                return (
                  <button
                    key={item.path}
                    onClick={() => handleNavigation(item.path)}
                    role="menuitem"
                    className={`flex items-center space-x-3 px-4 py-3 rounded-lg text-sm font-medium transition-all duration-200 text-left group ${
                      isActive 
                        ? 'bg-accent/15 text-accent border border-accent/30 shadow-sm' 
                        : 'text-muted-foreground hover:text-foreground hover:bg-muted/60 hover:border-border/50 border border-transparent'
                    }`}
                  >
                    <Icon className={`w-5 h-5 transition-colors ${
                      isActive ? 'text-accent' : 'group-hover:text-accent/70'
                    }`} />
                    <span className="font-medium">{item.label}</span>
                    {isActive && (
                      <div className="ml-auto w-2 h-2 bg-accent rounded-full animate-pulse" />
                    )}
                  </button>
                )
              })}


              
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
