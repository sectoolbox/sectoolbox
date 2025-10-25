import React, { useState, useEffect, useRef } from 'react'
import { Upload, Play, Download, Trash2, Save, FolderOpen, Package, Terminal, Code, BookOpen, Loader2, AlertCircle, Search, Lock, Unlock, X, Plus, Undo2, Redo2, File, ChevronRight, ChevronDown, FileText, Image as ImageIcon, Archive, FileCode, FileQuestion, Zap } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Card } from '../components/ui/card'
import { Input } from '../components/ui/input'
import Editor from '@monaco-editor/react'
import { Panel, PanelGroup, PanelResizeHandle } from 'react-resizable-panels'
import { loadPythonScripts, getScriptCategories, PythonScript } from '../lib/pythonScriptLoader'
import { initPyodide } from '../lib/pyodideManager'
import toast from 'react-hot-toast'

// Pyodide types
interface PyodideInterface {
  runPythonAsync: (code: string) => Promise<any>
  loadPackage: (packages: string | string[]) => Promise<void>
  FS: any
  globals: any
  loadPackagesFromImports: (code: string) => Promise<void>
  pyimport: (name: string) => any
}

interface ScriptTab {
  id: string
  name: string
  code: string
  unsaved: boolean
}

interface CodeHistoryEntry {
  timestamp: number
  code: string
  label: string
}

const PythonForensics: React.FC = () => {
  const [pyodide, setPyodide] = useState<PyodideInterface | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [loadingStatus, setLoadingStatus] = useState('Initializing...')

  // Tabs management
  const [tabs, setTabs] = useState<ScriptTab[]>([{
    id: 'default',
    name: 'script.py',
    code: `# Python Scripts
# Upload a file and run your analysis

import hashlib

# Example: Calculate file hash
file_path = 'sample.bin'

try:
    with open(file_path, 'rb') as f:
        data = f.read()

    print(f"File size: {len(data)} bytes")
    print(f"MD5: {hashlib.md5(data).hexdigest()}")
    print(f"SHA256: {hashlib.sha256(data).hexdigest()}")
except FileNotFoundError:
    print("Please upload a file first!")
`,
    unsaved: false
  }])
  const [activeTabId, setActiveTabId] = useState('default')
  const [codeHistory, setCodeHistory] = useState<Record<string, CodeHistoryEntry[]>>({})
  const [showHistory, setShowHistory] = useState(false)

  const [output, setOutput] = useState('')
  const [isRunning, setIsRunning] = useState(false)
  const [uploadedFiles, setUploadedFiles] = useState<{ name: string; size: number; path: string }[]>([])
  const [selectedExample, setSelectedExample] = useState<string>('')
  const [categoryFilter, setCategoryFilter] = useState('All')
  const [savedScripts, setSavedScripts] = useState<{ name: string; code: string }[]>([])
  const [showSaveDialog, setShowSaveDialog] = useState(false)
  const [scriptName, setScriptName] = useState('')
  const [installedPackages, setInstalledPackages] = useState<string[]>([])
  const [outputFilter, setOutputFilter] = useState('')
  const [autoScroll, setAutoScroll] = useState(true)
  const [lastUploadedFilename, setLastUploadedFilename] = useState<string>('sample.bin')
  const [pythonScripts, setPythonScripts] = useState<PythonScript[]>([])
  const [scriptCategories, setScriptCategories] = useState<string[]>(['All'])
  const [isDragging, setIsDragging] = useState(false)

  // File Browser state
  const [showFileBrowser, setShowFileBrowser] = useState(false)
  const [expandedFolders, setExpandedFolders] = useState<Set<string>>(new Set(['/uploads']))
  const [selectedFile, setSelectedFile] = useState<string | null>(null)
  const [filePreview, setFilePreview] = useState<string>('')
  const [imagePreview, setImagePreview] = useState<string>('')
  const [fileViewMode, setFileViewMode] = useState<'preview' | 'metadata' | 'hex'>('preview')
  const [fileMetadata, setFileMetadata] = useState<any>(null)
  const [hexData, setHexData] = useState<string>('')
  const [editingMetadata, setEditingMetadata] = useState(false)
  const [metadataEdits, setMetadataEdits] = useState<Record<string, string>>({})

  // Package Manager state
  const [showPackageManager, setShowPackageManager] = useState(false)
  const [packageSearch, setPackageSearch] = useState('')
  const [isInstalling, setIsInstalling] = useState(false)

  // Scripts Browser state
  const [showScriptsBrowser, setShowScriptsBrowser] = useState(false)
  const [scriptSearchQuery, setScriptSearchQuery] = useState('')

  // Quick Guide state
  const [showQuickGuide, setShowQuickGuide] = useState(false)

  // Text size control
  const [editorFontSize, setEditorFontSize] = useState(14)
  const [terminalFontSize, setTerminalFontSize] = useState(14)

  // Panel height control for bottom resize
  const [panelHeight, setPanelHeight] = useState(600)
  const [isResizing, setIsResizing] = useState(false)
  const resizeStartY = useRef(0)
  const resizeStartHeight = useRef(0)

  const fileInputRef = useRef<HTMLInputElement>(null)
  const folderInputRef = useRef<HTMLInputElement>(null)
  const outputRef = useRef<HTMLDivElement>(null)
  const editorRef = useRef<any>(null)

  const activeTab = tabs.find(t => t.id === activeTabId) || tabs[0]

  useEffect(() => {
    loadPyodide()
    loadScripts()

    // Restore state from localStorage
    const savedTabs = localStorage.getItem('sectoolbox_python_tabs')
    const savedOutput = localStorage.getItem('sectoolbox_python_output')
    const savedActiveTab = localStorage.getItem('sectoolbox_python_activeTab')

    if (savedTabs) {
      try {
        const parsedTabs = JSON.parse(savedTabs)
        setTabs(parsedTabs)
      } catch (e) {
        console.error('Failed to restore tabs:', e)
      }
    }

    if (savedOutput) {
      setOutput(savedOutput)
    }

    if (savedActiveTab) {
      setActiveTabId(savedActiveTab)
    }
  }, [])

  const loadScripts = async () => {
    try {
      const scripts = await loadPythonScripts()
      setPythonScripts(scripts)
      const categories = getScriptCategories(scripts)
      setScriptCategories(categories)
    } catch (error) {
      console.error('Failed to load Python scripts:', error)
      toast.error('Failed to load example scripts')
    }
  }

  useEffect(() => {
    const saved = localStorage.getItem('sectoolbox_python_scripts')
    if (saved) {
      try {
        setSavedScripts(JSON.parse(saved))
      } catch (e) {
        console.error('Failed to load saved scripts:', e)
      }
    }
  }, [])

  // Handle bottom panel resize
  const handleResizeStart = (e: React.MouseEvent) => {
    setIsResizing(true)
    resizeStartY.current = e.clientY
    resizeStartHeight.current = panelHeight
  }

  useEffect(() => {
    if (!isResizing) return

    const handleMouseMove = (e: MouseEvent) => {
      const deltaY = e.clientY - resizeStartY.current
      const newHeight = Math.max(300, resizeStartHeight.current + deltaY)
      setPanelHeight(newHeight)
    }

    const handleMouseUp = () => {
      setIsResizing(false)
    }

    document.addEventListener('mousemove', handleMouseMove)
    document.addEventListener('mouseup', handleMouseUp)

    return () => {
      document.removeEventListener('mousemove', handleMouseMove)
      document.removeEventListener('mouseup', handleMouseUp)
    }
  }, [isResizing])

  useEffect(() => {
    if (autoScroll && outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight
    }
  }, [output, autoScroll])

  // Auto-save state to localStorage
  useEffect(() => {
    const saveInterval = setInterval(() => {
      try {
        localStorage.setItem('sectoolbox_python_tabs', JSON.stringify(tabs))
        localStorage.setItem('sectoolbox_python_output', output)
        localStorage.setItem('sectoolbox_python_activeTab', activeTabId)
      } catch (e) {
        console.error('Failed to save state:', e)
      }
    }, 3000) // Save every 3 seconds

    return () => clearInterval(saveInterval)
  }, [tabs, output, activeTabId])

  const loadPyodide = async () => {
    try {
      const pyodideModule = await initPyodide((status) => {
        setLoadingStatus(status)
      })

      // If this is a cached instance, we still need to set component state
      setPyodide(pyodideModule)
      setLoadingStatus('Ready!')
      setIsLoading(false)
      setInstalledPackages(['micropip', 'sys', 'io', 'os', 'hashlib', 're', 'json', 'base64', 'struct', 'datetime', 'zipfile', 'tarfile'])

      // Only show success toast if not already cached
      const wasCached = pyodideModule !== null
      if (!wasCached) {
        toast.success('Python environment loaded successfully!')
      }
    } catch (error) {
      console.error('Failed to load Pyodide:', error)
      setOutput(`Failed to load Python environment: ${error}`)
      setIsLoading(false)
      toast.error('Failed to load Python environment')
    }
  }

  // Placeholder for old Python code (now in pyodideManager.ts)
  const _oldPythonCode = `
import sys
import os
from io import StringIO

class OutputCapture:
    def __init__(self):
        self.output = []
    def write(self, text):
        self.output.append(text)
    def flush(self):
        pass
    def get_output(self):
        result = ''.join(self.output)
        self.output = []
        return result

_stdout_capture = OutputCapture()
_stderr_capture = OutputCapture()

# Shell-like helper functions
def ls(path='.'):
    """List files in directory"""
    try:
        items = os.listdir(path)
        for item in sorted(items):
            full_path = os.path.join(path, item)
            if os.path.isdir(full_path):
                print(f"{item}/")
            else:
                size = os.path.getsize(full_path)
                print(f"{item:<30} {size:>10} bytes")
        return items
    except Exception as e:
        print(f"Error: {e}")
        return []

def cat(filename):
    """Display file contents"""
    try:
        with open(filename, 'rb') as f:
            data = f.read()
        try:
            print(data.decode('utf-8'))
        except:
            print(f"Binary file ({len(data)} bytes)")
            print("Use hexdump() to view binary data")
    except Exception as e:
        print(f"Error: {e}")

def head(filename, n=10):
    """Show first n lines of file"""
    try:
        with open(filename, 'r') as f:
            for i, line in enumerate(f):
                if i >= n:
                    break
                print(line.rstrip())
    except Exception as e:
        print(f"Error: {e}")

def tail(filename, n=10):
    """Show last n lines of file"""
    try:
        with open(filename, 'r') as f:
            lines = f.readlines()
        for line in lines[-n:]:
            print(line.rstrip())
    except Exception as e:
        print(f"Error: {e}")

def grep(pattern, filename):
    """Search for pattern in file"""
    try:
        import re
        with open(filename, 'rb') as f:
            data = f.read()
        text = data.decode('utf-8', errors='ignore')
        matches = []
        for i, line in enumerate(text.split('\\n'), 1):
            if re.search(pattern, line, re.IGNORECASE):
                print(f"{i}: {line}")
                matches.append((i, line))
        if not matches:
            print(f"No matches found for '{pattern}'")
        return matches
    except Exception as e:
        print(f"Error: {e}")
        return []

def hexdump(filename):
    """Display hex dump of entire file"""
    try:
        with open(filename, 'rb') as f:
            data = f.read()
        print(f"Hex dump of {filename} ({len(data)} bytes):\\n")
        for i in range(0, len(data), 16):
            chunk = data[i:i+16]
            hex_part = ' '.join(f'{b:02x}' for b in chunk)
            ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
            print(f"{i:08x}  {hex_part:<48}  |{ascii_part}|")
    except Exception as e:
        print(f"Error: {e}")

def tree(path='.', prefix='', max_depth=3, _depth=0):
    """Display directory tree"""
    if _depth >= max_depth:
        return
    try:
        items = sorted(os.listdir(path))
        for i, item in enumerate(items):
            is_last = i == len(items) - 1
            full_path = os.path.join(path, item)
            print(f"{prefix}{'└── ' if is_last else '├── '}{item}")
            if os.path.isdir(full_path):
                tree(full_path, prefix + ('    ' if is_last else '│   '), max_depth, _depth + 1)
    except Exception as e:
        print(f"Error: {e}")

def pwd():
    """Print working directory"""
    cwd = os.getcwd()
    print(cwd)
    return cwd

def fileinfo(filename):
    """Show detailed file information"""
    try:
        import hashlib
        stat = os.stat(filename)
        with open(filename, 'rb') as f:
            data = f.read()

        print(f"File: {filename}")
        print(f"Size: {stat.st_size} bytes")
        print(f"MD5:  {hashlib.md5(data).hexdigest()}")
        print(f"SHA1: {hashlib.sha1(data).hexdigest()}")

        # Check if printable
        printable = sum(1 for b in data if 32 <= b <= 126 or b in (9, 10, 13))
        print(f"Printable: {printable/len(data)*100:.1f}%")

        # File signature
        if data.startswith(b'\\xff\\xd8\\xff'):
            print("Type: JPEG image")
        elif data.startswith(b'\\x89PNG'):
            print("Type: PNG image")
        elif data.startswith(b'PK\\x03\\x04'):
            print("Type: ZIP archive")
        elif data.startswith(b'%PDF'):
            print("Type: PDF document")
        elif data.startswith(b'MZ'):
            print("Type: PE executable")

    except Exception as e:
        print(f"Error: {e}")
`

  const saveToHistory = (tabId: string, code: string, label: string) => {
    const entry: CodeHistoryEntry = { timestamp: Date.now(), code, label }
    setCodeHistory(prev => ({
      ...prev,
      [tabId]: [...(prev[tabId] || []), entry].slice(-20)
    }))
  }

  const runCode = async () => {
    if (!pyodide) {
      toast.error('Python environment not loaded')
      return
    }

    saveToHistory(activeTabId, activeTab.code, 'Before run')
    setIsRunning(true)
    setOutput('>>> Running...\n')

    try {
      await pyodide.runPythonAsync(`
sys.stdout = _stdout_capture
sys.stderr = _stderr_capture
_stdout_capture.output = []
_stderr_capture.output = []
`)

      try {
        await pyodide.loadPackagesFromImports(activeTab.code)
      } catch (e) {
        console.log('Could not auto-load packages:', e)
      }

      await pyodide.runPythonAsync(activeTab.code)
      const stdout = await pyodide.runPythonAsync('_stdout_capture.get_output()')
      const stderr = await pyodide.runPythonAsync('_stderr_capture.get_output()')

      let result = ''
      if (stdout) result += stdout
      if (stderr) result += '\n' + stderr

      setOutput(result || 'Code executed successfully (no output)')
    } catch (error: any) {
      setOutput(`Error:\n${error.message || String(error)}`)
      toast.error('Script execution failed')
    } finally {
      setIsRunning(false)
    }
  }

  const handleDragEnter = (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(true)
  }

  const handleDragLeave = (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(false)
  }

  const handleDragOver = (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
  }

  const handleDrop = async (e: React.DragEvent) => {
    e.preventDefault()
    e.stopPropagation()
    setIsDragging(false)

    if (!pyodide) {
      toast.error('Python environment not ready')
      return
    }

    const items = Array.from(e.dataTransfer.items)
    for (const item of items) {
      if (item.kind === 'file') {
        const entry = item.webkitGetAsEntry()
        if (entry) await processEntry(entry, '')
      }
    }
  }

  const processEntry = async (entry: any, path: string) => {
    if (!pyodide) return

    if (entry.isFile) {
      entry.file(async (file: File) => {
        try {
          const fullPath = path ? `${path}/${file.name}` : file.name
          const arrayBuffer = await file.arrayBuffer()
          const uint8Array = new Uint8Array(arrayBuffer)

          const dirPath = fullPath.includes('/') ? fullPath.substring(0, fullPath.lastIndexOf('/')) : ''
          if (dirPath) {
            const dirs = dirPath.split('/')
            let currentPath = '/uploads'
            for (const dir of dirs) {
              currentPath += `/${dir}`
              try {
                pyodide.FS.mkdir(currentPath)
              } catch (e) {}
            }
          }

          pyodide.FS.writeFile(`/uploads/${fullPath}`, uint8Array)
          setUploadedFiles(prev => [...prev, { name: file.name, size: file.size, path: fullPath }])
          setLastUploadedFilename(file.name)
          toast.success(`Uploaded: ${fullPath}`)

          // Replace 'sample.bin' with uploaded filename in all tabs
          setTabs(prevTabs => prevTabs.map(tab => ({
            ...tab,
            code: tab.code.replace(/(['"])sample\.bin\1/g, `$1${fullPath}$1`)
          })))
        } catch (error) {
          console.error('File upload error:', error)
          toast.error(`Failed to upload ${file.name}`)
        }
      })
    } else if (entry.isDirectory) {
      const dirReader = entry.createReader()
      dirReader.readEntries(async (entries: any[]) => {
        for (const childEntry of entries) {
          const newPath = path ? `${path}/${entry.name}` : entry.name
          await processEntry(childEntry, newPath)
        }
      })
    }
  }

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    if (!pyodide || !event.target.files) return

    const files = Array.from(event.target.files)
    for (const file of files) {
      try {
        const arrayBuffer = await file.arrayBuffer()
        const uint8Array = new Uint8Array(arrayBuffer)

        pyodide.FS.writeFile(`/uploads/${file.name}`, uint8Array)
        setUploadedFiles(prev => [...prev, { name: file.name, size: file.size, path: file.name }])
        setLastUploadedFilename(file.name)
        toast.success(`Uploaded: ${file.name}`)

        // Replace 'sample.bin' with uploaded filename in all tabs
        setTabs(prevTabs => prevTabs.map(tab => ({
          ...tab,
          code: tab.code.replace(/(['"])sample\.bin\1/g, `$1${file.name}$1`)
        })))
      } catch (error) {
        console.error('File upload error:', error)
        toast.error(`Failed to upload ${file.name}`)
      }
    }
  }

  const handleFolderUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    if (!pyodide || !event.target.files) return

    const files = Array.from(event.target.files)
    for (const file of files) {
      try {
        // @ts-ignore
        const relativePath = file.webkitRelativePath || file.name
        const arrayBuffer = await file.arrayBuffer()
        const uint8Array = new Uint8Array(arrayBuffer)

        const parts = relativePath.split('/')
        let currentPath = '/uploads'
        for (let i = 0; i < parts.length - 1; i++) {
          currentPath += `/${parts[i]}`
          try {
            pyodide.FS.mkdir(currentPath)
          } catch (e) {}
        }

        pyodide.FS.writeFile(`/uploads/${relativePath}`, uint8Array)
        setUploadedFiles(prev => [...prev, { name: file.name, size: file.size, path: relativePath }])
        toast.success(`Uploaded: ${relativePath}`)
      } catch (error) {
        console.error('File upload error:', error)
        toast.error(`Failed to upload ${file.name}`)
      }
    }
  }

  const loadExample = (exampleId: string) => {
    const example = pythonScripts.find(ex => ex.id === exampleId)
    if (example) {
      // Replace 'sample.bin' with the last uploaded filename
      const updatedCode = example.code.replace(/(['"])sample\.bin\1/g, `$1${lastUploadedFilename}$1`)

      const newTab: ScriptTab = {
        id: `example-${Date.now()}`,
        name: example.title.replace(/[^\w\s-]/g, '').replace(/\s+/g, '_').substring(0, 20) + '.py',
        code: updatedCode,
        unsaved: false
      }

      setTabs(prev => [...prev, newTab])
      setActiveTabId(newTab.id)
      setSelectedExample(exampleId)
      setOutput('')
      toast.success(`Loaded: ${example.title}`)
    }
  }

  const createNewTab = () => {
    const newTab: ScriptTab = {
      id: `tab-${Date.now()}`,
      name: `script_${tabs.length + 1}.py`,
      code: '# New Python Script\n\n',
      unsaved: false
    }
    setTabs(prev => [...prev, newTab])
    setActiveTabId(newTab.id)
  }

  const closeTab = (tabId: string) => {
    if (tabs.length === 1) {
      toast.error('Cannot close last tab')
      return
    }

    const tab = tabs.find(t => t.id === tabId)
    if (tab?.unsaved && !confirm(`Close unsaved tab "${tab.name}"?`)) return

    const newTabs = tabs.filter(t => t.id !== tabId)
    setTabs(newTabs)
    if (activeTabId === tabId) setActiveTabId(newTabs[0].id)

    setCodeHistory(prev => {
      const newHistory = { ...prev }
      delete newHistory[tabId]
      return newHistory
    })
  }

  const updateActiveTabCode = (newCode: string) => {
    setTabs(prev => prev.map(tab =>
      tab.id === activeTabId ? { ...tab, code: newCode, unsaved: true } : tab
    ))
  }

  const renameTab = (tabId: string) => {
    const tab = tabs.find(t => t.id === tabId)
    if (!tab) return

    const newName = prompt('Enter new name:', tab.name)
    if (newName && newName.trim()) {
      setTabs(prev => prev.map(t => t.id === tabId ? { ...t, name: newName.trim() } : t))
    }
  }

  const handleUndo = () => {
    if (editorRef.current) {
      editorRef.current.trigger('keyboard', 'undo', null)
    }
  }

  const handleRedo = () => {
    if (editorRef.current) {
      editorRef.current.trigger('keyboard', 'redo', null)
    }
  }

  const revertToHistory = (entry: CodeHistoryEntry) => {
    updateActiveTabCode(entry.code)
    setShowHistory(false)
    toast.success(`Reverted to: ${entry.label}`)
  }

  const saveScript = () => {
    if (!scriptName.trim()) {
      toast.error('Please enter a script name')
      return
    }

    const newScript = { name: scriptName, code: activeTab.code }
    const updated = [...savedScripts, newScript]
    setSavedScripts(updated)
    localStorage.setItem('sectoolbox_python_scripts', JSON.stringify(updated))

    setTabs(prev => prev.map(tab =>
      tab.id === activeTabId ? { ...tab, unsaved: false } : tab
    ))

    setShowSaveDialog(false)
    setScriptName('')
    toast.success(`Saved: ${scriptName}`)
  }

  const loadSavedScript = (script: { name: string; code: string }) => {
    const newTab: ScriptTab = {
      id: `saved-${Date.now()}`,
      name: script.name + '.py',
      code: script.code,
      unsaved: false
    }
    setTabs(prev => [...prev, newTab])
    setActiveTabId(newTab.id)
    setOutput('')
    toast.success(`Loaded: ${script.name}`)
  }

  const deleteSavedScript = (index: number) => {
    const updated = savedScripts.filter((_, i) => i !== index)
    setSavedScripts(updated)
    localStorage.setItem('sectoolbox_python_scripts', JSON.stringify(updated))
    toast.success('Script deleted')
  }

  const clearOutput = () => setOutput('')

  const deleteUploadedFile = (filePath: string) => {
    if (!pyodide) return
    try {
      pyodide.FS.unlink(`/uploads/${filePath}`)
      setUploadedFiles(prev => prev.filter(f => f.path !== filePath))
      toast.success(`Deleted: ${filePath}`)
    } catch (error) {
      toast.error('Failed to delete file')
    }
  }

  const downloadOutput = () => {
    const blob = new Blob([output], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'python_output.txt'
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
    toast.success('Output downloaded')
  }

  const copyOutput = () => {
    navigator.clipboard.writeText(output)
    toast.success('Output copied to clipboard')
  }

  const installPackage = async (packageName: string) => {
    if (!pyodide) return
    setIsInstalling(true)
    try {
      setOutput(prev => prev + `>>> Installing ${packageName}...\n`)
      await pyodide.runPythonAsync(`
import micropip
await micropip.install('${packageName}')
`)
      setInstalledPackages(prev => {
        if (!prev.includes(packageName)) {
          return [...prev, packageName]
        }
        return prev
      })
      setOutput(prev => prev + `${packageName} installed successfully\n`)
      toast.success(`Installed: ${packageName}`)
    } catch (error: any) {
      setOutput(prev => prev + `Failed to install ${packageName}: ${error.message}\n`)
      toast.error(`Failed to install ${packageName}`)
    } finally {
      setIsInstalling(false)
    }
  }

  const uninstallPackage = async (packageName: string) => {
    if (!pyodide) return
    try {
      await pyodide.runPythonAsync(`
import micropip
micropip.uninstall('${packageName}')
`)
      setInstalledPackages(prev => prev.filter(p => p !== packageName))
      setOutput(prev => prev + `${packageName} uninstalled successfully\n`)
      toast.success(`Uninstalled: ${packageName}`)
    } catch (error: any) {
      setOutput(prev => prev + `Failed to uninstall ${packageName}: ${error.message}\n`)
      toast.error(`Failed to uninstall ${packageName}`)
    }
  }

  // Popular CTF/Forensics packages
  const popularPackages = [
    { name: 'pycryptodome', description: 'Cryptographic library' },
    { name: 'pillow', description: 'Image processing' },
    { name: 'numpy', description: 'Numerical computing' },
    { name: 'requests', description: 'HTTP library' },
    { name: 'beautifulsoup4', description: 'HTML/XML parsing' },
    { name: 'pefile', description: 'PE file parser' },
    { name: 'pyzipper', description: 'ZIP file handling' },
    { name: 'pathlib', description: 'Object-oriented filesystem paths' },
    { name: 'piexif', description: 'EXIF data manipulation for images' },
    { name: 'exifread', description: 'Read EXIF metadata from images' },
  ]

  // File Browser Functions
  interface FileTreeNode {
    name: string
    path: string
    isDirectory: boolean
    size?: number
    children?: FileTreeNode[]
  }

  const buildFileTree = (): FileTreeNode => {
    if (!pyodide) return { name: 'uploads', path: '/uploads', isDirectory: true, children: [] }

    const root: FileTreeNode = { name: 'uploads', path: '/uploads', isDirectory: true, children: [] }

    const processDirectory = (dirPath: string, node: FileTreeNode) => {
      try {
        const items = pyodide.FS.readdir(dirPath)

        for (const item of items) {
          if (item === '.' || item === '..') continue

          const fullPath = dirPath === '/uploads' ? `/uploads/${item}` : `${dirPath}/${item}`

          try {
            const stat = pyodide.FS.stat(fullPath)
            const isDir = pyodide.FS.isDir(stat.mode)

            const childNode: FileTreeNode = {
              name: item,
              path: fullPath,
              isDirectory: isDir,
              size: isDir ? undefined : stat.size,
              children: isDir ? [] : undefined
            }

            if (isDir && expandedFolders.has(fullPath)) {
              processDirectory(fullPath, childNode)
            }

            node.children!.push(childNode)
          } catch (e) {
            console.error(`Error processing ${fullPath}:`, e)
          }
        }

        // Sort: directories first, then files
        node.children!.sort((a, b) => {
          if (a.isDirectory && !b.isDirectory) return -1
          if (!a.isDirectory && b.isDirectory) return 1
          return a.name.localeCompare(b.name)
        })
      } catch (e) {
        console.error(`Error reading directory ${dirPath}:`, e)
      }
    }

    processDirectory('/uploads', root)
    return root
  }

  const toggleFolder = (path: string) => {
    setExpandedFolders(prev => {
      const newSet = new Set(prev)
      if (newSet.has(path)) {
        newSet.delete(path)
      } else {
        newSet.add(path)
      }
      return newSet
    })
  }

  const downloadFile = (filePath: string) => {
    if (!pyodide) return
    try {
      const data = pyodide.FS.readFile(filePath)
      const blob = new Blob([data], { type: 'application/octet-stream' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = filePath.split('/').pop() || 'file'
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
      toast.success(`Downloaded: ${filePath.split('/').pop()}`)
    } catch (error) {
      console.error('Download error:', error)
      toast.error('Failed to download file')
    }
  }

  const extractMetadata = async (filePath: string) => {
    if (!pyodide) return null

    try {
      const metadataJson = await pyodide.runPythonAsync(`
import json
import hashlib
import os
import struct
from datetime import datetime

file_path = '${filePath}'
metadata = {}

# Basic file stats
try:
    stat = os.stat(file_path)
    metadata['size'] = stat.st_size
    metadata['created'] = datetime.fromtimestamp(stat.st_ctime).isoformat()
    metadata['modified'] = datetime.fromtimestamp(stat.st_mtime).isoformat()
    metadata['accessed'] = datetime.fromtimestamp(stat.st_atime).isoformat()
    metadata['mode'] = oct(stat.st_mode)
except Exception as e:
    metadata['stat_error'] = str(e)

# Read file data
with open(file_path, 'rb') as f:
    data = f.read()

metadata['actual_size'] = len(data)

# File hashes
metadata['md5'] = hashlib.md5(data).hexdigest()
metadata['sha1'] = hashlib.sha1(data).hexdigest()
metadata['sha256'] = hashlib.sha256(data).hexdigest()

# File signature
if len(data) >= 16:
    metadata['magic_bytes'] = ' '.join(f'{b:02x}' for b in data[:16])

    # File type detection
    if data.startswith(b'\\xff\\xd8\\xff'):
        metadata['file_type'] = 'JPEG Image'
    elif data.startswith(b'\\x89PNG\\r\\n\\x1a\\n'):
        metadata['file_type'] = 'PNG Image'
    elif data.startswith(b'GIF8'):
        metadata['file_type'] = 'GIF Image'
    elif data.startswith(b'BM'):
        metadata['file_type'] = 'BMP Image'
    elif data.startswith(b'PK\\x03\\x04'):
        metadata['file_type'] = 'ZIP Archive'
    elif data.startswith(b'%PDF'):
        metadata['file_type'] = 'PDF Document'
    elif data.startswith(b'MZ'):
        metadata['file_type'] = 'PE Executable'
    elif data.startswith(b'\\x7fELF'):
        metadata['file_type'] = 'ELF Executable'

# Entropy calculation
import math
byte_counts = [0] * 256
for byte in data:
    byte_counts[byte] += 1
entropy = 0
for count in byte_counts:
    if count > 0:
        p = count / len(data)
        entropy -= p * math.log2(p)
metadata['entropy'] = round(entropy, 4)
metadata['entropy_note'] = 'High (>7.5) = Encrypted/Compressed, Low (<5) = Plain text'

# String extraction - Extract ALL strings from entire file
printable_strings = []
current = []
for byte in data:
    if 32 <= byte <= 126:
        current.append(chr(byte))
    else:
        if len(current) >= 4:
            printable_strings.append(''.join(current))
        current = []
# Don't forget last string if file ends with printable chars
if len(current) >= 4:
    printable_strings.append(''.join(current))
metadata['strings_found'] = len(printable_strings)
if printable_strings:
    metadata['all_strings'] = printable_strings

# EXIF for images
if metadata.get('file_type', '').endswith('Image'):
    exif_data = {}
    for search_str in [b'Make', b'Model', b'DateTime', b'Software', b'GPS', b'Copyright']:
        idx = data.find(search_str)
        if idx != -1:
            exif_data[search_str.decode('ascii')] = f'Found at offset {idx}'
    if exif_data:
        metadata['exif_markers'] = exif_data

# Hidden data detection
null_count = data.count(b'\\x00')
metadata['null_bytes'] = null_count
metadata['null_percentage'] = round((null_count / len(data)) * 100, 2)

# LSB analysis
if len(data) > 1000:
    lsb_bytes = [b & 1 for b in data[:1000]]
    lsb_ones = sum(lsb_bytes)
    metadata['lsb_ratio'] = round(lsb_ones / len(lsb_bytes), 4)
    metadata['lsb_suspicious'] = abs(lsb_ones / len(lsb_bytes) - 0.5) > 0.1

# Filename
metadata['filename'] = os.path.basename(file_path)
metadata['extension'] = os.path.splitext(file_path)[1]

json.dumps(metadata)
`)

      return JSON.parse(metadataJson)
    } catch (error) {
      console.error('Metadata extraction error:', error)
      return { error: String(error) }
    }
  }

  const previewFile = async (filePath: string) => {
    if (!pyodide) return
    try {
      const data = pyodide.FS.readFile(filePath)
      const size = data.length

      // Extract metadata using Python
      const metadata = await extractMetadata(filePath)
      setFileMetadata(metadata)

      // Generate full hex dump
      let hexDump = ''
      for (let i = 0; i < size; i += 16) {
        const hex = Array.from(data.slice(i, i + 16))
          .map((b: number) => b.toString(16).padStart(2, '0'))
          .join(' ')
        const ascii = Array.from(data.slice(i, i + 16))
          .map((b: number) => (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.')
          .join('')
        hexDump += `${i.toString(16).padStart(8, '0')}  ${hex.padEnd(48, ' ')}  |${ascii}|\n`
      }
      setHexData(hexDump)

      // Check if file is an image
      const fileName = filePath.split('/').pop()?.toLowerCase() || ''
      const isImage = ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp'].some(ext => fileName.endsWith(`.${ext}`))

      if (isImage || data.length >= 4 && (
        (data[0] === 0xFF && data[1] === 0xD8 && data[2] === 0xFF) || // JPEG
        (data[0] === 0x89 && data[1] === 0x50 && data[2] === 0x4E && data[3] === 0x47) || // PNG
        (data[0] === 0x47 && data[1] === 0x49 && data[2] === 0x46) || // GIF
        (data[0] === 0x42 && data[1] === 0x4D) // BMP
      )) {
        // Display image
        let mimeType = 'image/png'
        if (data[0] === 0xFF && data[1] === 0xD8) mimeType = 'image/jpeg'
        else if (data[0] === 0x47 && data[1] === 0x49) mimeType = 'image/gif'
        else if (data[0] === 0x42 && data[1] === 0x4D) mimeType = 'image/bmp'

        const blob = new Blob([data], { type: mimeType })
        const url = URL.createObjectURL(blob)
        setImagePreview(url)
        setFilePreview('')
      } else {
        // Check if file is text
        setImagePreview('')
        let preview = ''
        const printable = data.filter((b: number) => (b >= 32 && b <= 126) || b === 9 || b === 10 || b === 13).length
        const ratio = printable / size

        if (ratio > 0.7) {
          // Text file - show ALL content
          const decoder = new TextDecoder('utf-8', { fatal: false })
          preview = decoder.decode(data)
        } else {
          // Binary file - show FULL hex dump
          preview = `Binary file - Full hex dump (${size} bytes):\n\n`
          for (let i = 0; i < size; i += 16) {
            const hex = Array.from(data.slice(i, i + 16))
              .map((b: number) => b.toString(16).padStart(2, '0'))
              .join(' ')
            const ascii = Array.from(data.slice(i, i + 16))
              .map((b: number) => (b >= 32 && b <= 126) ? String.fromCharCode(b) : '.')
              .join('')
            preview += `${i.toString(16).padStart(8, '0')}  ${hex.padEnd(48, ' ')}  |${ascii}|\n`
          }
        }
        setFilePreview(preview)
      }

      setSelectedFile(filePath)
      setFileViewMode('preview')
    } catch (error) {
      console.error('Preview error:', error)
      toast.error('Failed to preview file')
    }
  }

  const deleteFile = (filePath: string) => {
    if (!pyodide) return
    if (!confirm(`Delete ${filePath.split('/').pop()}?`)) return

    try {
      pyodide.FS.unlink(filePath)
      setUploadedFiles(prev => prev.filter(f => `/uploads/${f.path}` !== filePath))
      if (selectedFile === filePath) {
        setSelectedFile(null)
        setFilePreview('')
        setImagePreview('')
        setFileMetadata(null)
        setHexData('')
      }
      toast.success('File deleted')
    } catch (error) {
      console.error('Delete error:', error)
      toast.error('Failed to delete file')
    }
  }

  const getFileIcon = (fileName: string, isDirectory: boolean) => {
    if (isDirectory) return <FolderOpen className="h-4 w-4 text-yellow-400" />

    const ext = fileName.split('.').pop()?.toLowerCase()

    if (['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp'].includes(ext || '')) {
      return <ImageIcon className="h-4 w-4 text-purple-400" />
    }
    if (['zip', 'tar', 'gz', 'rar', '7z'].includes(ext || '')) {
      return <Archive className="h-4 w-4 text-orange-400" />
    }
    if (['py', 'js', 'ts', 'html', 'css', 'json', 'xml'].includes(ext || '')) {
      return <FileCode className="h-4 w-4 text-green-400" />
    }
    if (['txt', 'md', 'log', 'csv'].includes(ext || '')) {
      return <FileText className="h-4 w-4 text-blue-400" />
    }

    return <FileQuestion className="h-4 w-4 text-gray-400" />
  }

  const renderFileTree = (node: FileTreeNode, depth: number = 0): JSX.Element => {
    const isExpanded = expandedFolders.has(node.path)
    const isSelected = selectedFile === node.path

    return (
      <div key={node.path}>
        <div
          className={`flex items-center gap-2 py-1 px-2 rounded cursor-pointer hover:bg-muted/50 ${isSelected ? 'bg-accent/20 border-l-2 border-accent' : ''}`}
          style={{ paddingLeft: `${depth * 12 + 8}px` }}
          onClick={() => {
            if (node.isDirectory) {
              toggleFolder(node.path)
            } else {
              previewFile(node.path)
            }
          }}
        >
          {node.isDirectory && (
            isExpanded ? <ChevronDown className="h-3 w-3" /> : <ChevronRight className="h-3 w-3" />
          )}
          {!node.isDirectory && <span className="w-3" />}
          {getFileIcon(node.name, node.isDirectory)}
          <span className="flex-1 text-xs font-mono truncate">{node.name}</span>
          {!node.isDirectory && node.size !== undefined && (
            <span className="text-xs text-muted-foreground">{(node.size / 1024).toFixed(1)} KB</span>
          )}
          {!node.isDirectory && (
            <div className="flex gap-1 opacity-0 group-hover:opacity-100">
              <Button
                variant="ghost"
                size="sm"
                className="h-5 w-5 p-0"
                onClick={(e) => {
                  e.stopPropagation()
                  downloadFile(node.path)
                }}
                title="Download"
              >
                <Download className="h-3 w-3" />
              </Button>
              <Button
                variant="ghost"
                size="sm"
                className="h-5 w-5 p-0"
                onClick={(e) => {
                  e.stopPropagation()
                  deleteFile(node.path)
                }}
                title="Delete"
              >
                <Trash2 className="h-3 w-3 text-red-400" />
              </Button>
            </div>
          )}
        </div>
        {node.isDirectory && isExpanded && node.children && node.children.length > 0 && (
          <div>
            {node.children.map(child => renderFileTree(child, depth + 1))}
          </div>
        )}
      </div>
    )
  }

  const filteredExamples = categoryFilter === 'All'
    ? pythonScripts
    : pythonScripts.filter(ex => ex.category === categoryFilter)

  const displayOutput = outputFilter.trim()
    ? output.split('\n').filter(line => line.toLowerCase().includes(outputFilter.toLowerCase())).join('\n')
    : output

  const formatOutput = (text: string) => {
    const lines = text.split('\n')
    return lines.map((line, index) => {
      let className = 'text-green-400'
      if (line.includes('Error') || line.includes('Exception') || line.includes('Traceback') || line.startsWith('Error:')) className = 'text-red-400 font-semibold'
      else if (line.includes('Warning')) className = 'text-yellow-400'
      else if (line.includes('Success')) className = 'text-green-300 font-semibold'
      else if (line.startsWith('>>>') || line.startsWith('===')) className = 'text-blue-400'

      return <div key={index} className={`${className} font-mono leading-relaxed hover:bg-white/5`} style={{ fontSize: `${terminalFontSize}px` }}>{line || '\u00A0'}</div>
    })
  }

  if (isLoading) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="text-center space-y-4">
          <Loader2 className="w-12 h-12 animate-spin mx-auto text-accent" />
          <h2 className="text-2xl font-bold">Loading Python Environment</h2>
          <p className="text-muted-foreground">{loadingStatus}</p>
          <p className="text-sm text-muted-foreground">This may take a few seconds on first load...</p>
        </div>
      </div>
    )
  }

  return (
    <div className="p-6 min-h-screen flex flex-col" onDragEnter={handleDragEnter} onDragOver={handleDragOver} onDragLeave={handleDragLeave} onDrop={handleDrop}>
      {isDragging && (
        <div className="fixed inset-0 bg-accent/20 border-4 border-dashed border-accent z-50 flex items-center justify-center pointer-events-none">
          <div className="text-center">
            <Upload className="w-16 h-16 mx-auto text-accent mb-4" />
            <p className="text-2xl font-bold text-accent">Drop files or folders here</p>
          </div>
        </div>
      )}

      <input ref={fileInputRef} type="file" multiple onChange={handleFileUpload} className="hidden" />
      <input ref={folderInputRef} type="file" webkitdirectory="" directory="" onChange={handleFolderUpload} className="hidden" />

      <div className="flex justify-center gap-3 mb-4 flex-shrink-0 items-center flex-wrap">
        <Button onClick={() => fileInputRef.current?.click()} variant="outline" size="sm">
          <Upload className="h-4 w-4 mr-2" />
          Upload File
          {uploadedFiles.length > 0 && (
            <span className="ml-2 px-1.5 py-0.5 bg-accent/20 text-accent rounded-full text-xs font-bold">{uploadedFiles.length}</span>
          )}
        </Button>
        <Button onClick={() => folderInputRef.current?.click()} variant="outline" size="sm">
          <FolderOpen className="h-4 w-4 mr-2" />
          Upload Folder
        </Button>
        <Button onClick={() => setShowScriptsBrowser(true)} variant="outline" size="sm">
          <BookOpen className="h-4 w-4 mr-2" />
          Scripts
        </Button>
        <Button onClick={() => setShowFileBrowser(true)} variant="outline" size="sm">
          <FolderOpen className="h-4 w-4 mr-2" />
          File Browser
        </Button>
        <Button onClick={() => setShowPackageManager(true)} variant="outline" size="sm">
          <Package className="h-4 w-4 mr-2" />
          Package Manager
        </Button>
        <Button onClick={() => setShowQuickGuide(true)} variant="outline" size="sm">
          <AlertCircle className="h-4 w-4 mr-2" />
          Quick Guide
        </Button>
      </div>

      <div style={{ height: `${panelHeight}px`, display: 'flex', flexDirection: 'column' }}>
        <PanelGroup direction="horizontal">
          <Panel defaultSize={50} minSize={30}>
            <Card className="p-4 h-full flex flex-col">
              <div className="flex items-center gap-2 mb-3 border-b border-border pb-2 overflow-x-auto">
                {tabs.map(tab => (
                  <div key={tab.id} className={`flex items-center gap-2 px-3 py-1.5 rounded-t text-xs cursor-pointer transition-colors ${tab.id === activeTabId ? 'bg-accent text-white' : 'bg-muted/20 hover:bg-muted/40'}`}>
                    <button onClick={() => setActiveTabId(tab.id)} onDoubleClick={() => renameTab(tab.id)} className="flex items-center gap-1">
                      <Code className="h-3 w-3" />
                      <span>{tab.name}</span>
                      {tab.unsaved && <span className="text-yellow-400">*</span>}
                    </button>
                    <button onClick={() => closeTab(tab.id)} className="hover:text-red-400">
                      <X className="h-3 w-3" />
                    </button>
                  </div>
                ))}
                <Button onClick={createNewTab} variant="ghost" size="sm" className="h-7 w-7 p-0 flex-shrink-0">
                  <Plus className="h-4 w-4" />
                </Button>
              </div>

              <div className="flex items-center justify-between mb-3">
                <h3 className="font-semibold flex items-center gap-2">
                  <Code className="h-4 w-4" />
                  Python Editor
                </h3>
                <div className="flex gap-2 items-center">
                  <div className="flex items-center gap-2 border-r border-border pr-2">
                    <label htmlFor="editorFontSize" className="text-xs text-muted-foreground whitespace-nowrap font-medium">
                      Text Size:
                    </label>
                    <Input
                      id="editorFontSize"
                      type="number"
                      min="8"
                      max="32"
                      value={editorFontSize}
                      onChange={(e) => setEditorFontSize(Math.max(8, Math.min(32, parseInt(e.target.value) || 14)))}
                      className="w-16 h-8 text-xs text-center [color-scheme:dark] bg-background hover:bg-accent/10 transition-colors"
                    />
                    <span className="text-xs text-muted-foreground">px</span>
                  </div>
                  <Button onClick={handleUndo} variant="outline" size="sm" title="Undo (Ctrl+Z)">
                    <Undo2 className="h-4 w-4" />
                  </Button>
                  <Button onClick={handleRedo} variant="outline" size="sm" title="Redo (Ctrl+Y)">
                    <Redo2 className="h-4 w-4" />
                  </Button>
                  <Button onClick={() => setShowSaveDialog(true)} variant="outline" size="sm">
                    <Save className="h-4 w-4 mr-2" />
                    Save
                  </Button>

                  <Button onClick={runCode} disabled={isRunning} size="sm" className="bg-accent hover:bg-accent/90">
                    {isRunning ? (
                      <>
                        <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                        Running...
                      </>
                    ) : (
                      <>
                        <Play className="h-4 w-4 mr-2" />
                        Run Script
                      </>
                    )}
                  </Button>
                </div>
              </div>

              <div className="flex-1 border border-border rounded-lg overflow-hidden">
                <Editor
                  language="python"
                  value={activeTab.code}
                  onChange={(value) => updateActiveTabCode(value || '')}
                  onMount={(editor) => { editorRef.current = editor }}
                  theme="vs-dark"
                  options={{
                  minimap: { enabled: false },
                  fontSize: editorFontSize,
                  lineNumbers: 'on',
                  scrollBeyondLastLine: false,
                  automaticLayout: true,
                  tabSize: 4,
                  wordWrap: 'on',
                  padding: { top: 10, bottom: 10 },
                  find: {
                    addExtraSpaceOnTop: false,
                    autoFindInSelection: 'never',
                    seedSearchStringFromSelection: 'always'
                  }
                }} />
              </div>
              <div className="mt-2 text-xs text-muted-foreground">
                Press <kbd className="px-1.5 py-0.5 bg-muted rounded border border-border">Ctrl+F</kbd> to find, <kbd className="px-1.5 py-0.5 bg-muted rounded border border-border">Ctrl+H</kbd> to find & replace
              </div>
            </Card>
          </Panel>

          <PanelResizeHandle className="w-2 bg-border hover:bg-accent transition-colors cursor-col-resize" />

          <Panel defaultSize={50} minSize={30}>
            <Card className="p-4 h-full flex flex-col">
              <div className="flex items-center justify-between mb-3">
                <h3 className="font-semibold flex items-center gap-2">
                  <Terminal className="h-4 w-4" />
                  Output Terminal
                </h3>
                <div className="flex gap-2 items-center">
                  <div className="flex items-center gap-2 border-r border-border pr-2">
                    <label htmlFor="terminalFontSize" className="text-xs text-muted-foreground whitespace-nowrap font-medium">
                      Text Size:
                    </label>
                    <Input
                      id="terminalFontSize"
                      type="number"
                      min="8"
                      max="32"
                      value={terminalFontSize}
                      onChange={(e) => setTerminalFontSize(Math.max(8, Math.min(32, parseInt(e.target.value) || 14)))}
                      className="w-16 h-7 text-xs text-center [color-scheme:dark] bg-background hover:bg-accent/10 transition-colors"
                    />
                    <span className="text-xs text-muted-foreground">px</span>
                  </div>
                  <div className="relative">
                    <Search className="absolute left-2 top-1/2 transform -translate-y-1/2 w-3 h-3 text-muted-foreground" />
                    <Input type="text" placeholder="Filter output..." value={outputFilter} onChange={(e) => setOutputFilter(e.target.value)} className="pl-7 pr-2 h-7 w-40 text-xs" />
                  </div>

                  <Button variant="ghost" size="sm" onClick={() => setAutoScroll(!autoScroll)} className="h-7 w-7 p-0" title={autoScroll ? 'Disable auto-scroll' : 'Enable auto-scroll'}>
                    {autoScroll ? <Lock className="h-3 w-3" /> : <Unlock className="h-3 w-3" />}
                  </Button>

                  {output && (
                    <>
                      <Button onClick={copyOutput} variant="ghost" size="sm" className="h-7 w-7 p-0" title="Copy output">
                        <Code className="h-3 w-3" />
                      </Button>
                      <Button onClick={downloadOutput} variant="ghost" size="sm" className="h-7 w-7 p-0" title="Download output">
                        <Download className="h-3 w-3" />
                      </Button>
                      <Button onClick={clearOutput} variant="ghost" size="sm" className="h-7 w-7 p-0" title="Clear output">
                        <Trash2 className="h-3 w-3" />
                      </Button>
                    </>
                  )}
                </div>
              </div>

              <div ref={outputRef} className="flex-1 bg-black/90 p-4 rounded border border-border overflow-y-auto">
                {displayOutput ? (
                  formatOutput(displayOutput)
                ) : (
                  <pre className="text-green-400/60 font-mono leading-tight" style={{ fontSize: `${terminalFontSize}px` }}>
{`System initialized...

|+| Pyodide Version | v0.28.3
|+| Premade Tools   | 17


★ 𝗦𝘂𝗽𝗽𝗼𝗿𝘁 𝘂𝘀 𝗼𝗻 𝗚𝗶𝘁𝗵𝘂𝗯! ★

`}
<a href="https://github.com/sectoolbox/sectoolbox" target="_blank" rel="noopener noreferrer" className="text-cyan-400/70 hover:text-cyan-400 no-underline">
╰┈➤ https://github.com/sectoolbox/sectoolbox
</a>
{`

             ╱|、
            (˚ˎ 。7   what is that...
            |、˜〵          
            じしˍ,)ノ
            
`}
                  </pre>
                )}
              </div>

              {output && (
                <div className="mt-2 flex items-center justify-between text-xs text-muted-foreground">
                  <div>
                    Lines: {output.split('\n').length} |
                    Characters: {output.length}
                    {outputFilter && ` | Filtered: ${displayOutput.split('\n').length} lines`}
                  </div>
                  <div className="flex items-center gap-2">
                    <span className={autoScroll ? 'text-green-400' : 'text-muted-foreground'}>
                      Auto-scroll: {autoScroll ? 'ON' : 'OFF'}
                    </span>
                  </div>
                </div>
              )}
            </Card>
          </Panel>
          </PanelGroup>

        {/* Bottom resize handle */}
        <div
          onMouseDown={handleResizeStart}
          className="h-3 bg-border hover:bg-accent transition-colors cursor-row-resize flex items-center justify-center"
          style={{ userSelect: 'none' }}
        >
          <div className="w-12 h-1 bg-muted-foreground/30 rounded"></div>
        </div>
      </div>

      {showSaveDialog && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <Card className="p-6 w-96">
            <h3 className="font-semibold mb-4">Save Script</h3>
            <input type="text" placeholder="Script name..." value={scriptName} onChange={(e) => setScriptName(e.target.value)} className="w-full p-2 rounded bg-background border border-border mb-4" autoFocus onKeyDown={(e) => {
              if (e.key === 'Enter') saveScript()
              if (e.key === 'Escape') setShowSaveDialog(false)
            }} />
            <div className="flex gap-2 justify-end">
              <Button onClick={() => setShowSaveDialog(false)} variant="outline" size="sm">Cancel</Button>
              <Button onClick={saveScript} size="sm">Save</Button>
            </div>
          </Card>
        </div>
      )}

      {showPackageManager && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <Card className="w-full max-w-4xl h-[75vh] flex flex-col">
            <div className="flex items-center justify-between p-4 border-b border-border">
              <h3 className="font-semibold text-xl flex items-center gap-2">
                <Package className="h-5 w-5 text-accent" />
                Package Manager
              </h3>
              <Button onClick={() => setShowPackageManager(false)} variant="ghost" size="sm">
                <X className="h-4 w-4" />
              </Button>
            </div>

            <div className="p-4 border-b border-border">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  type="text"
                  placeholder="Search or enter package name to install..."
                  value={packageSearch}
                  onChange={(e) => setPackageSearch(e.target.value)}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' && packageSearch.trim()) {
                      installPackage(packageSearch.trim())
                      setPackageSearch('')
                    }
                  }}
                  className="pl-10"
                />
              </div>
              <p className="text-xs text-muted-foreground mt-2">
                Press Enter to install. Packages are downloaded from PyPI via micropip.
              </p>
            </div>

            <div className="flex-1 overflow-hidden p-4">
              <PanelGroup direction="vertical">
                <Panel defaultSize={60} minSize={40}>
                  <div className="h-full flex flex-col">
                    <h4 className="font-semibold text-sm mb-3 flex items-center gap-2">
                      <Package className="h-4 w-4 text-accent" />
                      Popular Forensics & CTF Packages
                    </h4>
                    <div className="flex-1 overflow-y-auto space-y-2">
                      {popularPackages
                        .filter(pkg =>
                          packageSearch === '' ||
                          pkg.name.toLowerCase().includes(packageSearch.toLowerCase()) ||
                          pkg.description.toLowerCase().includes(packageSearch.toLowerCase())
                        )
                        .map(pkg => {
                          const isInstalled = installedPackages.includes(pkg.name)
                          return (
                            <div
                              key={pkg.name}
                              className="flex items-center justify-between p-3 bg-muted/20 rounded border border-border hover:border-accent/30 transition-colors"
                            >
                              <div className="flex-1">
                                <div className="font-mono font-semibold text-sm flex items-center gap-2">
                                  {pkg.name}
                                  {isInstalled && (
                                    <span className="px-2 py-0.5 bg-green-500/20 text-green-400 text-xs rounded">
                                      Installed
                                    </span>
                                  )}
                                </div>
                                <div className="text-xs text-muted-foreground mt-1">{pkg.description}</div>
                              </div>
                              <Button
                                onClick={() => installPackage(pkg.name)}
                                disabled={isInstalling || isInstalled}
                                size="sm"
                                variant={isInstalled ? 'outline' : 'default'}
                                className="ml-4"
                              >
                                {isInstalling ? (
                                  <Loader2 className="h-3 w-3 animate-spin" />
                                ) : isInstalled ? (
                                  'Installed'
                                ) : (
                                  'Install'
                                )}
                              </Button>
                            </div>
                          )
                        })}
                    </div>
                  </div>
                </Panel>

                <PanelResizeHandle className="h-2 bg-border hover:bg-accent transition-colors cursor-row-resize my-2" />

                <Panel defaultSize={40} minSize={30}>
                  <div className="h-full flex flex-col">
                    <h4 className="font-semibold text-sm mb-3 flex items-center gap-2">
                      <Package className="h-4 w-4 text-green-400" />
                      Installed Packages ({installedPackages.length})
                    </h4>
                    <div className="flex-1 overflow-y-auto space-y-1">
                      {installedPackages.map(pkg => (
                        <div
                          key={pkg}
                          className="flex items-center justify-between p-2 bg-muted/10 rounded text-xs hover:bg-muted/20 transition-colors"
                        >
                          <span className="font-mono">{pkg}</span>
                          {!['micropip', 'sys', 'io', 'os', 'hashlib', 're', 'json', 'base64', 'struct', 'datetime', 'zipfile', 'tarfile'].includes(pkg) && (
                            <Button
                              onClick={() => uninstallPackage(pkg)}
                              variant="ghost"
                              size="sm"
                              className="h-6 px-2 text-red-400 hover:text-red-300"
                            >
                              <Trash2 className="h-3 w-3" />
                            </Button>
                          )}
                        </div>
                      ))}
                    </div>
                  </div>
                </Panel>
              </PanelGroup>
            </div>

            <div className="flex items-center justify-between p-4 border-t border-border bg-muted/20 text-xs text-muted-foreground">
              <div>
                Packages are installed via micropip from PyPI
              </div>
              <div className="flex items-center gap-2">
                <span className="text-accent">Tip:</span>
                Core packages cannot be uninstalled
              </div>
            </div>
          </Card>
        </div>
      )}

      {showFileBrowser && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <Card className="w-full max-w-6xl h-[80vh] flex flex-col">
            <div className="flex items-center justify-between p-4 border-b border-border">
              <h3 className="font-semibold text-xl flex items-center gap-2">
                <FolderOpen className="h-5 w-5 text-accent" />
                File Browser - /uploads/
              </h3>
              <Button onClick={() => setShowFileBrowser(false)} variant="ghost" size="sm">
                <X className="h-4 w-4" />
              </Button>
            </div>

            <div className="flex-1 overflow-hidden">
              <PanelGroup direction="horizontal">
                <Panel defaultSize={40} minSize={25}>
                  <div className="h-full overflow-y-auto p-4 border-r border-border">
                    <div className="space-y-1 group">
                      {buildFileTree().children && buildFileTree().children.length > 0 ? (
                        buildFileTree().children.map(child => renderFileTree(child, 0))
                      ) : (
                        <div className="text-center text-muted-foreground text-sm py-8">
                          <FolderOpen className="h-12 w-12 mx-auto mb-3 opacity-50" />
                          <p>No files uploaded yet</p>
                          <p className="text-xs mt-2">Upload files to get started</p>
                        </div>
                      )}
                    </div>
                  </div>
                </Panel>

                <PanelResizeHandle className="w-2 bg-border hover:bg-accent transition-colors cursor-col-resize" />

                <Panel defaultSize={60} minSize={30}>
                  <div className="h-full flex flex-col">
                    <div className="flex items-center justify-between p-4 border-b border-border bg-muted/20">
                      <h4 className="font-semibold text-sm flex items-center gap-2">
                        <File className="h-4 w-4" />
                        {selectedFile ? selectedFile.split('/').pop() : 'File Preview'}
                      </h4>
                      {selectedFile && (
                        <div className="flex gap-2">
                          <Button onClick={() => downloadFile(selectedFile)} variant="outline" size="sm">
                            <Download className="h-3 w-3 mr-2" />
                            Download
                          </Button>
                          <Button onClick={() => deleteFile(selectedFile)} variant="outline" size="sm" className="text-red-400 hover:text-red-300">
                            <Trash2 className="h-3 w-3 mr-2" />
                            Delete
                          </Button>
                        </div>
                      )}
                    </div>

                    {selectedFile && (
                      <div className="flex gap-2 p-2 bg-muted/10 border-b border-border">
                        <Button
                          onClick={() => setFileViewMode('preview')}
                          variant={fileViewMode === 'preview' ? 'default' : 'outline'}
                          size="sm"
                          className="flex-1"
                        >
                          Preview
                        </Button>
                        <Button
                          onClick={() => setFileViewMode('metadata')}
                          variant={fileViewMode === 'metadata' ? 'default' : 'outline'}
                          size="sm"
                          className="flex-1"
                        >
                          Metadata
                        </Button>
                        <Button
                          onClick={() => setFileViewMode('hex')}
                          variant={fileViewMode === 'hex' ? 'default' : 'outline'}
                          size="sm"
                          className="flex-1"
                        >
                          Hex View
                        </Button>
                      </div>
                    )}

                    <div className="flex-1 overflow-y-auto p-4">
                      {!selectedFile ? (
                        <div className="h-full flex items-center justify-center text-muted-foreground">
                          <div className="text-center">
                            <File className="h-16 w-16 mx-auto mb-4 opacity-50" />
                            <p>Select a file to preview</p>
                            <p className="text-xs mt-2">Click on any file in the tree to view its contents</p>
                          </div>
                        </div>
                      ) : fileViewMode === 'preview' ? (
                        <>
                          {imagePreview ? (
                            <div className="h-full flex items-center justify-center bg-black/50 rounded">
                              <img
                                src={imagePreview}
                                alt={selectedFile?.split('/').pop() || 'Preview'}
                                className="max-w-full max-h-full object-contain"
                              />
                            </div>
                          ) : filePreview ? (
                            <pre className="font-mono text-xs bg-black/50 p-4 rounded whitespace-pre-wrap break-words">
                              {filePreview}
                            </pre>
                          ) : (
                            <div className="h-full flex items-center justify-center text-muted-foreground">
                              <Loader2 className="h-8 w-8 animate-spin" />
                            </div>
                          )}
                        </>
                      ) : fileViewMode === 'metadata' ? (
                        <div className="space-y-3">
                          {fileMetadata ? (
                            <>
                              {fileMetadata.error ? (
                                <div className="text-red-400 bg-red-900/20 p-4 rounded border border-red-500/30">
                                  <p className="font-semibold mb-2">Error extracting metadata:</p>
                                  <pre className="text-xs">{fileMetadata.error}</pre>
                                </div>
                              ) : (
                                <>
                                  <div className="bg-muted/20 p-4 rounded border border-border">
                                    <h5 className="font-semibold text-sm text-accent mb-3">File Information</h5>
                                    <div className="space-y-2 text-xs font-mono">
                                      <div className="flex justify-between">
                                        <span className="text-muted-foreground">Filename:</span>
                                        <span className="text-right">{fileMetadata.filename}</span>
                                      </div>
                                      <div className="flex justify-between">
                                        <span className="text-muted-foreground">Extension:</span>
                                        <span className="text-right">{fileMetadata.extension || 'None'}</span>
                                      </div>
                                      <div className="flex justify-between">
                                        <span className="text-muted-foreground">Size:</span>
                                        <span className="text-right">{fileMetadata.actual_size?.toLocaleString()} bytes</span>
                                      </div>
                                      {fileMetadata.file_type && (
                                        <div className="flex justify-between">
                                          <span className="text-muted-foreground">Type:</span>
                                          <span className="text-right text-accent">{fileMetadata.file_type}</span>
                                        </div>
                                      )}
                                      <div className="flex justify-between">
                                        <span className="text-muted-foreground">Mode:</span>
                                        <span className="text-right">{fileMetadata.mode}</span>
                                      </div>
                                    </div>
                                  </div>

                                  <div className="bg-muted/20 p-4 rounded border border-border">
                                    <h5 className="font-semibold text-sm text-accent mb-3">Timestamps</h5>
                                    <div className="space-y-2 text-xs font-mono">
                                      <div className="flex justify-between">
                                        <span className="text-muted-foreground">Created:</span>
                                        <span className="text-right">{fileMetadata.created}</span>
                                      </div>
                                      <div className="flex justify-between">
                                        <span className="text-muted-foreground">Modified:</span>
                                        <span className="text-right">{fileMetadata.modified}</span>
                                      </div>
                                      <div className="flex justify-between">
                                        <span className="text-muted-foreground">Accessed:</span>
                                        <span className="text-right">{fileMetadata.accessed}</span>
                                      </div>
                                    </div>
                                  </div>

                                  <div className="bg-muted/20 p-4 rounded border border-border">
                                    <h5 className="font-semibold text-sm text-accent mb-3">Cryptographic Hashes</h5>
                                    <div className="space-y-2 text-xs font-mono">
                                      <div>
                                        <span className="text-muted-foreground">MD5:</span>
                                        <div className="mt-1 p-2 bg-black/30 rounded break-all">{fileMetadata.md5}</div>
                                      </div>
                                      <div>
                                        <span className="text-muted-foreground">SHA1:</span>
                                        <div className="mt-1 p-2 bg-black/30 rounded break-all">{fileMetadata.sha1}</div>
                                      </div>
                                      <div>
                                        <span className="text-muted-foreground">SHA256:</span>
                                        <div className="mt-1 p-2 bg-black/30 rounded break-all">{fileMetadata.sha256}</div>
                                      </div>
                                    </div>
                                  </div>

                                  {fileMetadata.magic_bytes && (
                                    <div className="bg-muted/20 p-4 rounded border border-border">
                                      <h5 className="font-semibold text-sm text-accent mb-3">File Signature (Magic Bytes)</h5>
                                      <div className="text-xs font-mono p-2 bg-black/30 rounded break-all">
                                        {fileMetadata.magic_bytes}
                                      </div>
                                    </div>
                                  )}

                                  <div className="bg-muted/20 p-4 rounded border border-border">
                                    <h5 className="font-semibold text-sm text-accent mb-3">Entropy Analysis</h5>
                                    <div className="space-y-2 text-xs font-mono">
                                      <div className="flex justify-between">
                                        <span className="text-muted-foreground">Entropy:</span>
                                        <span className={`text-right font-bold ${fileMetadata.entropy > 7.5 ? 'text-red-400' : fileMetadata.entropy < 5 ? 'text-green-400' : 'text-yellow-400'}`}>
                                          {fileMetadata.entropy}
                                        </span>
                                      </div>
                                      <div className="text-muted-foreground text-[10px] italic">
                                        {fileMetadata.entropy_note}
                                      </div>
                                    </div>
                                  </div>

                                  {fileMetadata.null_bytes !== undefined && (
                                    <div className="bg-muted/20 p-4 rounded border border-border">
                                      <h5 className="font-semibold text-sm text-accent mb-3">Hidden Data Detection</h5>
                                      <div className="space-y-2 text-xs font-mono">
                                        <div className="flex justify-between">
                                          <span className="text-muted-foreground">Null Bytes:</span>
                                          <span className="text-right">{fileMetadata.null_bytes?.toLocaleString()}</span>
                                        </div>
                                        <div className="flex justify-between">
                                          <span className="text-muted-foreground">Null %:</span>
                                          <span className={`text-right ${fileMetadata.null_percentage > 10 ? 'text-yellow-400' : 'text-green-400'}`}>
                                            {fileMetadata.null_percentage}%
                                          </span>
                                        </div>
                                      </div>
                                    </div>
                                  )}

                                  {fileMetadata.lsb_ratio !== undefined && (
                                    <div className="bg-muted/20 p-4 rounded border border-border">
                                      <h5 className="font-semibold text-sm text-accent mb-3">LSB Steganography Analysis</h5>
                                      <div className="space-y-2 text-xs font-mono">
                                        <div className="flex justify-between">
                                          <span className="text-muted-foreground">LSB Ratio:</span>
                                          <span className={`text-right ${fileMetadata.lsb_suspicious ? 'text-red-400 font-bold' : 'text-green-400'}`}>
                                            {fileMetadata.lsb_ratio}
                                          </span>
                                        </div>
                                        <div className="flex justify-between">
                                          <span className="text-muted-foreground">Suspicious:</span>
                                          <span className={`text-right font-bold ${fileMetadata.lsb_suspicious ? 'text-red-400' : 'text-green-400'}`}>
                                            {fileMetadata.lsb_suspicious ? 'YES - Possible steganography!' : 'No'}
                                          </span>
                                        </div>
                                        <div className="text-muted-foreground text-[10px] italic">
                                          Normal ratio is ~0.5. Deviation &gt; 0.1 may indicate hidden data in LSB.
                                        </div>
                                      </div>
                                    </div>
                                  )}

                                  {fileMetadata.strings_found > 0 && (
                                    <div className="bg-muted/20 p-4 rounded border border-border">
                                      <h5 className="font-semibold text-sm text-accent mb-3">String Extraction</h5>
                                      <div className="space-y-2 text-xs">
                                        <div className="flex justify-between font-mono">
                                          <span className="text-muted-foreground">Total Strings Found:</span>
                                          <span className="text-right">{fileMetadata.strings_found}</span>
                                        </div>
                                        {fileMetadata.all_strings && (
                                          <div>
                                            <p className="text-muted-foreground mb-2">All Strings:</p>
                                            <div className="space-y-1 max-h-96 overflow-y-auto">
                                              {fileMetadata.all_strings.map((str: string, idx: number) => (
                                                <div key={idx} className="p-2 bg-black/30 rounded font-mono text-[10px] break-all">
                                                  {str}
                                                </div>
                                              ))}
                                            </div>
                                          </div>
                                        )}
                                      </div>
                                    </div>
                                  )}

                                  {fileMetadata.exif_markers && (
                                    <div className="bg-muted/20 p-4 rounded border border-border">
                                      <h5 className="font-semibold text-sm text-accent mb-3">EXIF Markers Found</h5>
                                      <div className="space-y-2 text-xs font-mono">
                                        {Object.entries(fileMetadata.exif_markers).map(([key, value]) => (
                                          <div key={key} className="flex justify-between">
                                            <span className="text-muted-foreground">{key}:</span>
                                            <span className="text-right text-yellow-400">{String(value)}</span>
                                          </div>
                                        ))}
                                        <div className="text-muted-foreground text-[10px] italic mt-2">
                                          Note: Full EXIF extraction requires pillow package. These are raw marker positions.
                                        </div>
                                      </div>
                                    </div>
                                  )}
                                </>
                              )}
                            </>
                          ) : (
                            <div className="h-full flex items-center justify-center text-muted-foreground">
                              <Loader2 className="h-8 w-8 animate-spin" />
                            </div>
                          )}
                        </div>
                      ) : fileViewMode === 'hex' ? (
                        <div className="h-full">
                          {hexData ? (
                            <pre className="font-mono text-[10px] bg-black/50 p-4 rounded whitespace-pre leading-tight">
                              {hexData}
                            </pre>
                          ) : (
                            <div className="h-full flex items-center justify-center text-muted-foreground">
                              <Loader2 className="h-8 w-8 animate-spin" />
                            </div>
                          )}
                        </div>
                      ) : null}
                    </div>
                  </div>
                </Panel>
              </PanelGroup>
            </div>

            <div className="flex items-center justify-between p-4 border-t border-border bg-muted/20 text-xs text-muted-foreground">
              <div>
                Total files: {uploadedFiles.length} |
                Total size: {(uploadedFiles.reduce((sum, f) => sum + f.size, 0) / 1024 / 1024).toFixed(2)} MB
              </div>
              <div className="flex items-center gap-2">
                <span className="text-accent">Tip:</span>
                Click file to preview | Download or delete using buttons
              </div>
            </div>
          </Card>
        </div>
      )}

      {showScriptsBrowser && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <Card className="w-full max-w-6xl h-[85vh] flex flex-col">
            <div className="flex items-center justify-between p-4 border-b border-border">
              <h3 className="font-semibold text-xl flex items-center gap-2">
                <BookOpen className="h-5 w-5 text-accent" />
                Python Scripts Browser
              </h3>
              <Button onClick={() => setShowScriptsBrowser(false)} variant="ghost" size="sm">
                <X className="h-4 w-4" />
              </Button>
            </div>

            <div className="p-4 border-b border-border">
              <div className="flex gap-3 items-center">
                <div className="relative flex-1">
                  <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <Input
                    type="text"
                    placeholder="Search scripts..."
                    value={scriptSearchQuery}
                    onChange={(e) => setScriptSearchQuery(e.target.value)}
                    className="pl-10"
                  />
                </div>
                <select
                  value={categoryFilter}
                  onChange={(e) => setCategoryFilter(e.target.value)}
                  className="p-2 rounded bg-background border border-border text-sm min-w-[150px]"
                >
                  {scriptCategories.map(cat => <option key={cat} value={cat}>{cat}</option>)}
                </select>
              </div>
            </div>

            <div className="flex-1 overflow-y-auto p-6">
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {pythonScripts
                  .filter(script => {
                    const matchesCategory = categoryFilter === 'All' || script.category === categoryFilter
                    const matchesSearch = scriptSearchQuery === '' ||
                      script.title.toLowerCase().includes(scriptSearchQuery.toLowerCase()) ||
                      script.description.toLowerCase().includes(scriptSearchQuery.toLowerCase())
                    return matchesCategory && matchesSearch
                  })
                  .map(script => (
                    <Card
                      key={script.id}
                      className={`p-4 cursor-pointer transition-all hover:border-accent/50 hover:shadow-lg ${selectedExample === script.id ? 'border-accent bg-accent/5' : 'border-border'}`}
                      onClick={() => {
                        loadExample(script.id)
                        setShowScriptsBrowser(false)
                      }}
                    >
                      <div className="flex items-start justify-between mb-2">
                        <h4 className="font-semibold text-sm line-clamp-1">{script.title}</h4>
                        <span className="px-2 py-0.5 bg-accent/20 text-accent text-[10px] rounded-full ml-2 flex-shrink-0">
                          {script.category}
                        </span>
                      </div>
                      <p className="text-xs text-muted-foreground mb-3 line-clamp-2">{script.description}</p>
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] text-muted-foreground font-mono">
                          {script.code.split('\n').length} lines
                        </span>
                        <Button
                          size="sm"
                          variant="outline"
                          className="h-7 text-xs"
                          onClick={(e) => {
                            e.stopPropagation()
                            loadExample(script.id)
                            setShowScriptsBrowser(false)
                          }}
                        >
                          Load Script
                        </Button>
                      </div>
                    </Card>
                  ))}
              </div>

              {pythonScripts.filter(script => {
                const matchesCategory = categoryFilter === 'All' || script.category === categoryFilter
                const matchesSearch = scriptSearchQuery === '' ||
                  script.title.toLowerCase().includes(scriptSearchQuery.toLowerCase()) ||
                  script.description.toLowerCase().includes(scriptSearchQuery.toLowerCase())
                return matchesCategory && matchesSearch
              }).length === 0 && (
                <div className="text-center text-muted-foreground py-12">
                  <BookOpen className="h-16 w-16 mx-auto mb-4 opacity-50" />
                  <p className="text-lg font-semibold mb-2">No scripts found</p>
                  <p className="text-sm">Try adjusting your search or category filter</p>
                </div>
              )}
            </div>

            <div className="flex items-center justify-between p-4 border-t border-border bg-muted/20 text-xs text-muted-foreground">
              <div>
                Showing {pythonScripts.filter(script => {
                  const matchesCategory = categoryFilter === 'All' || script.category === categoryFilter
                  const matchesSearch = scriptSearchQuery === '' ||
                    script.title.toLowerCase().includes(scriptSearchQuery.toLowerCase()) ||
                    script.description.toLowerCase().includes(scriptSearchQuery.toLowerCase())
                  return matchesCategory && matchesSearch
                }).length} of {pythonScripts.length} scripts
              </div>
              <div className="flex items-center gap-2">
                <span className="text-accent">Tip:</span>
                Click any script card to load it instantly
              </div>
            </div>
          </Card>
        </div>
      )}

      {showQuickGuide && (
        <div className="fixed inset-0 bg-black/70 flex items-center justify-center z-50 p-4">
          <Card className="w-full max-w-2xl max-h-[85vh] flex flex-col">
            <div className="flex items-center justify-between p-4 border-b border-border">
              <h3 className="font-semibold text-xl flex items-center gap-2">
                <AlertCircle className="h-5 w-5 text-accent" />
                Quick Guide & Commands
              </h3>
              <Button onClick={() => setShowQuickGuide(false)} variant="ghost" size="sm">
                <X className="h-4 w-4" />
              </Button>
            </div>

            <div className="flex-1 overflow-y-auto p-6 space-y-6">
              <div className="space-y-3">
                <h4 className="font-semibold text-accent flex items-center gap-2">
                  <span className="flex h-6 w-6 items-center justify-center rounded-full bg-accent/20 text-xs">1</span>
                  Upload Files or Folders
                </h4>
                <p className="text-sm text-muted-foreground pl-8">
                  Use the Upload File or Upload Folder buttons, or drag and drop files directly onto the page.
                </p>
              </div>

              <div className="space-y-3">
                <h4 className="font-semibold text-accent flex items-center gap-2">
                  <span className="flex h-6 w-6 items-center justify-center rounded-full bg-accent/20 text-xs">2</span>
                  Use Simple Paths
                </h4>
                <p className="text-sm text-muted-foreground pl-8">
                  Reference uploaded files with simple names like <code className="px-1.5 py-0.5 bg-muted rounded text-xs">sample.bin</code> or relative paths.
                </p>
              </div>

              <div className="space-y-3">
                <h4 className="font-semibold text-accent flex items-center gap-2">
                  <span className="flex h-6 w-6 items-center justify-center rounded-full bg-accent/20 text-xs">3</span>
                  Load Example or Write Code
                </h4>
                <p className="text-sm text-muted-foreground pl-8">
                  Browse example scripts from the Scripts button or write your own Python code in the editor.
                </p>
              </div>

              <div className="space-y-3">
                <h4 className="font-semibold text-accent flex items-center gap-2">
                  <span className="flex h-6 w-6 items-center justify-center rounded-full bg-accent/20 text-xs">4</span>
                  Run Your Script
                </h4>
                <p className="text-sm text-muted-foreground pl-8">
                  Click the <span className="text-accent font-semibold">Run Script</span> button to execute your Python code.
                </p>
              </div>

              <div className="border-t border-border pt-6">
                <h4 className="font-semibold text-accent mb-4">Shell-like Helper Functions</h4>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
                  <div className="bg-muted/20 p-3 rounded">
                    <code className="text-accent">ls()</code>
                    <p className="text-xs text-muted-foreground mt-1">List files in directory</p>
                  </div>
                  <div className="bg-muted/20 p-3 rounded">
                    <code className="text-accent">cat('file')</code>
                    <p className="text-xs text-muted-foreground mt-1">Display file contents</p>
                  </div>
                  <div className="bg-muted/20 p-3 rounded">
                    <code className="text-accent">head('file', 10)</code>
                    <p className="text-xs text-muted-foreground mt-1">Show first 10 lines</p>
                  </div>
                  <div className="bg-muted/20 p-3 rounded">
                    <code className="text-accent">tail('file', 10)</code>
                    <p className="text-xs text-muted-foreground mt-1">Show last 10 lines</p>
                  </div>
                  <div className="bg-muted/20 p-3 rounded">
                    <code className="text-accent">grep('pattern', 'file')</code>
                    <p className="text-xs text-muted-foreground mt-1">Search for pattern</p>
                  </div>
                  <div className="bg-muted/20 p-3 rounded">
                    <code className="text-accent">hexdump('file')</code>
                    <p className="text-xs text-muted-foreground mt-1">Display hex view</p>
                  </div>
                  <div className="bg-muted/20 p-3 rounded">
                    <code className="text-accent">tree()</code>
                    <p className="text-xs text-muted-foreground mt-1">Show directory tree</p>
                  </div>
                  <div className="bg-muted/20 p-3 rounded">
                    <code className="text-accent">pwd()</code>
                    <p className="text-xs text-muted-foreground mt-1">Print working directory</p>
                  </div>
                  <div className="bg-muted/20 p-3 rounded col-span-full">
                    <code className="text-accent">fileinfo('file')</code>
                    <p className="text-xs text-muted-foreground mt-1">Display detailed file information (hashes, type, etc.)</p>
                  </div>
                </div>
              </div>
            </div>

            <div className="flex items-center justify-between p-4 border-t border-border bg-muted/20 text-xs text-muted-foreground">
              <div>
                Python 3.11 via Pyodide | Runs locally in your browser
              </div>
              <div className="flex items-center gap-2">
                <span className="text-accent">Tip:</span>
                Use File Browser to explore uploaded files
              </div>
            </div>
          </Card>
        </div>
      )}
    </div>
  )
}

export default PythonForensics
