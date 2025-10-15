import React, { useState, useEffect, useRef } from 'react'
import { Upload, Play, Download, Trash2, Save, FolderOpen, Package, Terminal, Code, BookOpen, Loader2, AlertCircle, Search, Lock, Unlock, X, Plus, Undo2, Redo2 } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Card } from '../components/ui/card'
import { Input } from '../components/ui/input'
import Editor from '@monaco-editor/react'
import { Panel, PanelGroup, PanelResizeHandle } from 'react-resizable-panels'
import { loadPythonScripts, getScriptCategories, PythonScript } from '../lib/pythonScriptLoader'
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
file_path = '/uploads/sample.bin'

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

  const fileInputRef = useRef<HTMLInputElement>(null)
  const folderInputRef = useRef<HTMLInputElement>(null)
  const outputRef = useRef<HTMLDivElement>(null)
  const editorRef = useRef<any>(null)

  const activeTab = tabs.find(t => t.id === activeTabId) || tabs[0]

  useEffect(() => {
    loadPyodide()
    loadScripts()
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

  useEffect(() => {
    if (autoScroll && outputRef.current) {
      outputRef.current.scrollTop = outputRef.current.scrollHeight
    }
  }, [output, autoScroll])

  const loadPyodide = async () => {
    try {
      setLoadingStatus('Loading Python environment...')
      const pyodideModule = await (window as any).loadPyodide({
        indexURL: 'https://cdn.jsdelivr.net/pyodide/v0.28.3/full/'
      })

      setLoadingStatus('Installing core packages...')
      await pyodideModule.loadPackage(['micropip'])

      pyodideModule.runPython(`
import sys
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
`)

      try {
        pyodideModule.FS.mkdir('/uploads')
      } catch (e) {}

      setPyodide(pyodideModule)
      setLoadingStatus('Ready!')
      setIsLoading(false)
      setInstalledPackages(['micropip', 'sys', 'io', 'os', 'hashlib', 're', 'json', 'base64', 'struct', 'datetime', 'zipfile', 'tarfile'])
      toast.success('Python environment loaded successfully!')
    } catch (error) {
      console.error('Failed to load Pyodide:', error)
      setOutput(`❌ Failed to load Python environment: ${error}`)
      setIsLoading(false)
      toast.error('Failed to load Python environment')
    }
  }

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
      setOutput(result || '✅ Code executed successfully (no output)')
    } catch (error: any) {
      setOutput(`❌ Error:\n${error.message || String(error)}`)
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

          const oldPattern = /['"]\/uploads\/[^'"]+['"]/g
          const newPath = `'/uploads/${fullPath}'`
          updateActiveTabCode(activeTab.code.replace(oldPattern, newPath))
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

        const oldPattern = /['"]\/uploads\/[^'"]+['"]/g
        const newPath = `'/uploads/${file.name}'`
        updateActiveTabCode(activeTab.code.replace(oldPattern, newPath))
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
      const oldPattern = /['"]\/uploads\/[^'"]+['"]/g
      const newPath = `'/uploads/${lastUploadedFilename}'`
      const updatedCode = example.code.replace(oldPattern, newPath)

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
    try {
      setOutput(`>>> Installing ${packageName}...\n`)
      await pyodide.runPythonAsync(`
import micropip
await micropip.install('${packageName}')
`)
      setInstalledPackages(prev => [...prev, packageName])
      setOutput(prev => prev + `✅ ${packageName} installed successfully\n`)
      toast.success(`Installed: ${packageName}`)
    } catch (error: any) {
      setOutput(prev => prev + `❌ Failed to install ${packageName}: ${error.message}\n`)
      toast.error(`Failed to install ${packageName}`)
    }
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
      if (line.includes('Error') || line.includes('Exception') || line.includes('Traceback') || line.startsWith('❌')) className = 'text-red-400 font-semibold'
      else if (line.includes('Warning') || line.includes('⚠️')) className = 'text-yellow-400'
      else if (line.includes('✅') || line.includes('Success')) className = 'text-green-300 font-semibold'
      else if (line.startsWith('>>>') || line.startsWith('===')) className = 'text-blue-400'

      return <div key={index} className={`${className} font-mono text-xs leading-relaxed hover:bg-white/5`}>{line || '\u00A0'}</div>
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
    <div className="p-6 space-y-4 h-screen flex flex-col" onDragEnter={handleDragEnter} onDragOver={handleDragOver} onDragLeave={handleDragLeave} onDrop={handleDrop}>
      {isDragging && (
        <div className="fixed inset-0 bg-accent/20 border-4 border-dashed border-accent z-50 flex items-center justify-center pointer-events-none">
          <div className="text-center">
            <Upload className="w-16 h-16 mx-auto text-accent mb-4" />
            <p className="text-2xl font-bold text-accent">Drop files or folders here</p>
          </div>
        </div>
      )}

      <div className="text-center space-y-2 flex-shrink-0">
        <h1 className="text-3xl font-bold flex items-center justify-center gap-2">
          <Code className="h-8 w-8 text-accent" />
          Python Forensics Environment
        </h1>
        <p className="text-muted-foreground max-w-3xl mx-auto">
          Python environment running locally in your browser. Upload files, run scripts & and analyze data!
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4 flex-shrink-0">
        <Card className="p-4 flex flex-col">
          <div className="flex items-center justify-between mb-3">
            <h3 className="font-semibold flex items-center gap-2">
              <Upload className="h-4 w-4 text-accent" />
              Upload Files
            </h3>
            {uploadedFiles.length > 0 && (
              <span className="px-2 py-1 bg-accent/20 text-accent rounded-full text-xs font-bold">{uploadedFiles.length}</span>
            )}
          </div>

          <input ref={fileInputRef} type="file" multiple onChange={handleFileUpload} className="hidden" />
          <input ref={folderInputRef} type="file" webkitdirectory="" directory="" onChange={handleFolderUpload} className="hidden" />

          <div className="space-y-2 mb-3">
            <Button onClick={() => fileInputRef.current?.click()} variant="outline" className="w-full" size="sm">
              <Upload className="h-4 w-4 mr-2" />
              Choose Files
            </Button>
            <Button onClick={() => folderInputRef.current?.click()} variant="outline" className="w-full" size="sm">
              <FolderOpen className="h-4 w-4 mr-2" />
              Choose Folder
            </Button>
          </div>

          <div className="text-xs text-center text-muted-foreground mb-2">or drag & drop files/folders</div>

          <div className="flex-1 space-y-1 max-h-32 overflow-y-auto">
            {uploadedFiles.map((file, index) => (
              <div key={index} className="flex items-center justify-between bg-muted/20 p-2 rounded text-xs">
                <div className="flex-1 truncate">
                  <div className="font-mono truncate">{file.path}</div>
                  <div className="text-muted-foreground">{(file.size / 1024).toFixed(1)} KB</div>
                </div>
                <Button variant="ghost" size="sm" onClick={() => deleteUploadedFile(file.path)} className="h-6 w-6 p-0 ml-2">
                  <Trash2 className="h-3 w-3" />
                </Button>
              </div>
            ))}
            {uploadedFiles.length === 0 && (
              <div className="text-center text-muted-foreground text-xs py-4">No files uploaded yet</div>
            )}
          </div>
        </Card>

        <Card className="p-4 flex flex-col">
          <div className="flex items-center justify-between mb-3">
            <h3 className="font-semibold flex items-center gap-2">
              <BookOpen className="h-4 w-4 text-accent" />
              Scripts
            </h3>
          </div>

          <select value={categoryFilter} onChange={(e) => setCategoryFilter(e.target.value)} className="w-full mb-2 p-2 rounded bg-background border border-border text-xs">
            {scriptCategories.map(cat => <option key={cat} value={cat}>{cat}</option>)}
          </select>

          <div className="flex-1 space-y-1 max-h-32 overflow-y-auto">
            {filteredExamples.map(example => (
              <button key={example.id} onClick={() => loadExample(example.id)} className={`w-full text-left p-2 rounded text-xs hover:bg-muted/50 transition-colors ${selectedExample === example.id ? 'bg-accent/20 border border-accent' : 'bg-muted/20'}`}>
                <div className="font-medium truncate">{example.title}</div>
              </button>
            ))}
            {filteredExamples.length === 0 && (
              <div className="text-center text-muted-foreground text-xs py-4">No scripts available</div>
            )}
          </div>
        </Card>

        <Card className="p-4 flex flex-col">
          <h3 className="font-semibold mb-3 flex items-center gap-2">
            <Package className="h-4 w-4 text-accent" />
            Install Package
          </h3>

          <input type="text" placeholder="Package name (e.g., pefile)" className="w-full p-2 rounded bg-background border border-border text-xs mb-2" onKeyDown={(e) => {
            if (e.key === 'Enter') {
              const input = e.target as HTMLInputElement
              if (input.value.trim()) {
                installPackage(input.value.trim())
                input.value = ''
              }
            }
          }} />

          <div className="flex-1 space-y-1">
            <div className="text-xs text-muted-foreground mb-1">Installed ({installedPackages.length}):</div>
            <div className="max-h-20 overflow-y-auto space-y-1">
              {installedPackages.slice(0, 10).map((pkg, index) => (
                <div key={index} className="text-xs font-mono bg-muted/20 px-2 py-1 rounded">{pkg}</div>
              ))}
            </div>
          </div>
        </Card>

        <Card className="p-4 flex flex-col">
          <h3 className="font-semibold mb-3 flex items-center gap-2">
            <AlertCircle className="h-4 w-4 text-accent" />
            Quick Guide
          </h3>

          <div className="flex-1 space-y-2 text-xs text-muted-foreground">
            <p className="flex items-start gap-2">
              <span className="text-accent font-bold">1.</span>
              Upload files or folders
            </p>
            <p className="flex items-start gap-2">
              <span className="text-accent font-bold">2.</span>
              Files accessible at <code className="bg-muted px-1 rounded text-[10px]">/uploads/</code>
            </p>
            <p className="flex items-start gap-2">
              <span className="text-accent font-bold">3.</span>
              Load example or write code
            </p>
            <p className="flex items-start gap-2">
              <span className="text-accent font-bold">4.</span>
              Click <span className="text-accent">Run Script</span>
            </p>
            <p className="flex items-start gap-2">
              <span className="text-accent font-bold">5.</span>
              View results in output panel
            </p>
          </div>
        </Card>
      </div>

      <div className="flex-1 min-h-0">
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
                <div className="flex gap-2">
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
                  fontSize: 13,
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
                  <pre className="text-green-400/60 font-mono text-[14px] leading-tight">
{`System initialized...
|+| Pyodide Version      | v0.28.3 loaded
|+| Premade Tools Loaded | 17 forensic tools ready

   __                                  __                 
  (_     _  _  _  _|_      _   _  _   / _ .|_|__|   |_ |  
  __)|_||_)|_)(_)| |_  |_|_)  (_)| )  \__)||_|  ||_||_).  
        |  |  

`}
<a href="https://github.com/sectoolbox/sectoolbox" target="_blank" rel="noopener noreferrer" className="text-cyan-400/70 hover:text-cyan-400 no-underline">
╰┈➤ https://github.com/sectoolbox/sectoolbox
</a>
{`
              ╱|、
            (˚ˎ 。7
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
    </div>
  )
}

export default PythonForensics
