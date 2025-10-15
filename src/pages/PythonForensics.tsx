import React, { useState, useEffect, useRef } from 'react'
import { Upload, Play, Download, Trash2, Save, FolderOpen, Package, Terminal, Code, BookOpen, Loader2, AlertCircle } from 'lucide-react'
import { Button } from '../components/ui/button'
import { Card } from '../components/ui/card'
import Editor from '@monaco-editor/react'
import { pythonExamples, exampleCategories, PythonExample } from '../lib/pythonExamples'
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

const PythonForensics: React.FC = () => {
  const [pyodide, setPyodide] = useState<PyodideInterface | null>(null)
  const [isLoading, setIsLoading] = useState(true)
  const [loadingStatus, setLoadingStatus] = useState('Initializing...')
  const [code, setCode] = useState(`# Python Forensics Environment
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
`)
  const [output, setOutput] = useState('')
  const [isRunning, setIsRunning] = useState(false)
  const [uploadedFiles, setUploadedFiles] = useState<{ name: string; size: number }[]>([])
  const [selectedExample, setSelectedExample] = useState<string>('')
  const [categoryFilter, setCategoryFilter] = useState('All')
  const [savedScripts, setSavedScripts] = useState<{ name: string; code: string }[]>([])
  const [showSaveDialog, setShowSaveDialog] = useState(false)
  const [scriptName, setScriptName] = useState('')
  const [installedPackages, setInstalledPackages] = useState<string[]>([])
  const fileInputRef = useRef<HTMLInputElement>(null)
  const outputRef = useRef<HTMLDivElement>(null)

  // Initialize Pyodide
  useEffect(() => {
    loadPyodide()
  }, [])

  // Load saved scripts from localStorage
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

  const loadPyodide = async () => {
    try {
      setLoadingStatus('Loading Python environment...')

      // Load Pyodide from CDN
      const pyodideModule = await (window as any).loadPyodide({
        indexURL: 'https://cdn.jsdelivr.net/pyodide/v0.28.3/full/'
      })

      setLoadingStatus('Installing core packages...')

      // Install essential packages
      await pyodideModule.loadPackage(['micropip'])

      // Setup stdout/stderr capture
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

      // Create uploads directory
      try {
        pyodideModule.FS.mkdir('/uploads')
      } catch (e) {
        // Directory might already exist
      }

      setPyodide(pyodideModule)
      setLoadingStatus('Ready!')
      setIsLoading(false)

      // Track installed packages
      setInstalledPackages(['micropip', 'sys', 'io', 'os', 'hashlib', 're', 'json', 'base64', 'struct', 'datetime'])

      toast.success('Python environment loaded successfully!')
    } catch (error) {
      console.error('Failed to load Pyodide:', error)
      setOutput(`❌ Failed to load Python environment: ${error}`)
      setIsLoading(false)
      toast.error('Failed to load Python environment')
    }
  }

  const runCode = async () => {
    if (!pyodide) {
      toast.error('Python environment not loaded')
      return
    }

    setIsRunning(true)
    setOutput('Running...\n')

    try {
      // Reset output capture
      await pyodide.runPythonAsync(`
sys.stdout = _stdout_capture
sys.stderr = _stderr_capture
_stdout_capture.output = []
_stderr_capture.output = []
`)

      // Try to load packages from imports
      try {
        await pyodide.loadPackagesFromImports(code)
      } catch (e) {
        console.log('Could not auto-load packages:', e)
      }

      // Run the user code
      await pyodide.runPythonAsync(code)

      // Get captured output
      const stdout = await pyodide.runPythonAsync('_stdout_capture.get_output()')
      const stderr = await pyodide.runPythonAsync('_stderr_capture.get_output()')

      let result = ''
      if (stdout) result += stdout
      if (stderr) result += '\n' + stderr

      setOutput(result || '✅ Code executed successfully (no output)')

      // Scroll to bottom of output
      setTimeout(() => {
        if (outputRef.current) {
          outputRef.current.scrollTop = outputRef.current.scrollHeight
        }
      }, 100)

    } catch (error: any) {
      const errorMessage = error.message || String(error)
      setOutput(`❌ Error:\n${errorMessage}`)
      toast.error('Script execution failed')
    } finally {
      setIsRunning(false)
    }
  }

  const handleFileUpload = async (event: React.ChangeEvent<HTMLInputElement>) => {
    if (!pyodide || !event.target.files) return

    const files = Array.from(event.target.files)

    for (const file of files) {
      try {
        const arrayBuffer = await file.arrayBuffer()
        const uint8Array = new Uint8Array(arrayBuffer)

        // Write file to Pyodide filesystem
        pyodide.FS.writeFile(`/uploads/${file.name}`, uint8Array)

        setUploadedFiles(prev => [...prev, { name: file.name, size: file.size }])
        toast.success(`Uploaded: ${file.name}`)

      } catch (error) {
        console.error('File upload error:', error)
        toast.error(`Failed to upload ${file.name}`)
      }
    }

    // Update code to reference the uploaded file
    if (files.length > 0) {
      const fileName = files[0].name
      const newCode = code.replace("'/uploads/sample.bin'", `'/uploads/${fileName}'`)
      setCode(newCode)
    }
  }

  const loadExample = (exampleId: string) => {
    const example = pythonExamples.find(ex => ex.id === exampleId)
    if (example) {
      setCode(example.code)
      setSelectedExample(exampleId)
      setOutput('')
      toast.success(`Loaded: ${example.title}`)

      // Show info if packages are required
      if (example.requiredPackages && example.requiredPackages.length > 0) {
        toast(
          `This script requires: ${example.requiredPackages.join(', ')}\n` +
          `Install with: await micropip.install('${example.requiredPackages[0]}')`,
          { duration: 5000 }
        )
      }
    }
  }

  const saveScript = () => {
    if (!scriptName.trim()) {
      toast.error('Please enter a script name')
      return
    }

    const newScript = { name: scriptName, code }
    const updated = [...savedScripts, newScript]
    setSavedScripts(updated)
    localStorage.setItem('sectoolbox_python_scripts', JSON.stringify(updated))

    setShowSaveDialog(false)
    setScriptName('')
    toast.success(`Saved: ${scriptName}`)
  }

  const loadSavedScript = (script: { name: string; code: string }) => {
    setCode(script.code)
    setOutput('')
    toast.success(`Loaded: ${script.name}`)
  }

  const deleteSavedScript = (index: number) => {
    const updated = savedScripts.filter((_, i) => i !== index)
    setSavedScripts(updated)
    localStorage.setItem('sectoolbox_python_scripts', JSON.stringify(updated))
    toast.success('Script deleted')
  }

  const clearOutput = () => {
    setOutput('')
  }

  const deleteUploadedFile = (fileName: string) => {
    if (!pyodide) return

    try {
      pyodide.FS.unlink(`/uploads/${fileName}`)
      setUploadedFiles(prev => prev.filter(f => f.name !== fileName))
      toast.success(`Deleted: ${fileName}`)
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

  const installPackage = async (packageName: string) => {
    if (!pyodide) return

    try {
      setOutput(`Installing ${packageName}...\n`)
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
    ? pythonExamples
    : pythonExamples.filter(ex => ex.category === categoryFilter)

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
    <div className="p-6 space-y-4">
      {/* Header */}
      <div className="text-center space-y-2">
        <h1 className="text-3xl font-bold flex items-center justify-center gap-2">
          <Code className="h-8 w-8 text-accent" />
          Python Forensics Environment
        </h1>
        <p className="text-muted-foreground max-w-3xl mx-auto">
          Full Python environment running in your browser. Upload files, run forensics scripts, and analyze data with pre-installed libraries.
        </p>
      </div>

      {/* Main Grid */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Left Sidebar - File Manager & Examples */}
        <div className="lg:col-span-3 space-y-4">
          {/* File Upload */}
          <Card className="p-4">
            <h3 className="font-semibold mb-3 flex items-center gap-2">
              <Upload className="h-4 w-4" />
              Upload Files
            </h3>
            <input
              ref={fileInputRef}
              type="file"
              multiple
              onChange={handleFileUpload}
              className="hidden"
            />
            <Button
              onClick={() => fileInputRef.current?.click()}
              variant="outline"
              className="w-full"
              size="sm"
            >
              <Upload className="h-4 w-4 mr-2" />
              Choose Files
            </Button>

            {/* Uploaded Files List */}
            {uploadedFiles.length > 0 && (
              <div className="mt-3 space-y-2">
                <p className="text-xs text-muted-foreground">Uploaded ({uploadedFiles.length}):</p>
                <div className="space-y-1 max-h-48 overflow-y-auto">
                  {uploadedFiles.map((file, index) => (
                    <div key={index} className="flex items-center justify-between bg-muted/20 p-2 rounded text-xs">
                      <div className="flex-1 truncate">
                        <div className="font-mono truncate">{file.name}</div>
                        <div className="text-muted-foreground">
                          {(file.size / 1024).toFixed(1)} KB
                        </div>
                      </div>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => deleteUploadedFile(file.name)}
                        className="h-6 w-6 p-0"
                      >
                        <Trash2 className="h-3 w-3" />
                      </Button>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </Card>

          {/* Example Scripts */}
          <Card className="p-4">
            <h3 className="font-semibold mb-3 flex items-center gap-2">
              <BookOpen className="h-4 w-4" />
              Example Scripts
            </h3>

            {/* Category Filter */}
            <select
              value={categoryFilter}
              onChange={(e) => setCategoryFilter(e.target.value)}
              className="w-full mb-3 p-2 rounded bg-background border border-border text-sm"
            >
              {exampleCategories.map(cat => (
                <option key={cat} value={cat}>{cat}</option>
              ))}
            </select>

            {/* Examples List */}
            <div className="space-y-1 max-h-96 overflow-y-auto">
              {filteredExamples.map(example => (
                <button
                  key={example.id}
                  onClick={() => loadExample(example.id)}
                  className={`w-full text-left p-2 rounded text-xs hover:bg-muted/50 transition-colors ${
                    selectedExample === example.id ? 'bg-accent/20 border border-accent' : 'bg-muted/20'
                  }`}
                >
                  <div className="font-medium">{example.title}</div>
                  <div className="text-muted-foreground text-[10px] mt-1">
                    {example.description}
                  </div>
                </button>
              ))}
            </div>
          </Card>

          {/* Saved Scripts */}
          {savedScripts.length > 0 && (
            <Card className="p-4">
              <h3 className="font-semibold mb-3 flex items-center gap-2">
                <FolderOpen className="h-4 w-4" />
                Saved Scripts
              </h3>
              <div className="space-y-1 max-h-48 overflow-y-auto">
                {savedScripts.map((script, index) => (
                  <div key={index} className="flex items-center justify-between bg-muted/20 p-2 rounded text-xs">
                    <button
                      onClick={() => loadSavedScript(script)}
                      className="flex-1 text-left truncate hover:text-accent"
                    >
                      {script.name}
                    </button>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => deleteSavedScript(index)}
                      className="h-6 w-6 p-0"
                    >
                      <Trash2 className="h-3 w-3" />
                    </Button>
                  </div>
                ))}
              </div>
            </Card>
          )}
        </div>

        {/* Center - Code Editor */}
        <div className="lg:col-span-6 space-y-4">
          <Card className="p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="font-semibold flex items-center gap-2">
                <Code className="h-4 w-4" />
                Python Editor
              </h3>
              <div className="flex gap-2">
                <Button
                  onClick={() => setShowSaveDialog(true)}
                  variant="outline"
                  size="sm"
                >
                  <Save className="h-4 w-4 mr-2" />
                  Save
                </Button>
                <Button
                  onClick={runCode}
                  disabled={isRunning}
                  size="sm"
                  className="bg-accent hover:bg-accent/90"
                >
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

            <div className="border border-border rounded-lg overflow-hidden">
              <Editor
                height="500px"
                defaultLanguage="python"
                value={code}
                onChange={(value) => setCode(value || '')}
                theme="vs-dark"
                options={{
                  minimap: { enabled: false },
                  fontSize: 13,
                  lineNumbers: 'on',
                  scrollBeyondLastLine: false,
                  automaticLayout: true,
                  tabSize: 4,
                  wordWrap: 'on'
                }}
              />
            </div>
          </Card>
        </div>

        {/* Right - Output Terminal & Info */}
        <div className="lg:col-span-3 space-y-4">
          {/* Output Terminal */}
          <Card className="p-4">
            <div className="flex items-center justify-between mb-3">
              <h3 className="font-semibold flex items-center gap-2">
                <Terminal className="h-4 w-4" />
                Output
              </h3>
              <div className="flex gap-1">
                {output && (
                  <>
                    <Button
                      onClick={downloadOutput}
                      variant="ghost"
                      size="sm"
                      className="h-7 w-7 p-0"
                    >
                      <Download className="h-3 w-3" />
                    </Button>
                    <Button
                      onClick={clearOutput}
                      variant="ghost"
                      size="sm"
                      className="h-7 w-7 p-0"
                    >
                      <Trash2 className="h-3 w-3" />
                    </Button>
                  </>
                )}
              </div>
            </div>

            <div
              ref={outputRef}
              className="bg-black/80 text-green-400 p-3 rounded font-mono text-xs h-[300px] overflow-y-auto whitespace-pre-wrap break-words"
            >
              {output || '>>> Ready to execute Python code...'}
            </div>
          </Card>

          {/* Quick Actions */}
          <Card className="p-4">
            <h3 className="font-semibold mb-3 flex items-center gap-2">
              <Package className="h-4 w-4" />
              Install Package
            </h3>
            <div className="space-y-2">
              <input
                type="text"
                placeholder="Package name (e.g., pefile)"
                className="w-full p-2 rounded bg-background border border-border text-sm"
                onKeyDown={(e) => {
                  if (e.key === 'Enter') {
                    const input = e.target as HTMLInputElement
                    if (input.value.trim()) {
                      installPackage(input.value.trim())
                      input.value = ''
                    }
                  }
                }}
              />
              <div className="text-xs text-muted-foreground">
                Common packages: pefile, yara-python, dpkt, Pillow
              </div>
            </div>
          </Card>

          {/* Info Card */}
          <Card className="p-4">
            <h3 className="font-semibold mb-3 flex items-center gap-2">
              <AlertCircle className="h-4 w-4" />
              Quick Guide
            </h3>
            <div className="space-y-2 text-xs text-muted-foreground">
              <p>1. Upload your files using the upload button</p>
              <p>2. Access files at: <code className="bg-muted px-1 rounded">/uploads/filename</code></p>
              <p>3. Load an example or write custom code</p>
              <p>4. Click "Run Script" to execute</p>
              <p>5. View results in the output terminal</p>
              <div className="pt-2 border-t border-border mt-3">
                <p className="font-medium text-foreground mb-1">Pre-installed:</p>
                <p>hashlib, re, json, base64, struct, datetime, zipfile</p>
              </div>
            </div>
          </Card>
        </div>
      </div>

      {/* Save Script Dialog */}
      {showSaveDialog && (
        <div className="fixed inset-0 bg-black/50 flex items-center justify-center z-50">
          <Card className="p-6 w-96">
            <h3 className="font-semibold mb-4">Save Script</h3>
            <input
              type="text"
              placeholder="Script name..."
              value={scriptName}
              onChange={(e) => setScriptName(e.target.value)}
              className="w-full p-2 rounded bg-background border border-border mb-4"
              autoFocus
              onKeyDown={(e) => {
                if (e.key === 'Enter') saveScript()
                if (e.key === 'Escape') setShowSaveDialog(false)
              }}
            />
            <div className="flex gap-2 justify-end">
              <Button
                onClick={() => setShowSaveDialog(false)}
                variant="outline"
                size="sm"
              >
                Cancel
              </Button>
              <Button onClick={saveScript} size="sm">
                Save
              </Button>
            </div>
          </Card>
        </div>
      )}
    </div>
  )
}

export default PythonForensics
