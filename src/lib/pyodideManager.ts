/**
 * Global Pyodide Manager
 * Maintains a single Pyodide instance that persists across component unmounts
 * Prevents re-initialization when navigating away and back to /python
 */

let globalPyodide: any = null
let isLoading = false
let loadPromise: Promise<any> | null = null

/**
 * Initialize or retrieve the cached Pyodide instance
 */
export const initPyodide = async (statusCallback?: (status: string) => void): Promise<any> => {
  // Return cached instance if already loaded
  if (globalPyodide) {
    console.log('[Pyodide] Using cached instance')
    statusCallback?.('Python environment ready!')
    return globalPyodide
  }

  // If already loading, wait for that promise
  if (isLoading && loadPromise) {
    console.log('[Pyodide] Waiting for existing load operation')
    return loadPromise
  }

  // Start fresh load
  isLoading = true
  console.log('[Pyodide] Starting fresh load')

  loadPromise = (async () => {
    try {
      statusCallback?.('Loading Python environment...')

      const pyodideModule = await (window as any).loadPyodide({
        indexURL: 'https://cdn.jsdelivr.net/pyodide/v0.28.3/full/'
      })

      statusCallback?.('Installing core packages...')
      await pyodideModule.loadPackage(['micropip'])

      statusCallback?.('Setting up environment...')
      pyodideModule.runPython(`
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
                print(f'📁 {item}/')
            else:
                size = os.path.getsize(full_path)
                print(f'📄 {item} ({size} bytes)')
    except Exception as e:
        print(f'Error: {e}')

def cat(filename):
    """Display file contents"""
    try:
        with open(filename, 'r') as f:
            print(f.read())
    except Exception as e:
        print(f'Error: {e}')

def head(filename, lines=10):
    """Display first N lines of file"""
    try:
        with open(filename, 'r') as f:
            for i, line in enumerate(f):
                if i >= lines:
                    break
                print(line, end='')
    except Exception as e:
        print(f'Error: {e}')

def tail(filename, lines=10):
    """Display last N lines of file"""
    try:
        with open(filename, 'r') as f:
            all_lines = f.readlines()
            for line in all_lines[-lines:]:
                print(line, end='')
    except Exception as e:
        print(f'Error: {e}')

def grep(pattern, filename):
    """Search for pattern in file"""
    try:
        with open(filename, 'r') as f:
            for i, line in enumerate(f, 1):
                if pattern in line:
                    print(f'{i}: {line}', end='')
    except Exception as e:
        print(f'Error: {e}')

def hexdump(filename, length=256):
    """Display hex dump of file"""
    try:
        with open(filename, 'rb') as f:
            data = f.read(length)
            for i in range(0, len(data), 16):
                hex_str = ' '.join(f'{b:02x}' for b in data[i:i+16])
                ascii_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in data[i:i+16])
                print(f'{i:08x}  {hex_str:<48}  |{ascii_str}|')
    except Exception as e:
        print(f'Error: {e}')

def tree(path='.', prefix='', max_depth=5, _depth=0):
    """Display directory tree"""
    if _depth >= max_depth:
        return
    try:
        items = sorted(os.listdir(path))
        for i, item in enumerate(items):
            is_last = i == len(items) - 1
            full_path = os.path.join(path, item)
            connector = '└── ' if is_last else '├── '

            if os.path.isdir(full_path):
                print(f'{prefix}{connector}📁 {item}/')
                extension = '    ' if is_last else '│   '
                tree(full_path, prefix + extension, max_depth, _depth + 1)
            else:
                size = os.path.getsize(full_path)
                print(f'{prefix}{connector}📄 {item} ({size} bytes)')
    except Exception as e:
        print(f'Error: {e}')

def pwd():
    """Print working directory"""
    print(os.getcwd())

def fileinfo(filename):
    """Display detailed file information"""
    try:
        import hashlib
        stat = os.stat(filename)
        with open(filename, 'rb') as f:
            data = f.read()

        print(f'File: {filename}')
        print(f'Size: {len(data)} bytes')
        print(f'MD5: {hashlib.md5(data).hexdigest()}')
        print(f'SHA1: {hashlib.sha1(data).hexdigest()}')
        print(f'SHA256: {hashlib.sha256(data).hexdigest()}')
    except Exception as e:
        print(f'Error: {e}')
`)

      // Create /uploads directory
      try {
        pyodideModule.FS.mkdir('/uploads')
      } catch (e) {
        // Directory might already exist
      }

      pyodideModule.FS.chdir('/uploads')

      // Cache the instance globally
      globalPyodide = pyodideModule
      isLoading = false

      statusCallback?.('Ready!')
      console.log('[Pyodide] Successfully loaded and cached')

      return pyodideModule
    } catch (error) {
      isLoading = false
      loadPromise = null
      console.error('[Pyodide] Failed to load:', error)
      throw error
    }
  })()

  return loadPromise
}

/**
 * Get the cached Pyodide instance (if available)
 */
export const getPyodide = () => globalPyodide

/**
 * Check if Pyodide is currently loading
 */
export const isPyodideLoading = () => isLoading

/**
 * Clear the cached instance (useful for testing/debugging)
 */
export const clearPyodideCache = () => {
  globalPyodide = null
  isLoading = false
  loadPromise = null
  console.log('[Pyodide] Cache cleared')
}
