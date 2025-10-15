// Python Script Loader - Load scripts from /pythonScripts folder

export interface PythonScript {
  id: string
  title: string
  description: string
  category: string
  author: string
  code: string
  filename: string
}

/**
 * Parse metadata from Python script comments
 */
function parseScriptMetadata(content: string, filename: string): PythonScript {
  const lines = content.split('\n')

  let title = filename.replace('.py', '').replace(/-/g, ' ')
  let description = ''
  let category = 'Uncategorized'
  let author = 'Unknown'
  let code = content

  // Parse metadata from comments
  for (const line of lines) {
    if (line.startsWith('# TITLE:')) {
      title = line.replace('# TITLE:', '').trim()
    } else if (line.startsWith('# DESCRIPTION:')) {
      description = line.replace('# DESCRIPTION:', '').trim()
    } else if (line.startsWith('# CATEGORY:')) {
      category = line.replace('# CATEGORY:', '').trim()
    } else if (line.startsWith('# AUTHOR:')) {
      author = line.replace('# AUTHOR:', '').trim()
    }
  }

  // Remove metadata comments from code (optional - keep them for documentation)
  // code = lines.filter(line => !line.startsWith('# TITLE:') && !line.startsWith('# DESCRIPTION:') && !line.startsWith('# CATEGORY:') && !line.startsWith('# AUTHOR:')).join('\n')

  return {
    id: filename.replace('.py', ''),
    title,
    description,
    category,
    author,
    code,
    filename
  }
}

/**
 * Load all Python scripts from the /pythonScripts folder
 * Automatically discovers all .py files using Vite's import.meta.glob
 */
export async function loadPythonScripts(): Promise<PythonScript[]> {
  const scripts: PythonScript[] = []

  // Automatically discover all .py files in /public/pythonScripts
  // Using eager: true to load all scripts at build time
  const scriptModules = import.meta.glob('../../public/pythonScripts/*.py', {
    query: '?raw',
    import: 'default',
    eager: true
  })

  for (const path in scriptModules) {
    try {
      // Extract filename from path: '../../public/pythonScripts/string-extractor.py' -> 'string-extractor.py'
      const filename = path.split('/').pop() || ''

      // Get the script content (already loaded due to eager: true)
      const content = scriptModules[path] as string
      const script = parseScriptMetadata(content, filename)
      scripts.push(script)
    } catch (error) {
      console.warn(`Failed to load script from ${path}:`, error)
    }
  }

  return scripts
}

/**
 * Get unique categories from loaded scripts
 */
export function getScriptCategories(scripts: PythonScript[]): string[] {
  const categories = new Set<string>(['All'])
  scripts.forEach(script => categories.add(script.category))
  return Array.from(categories)
}
