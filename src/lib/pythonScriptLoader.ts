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
 * @param content - The script content
 * @param filename - The script filename
 * @param folderCategory - Optional category from folder structure
 */
function parseScriptMetadata(content: string, filename: string, folderCategory?: string): PythonScript {
  const lines = content.split('\n')

  let title = filename.replace('.py', '').replace(/-/g, ' ')
  let description = ''
  let category = folderCategory || 'Uncategorized'
  let author = 'Unknown'
  let code = content

  // Parse metadata from comments (override folder category if specified)
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
 * Supports category subfolders (e.g., /pythonScripts/Analysis/script.py)
 */
export async function loadPythonScripts(): Promise<PythonScript[]> {
  const scripts: PythonScript[] = []

  // Automatically discover all .py files in /public/pythonScripts and subdirectories
  // Using eager: true to load all scripts at build time
  // Pattern /**/*.py matches files in root and all subdirectories
  const scriptModules = import.meta.glob('../../public/pythonScripts/**/*.py', {
    query: '?raw',
    import: 'default',
    eager: true
  })

  for (const path in scriptModules) {
    try {
      // Extract filename and category from path
      // e.g., '../../public/pythonScripts/Analysis/file-hash.py'
      const pathParts = path.split('/')
      const filename = pathParts.pop() || ''

      // Get category from folder name (if in subfolder)
      // e.g., 'Analysis' from '/pythonScripts/Analysis/file.py'
      let folderCategory: string | undefined
      const pythonScriptsIndex = pathParts.indexOf('pythonScripts')
      if (pythonScriptsIndex !== -1 && pythonScriptsIndex < pathParts.length - 1) {
        folderCategory = pathParts[pythonScriptsIndex + 1]
      }

      // Get the script content (already loaded due to eager: true)
      const content = scriptModules[path] as string
      const script = parseScriptMetadata(content, filename, folderCategory)
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
