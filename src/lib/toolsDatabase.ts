// Comprehensive database of all available tools for search functionality
export interface Tool {
  id: string
  name: string
  description: string
  category: string
  path: string
  keywords: string[]
  operations: string[]
}

export const toolsDatabase: Tool[] = [
  // Cryptography Tools
  {
    id: 'md5-hash',
    name: 'MD5 Hash',
    description: 'Generate MD5 hash from text input',
    category: 'Cryptography',
    path: '/crypto',
    keywords: ['md5', 'hash', 'checksum', 'digest'],
    operations: ['hash', 'generate', 'calculate']
  },
  {
    id: 'sha1-hash',
    name: 'SHA1 Hash',
    description: 'Generate SHA1 hash from text input',
    category: 'Cryptography',
    path: '/crypto',
    keywords: ['sha1', 'hash', 'checksum', 'digest'],
    operations: ['hash', 'generate', 'calculate']
  },
  {
    id: 'sha256-hash',
    name: 'SHA256 Hash',
    description: 'Generate SHA256 hash from text input',
    category: 'Cryptography',
    path: '/crypto',
    keywords: ['sha256', 'hash', 'checksum', 'digest'],
    operations: ['hash', 'generate', 'calculate']
  },
  {
    id: 'sha512-hash',
    name: 'SHA512 Hash',
    description: 'Generate SHA512 hash from text input',
    category: 'Cryptography',
    path: '/crypto',
    keywords: ['sha512', 'hash', 'checksum', 'digest'],
    operations: ['hash', 'generate', 'calculate']
  },
  {
    id: 'base64-encode',
    name: 'Base64 Encode',
    description: 'Encode text to Base64 format',
    category: 'Cryptography',
    path: '/crypto',
    keywords: ['base64', 'encoding', 'encode'],
    operations: ['encode', 'convert']
  },
  {
    id: 'base64-decode',
    name: 'Base64 Decode',
    description: 'Decode Base64 encoded text',
    category: 'Cryptography',
    path: '/crypto',
    keywords: ['base64', 'decoding', 'decode'],
    operations: ['decode', 'convert']
  },
  {
    id: 'url-encode',
    name: 'URL Encode',
    description: 'Encode text for URL usage',
    category: 'Cryptography',
    path: '/crypto',
    keywords: ['url', 'encoding', 'encode', 'percent'],
    operations: ['encode', 'convert']
  },
  {
    id: 'url-decode',
    name: 'URL Decode',
    description: 'Decode URL encoded text',
    category: 'Cryptography',
    path: '/crypto',
    keywords: ['url', 'decoding', 'decode', 'percent'],
    operations: ['decode', 'convert']
  },
  {
    id: 'hex-encode',
    name: 'Hex Encode',
    description: 'Encode text to hexadecimal format',
    category: 'Cryptography',
    path: '/crypto',
    keywords: ['hex', 'hexadecimal', 'encoding', 'encode'],
    operations: ['encode', 'convert']
  },
  {
    id: 'hex-decode',
    name: 'Hex Decode',
    description: 'Decode hexadecimal encoded text',
    category: 'Cryptography',
    path: '/crypto',
    keywords: ['hex', 'hexadecimal', 'decoding', 'decode'],
    operations: ['decode', 'convert']
  },
  {
    id: 'caesar-cipher',
    name: 'Caesar Cipher',
    description: 'Encrypt/decrypt text using Caesar cipher',
    category: 'Cryptography',
    path: '/crypto',
    keywords: ['caesar', 'cipher', 'shift', 'encrypt', 'decrypt'],
    operations: ['encrypt', 'decrypt', 'encode', 'decode']
  },
  {
    id: 'rot13',
    name: 'ROT13',
    description: 'Apply ROT13 cipher transformation',
    category: 'Cryptography',
    path: '/crypto',
    keywords: ['rot13', 'cipher', 'rotate', 'transform'],
    operations: ['encrypt', 'decrypt', 'transform']
  },
  {
    id: 'atbash',
    name: 'Atbash Cipher',
    description: 'Apply Atbash cipher transformation',
    category: 'Cryptography',
    path: '/crypto',
    keywords: ['atbash', 'cipher', 'reverse', 'alphabet'],
    operations: ['encrypt', 'decrypt', 'transform']
  },
  {
    id: 'magic-decode',
    name: 'Magic Decode',
    description: 'Intelligent multi-layer decoding',
    category: 'Cryptography',
    path: '/crypto',
    keywords: ['magic', 'auto', 'decode', 'multi', 'intelligent'],
    operations: ['decode', 'analyze', 'auto-detect']
  },
  {
    id: 'text-analysis',
    name: 'Text Analysis',
    description: 'Analyze text entropy and detect encodings',
    category: 'Cryptography',
    path: '/crypto',
    keywords: ['analysis', 'entropy', 'detect', 'encoding'],
    operations: ['analyze', 'detect', 'calculate']
  },

  // Web Security Tools
  {
    id: 'sql-injection',
    name: 'SQL Injection Tester',
    description: 'Test for SQL injection vulnerabilities',
    category: 'Web Security',
    path: '/web',
    keywords: ['sql', 'injection', 'sqli', 'database', 'vulnerability'],
    operations: ['test', 'scan', 'exploit']
  },
  {
    id: 'xss-tester',
    name: 'XSS Tester',
    description: 'Test for Cross-Site Scripting vulnerabilities',
    category: 'Web Security',
    path: '/web',
    keywords: ['xss', 'cross-site', 'scripting', 'javascript', 'vulnerability'],
    operations: ['test', 'scan', 'exploit']
  },
  {
    id: 'header-analyzer',
    name: 'Security Headers Analyzer',
    description: 'Analyze HTTP security headers',
    category: 'Web Security',
    path: '/web',
    keywords: ['headers', 'http', 'security', 'analyze', 'csp'],
    operations: ['analyze', 'scan', 'check']
  },
  {
    id: 'directory-fuzzer',
    name: 'Directory Fuzzer',
    description: 'Discover hidden directories and files',
    category: 'Web Security',
    path: '/web',
    keywords: ['directory', 'fuzzer', 'brute', 'force', 'discover'],
    operations: ['fuzz', 'scan', 'discover', 'brute-force']
  },

  // Image Analysis Tools
  {
    id: 'exif-extractor',
    name: 'EXIF Data Extractor',
    description: 'Extract metadata from image files',
    category: 'Image Analysis',
    path: '/image',
    keywords: ['exif', 'metadata', 'image', 'extract', 'gps'],
    operations: ['extract', 'analyze', 'read']
  },
  {
    id: 'steganography-detector',
    name: 'Steganography Detector',
    description: 'Detect hidden data in images using LSB analysis',
    category: 'Image Analysis',
    path: '/image',
    keywords: ['steganography', 'stego', 'hidden', 'lsb', 'embed'],
    operations: ['detect', 'analyze', 'extract']
  },
  {
    id: 'string-extractor',
    name: 'String Extractor',
    description: 'Extract printable strings from image files',
    category: 'Image Analysis',
    path: '/image',
    keywords: ['strings', 'extract', 'text', 'printable'],
    operations: ['extract', 'search', 'find']
  },

  // PCAP Analysis Tools
  {
    id: 'packet-analyzer',
    name: 'Packet Analyzer',
    description: 'Deep packet inspection and analysis',
    category: 'Network Analysis',
    path: '/pcap',
    keywords: ['packet', 'pcap', 'network', 'traffic', 'analyze'],
    operations: ['analyze', 'inspect', 'decode']
  },
  {
    id: 'protocol-decoder',
    name: 'Protocol Decoder',
    description: 'Decode network protocols from PCAP files',
    category: 'Network Analysis',
    path: '/pcap',
    keywords: ['protocol', 'decode', 'tcp', 'udp', 'http'],
    operations: ['decode', 'parse', 'analyze']
  },
  {
    id: 'network-strings',
    name: 'Network String Extractor',
    description: 'Extract strings from network traffic',
    category: 'Network Analysis',
    path: '/pcap',
    keywords: ['strings', 'network', 'extract', 'traffic'],
    operations: ['extract', 'search', 'find']
  },

  // Digital Forensics Tools
  {
    id: 'disk-image-analyzer',
    name: 'Disk Image Analyzer',
    description: 'Comprehensive analysis of disk images and raw dumps',
    category: 'Digital Forensics',
    path: '/forensics',
    keywords: ['disk', 'image', 'analyze', 'dd', 'raw', 'img', 'forensics'],
    operations: ['analyze', 'carve', 'extract']
  },
  {
    id: 'memory-dump-analyzer',
    name: 'Memory Dump Analyzer',
    description: 'Analyze memory dumps for processes, network connections, and artifacts',
    category: 'Digital Forensics',
    path: '/forensics',
    keywords: ['memory', 'dump', 'dmp', 'mem', 'process', 'volatility'],
    operations: ['analyze', 'extract', 'investigate']
  },
  {
    id: 'evtx-analyzer',
    name: 'Windows Event Log Analyzer',
    description: 'Parse and analyze Windows .evtx event log files',
    category: 'Digital Forensics',
    path: '/forensics',
    keywords: ['evtx', 'event', 'log', 'windows', 'timeline', 'security'],
    operations: ['parse', 'analyze', 'timeline']
  },
  {
    id: 'file-carver',
    name: 'File Carver',
    description: 'Recover deleted files using file signature analysis',
    category: 'Digital Forensics',
    path: '/forensics',
    keywords: ['carve', 'recover', 'deleted', 'signature', 'undelete'],
    operations: ['carve', 'recover', 'extract']
  },
  {
    id: 'hex-viewer',
    name: 'Hex Viewer',
    description: 'View file contents in hexadecimal format with ASCII representation',
    category: 'Digital Forensics',
    path: '/forensics',
    keywords: ['hex', 'hexadecimal', 'viewer', 'binary', 'ascii'],
    operations: ['view', 'inspect', 'examine']
  },
  {
    id: 'string-extractor',
    name: 'String Extractor',
    description: 'Extract printable strings from binary files and disk images',
    category: 'Digital Forensics',
    path: '/forensics',
    keywords: ['strings', 'extract', 'printable', 'text', 'ascii'],
    operations: ['extract', 'search', 'find']
  },
  {
    id: 'entropy-analyzer',
    name: 'Entropy Analyzer',
    description: 'Calculate file entropy to detect encryption and compression',
    category: 'Digital Forensics',
    path: '/forensics',
    keywords: ['entropy', 'encryption', 'compression', 'randomness', 'analyze'],
    operations: ['calculate', 'analyze', 'detect']
  },
  {
    id: 'hash-calculator',
    name: 'Forensic Hash Calculator',
    description: 'Generate cryptographic hashes for evidence integrity',
    category: 'Digital Forensics',
    path: '/forensics',
    keywords: ['hash', 'md5', 'sha1', 'sha256', 'integrity', 'checksum'],
    operations: ['calculate', 'verify', 'generate']
  },
  {
    id: 'folder-scanner',
    name: 'Folder',
    description: 'Bulk scan folders and filter files by content, including hidden files',
    category: 'Digital Forensics',
    path: '/folder-scanner',
    keywords: ['folder', 'directory', 'bulk', 'scan', 'batch', 'hidden', 'files', 'filter', 'search', 'recursive'],
    operations: ['scan', 'filter', 'search', 'analyze', 'batch']
  },
  {
    id: 'audio-analysis',
    name: 'Audio Analysis',
    description: 'Detect hidden messages in audio files: morse code, DTMF, LSB steganography, spectrograms',
    category: 'Digital Forensics',
    path: '/audio',
    keywords: ['audio', 'sound', 'mp3', 'wav', 'morse', 'dtmf', 'steganography', 'spectrogram', 'frequency', 'hidden', 'message'],
    operations: ['analyze', 'detect', 'decode', 'extract', 'spectrogram']
  }
]

// Search function that matches tools based on name, keywords, and operations
export function searchTools(query: string): Tool[] {
  if (!query.trim()) return []
  
  const searchTerm = query.toLowerCase().trim()
  
  return toolsDatabase.filter(tool => {
    // Search in tool name
    if (tool.name.toLowerCase().includes(searchTerm)) return true
    
    // Search in keywords
    if (tool.keywords.some(keyword => keyword.includes(searchTerm))) return true
    
    // Search in operations
    if (tool.operations.some(operation => operation.includes(searchTerm))) return true
    
    // Search in description
    if (tool.description.toLowerCase().includes(searchTerm)) return true
    
    return false
  })
}

// Get tools by category
export function getToolsByCategory(category: string): Tool[] {
  return toolsDatabase.filter(tool => tool.category === category)
}

// Get all categories
export function getCategories(): string[] {
  return [...new Set(toolsDatabase.map(tool => tool.category))]
}