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
    id: 'vigenere-cipher',
    name: 'Vigenere Cipher',
    description: 'Encrypt/decrypt using Vigenere cipher with key',
    category: 'Cryptography',
    path: '/crypto',
    keywords: ['vigenere', 'cipher', 'polyalphabetic', 'key'],
    operations: ['encrypt', 'decrypt', 'crack']
  },
  {
    id: 'base32-encode-decode',
    name: 'Base32 Encode/Decode',
    description: 'Encode and decode Base32 format',
    category: 'Cryptography',
    path: '/crypto',
    keywords: ['base32', 'encoding', 'decode', 'encode'],
    operations: ['encode', 'decode', 'convert']
  },
  {
    id: 'ascii-hex-binary',
    name: 'ASCII/Hex/Binary Converter',
    description: 'Convert between ASCII, hexadecimal, and binary',
    category: 'Cryptography',
    path: '/crypto',
    keywords: ['ascii', 'hex', 'binary', 'convert', 'transform'],
    operations: ['convert', 'encode', 'decode']
  },
  {
    id: 'morse-code',
    name: 'Morse Code',
    description: 'Encode/decode Morse code',
    category: 'Cryptography',
    path: '/crypto',
    keywords: ['morse', 'code', 'encode', 'decode', 'telegraph'],
    operations: ['encode', 'decode', 'morse']
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
  {
    id: 'frequency-analysis',
    name: 'Frequency Analysis',
    description: 'Analyze character frequency for cipher breaking',
    category: 'Cryptography',
    path: '/crypto',
    keywords: ['frequency', 'analysis', 'cipher', 'break', 'cryptanalysis'],
    operations: ['analyze', 'frequency', 'break']
  },

  // Web Security Tools - SQL Injection Payloads
  {
    id: 'sql-injection-union',
    name: 'SQL Injection - Union Select',
    description: 'Basic union select payloads to identify injectable columns',
    category: 'Web Tools',
    path: '/web',
    keywords: ['sql', 'injection', 'sqli', 'union', 'select', 'database'],
    operations: ['union', 'select', 'exploit']
  },
  {
    id: 'sql-injection-blind',
    name: 'SQL Injection - Blind',
    description: 'Boolean and time-based blind SQL injection techniques',
    category: 'Web Tools',
    path: '/web',
    keywords: ['sql', 'injection', 'blind', 'boolean', 'time-based'],
    operations: ['blind', 'test', 'exploit']
  },
  {
    id: 'sql-injection-error',
    name: 'SQL Injection - Error Based',
    description: 'Error-based SQL injection for information disclosure',
    category: 'Web Tools',
    path: '/web',
    keywords: ['sql', 'injection', 'error', 'mssql', 'oracle'],
    operations: ['error', 'exploit', 'extract']
  },
  {
    id: 'sql-injection-auth-bypass',
    name: 'SQL Injection - Auth Bypass',
    description: 'Authentication bypass using SQL injection',
    category: 'Web Tools',
    path: '/web',
    keywords: ['sql', 'injection', 'auth', 'bypass', 'login'],
    operations: ['bypass', 'authenticate', 'exploit']
  },
  {
    id: 'sql-injection-file-ops',
    name: 'SQL Injection - File Operations',
    description: 'Read/write files using SQL injection (LOAD_FILE, INTO OUTFILE)',
    category: 'Web Tools',
    path: '/web',
    keywords: ['sql', 'injection', 'file', 'load_file', 'outfile', 'rce'],
    operations: ['file', 'read', 'write', 'exploit']
  },
  {
    id: 'sql-injection-waf-bypass',
    name: 'SQL Injection - WAF Bypass',
    description: 'WAF bypass techniques using encoding and comments',
    category: 'Web Tools',
    path: '/web',
    keywords: ['sql', 'injection', 'waf', 'bypass', 'encoding'],
    operations: ['bypass', 'waf', 'evade']
  },

  // XSS Payloads
  {
    id: 'xss-basic',
    name: 'XSS - Basic Payloads',
    description: 'Basic Cross-Site Scripting test payloads',
    category: 'Web Tools',
    path: '/web',
    keywords: ['xss', 'cross-site', 'scripting', 'javascript', 'alert'],
    operations: ['test', 'exploit', 'inject']
  },
  {
    id: 'xss-cookie-stealer',
    name: 'XSS - Cookie Stealing',
    description: 'Steal cookies and session tokens via XSS',
    category: 'Web Tools',
    path: '/web',
    keywords: ['xss', 'cookie', 'session', 'steal', 'exfiltrate'],
    operations: ['steal', 'exfiltrate', 'cookie']
  },
  {
    id: 'xss-dom',
    name: 'XSS - DOM Based',
    description: 'DOM-based XSS exploitation techniques',
    category: 'Web Tools',
    path: '/web',
    keywords: ['xss', 'dom', 'javascript', 'client-side'],
    operations: ['dom', 'exploit', 'inject']
  },
  {
    id: 'xss-polyglot',
    name: 'XSS - Polyglot Payloads',
    description: 'Multi-context XSS payloads that work in various scenarios',
    category: 'Web Tools',
    path: '/web',
    keywords: ['xss', 'polyglot', 'multi-context', 'bypass'],
    operations: ['polyglot', 'bypass', 'exploit']
  },
  {
    id: 'xss-filter-bypass',
    name: 'XSS - Filter Bypass',
    description: 'Bypass XSS filters using encoding and obfuscation',
    category: 'Web Tools',
    path: '/web',
    keywords: ['xss', 'filter', 'bypass', 'encoding', 'obfuscation'],
    operations: ['bypass', 'filter', 'evade']
  },

  // Other Web Exploitation
  {
    id: 'rce-payloads',
    name: 'RCE - Remote Code Execution',
    description: 'Remote code execution payloads for various languages',
    category: 'Web Tools',
    path: '/web',
    keywords: ['rce', 'remote', 'code', 'execution', 'shell', 'command'],
    operations: ['execute', 'exploit', 'shell']
  },
  {
    id: 'lfi-payloads',
    name: 'LFI - Local File Inclusion',
    description: 'Local file inclusion and path traversal payloads',
    category: 'Web Tools',
    path: '/web',
    keywords: ['lfi', 'local', 'file', 'inclusion', 'path', 'traversal'],
    operations: ['include', 'traverse', 'read']
  },
  {
    id: 'ssti-payloads',
    name: 'SSTI - Server-Side Template Injection',
    description: 'Template injection payloads for Jinja2, Twig, etc.',
    category: 'Web Tools',
    path: '/web',
    keywords: ['ssti', 'template', 'injection', 'jinja', 'twig'],
    operations: ['inject', 'template', 'exploit']
  },
  {
    id: 'xxe-payloads',
    name: 'XXE - XML External Entity',
    description: 'XML external entity injection payloads',
    category: 'Web Tools',
    path: '/web',
    keywords: ['xxe', 'xml', 'external', 'entity', 'injection'],
    operations: ['inject', 'xml', 'exploit']
  },
  {
    id: 'csrf-payloads',
    name: 'CSRF - Cross-Site Request Forgery',
    description: 'CSRF attack payloads and PoC generation',
    category: 'Web Tools',
    path: '/web',
    keywords: ['csrf', 'cross-site', 'request', 'forgery', 'token'],
    operations: ['forge', 'exploit', 'bypass']
  },
  {
    id: 'ssrf-payloads',
    name: 'SSRF - Server-Side Request Forgery',
    description: 'SSRF payloads to access internal resources',
    category: 'Web Tools',
    path: '/web',
    keywords: ['ssrf', 'server-side', 'request', 'forgery', 'internal'],
    operations: ['forge', 'access', 'exploit']
  },
  {
    id: 'nosql-injection',
    name: 'NoSQL Injection',
    description: 'NoSQL injection payloads for MongoDB, etc.',
    category: 'Web Tools',
    path: '/web',
    keywords: ['nosql', 'injection', 'mongodb', 'database'],
    operations: ['inject', 'exploit', 'bypass']
  },
  {
    id: 'graphql-injection',
    name: 'GraphQL Injection',
    description: 'GraphQL injection and introspection techniques',
    category: 'Web Tools',
    path: '/web',
    keywords: ['graphql', 'injection', 'introspection', 'api'],
    operations: ['inject', 'introspect', 'exploit']
  },
  {
    id: 'jwt-manipulation',
    name: 'JWT Manipulation',
    description: 'JWT token manipulation and cracking',
    category: 'Web Tools',
    path: '/web',
    keywords: ['jwt', 'json', 'web', 'token', 'crack', 'manipulate'],
    operations: ['crack', 'manipulate', 'forge']
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
    path: '/memory',
    keywords: ['memory', 'dump', 'dmp', 'mem', 'process', 'volatility'],
    operations: ['analyze', 'extract', 'investigate']
  },
  {
    id: 'evtx-analyzer',
    name: 'Windows Event Log Analyzer',
    description: 'Parse and analyze Windows .evtx event log files',
    category: 'Digital Forensics',
    path: '/evtx',
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
  },

  // Network Analysis Tools
  {
    id: 'subnet-calculator',
    name: 'Subnet Calculator',
    description: 'Calculate subnet information from CIDR notation',
    category: 'Network Analysis',
    path: '/network',
    keywords: ['subnet', 'cidr', 'network', 'mask', 'ip', 'calculator'],
    operations: ['calculate', 'subnet', 'network']
  },
  {
    id: 'dns-lookup',
    name: 'DNS Lookup',
    description: 'Perform DNS queries for A, AAAA, MX, TXT, NS, CNAME records',
    category: 'Network Analysis',
    path: '/network',
    keywords: ['dns', 'lookup', 'domain', 'nameserver', 'records', 'query'],
    operations: ['lookup', 'query', 'resolve']
  },
  {
    id: 'whois-lookup',
    name: 'WHOIS Lookup',
    description: 'Domain and IP WHOIS information lookup',
    category: 'Network Analysis',
    path: '/network',
    keywords: ['whois', 'domain', 'ip', 'registration', 'info'],
    operations: ['lookup', 'query', 'whois']
  },
  {
    id: 'http-headers',
    name: 'HTTP Headers Inspector',
    description: 'Inspect HTTP response headers and security headers',
    category: 'Network Analysis',
    path: '/network',
    keywords: ['http', 'headers', 'response', 'security', 'csp', 'hsts'],
    operations: ['inspect', 'analyze', 'headers']
  },
  {
    id: 'shodan-lookup',
    name: 'Shodan InternetDB',
    description: 'Lookup IP information from Shodan InternetDB',
    category: 'Network Analysis',
    path: '/network',
    keywords: ['shodan', 'ip', 'ports', 'vulnerabilities', 'internet', 'scan'],
    operations: ['lookup', 'scan', 'shodan']
  },
  {
    id: 'archive-search',
    name: 'Archive.org Wayback',
    description: 'Search historical URLs from Wayback Machine',
    category: 'Network Analysis',
    path: '/network',
    keywords: ['archive', 'wayback', 'historical', 'urls', 'snapshot'],
    operations: ['search', 'archive', 'historical']
  },
  {
    id: 'ipinfo-lookup',
    name: 'IPInfo.io Lookup',
    description: 'Detailed IP geolocation and ASN information',
    category: 'Network Analysis',
    path: '/network',
    keywords: ['ip', 'geolocation', 'asn', 'location', 'city', 'country'],
    operations: ['lookup', 'geolocation', 'info']
  },
  {
    id: 'passive-dns',
    name: 'Passive DNS',
    description: 'Historical DNS records and changes over time',
    category: 'Network Analysis',
    path: '/network',
    keywords: ['passive', 'dns', 'historical', 'records', 'mnemonic'],
    operations: ['lookup', 'historical', 'dns']
  },
  {
    id: 'certificate-transparency',
    name: 'Certificate Transparency',
    description: 'Find subdomains via SSL certificate logs',
    category: 'Network Analysis',
    path: '/network',
    keywords: ['certificate', 'ssl', 'tls', 'subdomain', 'crt.sh', 'transparency'],
    operations: ['search', 'subdomain', 'certificate']
  },
  {
    id: 'port-scanner',
    name: 'Port Scanner',
    description: 'Scan for open ports and services',
    category: 'Network Analysis',
    path: '/network',
    keywords: ['port', 'scan', 'service', 'open', 'nmap'],
    operations: ['scan', 'port', 'service']
  },

  // Threat Intelligence Tools
  {
    id: 'virustotal',
    name: 'VirusTotal',
    description: 'Scan files, URLs, domains, and IPs for malware using VirusTotal',
    category: 'Threat Intelligence',
    path: '/threat-intel',
    keywords: ['virustotal', 'malware', 'virus', 'scan', 'hash', 'file', 'url', 'domain', 'ip', 'antivirus'],
    operations: ['scan', 'analyze', 'detect', 'malware']
  },
  {
    id: 'haveibeenpwned',
    name: 'Have I Been Pwned',
    description: 'Check if email addresses or passwords have been in data breaches',
    category: 'Threat Intelligence',
    path: '/threat-intel',
    keywords: ['hibp', 'haveibeenpwned', 'breach', 'password', 'email', 'pwned', 'leak', 'compromise'],
    operations: ['check', 'breach', 'lookup', 'verify']
  },
  {
    id: 'urlhaus',
    name: 'URLhaus',
    description: 'Check URLs against malware database from abuse.ch',
    category: 'Threat Intelligence',
    path: '/threat-intel',
    keywords: ['urlhaus', 'malware', 'url', 'malicious', 'abuse', 'payload', 'hash'],
    operations: ['check', 'lookup', 'analyze', 'malware']
  },
  {
    id: 'phishstats',
    name: 'PhishStats',
    description: 'Search phishing URL database for malicious sites',
    category: 'Threat Intelligence',
    path: '/threat-intel',
    keywords: ['phishstats', 'phishing', 'url', 'malicious', 'domain', 'scam'],
    operations: ['search', 'check', 'lookup', 'phishing']
  },
  {
    id: 'cloudflare-trace',
    name: 'Cloudflare Trace',
    description: 'Get your IP information via Cloudflare',
    category: 'Threat Intelligence',
    path: '/threat-intel',
    keywords: ['cloudflare', 'ip', 'trace', 'location', 'user-agent', 'info'],
    operations: ['lookup', 'trace', 'info', 'geolocation']
  },
  {
    id: 'abuseipdb',
    name: 'AbuseIPDB',
    description: 'Check IP reputation and abuse reports',
    category: 'Threat Intelligence',
    path: '/threat-intel',
    keywords: ['abuseipdb', 'ip', 'abuse', 'reputation', 'blacklist', 'malicious'],
    operations: ['check', 'lookup', 'reputation', 'abuse']
  },
  {
    id: 'greynoise',
    name: 'GreyNoise',
    description: 'Identify internet scanners vs targeted attacks',
    category: 'Threat Intelligence',
    path: '/threat-intel',
    keywords: ['greynoise', 'ip', 'scanner', 'noise', 'benign', 'malicious', 'context'],
    operations: ['check', 'lookup', 'classify', 'analyze']
  },
  {
    id: 'alienvault',
    name: 'AlienVault OTX',
    description: 'Threat intelligence from AlienVault Open Threat Exchange',
    category: 'Threat Intelligence',
    path: '/threat-intel',
    keywords: ['alienvault', 'otx', 'threat', 'intelligence', 'ip', 'domain', 'hash', 'ioc', 'indicator'],
    operations: ['lookup', 'analyze', 'threat', 'intel']
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