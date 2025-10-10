// Nmap API endpoint using HackerTarget
// Requires HACKERTARGET_API_KEY in environment variables

export default async function handler(req, res) {
  // Enable CORS
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type')

  // Handle preflight
  if (req.method === 'OPTIONS') {
    return res.status(200).end()
  }

  // Check for API key
  const apiKey = process.env.HACKERTARGET_API_KEY
  if (!apiKey) {
    return res.status(401).json({
      error: 'HackerTarget API key required',
      message: 'Please add HACKERTARGET_API_KEY to your environment variables to use Nmap scanning'
    })
  }

  const { target, scanType = 'nmap' } = req.query

  if (!target) {
    return res.status(400).json({ error: 'Target parameter required' })
  }

  // Validate target (IP address or domain)
  const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
  const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/

  if (!ipRegex.test(target) && !domainRegex.test(target)) {
    return res.status(400).json({ error: 'Invalid target. Must be a valid IP address or domain name' })
  }

  // Map scan types to HackerTarget endpoints
  const scanEndpoints = {
    'nmap': 'nmap',           // Standard Nmap scan (10 common ports + version detection)
    'nmap-fast': 'nmap',      // Fast scan - same as standard for HackerTarget
    'nmap-full': 'nmap',      // Full scan - same as standard for HackerTarget
    'hostsearch': 'hostsearch', // Reverse DNS + IP lookup
    'dnslookup': 'dnslookup',   // DNS records
    'zonetransfer': 'zonetransfer', // DNS zone transfer
    'reversedns': 'reversedns',  // Reverse DNS lookup
    'whois': 'whois'            // WHOIS lookup
  }

  const endpoint = scanEndpoints[scanType] || 'nmap'

  try {
    const url = `https://api.hackertarget.com/${endpoint}/?q=${encodeURIComponent(target)}&apikey=${apiKey}`

    const response = await fetch(url, {
      headers: {
        'User-Agent': 'Sectoolbox'
      }
    })

    const text = await response.text()

    // Check for API errors
    if (text.includes('error') || text.includes('invalid')) {
      // HackerTarget returns plain text errors
      if (text.includes('API count exceeded') || text.includes('quota')) {
        return res.status(429).json({
          error: 'Rate limit exceeded',
          message: 'HackerTarget API quota exceeded. Please try again later.'
        })
      }
      if (text.includes('valid key required')) {
        return res.status(401).json({
          error: 'Invalid API key',
          message: 'Your HACKERTARGET_API_KEY is invalid. Please check your environment variables.'
        })
      }
      return res.status(400).json({ error: text })
    }

    // Parse the raw output if it's an nmap scan
    const ports = endpoint === 'nmap' ? parseNmapOutput(text) : []

    // Get quota information from headers if available
    const quota = {
      remaining: response.headers.get('x-api-quota'),
      used: response.headers.get('x-api-count')
    }

    return res.status(200).json({
      raw: text,
      ports,
      quota,
      target,
      scanType: endpoint
    })

  } catch (error) {
    console.error('Nmap API Error:', error)
    return res.status(500).json({
      error: 'Failed to perform Nmap scan',
      details: error.message
    })
  }
}

// Parse Nmap output to extract port information
function parseNmapOutput(text) {
  const ports = []
  const lines = text.split('\n')

  for (const line of lines) {
    // Look for lines with port information (e.g., "22/tcp   open  ssh")
    const portMatch = line.match(/^(\d+)\/(tcp|udp)\s+(open|closed|filtered)\s+(.*)/)
    if (portMatch) {
      ports.push({
        port: parseInt(portMatch[1]),
        protocol: portMatch[2],
        state: portMatch[3],
        service: portMatch[4].trim()
      })
    }
  }

  return ports
}
