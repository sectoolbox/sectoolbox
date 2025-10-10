// Nmap API endpoint using HackerTarget
// Free tier: 50 requests/day, 2 requests/second rate limit

export default async function handler(req, res) {
  // Enable CORS
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type')

  // Handle preflight
  if (req.method === 'OPTIONS') {
    return res.status(200).end()
  }

  const { target } = req.query

  if (!target) {
    return res.status(400).json({ error: 'Target parameter required' })
  }

  // Validate target (IP address or domain)
  const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/
  const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/

  if (!ipRegex.test(target) && !domainRegex.test(target)) {
    return res.status(400).json({ error: 'Invalid target. Must be a valid IP address or domain name' })
  }

  try {
    // Optional: Use API key if available (increases quota)
    const apiKey = process.env.HACKERTARGET_API_KEY
    const url = apiKey
      ? `https://api.hackertarget.com/nmap/?q=${encodeURIComponent(target)}&apikey=${apiKey}`
      : `https://api.hackertarget.com/nmap/?q=${encodeURIComponent(target)}`

    const response = await fetch(url, {
      headers: {
        'User-Agent': 'Sectoolbox'
      }
    })

    const text = await response.text()

    // Check for API errors
    if (text.includes('error')) {
      // HackerTarget returns plain text errors
      if (text.includes('API count exceeded')) {
        return res.status(429).json({
          error: 'Rate limit exceeded',
          message: 'HackerTarget free tier allows 50 requests per day. Please try again later or add HACKERTARGET_API_KEY to increase quota.'
        })
      }
      return res.status(400).json({ error: text })
    }

    // Parse the raw nmap output
    const ports = parseNmapOutput(text)

    // Get quota information from headers if available
    const quota = {
      remaining: response.headers.get('x-api-quota'),
      used: response.headers.get('x-api-count')
    }

    return res.status(200).json({
      raw: text,
      ports,
      quota,
      target
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
