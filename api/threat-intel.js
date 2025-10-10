// Unified threat intelligence API endpoint
// Consolidates all threat intel services into one function to stay within Vercel's limit

export const config = {
  api: {
    bodyParser: false,
  },
}

export default async function handler(req, res) {
  // Enable CORS
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type')

  // Handle preflight
  if (req.method === 'OPTIONS') {
    return res.status(200).end()
  }

  const { service, type, query, section } = req.query

  if (!service) {
    return res.status(400).json({ error: 'Service parameter required' })
  }

  try {
    switch (service) {
      case 'virustotal':
        return await handleVirusTotal(req, res, type, query)

      case 'virustotal-upload':
        return await handleVirusTotalUpload(req, res)

      case 'hibp':
        return await handleHIBP(req, res, type, query)

      case 'urlhaus':
        return await handleURLhaus(req, res, type, query)

      case 'phishstats':
        return await handlePhishStats(req, res, type, query)

      case 'cloudflare':
        return await handleCloudflare(req, res)

      case 'abuseipdb':
        return await handleAbuseIPDB(req, res, query)

      case 'greynoise':
        return await handleGreyNoise(req, res, query)

      case 'alienvault':
        return await handleAlienVault(req, res, type, query, section)

      case 'check-keys':
        return handleCheckKeys(req, res)

      default:
        return res.status(400).json({ error: 'Unknown service' })
    }
  } catch (error) {
    console.error(`${service} API Error:`, error)
    return res.status(500).json({ error: `Failed to fetch from ${service}`, details: error.message })
  }
}

// VirusTotal
async function handleVirusTotal(req, res, type, query) {
  if (!query) {
    return res.status(400).json({ error: 'Query parameter required' })
  }

  const apiKey = process.env.VIRUSTOTAL_API_KEY || '64d625f72c97fdaf5dba1062622f1862b6068aabfe1d0f52c8dab0bb515c5057'
  let url

  if (type === 'url') {
    const scanResponse = await fetch('https://www.virustotal.com/api/v3/urls', {
      method: 'POST',
      headers: {
        'x-apikey': apiKey,
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: `url=${encodeURIComponent(query)}`
    })
    const scanData = await scanResponse.json()
    return res.status(200).json(scanData)
  } else if (type === 'ip') {
    url = `https://www.virustotal.com/api/v3/ip_addresses/${query}`
  } else if (type === 'domain') {
    url = `https://www.virustotal.com/api/v3/domains/${query}`
  } else if (type === 'file-hash') {
    url = `https://www.virustotal.com/api/v3/files/${query}`
  } else {
    url = `https://www.virustotal.com/api/v3/domains/${query}`
  }

  const response = await fetch(url, {
    headers: { 'x-apikey': apiKey }
  })
  const data = await response.json()

  if (!response.ok) {
    return res.status(response.status).json({ error: data.error?.message || 'VirusTotal API error' })
  }

  return res.status(200).json(data)
}

// VirusTotal Upload
async function handleVirusTotalUpload(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' })
  }

  const apiKey = process.env.VIRUSTOTAL_API_KEY || '64d625f72c97fdaf5dba1062622f1862b6068aabfe1d0f52c8dab0bb515c5057'

  const response = await fetch('https://www.virustotal.com/api/v3/files', {
    method: 'POST',
    headers: { 'x-apikey': apiKey },
    body: req,
  })

  const data = await response.json()

  if (!response.ok) {
    return res.status(response.status).json({
      error: data.error?.message || 'VirusTotal upload error',
      details: data
    })
  }

  return res.status(200).json(data)
}

// HaveIBeenPwned
async function handleHIBP(req, res, type, query) {
  if (!query) {
    return res.status(400).json({ error: 'Query parameter required' })
  }

  const apiKey = process.env.HIBP_API_KEY || '21697467bc164ff884d0c01de797b29f'
  let url
  let options = {
    headers: {
      'hibp-api-key': apiKey,
      'User-Agent': 'Sectoolbox'
    }
  }

  if (type === 'breach') {
    url = `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(query)}`
  } else if (type === 'paste') {
    url = `https://haveibeenpwned.com/api/v3/pasteaccount/${encodeURIComponent(query)}`
  } else if (type === 'password') {
    const encoder = new TextEncoder()
    const data = encoder.encode(query)
    const hashBuffer = await crypto.subtle.digest('SHA-1', data)
    const hashArray = Array.from(new Uint8Array(hashBuffer))
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
    const prefix = hashHex.substring(0, 5).toUpperCase()
    const suffix = hashHex.substring(5).toUpperCase()

    url = `https://api.pwnedpasswords.com/range/${prefix}`
    options = {}

    const response = await fetch(url)
    const text = await response.text()

    const hashes = text.split('\r\n')
    let found = false
    let count = 0

    for (const line of hashes) {
      const [hashSuffix, occurrences] = line.split(':')
      if (hashSuffix === suffix) {
        found = true
        count = parseInt(occurrences, 10)
        break
      }
    }

    return res.status(200).json({
      pwned: found,
      count: count,
      message: found ? `This password has been seen ${count} times before` : 'Password not found in breach database'
    })
  } else {
    url = `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(query)}`
  }

  const response = await fetch(url, options)

  if (response.status === 404) {
    return res.status(200).json({
      found: false,
      message: type === 'paste' ? 'No pastes found' : 'No breaches found'
    })
  }

  const data = await response.json()
  return res.status(200).json({ found: true, data })
}

// URLhaus
async function handleURLhaus(req, res, type, query) {
  if (!query) {
    return res.status(400).json({ error: 'Query parameter required' })
  }

  let url = 'https://urlhaus-api.abuse.ch/v1/'
  let body

  if (type === 'url') {
    url += 'url/'
    body = `url=${encodeURIComponent(query)}`
  } else if (type === 'host') {
    url += 'host/'
    body = `host=${encodeURIComponent(query)}`
  } else if (type === 'payload') {
    url += 'payload/'
    body = `${query.length === 32 ? 'md5' : query.length === 64 ? 'sha256' : 'md5'}_hash=${query}`
  } else {
    url += 'url/'
    body = `url=${encodeURIComponent(query)}`
  }

  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body
  })

  const data = await response.json()
  return res.status(200).json(data)
}

// PhishStats
async function handlePhishStats(req, res, type, query) {
  if (!query) {
    return res.status(400).json({ error: 'Query parameter required' })
  }

  let url

  if (type === 'url') {
    url = `https://phishstats.info:2096/api/phishing?_where=(url,like,~${encodeURIComponent(query)}~)`
  } else if (type === 'ip') {
    url = `https://phishstats.info:2096/api/phishing?_where=(ip,eq,${encodeURIComponent(query)})`
  } else if (type === 'domain') {
    url = `https://phishstats.info:2096/api/phishing?_where=(url,like,~${encodeURIComponent(query)}~)`
  } else {
    url = `https://phishstats.info:2096/api/phishing?_where=(url,like,~${encodeURIComponent(query)}~)`
  }

  const response = await fetch(url, {
    headers: { 'User-Agent': 'Sectoolbox' }
  })

  const data = await response.json()

  return res.status(200).json({
    found: data && data.length > 0,
    count: data ? data.length : 0,
    results: data || []
  })
}

// Cloudflare Trace
async function handleCloudflare(req, res) {
  const response = await fetch('https://www.cloudflare.com/cdn-cgi/trace')
  const text = await response.text()

  const data = {}
  text.split('\n').forEach(line => {
    const [key, value] = line.split('=')
    if (key && value) {
      data[key.trim()] = value.trim()
    }
  })

  return res.status(200).json(data)
}

// AbuseIPDB
async function handleAbuseIPDB(req, res, query) {
  if (!query) {
    return res.status(400).json({ error: 'IP parameter required' })
  }

  const apiKey = process.env.ABUSEIPDB_API_KEY

  if (!apiKey) {
    return res.status(500).json({
      error: 'AbuseIPDB API key not configured',
      message: 'Please add ABUSEIPDB_API_KEY to environment variables'
    })
  }

  const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(query)}&maxAgeInDays=90&verbose`

  const response = await fetch(url, {
    headers: {
      'Key': apiKey,
      'Accept': 'application/json'
    }
  })

  const data = await response.json()

  if (!response.ok) {
    return res.status(response.status).json({
      error: data.errors?.[0]?.detail || 'AbuseIPDB API error',
      details: data
    })
  }

  return res.status(200).json(data)
}

// GreyNoise
async function handleGreyNoise(req, res, query) {
  if (!query) {
    return res.status(400).json({ error: 'IP parameter required' })
  }

  const url = `https://api.greynoise.io/v3/community/${encodeURIComponent(query)}`

  const response = await fetch(url, {
    headers: { 'User-Agent': 'Sectoolbox' }
  })

  const data = await response.json()

  if (!response.ok) {
    return res.status(response.status).json({
      error: data.message || 'GreyNoise API error',
      details: data
    })
  }

  return res.status(200).json(data)
}

// AlienVault OTX
async function handleAlienVault(req, res, type, query, section) {
  if (!query) {
    return res.status(400).json({ error: 'Query parameter required' })
  }

  const apiKey = process.env.ALIENVAULT_API_KEY
  let url

  if (type === 'ip' || type === 'IPv4') {
    if (section) {
      url = `https://otx.alienvault.com/api/v1/indicators/IPv4/${encodeURIComponent(query)}/${section}`
    } else {
      url = `https://otx.alienvault.com/api/v1/indicators/IPv4/${encodeURIComponent(query)}/general`
    }
  } else if (type === 'domain' || type === 'hostname') {
    if (section) {
      url = `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(query)}/${section}`
    } else {
      url = `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(query)}/general`
    }
  } else if (type === 'url') {
    if (section) {
      url = `https://otx.alienvault.com/api/v1/indicators/url/${encodeURIComponent(query)}/${section}`
    } else {
      url = `https://otx.alienvault.com/api/v1/indicators/url/${encodeURIComponent(query)}/general`
    }
  } else if (type === 'file' || type === 'hash') {
    if (section) {
      url = `https://otx.alienvault.com/api/v1/indicators/file/${query}/${section}`
    } else {
      url = `https://otx.alienvault.com/api/v1/indicators/file/${query}/general`
    }
  } else {
    url = `https://otx.alienvault.com/api/v1/indicators/IPv4/${encodeURIComponent(query)}/general`
  }

  const headers = { 'User-Agent': 'Sectoolbox' }
  if (apiKey) {
    headers['X-OTX-API-KEY'] = apiKey
  }

  const response = await fetch(url, { headers })
  const data = await response.json()

  if (!response.ok) {
    return res.status(response.status).json({
      error: data.detail || data.error || 'AlienVault OTX API error',
      details: data
    })
  }

  return res.status(200).json(data)
}

// Check API Keys
function handleCheckKeys(req, res) {
  const apiKeys = {
    virustotal: !!process.env.VIRUSTOTAL_API_KEY || true,
    hibp: !!process.env.HIBP_API_KEY || true,
    abuseipdb: !!process.env.ABUSEIPDB_API_KEY,
    alienvault: !!process.env.ALIENVAULT_API_KEY
  }

  return res.status(200).json(apiKeys)
}
