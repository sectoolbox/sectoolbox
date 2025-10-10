export default async function handler(req, res) {
  // Enable CORS
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type')

  // Handle preflight
  if (req.method === 'OPTIONS') {
    return res.status(200).end()
  }

  const { type, query } = req.query

  if (!query) {
    return res.status(400).json({ error: 'Query parameter required' })
  }

  const apiKey = process.env.VIRUSTOTAL_API_KEY || '64d625f72c97fdaf5dba1062622f1862b6068aabfe1d0f52c8dab0bb515c5057'

  try {
    let url

    if (type === 'url') {
      // URL scan
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
      // IP address lookup
      url = `https://www.virustotal.com/api/v3/ip_addresses/${query}`

    } else if (type === 'domain') {
      // Domain lookup
      url = `https://www.virustotal.com/api/v3/domains/${query}`

    } else if (type === 'file-hash') {
      // File hash lookup
      url = `https://www.virustotal.com/api/v3/files/${query}`

    } else {
      // Default to domain
      url = `https://www.virustotal.com/api/v3/domains/${query}`
    }

    const response = await fetch(url, {
      headers: {
        'x-apikey': apiKey
      }
    })

    const data = await response.json()

    if (!response.ok) {
      return res.status(response.status).json({ error: data.error?.message || 'VirusTotal API error' })
    }

    res.status(200).json(data)

  } catch (error) {
    console.error('VirusTotal API Error:', error)
    res.status(500).json({ error: 'Failed to fetch from VirusTotal', details: error.message })
  }
}
