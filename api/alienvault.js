export default async function handler(req, res) {
  // Enable CORS
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type')

  // Handle preflight
  if (req.method === 'OPTIONS') {
    return res.status(200).end()
  }

  const { type, query, section } = req.query

  if (!query) {
    return res.status(400).json({ error: 'Query parameter required' })
  }

  // AlienVault OTX API key (optional but recommended for higher rate limits)
  const apiKey = process.env.ALIENVAULT_API_KEY

  try {
    let url

    if (type === 'ip' || type === 'IPv4') {
      // IP address lookup
      if (section) {
        // Specific section like 'general', 'reputation', 'geo', 'malware', 'url_list', 'passive_dns'
        url = `https://otx.alienvault.com/api/v1/indicators/IPv4/${encodeURIComponent(query)}/${section}`
      } else {
        // General info
        url = `https://otx.alienvault.com/api/v1/indicators/IPv4/${encodeURIComponent(query)}/general`
      }

    } else if (type === 'domain' || type === 'hostname') {
      // Domain lookup
      if (section) {
        url = `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(query)}/${section}`
      } else {
        url = `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(query)}/general`
      }

    } else if (type === 'url') {
      // URL lookup
      if (section) {
        url = `https://otx.alienvault.com/api/v1/indicators/url/${encodeURIComponent(query)}/${section}`
      } else {
        url = `https://otx.alienvault.com/api/v1/indicators/url/${encodeURIComponent(query)}/general`
      }

    } else if (type === 'file' || type === 'hash') {
      // File hash lookup
      if (section) {
        url = `https://otx.alienvault.com/api/v1/indicators/file/${query}/${section}`
      } else {
        url = `https://otx.alienvault.com/api/v1/indicators/file/${query}/general`
      }

    } else {
      // Default to IP lookup
      url = `https://otx.alienvault.com/api/v1/indicators/IPv4/${encodeURIComponent(query)}/general`
    }

    const headers = {
      'User-Agent': 'Sectoolbox'
    }

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

    res.status(200).json(data)

  } catch (error) {
    console.error('AlienVault OTX API Error:', error)
    res.status(500).json({ error: 'Failed to fetch from AlienVault OTX', details: error.message })
  }
}
