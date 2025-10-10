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

  try {
    let url

    if (type === 'url') {
      // Search by URL
      url = `https://phishstats.info:2096/api/phishing?_where=(url,like,~${encodeURIComponent(query)}~)`

    } else if (type === 'ip') {
      // Search by IP
      url = `https://phishstats.info:2096/api/phishing?_where=(ip,eq,${encodeURIComponent(query)})`

    } else if (type === 'domain') {
      // Search by domain
      url = `https://phishstats.info:2096/api/phishing?_where=(url,like,~${encodeURIComponent(query)}~)`

    } else {
      // Default to URL search
      url = `https://phishstats.info:2096/api/phishing?_where=(url,like,~${encodeURIComponent(query)}~)`
    }

    const response = await fetch(url, {
      headers: {
        'User-Agent': 'Sectoolbox'
      }
    })

    if (!response.ok) {
      return res.status(response.status).json({ error: 'PhishStats API error' })
    }

    const data = await response.json()

    res.status(200).json({
      found: data && data.length > 0,
      count: data ? data.length : 0,
      results: data || []
    })

  } catch (error) {
    console.error('PhishStats API Error:', error)
    res.status(500).json({ error: 'Failed to fetch from PhishStats', details: error.message })
  }
}
