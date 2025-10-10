export default async function handler(req, res) {
  // Enable CORS
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type')

  // Handle preflight
  if (req.method === 'OPTIONS') {
    return res.status(200).end()
  }

  const { ip } = req.query

  if (!ip) {
    return res.status(400).json({ error: 'IP parameter required' })
  }

  // AbuseIPDB requires an API key - users should provide their own
  // Free tier: 1000 checks per day
  const apiKey = process.env.ABUSEIPDB_API_KEY

  if (!apiKey) {
    return res.status(500).json({
      error: 'AbuseIPDB API key not configured',
      message: 'Please add ABUSEIPDB_API_KEY to environment variables'
    })
  }

  try {
    const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90&verbose`

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

    res.status(200).json(data)

  } catch (error) {
    console.error('AbuseIPDB API Error:', error)
    res.status(500).json({ error: 'Failed to fetch from AbuseIPDB', details: error.message })
  }
}
