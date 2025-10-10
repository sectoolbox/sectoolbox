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

  // GreyNoise Community API is free and doesn't require authentication
  // But if you have a paid API key, you can use it for more features

  try {
    // Using Community API (free, no auth required)
    const url = `https://api.greynoise.io/v3/community/${encodeURIComponent(ip)}`

    const response = await fetch(url, {
      headers: {
        'User-Agent': 'Sectoolbox'
      }
    })

    const data = await response.json()

    if (!response.ok) {
      return res.status(response.status).json({
        error: data.message || 'GreyNoise API error',
        details: data
      })
    }

    res.status(200).json(data)

  } catch (error) {
    console.error('GreyNoise API Error:', error)
    res.status(500).json({ error: 'Failed to fetch from GreyNoise', details: error.message })
  }
}
