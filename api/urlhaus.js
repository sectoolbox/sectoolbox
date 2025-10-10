export default async function handler(req, res) {
  // Enable CORS
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS')
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
    let url = 'https://urlhaus-api.abuse.ch/v1/'
    let body

    if (type === 'url') {
      // URL lookup
      url += 'url/'
      body = `url=${encodeURIComponent(query)}`

    } else if (type === 'host') {
      // Host lookup
      url += 'host/'
      body = `host=${encodeURIComponent(query)}`

    } else if (type === 'payload') {
      // Payload (hash) lookup
      url += 'payload/'
      body = `${query.length === 32 ? 'md5' : query.length === 64 ? 'sha256' : 'md5'}_hash=${query}`

    } else {
      // Default to URL lookup
      url += 'url/'
      body = `url=${encodeURIComponent(query)}`
    }

    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body
    })

    const data = await response.json()

    if (!response.ok) {
      return res.status(response.status).json({ error: 'URLhaus API error', details: data })
    }

    res.status(200).json(data)

  } catch (error) {
    console.error('URLhaus API Error:', error)
    res.status(500).json({ error: 'Failed to fetch from URLhaus', details: error.message })
  }
}
