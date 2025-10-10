export default async function handler(req, res) {
  // Enable CORS
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type')

  // Handle preflight
  if (req.method === 'OPTIONS') {
    return res.status(200).end()
  }

  try {
    // Cloudflare trace endpoint
    const response = await fetch('https://www.cloudflare.com/cdn-cgi/trace')

    if (!response.ok) {
      return res.status(response.status).json({ error: 'Cloudflare Trace API error' })
    }

    const text = await response.text()

    // Parse the key=value pairs
    const data = {}
    text.split('\n').forEach(line => {
      const [key, value] = line.split('=')
      if (key && value) {
        data[key.trim()] = value.trim()
      }
    })

    res.status(200).json(data)

  } catch (error) {
    console.error('Cloudflare Trace API Error:', error)
    res.status(500).json({ error: 'Failed to fetch from Cloudflare Trace', details: error.message })
  }
}
