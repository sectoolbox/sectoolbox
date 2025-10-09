// Vercel Serverless Function for Archive.org API
// This bypasses CORS by making the request server-side

export default async function handler(req, res) {
  // Enable CORS
  res.setHeader('Access-Control-Allow-Credentials', true)
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type')

  // Handle OPTIONS preflight request
  if (req.method === 'OPTIONS') {
    res.status(200).end()
    return
  }

  // Only allow GET requests
  if (req.method !== 'GET') {
    return res.status(405).json({ error: 'Method not allowed' })
  }

  try {
    const { url } = req.query

    if (!url) {
      return res.status(400).json({ error: 'URL parameter is required' })
    }

    // Make request to Archive.org CDX API
    const archiveUrl = `https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(url)}*&output=json&fl=original,timestamp&collapse=urlkey&limit=1000`

    const response = await fetch(archiveUrl)

    if (!response.ok) {
      throw new Error(`Archive.org API error: ${response.statusText}`)
    }

    const data = await response.json()

    // Return the data
    res.status(200).json(data)
  } catch (error) {
    console.error('Archive API error:', error)
    res.status(500).json({
      error: 'Failed to fetch from Archive.org',
      message: error.message
    })
  }
}
