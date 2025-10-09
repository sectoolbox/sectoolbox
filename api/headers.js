// Vercel Serverless Function for HTTP Headers Inspection
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

    // Ensure URL has protocol
    let targetUrl = url
    if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
      targetUrl = 'https://' + targetUrl
    }

    const startTime = Date.now()

    // Make HEAD request to target URL
    const response = await fetch(targetUrl, {
      method: 'HEAD',
      redirect: 'follow'
    })

    const endTime = Date.now()

    // Extract headers
    const headers = {}
    response.headers.forEach((value, key) => {
      headers[key] = value
    })

    // Return response data
    res.status(200).json({
      url: response.url,
      status: response.status,
      statusText: response.statusText,
      headers: headers,
      timings: {
        total: endTime - startTime
      }
    })
  } catch (error) {
    console.error('Headers API error:', error)
    res.status(500).json({
      error: 'Failed to fetch headers',
      message: error.message
    })
  }
}
