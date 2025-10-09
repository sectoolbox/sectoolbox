// Vercel Serverless Function for PassiveDNS API (Mnemonic)
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
    const { domain } = req.query

    if (!domain) {
      return res.status(400).json({ error: 'Domain parameter is required' })
    }

    // Make request to Mnemonic PassiveDNS API
    const apiUrl = `https://api.mnemonic.no/pdns/v3/${encodeURIComponent(domain)}`

    const response = await fetch(apiUrl)

    if (!response.ok) {
      throw new Error(`PassiveDNS API error: ${response.statusText}`)
    }

    const data = await response.json()

    // Return the data
    res.status(200).json(data)
  } catch (error) {
    console.error('PassiveDNS API error:', error)
    res.status(500).json({
      error: 'Failed to fetch from PassiveDNS API',
      message: error.message
    })
  }
}
