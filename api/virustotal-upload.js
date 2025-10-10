export const config = {
  api: {
    bodyParser: false,
  },
}

export default async function handler(req, res) {
  // Enable CORS
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type')

  // Handle preflight
  if (req.method === 'OPTIONS') {
    return res.status(200).end()
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' })
  }

  const apiKey = process.env.VIRUSTOTAL_API_KEY || '64d625f72c97fdaf5dba1062622f1862b6068aabfe1d0f52c8dab0bb515c5057'

  try {
    // Forward the file upload to VirusTotal
    const response = await fetch('https://www.virustotal.com/api/v3/files', {
      method: 'POST',
      headers: {
        'x-apikey': apiKey,
      },
      body: req,
    })

    const data = await response.json()

    if (!response.ok) {
      return res.status(response.status).json({
        error: data.error?.message || 'VirusTotal upload error',
        details: data
      })
    }

    res.status(200).json(data)

  } catch (error) {
    console.error('VirusTotal Upload Error:', error)
    res.status(500).json({ error: 'Failed to upload to VirusTotal', details: error.message })
  }
}
