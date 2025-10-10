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

  const apiKey = process.env.HIBP_API_KEY || '21697467bc164ff884d0c01de797b29f'

  try {
    let url
    let options = {
      headers: {
        'hibp-api-key': apiKey,
        'User-Agent': 'Sectoolbox'
      }
    }

    if (type === 'breach') {
      // Check if account has been in a breach
      url = `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(query)}`

    } else if (type === 'paste') {
      // Check if account appears in pastes
      url = `https://haveibeenpwned.com/api/v3/pasteaccount/${encodeURIComponent(query)}`

    } else if (type === 'password') {
      // Check if password has been pwned using k-anonymity
      // We only send first 5 chars of SHA1 hash
      const encoder = new TextEncoder()
      const data = encoder.encode(query)
      const hashBuffer = await crypto.subtle.digest('SHA-1', data)
      const hashArray = Array.from(new Uint8Array(hashBuffer))
      const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
      const prefix = hashHex.substring(0, 5).toUpperCase()
      const suffix = hashHex.substring(5).toUpperCase()

      url = `https://api.pwnedpasswords.com/range/${prefix}`
      options = {} // No API key needed for password API

      const response = await fetch(url)
      const text = await response.text()

      // Parse response to find our hash
      const hashes = text.split('\r\n')
      let found = false
      let count = 0

      for (const line of hashes) {
        const [hashSuffix, occurrences] = line.split(':')
        if (hashSuffix === suffix) {
          found = true
          count = parseInt(occurrences, 10)
          break
        }
      }

      return res.status(200).json({
        pwned: found,
        count: count,
        message: found ? `This password has been seen ${count} times before` : 'Password not found in breach database'
      })

    } else {
      // Default to breach check
      url = `https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(query)}`
    }

    const response = await fetch(url, options)

    if (response.status === 404) {
      return res.status(200).json({
        found: false,
        message: type === 'paste' ? 'No pastes found' : 'No breaches found'
      })
    }

    if (!response.ok) {
      const error = await response.text()
      return res.status(response.status).json({ error: error || 'HIBP API error' })
    }

    const data = await response.json()
    res.status(200).json({ found: true, data })

  } catch (error) {
    console.error('HIBP API Error:', error)
    res.status(500).json({ error: 'Failed to fetch from HaveIBeenPwned', details: error.message })
  }
}
