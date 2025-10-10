export default async function handler(req, res) {
  // Enable CORS
  res.setHeader('Access-Control-Allow-Origin', '*')
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS')
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type')

  // Handle preflight
  if (req.method === 'OPTIONS') {
    return res.status(200).end()
  }

  // Check which API keys are configured
  const apiKeys = {
    virustotal: !!process.env.VIRUSTOTAL_API_KEY || true, // Has default key
    hibp: !!process.env.HIBP_API_KEY || true, // Has default key
    abuseipdb: !!process.env.ABUSEIPDB_API_KEY,
    alienvault: !!process.env.ALIENVAULT_API_KEY
  }

  res.status(200).json(apiKeys)
}
