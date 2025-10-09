import express from 'express'
import cors from 'cors'

const app = express()
const PORT = 3001

// Enable CORS for frontend
app.use(cors({
  origin: ['http://localhost:5173', 'http://localhost:4173'], // Vite dev and preview ports
  methods: ['GET', 'POST'],
  credentials: true
}))

app.use(express.json())

// Archive.org proxy endpoint
app.get('/api/archive/search', async (req, res) => {
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

    res.json(data)
  } catch (error) {
    console.error('Archive proxy error:', error)
    res.status(500).json({
      error: 'Failed to fetch from Archive.org',
      message: error.message
    })
  }
})

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', message: 'Proxy server is running' })
})

app.listen(PORT, () => {
  console.log(`🚀 Proxy server running on http://localhost:${PORT}`)
  console.log(`📡 Archive.org proxy available at /api/archive/search`)
})
