import express from 'express';
import axios from 'axios';
import { cacheGet, cacheSet } from '../services/queue.js';

const router = express.Router();

// Migrated from Vercel API functions
router.post('/virustotal', async (req, res) => {
  try {
    const { hash, url, ip, domain } = req.body;
    const cacheKey = `vt:${hash || url || ip || domain}`;

    // Check cache
    const cached = await cacheGet(cacheKey);
    if (cached) {
      return res.json(cached);
    }

    const apiKey = process.env.VIRUSTOTAL_API_KEY;
    if (!apiKey) {
      return res.status(500).json({ error: 'VirusTotal API key not configured' });
    }

    // Make VirusTotal API call
    let vtUrl = '';
    if (hash) vtUrl = `https://www.virustotal.com/api/v3/files/${hash}`;
    else if (url) vtUrl = `https://www.virustotal.com/api/v3/urls/${Buffer.from(url).toString('base64url')}`;
    else if (ip) vtUrl = `https://www.virustotal.com/api/v3/ip_addresses/${ip}`;
    else if (domain) vtUrl = `https://www.virustotal.com/api/v3/domains/${domain}`;

    const response = await axios.get(vtUrl, {
      headers: { 'x-apikey': apiKey }
    });

    // Cache for 1 hour
    await cacheSet(cacheKey, response.data, 3600);

    res.json(response.data);
  } catch (error: any) {
    res.status(error.response?.status || 500).json({ error: error.message });
  }
});

// Add other threat intel endpoints as needed

export default router;
