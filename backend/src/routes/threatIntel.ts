import express from 'express';
import axios from 'axios';
import { cacheGet, cacheSet } from '../services/queue.js';

const router = express.Router();

// VirusTotal proxy endpoint
router.post('/virustotal', async (req, res) => {
  try {
    const { hash, url, ip, domain, apiKey } = req.body;
    const indicator = hash || url || ip || domain;
    const cacheKey = `vt:${indicator}`;

    // Check cache
    const cached = await cacheGet(cacheKey);
    if (cached) {
      return res.json(cached);
    }

    // Use client-provided API key or fallback to server env variable
    const vtApiKey = apiKey || process.env.VIRUSTOTAL_API_KEY;
    if (!vtApiKey) {
      return res.status(400).json({ error: 'VirusTotal API key required' });
    }

    // Make VirusTotal API call
    let vtUrl = '';
    if (hash) vtUrl = `https://www.virustotal.com/api/v3/files/${hash}`;
    else if (url) vtUrl = `https://www.virustotal.com/api/v3/urls/${Buffer.from(url).toString('base64url')}`;
    else if (ip) vtUrl = `https://www.virustotal.com/api/v3/ip_addresses/${ip}`;
    else if (domain) vtUrl = `https://www.virustotal.com/api/v3/domains/${domain}`;

    const response = await axios.get(vtUrl, {
      headers: { 'x-apikey': vtApiKey },
      timeout: 10000,
    });

    // Cache for 1 hour
    await cacheSet(cacheKey, response.data, 3600);

    res.json(response.data);
  } catch (error: any) {
    console.error('VirusTotal API error:', error.response?.data || error.message);
    res.status(error.response?.status || 500).json({ 
      error: error.response?.data?.error?.message || error.message 
    });
  }
});

// AbuseIPDB proxy endpoint
router.post('/abuseipdb', async (req, res) => {
  try {
    const { ip, apiKey } = req.body;
    const cacheKey = `abuseipdb:${ip}`;

    // Check cache
    const cached = await cacheGet(cacheKey);
    if (cached) {
      return res.json(cached);
    }

    // Use client-provided API key or fallback to server env variable
    const abuseApiKey = apiKey || process.env.ABUSEIPDB_API_KEY;
    if (!abuseApiKey) {
      return res.status(400).json({ error: 'AbuseIPDB API key required' });
    }

    const response = await axios.get('https://api.abuseipdb.com/api/v2/check', {
      params: {
        ipAddress: ip,
        maxAgeInDays: 90,
      },
      headers: {
        Key: abuseApiKey,
        Accept: 'application/json',
      },
      timeout: 10000,
    });

    // Cache for 1 hour
    await cacheSet(cacheKey, response.data, 3600);

    res.json(response.data);
  } catch (error: any) {
    console.error('AbuseIPDB API error:', error.response?.data || error.message);
    res.status(error.response?.status || 500).json({ 
      error: error.response?.data?.errors?.[0]?.detail || error.message 
    });
  }
});

// AlienVault OTX proxy endpoint
router.post('/alienvault', async (req, res) => {
  try {
    const { ip, domain, apiKey } = req.body;
    const indicator = ip || domain;
    const type = ip ? 'IPv4' : 'domain';
    const cacheKey = `otx:${indicator}`;

    // Check cache
    const cached = await cacheGet(cacheKey);
    if (cached) {
      return res.json(cached);
    }

    // Use client-provided API key or fallback to server env variable
    const otxApiKey = apiKey || process.env.ALIENVAULT_API_KEY;
    if (!otxApiKey) {
      return res.status(400).json({ error: 'AlienVault OTX API key required' });
    }

    const url = `https://otx.alienvault.com/api/v1/indicators/${type}/${indicator}/general`;

    const response = await axios.get(url, {
      headers: {
        'X-OTX-API-KEY': otxApiKey,
      },
      timeout: 10000,
    });

    // Cache for 1 hour
    await cacheSet(cacheKey, response.data, 3600);

    res.json(response.data);
  } catch (error: any) {
    console.error('AlienVault API error:', error.response?.data || error.message);
    res.status(error.response?.status || 500).json({ 
      error: error.response?.data?.detail || error.message 
    });
  }
});

export default router;
