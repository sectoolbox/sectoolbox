/**
 * Threat Intelligence Integration
 * Integrates with VirusTotal, AbuseIPDB, and AlienVault OTX
 */

import axios from 'axios';

// ========== TYPE DEFINITIONS ==========

export interface ThreatIntelResult {
  source: 'virustotal' | 'abuseipdb' | 'alienvault';
  indicator: string;
  isMalicious: boolean;
  score: number; // 0-100
  details: {
    lastAnalysisStats?: {
      malicious: number;
      suspicious: number;
      harmless: number;
      undetected: number;
    };
    categories?: string[];
    country?: string;
    abuseConfidenceScore?: number;
    pulseCount?: number;
    tags?: string[];
  };
  timestamp: string;
  error?: string;
}

interface ThreatIntelCache {
  [key: string]: {
    result: ThreatIntelResult;
    cachedAt: number;
  };
}

// ========== CONFIGURATION ==========

const CACHE_DURATION = 24 * 60 * 60 * 1000; // 24 hours
const CACHE_KEY = 'sectoolbox_threat_intel_cache';

// Note: API keys are stored securely in Vercel environment variables
// No need to store them client-side

// ========== CACHE MANAGEMENT ==========

const getCache = (): ThreatIntelCache => {
  try {
    const stored = localStorage.getItem(CACHE_KEY);
    return stored ? JSON.parse(stored) : {};
  } catch {
    return {};
  }
};

const setCache = (cache: ThreatIntelCache) => {
  try {
    localStorage.setItem(CACHE_KEY, JSON.stringify(cache));
  } catch (error) {
    console.error('Failed to save threat intel cache:', error);
  }
};

const getCachedResult = (key: string): ThreatIntelResult | null => {
  const cache = getCache();
  const cached = cache[key];
  
  if (cached && Date.now() - cached.cachedAt < CACHE_DURATION) {
    return cached.result;
  }
  
  return null;
};

const cacheResult = (key: string, result: ThreatIntelResult) => {
  const cache = getCache();
  cache[key] = {
    result,
    cachedAt: Date.now(),
  };
  setCache(cache);
};

// ========== VIRUSTOTAL ==========

export const checkVirusTotal = async (indicator: string, type: 'ip' | 'domain' | 'hash'): Promise<ThreatIntelResult> => {
  const cacheKey = `vt_${type}_${indicator}`;
  const cached = getCachedResult(cacheKey);
  if (cached) return cached;

  try {
    // Use the Vercel serverless API (API key stored in environment variables)
    const vtType = type === 'hash' ? 'file-hash' : type;
    const response = await axios.get(`/api/threat-intel?service=virustotal&type=${vtType}&query=${encodeURIComponent(indicator)}`);

    const data = response.data.data.attributes;
    const stats = data.last_analysis_stats || {};
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const total = Object.values(stats).reduce((a: any, b: any) => a + b, 0) as number;

    const score = total > 0 ? Math.round(((malicious + suspicious) / total) * 100) : 0;

    const result: ThreatIntelResult = {
      source: 'virustotal',
      indicator,
      isMalicious: malicious > 0,
      score,
      details: {
        lastAnalysisStats: stats,
        tags: data.tags || [],
        categories: data.categories ? Object.keys(data.categories) : [],
      },
      timestamp: new Date().toISOString(),
    };

    cacheResult(cacheKey, result);
    return result;
  } catch (error: any) {
    const result: ThreatIntelResult = {
      source: 'virustotal',
      indicator,
      isMalicious: false,
      score: 0,
      details: {},
      timestamp: new Date().toISOString(),
      error: error.response?.data?.error || error.message,
    };
    return result;
  }
};

// ========== ABUSEIPDB ==========

export const checkAbuseIPDB = async (ip: string): Promise<ThreatIntelResult> => {
  const cacheKey = `abuseipdb_${ip}`;
  const cached = getCachedResult(cacheKey);
  if (cached) return cached;

  try {
    // Use the Vercel serverless API (API key stored in environment variables)
    const response = await axios.get(`/api/threat-intel?service=abuseipdb&query=${encodeURIComponent(ip)}`);

    const data = response.data.data;
    const score = data.abuseConfidenceScore || 0;

    const result: ThreatIntelResult = {
      source: 'abuseipdb',
      indicator: ip,
      isMalicious: score > 50,
      score,
      details: {
        abuseConfidenceScore: score,
        country: data.countryCode,
        categories: data.usageType ? [data.usageType] : [],
      },
      timestamp: new Date().toISOString(),
    };

    cacheResult(cacheKey, result);
    return result;
  } catch (error: any) {
    const result: ThreatIntelResult = {
      source: 'abuseipdb',
      indicator: ip,
      isMalicious: false,
      score: 0,
      details: {},
      timestamp: new Date().toISOString(),
      error: error.response?.data?.error || error.message,
    };
    return result;
  }
};

// ========== ALIENVAULT OTX ==========

export const checkAlienVault = async (indicator: string, type: 'ip' | 'domain' | 'hash'): Promise<ThreatIntelResult> => {
  const cacheKey = `otx_${type}_${indicator}`;
  const cached = getCachedResult(cacheKey);
  if (cached) return cached;

  try {
    // Use the Vercel serverless API (API key stored in environment variables)
    const otxType = type === 'hash' ? 'file' : type;
    const response = await axios.get(`/api/threat-intel?service=alienvault&type=${otxType}&query=${encodeURIComponent(indicator)}&section=general`);

    const data = response.data;
    const pulseCount = data.pulse_info?.count || 0;
    const score = Math.min(pulseCount * 10, 100); // Simple scoring

    const result: ThreatIntelResult = {
      source: 'alienvault',
      indicator,
      isMalicious: pulseCount > 0,
      score,
      details: {
        pulseCount,
        tags: data.pulse_info?.pulses?.slice(0, 5).map((p: any) => p.name) || [],
      },
      timestamp: new Date().toISOString(),
    };

    cacheResult(cacheKey, result);
    return result;
  } catch (error: any) {
    const result: ThreatIntelResult = {
      source: 'alienvault',
      indicator,
      isMalicious: false,
      score: 0,
      details: {},
      timestamp: new Date().toISOString(),
      error: error.response?.data?.error || error.message,
    };
    return result;
  }
};

// ========== BATCH CHECKING ==========

export const checkIndicatorAll = async (
  indicator: string,
  type: 'ip' | 'domain' | 'hash'
): Promise<ThreatIntelResult[]> => {
  const results = await Promise.allSettled([
    checkVirusTotal(indicator, type),
    type === 'ip' ? checkAbuseIPDB(indicator) : Promise.resolve(null),
    checkAlienVault(indicator, type),
  ]);

  return results
    .filter((r): r is PromiseFulfilledResult<ThreatIntelResult> => 
      r.status === 'fulfilled' && r.value !== null
    )
    .map(r => r.value);
};

export const batchCheckIndicators = async (
  indicators: string[],
  type: 'ip' | 'domain' | 'hash',
  onProgress?: (completed: number, total: number) => void
): Promise<Map<string, ThreatIntelResult[]>> => {
  const results = new Map<string, ThreatIntelResult[]>();
  
  for (let i = 0; i < indicators.length; i++) {
    const indicator = indicators[i];
    const result = await checkIndicatorAll(indicator, type);
    results.set(indicator, result);
    
    if (onProgress) {
      onProgress(i + 1, indicators.length);
    }
    
    // Rate limiting - wait 1 second between requests
    if (i < indicators.length - 1) {
      await new Promise(resolve => setTimeout(resolve, 1000));
    }
  }
  
  return results;
};

// ========== AGGREGATED SCORING ==========

export const getAggregatedScore = (results: ThreatIntelResult[]): {
  isMalicious: boolean;
  averageScore: number;
  highestScore: number;
  consensus: 'malicious' | 'suspicious' | 'clean' | 'unknown';
} => {
  if (results.length === 0) {
    return {
      isMalicious: false,
      averageScore: 0,
      highestScore: 0,
      consensus: 'unknown',
    };
  }

  const validResults = results.filter(r => !r.error);
  if (validResults.length === 0) {
    return {
      isMalicious: false,
      averageScore: 0,
      highestScore: 0,
      consensus: 'unknown',
    };
  }

  const scores = validResults.map(r => r.score);
  const averageScore = scores.reduce((a, b) => a + b, 0) / scores.length;
  const highestScore = Math.max(...scores);
  const maliciousCount = validResults.filter(r => r.isMalicious).length;

  let consensus: 'malicious' | 'suspicious' | 'clean' | 'unknown';
  if (maliciousCount >= validResults.length / 2) {
    consensus = 'malicious';
  } else if (averageScore > 30) {
    consensus = 'suspicious';
  } else if (averageScore > 0) {
    consensus = 'suspicious';
  } else {
    consensus = 'clean';
  }

  return {
    isMalicious: maliciousCount > 0,
    averageScore: Math.round(averageScore),
    highestScore,
    consensus,
  };
};

// ========== CACHE MANAGEMENT ==========

export const clearThreatIntelCache = () => {
  localStorage.removeItem(CACHE_KEY);
};

export const getCacheStats = () => {
  const cache = getCache();
  const entries = Object.keys(cache).length;
  const oldEntries = Object.values(cache).filter(
    c => Date.now() - c.cachedAt > CACHE_DURATION
  ).length;
  
  return {
    totalEntries: entries,
    validEntries: entries - oldEntries,
    expiredEntries: oldEntries,
  };
};
