# API Reference

This document provides comprehensive documentation for Sectoolbox API endpoints, covering both Vercel serverless functions and backend REST APIs.

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Vercel Serverless Functions](#vercel-serverless-functions)
- [Backend REST API](#backend-rest-api)
- [Authentication](#authentication)
- [Rate Limiting](#rate-limiting)
- [Error Handling](#error-handling)

---

## Architecture Overview

Sectoolbox uses a hybrid API architecture:

1. **Vercel Serverless Functions** (`/api/*`) - Lightweight operations, external API proxies
2. **Backend REST API** (`/api/v1/*`) - Heavy processing, file uploads, queue management

### Base URLs

```
Production Frontend: https://sectoolbox.cc
Vercel API:         https://sectoolbox.cc/api
Backend API:        https://your-backend.railway.app/api/v1
```

---

## Vercel Serverless Functions

These functions run on Vercel's edge network and handle lightweight operations.

### Threat Intelligence

**Endpoint:** `GET /api/threat-intel`

Unified threat intelligence endpoint supporting multiple services.

#### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| service | string | Yes | Service name (see below) |
| type | string | Varies | Indicator type (ip, domain, url, file-hash) |
| query | string | Yes | Indicator to check |
| section | string | No | AlienVault section (default: general) |

#### Supported Services

**virustotal**
```
GET /api/threat-intel?service=virustotal&type=ip&query=1.2.3.4
GET /api/threat-intel?service=virustotal&type=domain&query=evil.com
GET /api/threat-intel?service=virustotal&type=file-hash&query=abc123...
GET /api/threat-intel?service=virustotal&type=url&query=http://evil.com
```

**abuseipdb**
```
GET /api/threat-intel?service=abuseipdb&query=1.2.3.4
```

**alienvault**
```
GET /api/threat-intel?service=alienvault&type=ip&query=1.2.3.4&section=general
GET /api/threat-intel?service=alienvault&type=domain&query=evil.com
```

**hibp** (Have I Been Pwned)
```
GET /api/threat-intel?service=hibp&type=breach&query=email@example.com
GET /api/threat-intel?service=hibp&type=paste&query=email@example.com
GET /api/threat-intel?service=hibp&type=password&query=password123
```

**urlhaus**
```
GET /api/threat-intel?service=urlhaus&type=url&query=http://evil.com
GET /api/threat-intel?service=urlhaus&type=host&query=evil.com
GET /api/threat-intel?service=urlhaus&type=payload&query=md5hash
```

**phishstats**
```
GET /api/threat-intel?service=phishstats&type=url&query=http://phish.com
GET /api/threat-intel?service=phishstats&type=ip&query=1.2.3.4
```

**greynoise**
```
GET /api/threat-intel?service=greynoise&query=1.2.3.4
```

**cloudflare**
```
GET /api/threat-intel?service=cloudflare
```

**check-keys**
```
GET /api/threat-intel?service=check-keys
```

#### Response Examples

**VirusTotal IP Response**
```json
{
  "data": {
    "attributes": {
      "last_analysis_stats": {
        "malicious": 5,
        "suspicious": 2,
        "harmless": 82,
        "undetected": 3
      },
      "tags": ["scanner"],
      "country": "US",
      "asn": 15169
    }
  }
}
```

**AbuseIPDB Response**
```json
{
  "data": {
    "abuseConfidenceScore": 100,
    "countryCode": "CN",
    "usageType": "Data Center/Web Hosting/Transit",
    "totalReports": 1234
  }
}
```

#### Error Responses

```json
{
  "error": "Service parameter required"
}
```

```json
{
  "error": "Query parameter required"
}
```

```json
{
  "error": "API quota exceeded",
  "message": "Rate limit hit. Try again later."
}
```

---

### Network Scanning

**Endpoint:** `GET /api/nmap`

Perform network scans using HackerTarget API.

#### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| target | string | Yes | IP address or domain name |
| scanType | string | No | Scan type (default: nmap) |

#### Scan Types

- `nmap` - Standard Nmap scan (10 common ports + version detection)
- `hostsearch` - Reverse DNS + IP lookup
- `dnslookup` - DNS records
- `zonetransfer` - DNS zone transfer
| `reversedns` - Reverse DNS lookup
- `whois` - WHOIS lookup

#### Example Request

```
GET /api/nmap?target=example.com&scanType=nmap
```

#### Response

```json
{
  "raw": "Starting Nmap...\n80/tcp open http\n443/tcp open https\n",
  "ports": [
    { "port": 80, "state": "open", "service": "http" },
    { "port": 443, "state": "open", "service": "https" }
  ],
  "quota": {
    "remaining": "95",
    "used": "5"
  },
  "target": "example.com",
  "scanType": "nmap"
}
```

#### Error Responses

```json
{
  "error": "Target parameter required"
}
```

```json
{
  "error": "Invalid target. Must be a valid IP address or domain name"
}
```

```json
{
  "error": "Rate limit exceeded",
  "message": "HackerTarget API quota exceeded. Please try again later."
}
```

---

### HTTP Headers

**Endpoint:** `GET /api/headers`

Fetch HTTP headers from any URL, bypassing CORS restrictions.

#### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| url | string | Yes | Target URL (protocol optional) |

#### Example Request

```
GET /api/headers?url=example.com
GET /api/headers?url=https://example.com
```

#### Response

```json
{
  "url": "https://example.com/",
  "status": 200,
  "statusText": "OK",
  "headers": {
    "content-type": "text/html; charset=UTF-8",
    "server": "nginx",
    "x-frame-options": "SAMEORIGIN",
    "strict-transport-security": "max-age=31536000"
  },
  "timings": {
    "total": 234
  }
}
```

#### Error Responses

```json
{
  "error": "URL parameter is required"
}
```

```json
{
  "error": "Failed to fetch headers",
  "message": "getaddrinfo ENOTFOUND invalid.domain"
}
```

---

### Passive DNS

**Endpoint:** `GET /api/passivedns`

Query Mnemonic PassiveDNS API for historical DNS records.

#### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| domain | string | Yes | Domain name to query |

#### Example Request

```
GET /api/passivedns?domain=example.com
```

#### Response

```json
{
  "data": [
    {
      "rrname": "example.com",
      "rrtype": "A",
      "rdata": "93.184.216.34",
      "first_seen": "2020-01-01T00:00:00Z",
      "last_seen": "2024-10-26T12:00:00Z"
    }
  ]
}
```

#### Error Responses

```json
{
  "error": "Domain parameter is required"
}
```

---

### Archive.org

**Endpoint:** `GET /api/archive`

Fetch archived snapshots from Wayback Machine.

#### Query Parameters

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| url | string | Yes | URL to search for |

#### Example Request

```
GET /api/archive?url=example.com
```

#### Response

```json
[
  ["original", "timestamp"],
  ["http://example.com/", "20240101120000"],
  ["http://example.com/about", "20240201130000"]
]
```

#### Error Responses

```json
{
  "error": "URL parameter is required"
}
```

---

## Backend REST API

These endpoints handle heavy processing, file uploads, and queue management.

### Base Configuration

**Base URL:** `https://your-backend.railway.app/api/v1`

**Max File Size:** 2GB (configurable via `MAX_FILE_SIZE` env variable)

**Supported Methods:** `GET`, `POST`

---

### Health Check

**Endpoint:** `GET /health`

Check backend service status.

#### Response

```json
{
  "status": "ok",
  "timestamp": "2024-10-26T12:00:00.000Z"
}
```

---

### PCAP Analysis

**Endpoint:** `POST /api/v1/pcap/analyze`

Upload and analyze network packet capture files.

#### Request

**Content-Type:** `multipart/form-data`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| file | File | Yes | PCAP/PCAPNG file |
| depth | string | No | Analysis depth: "quick" or "full" (default: full) |

#### Example Request

```bash
curl -X POST https://backend.railway.app/api/v1/pcap/analyze \
  -F "file=@capture.pcap" \
  -F "depth=full"
```

#### Response

```json
{
  "jobId": "550e8400-e29b-41d4-a716-446655440000",
  "status": "queued",
  "message": "PCAP analysis queued"
}
```

#### File Restrictions

- **Accepted formats:** `.pcap`, `.pcapng`, `.cap`
- **Max size:** 2GB
- **Processing:** Files are deleted after 1 hour

---

### Audio Analysis

**Endpoint:** `POST /api/v1/audio/spectrogram`

Generate spectrograms and analyze audio files.

#### Request

**Content-Type:** `multipart/form-data`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| file | File | Yes | Audio file |

#### Example Request

```bash
curl -X POST https://backend.railway.app/api/v1/audio/spectrogram \
  -F "file=@audio.wav"
```

#### Response

```json
{
  "jobId": "550e8400-e29b-41d4-a716-446655440001",
  "status": "queued",
  "message": "Audio analysis queued"
}
```

#### File Restrictions

- **Accepted formats:** `.wav`, `.mp3`, `.ogg`, `.flac`, `.aac`
- **Max size:** 500MB

---

### Event Log Analysis

**Endpoint:** `POST /api/v1/eventlogs/parse`

Parse and analyze Windows Event Log files.

#### Request

**Content-Type:** `multipart/form-data`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| file | File | Yes | EVTX file |

#### Example Request

```bash
curl -X POST https://backend.railway.app/api/v1/eventlogs/parse \
  -F "file=@Security.evtx"
```

#### Response

```json
{
  "jobId": "550e8400-e29b-41d4-a716-446655440002",
  "status": "queued",
  "message": "Event log parsing queued"
}
```

#### File Restrictions

- **Accepted formats:** `.evtx`
- **Max size:** 1.5GB

---

### Python Script Execution

**Endpoint:** `GET /api/v1/python/scripts`

List available Python forensics scripts.

#### Response

```json
{
  "scripts": [
    {
      "id": "Forensics/analyze_pdf",
      "name": "PDF Analysis",
      "category": "Forensics",
      "description": "Extract metadata and analyze PDF files",
      "author": "Sectoolbox Team",
      "version": "1.0.0"
    }
  ]
}
```

---

**Endpoint:** `POST /api/v1/python/execute`

Execute a Python script on uploaded file.

#### Request

**Content-Type:** `multipart/form-data`

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| file | File | Yes | File to analyze |
| scriptId | string | Yes | Script ID from /scripts endpoint |

#### Example Request

```bash
curl -X POST https://backend.railway.app/api/v1/python/execute \
  -F "file=@document.pdf" \
  -F "scriptId=Forensics/analyze_pdf"
```

#### Response

```json
{
  "jobId": "550e8400-e29b-41d4-a716-446655440003",
  "status": "queued",
  "message": "Python script execution queued"
}
```

---

### Job Status

**Endpoint:** `GET /api/v1/jobs/:jobId`

Check status of queued job.

#### Example Request

```
GET /api/v1/jobs/550e8400-e29b-41d4-a716-446655440000
```

#### Response - Processing

```json
{
  "jobId": "550e8400-e29b-41d4-a716-446655440000",
  "status": "active",
  "progress": 45,
  "message": "Processing PCAP file..."
}
```

#### Response - Completed

```json
{
  "jobId": "550e8400-e29b-41d4-a716-446655440000",
  "status": "completed",
  "progress": 100,
  "result": {
    "packets": [...],
    "statistics": {...}
  }
}
```

#### Response - Failed

```json
{
  "jobId": "550e8400-e29b-41d4-a716-446655440000",
  "status": "failed",
  "error": "Invalid PCAP format",
  "failedReason": "File corrupted or incompatible"
}
```

---

### Stream Following

**Endpoint:** `POST /api/v1/follow/tcp`
**Endpoint:** `POST /api/v1/follow/http`

Follow TCP/HTTP streams in PCAP files.

#### Request

```json
{
  "pcapPath": "/path/to/capture.pcap",
  "streamIndex": 0
}
```

#### Response

```json
{
  "stream": "GET / HTTP/1.1\nHost: example.com\n\nHTTP/1.1 200 OK...",
  "contentType": "text/html"
}
```

---

## Authentication

### API Keys

Some services require API keys configured as environment variables:

**Vercel Environment Variables:**
- `VIRUSTOTAL_API_KEY` - VirusTotal API access
- `HIBP_API_KEY` - Have I Been Pwned API access
- `ABUSEIPDB_API_KEY` - AbuseIPDB API access (optional)
- `ALIENVAULT_API_KEY` - AlienVault OTX API access (optional)
- `HACKERTARGET_API_KEY` - HackerTarget Nmap scanning

**Backend Environment Variables:**
- `REDIS_URL` - Redis connection string for queue management
- `ALLOWED_ORIGINS` - CORS allowed origins (comma-separated)

---

## Rate Limiting

### Vercel Functions

- **Timeout:** 10 seconds per request
- **Concurrent:** 100 requests per deployment
- **External APIs:** Subject to third-party rate limits

### Backend API

- **File uploads:** 10 requests per minute per IP
- **Job status:** 60 requests per minute per IP
- **Max concurrent jobs:** 50 per worker type

### Third-Party APIs

- **HackerTarget:** 100 requests per day (free tier)
- **VirusTotal:** 4 requests per minute (free tier)
- **AbuseIPDB:** 1000 requests per day (free tier)

---

## Error Handling

### Error Response Format

All errors follow a consistent format:

```json
{
  "error": "Brief error message",
  "message": "Detailed explanation (optional)",
  "details": "Additional context (optional)"
}
```

### HTTP Status Codes

| Code | Meaning |
|------|---------|
| 200 | Success |
| 400 | Bad Request - Invalid parameters |
| 401 | Unauthorized - API key missing or invalid |
| 404 | Not Found - Resource does not exist |
| 405 | Method Not Allowed - Wrong HTTP method |
| 413 | Payload Too Large - File exceeds size limit |
| 429 | Too Many Requests - Rate limit exceeded |
| 500 | Internal Server Error - Server-side failure |
| 503 | Service Unavailable - Temporary outage |

### Common Error Scenarios

**File Too Large**
```json
{
  "error": "File size exceeds maximum limit of 2GB"
}
```

**Invalid File Type**
```json
{
  "error": "Invalid file type. Expected: .pcap, .pcapng, .cap"
}
```

**Queue Full**
```json
{
  "error": "Job queue is full. Please try again later."
}
```

**External API Failure**
```json
{
  "error": "Failed to fetch from VirusTotal",
  "message": "API key invalid or quota exceeded"
}
```

---

## WebSocket Events

For real-time job updates, connect to WebSocket endpoint:

**Endpoint:** `wss://your-backend.railway.app`

### Client Events

```javascript
socket.emit('subscribe', { jobId: '550e8400-...' });
```

### Server Events

**progress**
```javascript
socket.on('progress', (data) => {
  // data: { jobId, progress: 45, message: "Processing..." }
});
```

**completed**
```javascript
socket.on('completed', (data) => {
  // data: { jobId, result: {...} }
});
```

**failed**
```javascript
socket.on('failed', (data) => {
  // data: { jobId, error: "..." }
});
```

---

## Best Practices

### File Uploads

1. Validate file size before upload
2. Check file extension matches expected format
3. Poll job status or use WebSocket for updates
4. Handle timeout scenarios (max 5 minutes processing)

### API Calls

1. Implement exponential backoff for retries
2. Cache responses when appropriate
3. Handle rate limiting gracefully
4. Validate input parameters client-side

### Security

1. Never expose API keys in client-side code
2. Use environment variables for sensitive data
3. Validate file contents, not just extensions
4. Implement CSRF protection for state-changing operations

---

## Support

For API issues or questions:

- GitHub Issues: https://github.com/sectoolbox/sectoolbox/issues
- Discord: https://discord.gg/SvvKKMzE5Q
- Documentation: https://github.com/sectoolbox/sectoolbox/docs
