# Sectoolbox Proxy Server

CORS proxy server for Archive.org API requests.

## Purpose

This proxy server bypasses CORS restrictions when the frontend makes requests to Archive.org's CDX API. The browser's same-origin policy would normally block these requests, so the proxy acts as an intermediary.

## Setup

1. **Install dependencies**:
```bash
cd server
npm install
```

2. **Start the server**:
```bash
npm start
```

The server will run on `http://localhost:3001`

## Development

For development with auto-restart on file changes:
```bash
npm run dev
```

## API Endpoints

### GET /api/archive/search
Proxies requests to Archive.org CDX API.

**Query Parameters:**
- `url` (required) - Domain to search for archived URLs

**Example:**
```
GET http://localhost:3001/api/archive/search?url=example.com
```

### GET /api/health
Health check endpoint.

**Example:**
```
GET http://localhost:3001/api/health
```

## How It Works

1. Frontend tries to call proxy first (`http://localhost:3001/api/archive/search`)
2. If proxy is available, it forwards the request to Archive.org and returns results
3. If proxy is unavailable, frontend falls back to direct Archive.org API (may fail due to CORS)

## Security Notes

- Only accepts GET requests
- CORS is configured to allow requests from Vite dev/preview ports
- No authentication required (local development only)
- Do NOT expose this server to the internet without proper security measures
