# Architecture

This document provides a comprehensive overview of Sectoolbox's architecture, explaining how different components work together to deliver a powerful web-based security analysis platform.

## Table of Contents

- [Overview](#overview)
- [System Architecture](#system-architecture)
- [Component Details](#component-details)
- [Data Flow](#data-flow)
- [Deployment](#deployment)
- [Scalability](#scalability)

---

## Overview

Sectoolbox uses a hybrid architecture combining client-side processing, serverless functions, and a dedicated backend server. This approach optimizes for:

- **Performance** - Heavy operations offloaded to backend
- **Cost efficiency** - Serverless functions for lightweight operations
- **Scalability** - Independent scaling of frontend and backend
- **User experience** - Real-time updates via WebSocket

### Key Design Principles

1. **Progressive Enhancement** - Basic features work without backend, advanced features require server processing
2. **Separation of Concerns** - Frontend handles UI, serverless handles proxying, backend handles computation
3. **Stateless Design** - No server-side sessions, jobs tracked by ID
4. **Fail-Safe** - Graceful degradation when services unavailable

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────┐
│                            User Browser                              │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                     React Frontend (SPA)                      │  │
│  │  - UI Components (shadcn/ui + Tailwind)                       │  │
│  │  - Client-side Analysis (Pyodide/WebAssembly)                 │  │
│  │  - State Management (React hooks)                             │  │
│  └──────────────────────────────────────────────────────────────┘  │
│              │                          │                            │
│              │ HTTP/REST                │ WebSocket                  │
│              ▼                          ▼                            │
└─────────────────────────────────────────────────────────────────────┘
              │                          │
              │                          │
┌─────────────▼──────────────┐  ┌───────▼───────────────────────────┐
│   Vercel Edge Network      │  │    Railway Backend Server         │
│  ┌──────────────────────┐  │  │  ┌─────────────────────────────┐ │
│  │  Frontend Assets     │  │  │  │    Express.js Server        │ │
│  │  (Static Hosting)    │  │  │  │  - REST API Endpoints       │ │
│  └──────────────────────┘  │  │  │  - File Upload Handling     │ │
│                             │  │  │  - WebSocket Server         │ │
│  ┌──────────────────────┐  │  │  └─────────────────────────────┘ │
│  │  Serverless Funcs    │  │  │              │                    │
│  │  - /api/threat-intel │  │  │              ▼                    │
│  │  - /api/nmap         │  │  │  ┌─────────────────────────────┐ │
│  │  - /api/headers      │  │  │  │    Bull Queue Manager       │ │
│  │  - /api/passivedns   │  │  │  │  - Job Scheduling           │ │
│  │  - /api/archive      │  │  │  │  - Priority Management      │ │
│  └──────────────────────┘  │  │  │  - Retry Logic              │ │
│              │              │  │  └─────────────────────────────┘ │
│              ▼              │  │              │                    │
│  ┌──────────────────────┐  │  │              ▼                    │
│  │   External APIs      │  │  │  ┌─────────────────────────────┐ │
│  │  - VirusTotal        │  │  │  │    Background Workers       │ │
│  │  - AbuseIPDB         │  │  │  │  - PCAP Worker (tshark)     │ │
│  │  - HackerTarget      │  │  │  │  - Audio Worker (ffmpeg)    │ │
│  │  - AlienVault OTX    │  │  │  │  - Python Worker            │ │
│  │  - HIBP              │  │  │  │  - Event Log Worker         │ │
│  └──────────────────────┘  │  │  └─────────────────────────────┘ │
└─────────────────────────────┘  │              │                    │
                                 │              ▼                    │
                                 │  ┌─────────────────────────────┐ │
                                 │  │      File Storage           │ │
                                 │  │  - Uploads Directory        │ │
                                 │  │  - Results Directory        │ │
                                 │  │  - Auto-Cleanup (1 hour)    │ │
                                 │  └─────────────────────────────┘ │
                                 └──────────────────────────────────┘
                                              │
                                              ▼
                                 ┌──────────────────────────────────┐
                                 │       Redis Database             │
                                 │  - Job Queue Storage             │
                                 │  - Result Caching                │
                                 │  - WebSocket State               │
                                 └──────────────────────────────────┘
```

---

## Component Details

### Frontend (React + Vite)

**Location:** `/src`

**Technology Stack:**
- React 19.1 with TypeScript 5.8
- Vite 7.1 for build tooling
- Tailwind CSS + shadcn/ui for styling
- Pyodide 0.28.3 for WebAssembly Python
- Monaco Editor for code editing
- Socket.io-client for WebSocket

**Responsibilities:**
- User interface rendering
- Client-side file parsing (small files)
- Pyodide Python environment for forensics scripts
- Image analysis (steganography, EXIF)
- Basic cryptography operations
- WebSocket connection management
- API client implementation

**Key Features:**
- No server required for basic operations
- Progressive Web App capabilities
- Responsive design for mobile/desktop
- Dark mode support

**File Structure:**
```
src/
├── components/       # Reusable UI components
│   ├── ui/           # shadcn/ui primitives
│   ├── eventlogs/    # Event log specific components
│   └── pcap/         # PCAP specific components
├── pages/            # Route components
│   ├── Dashboard.tsx
│   ├── PcapAnalysis.tsx
│   ├── EventLogs.tsx
│   └── ...
├── lib/              # Business logic
│   ├── pcap.ts       # PCAP parsing
│   ├── eventLogUtils.ts
│   ├── mitreAttack.ts
│   └── ...
├── services/         # External communication
│   ├── api.ts        # Backend API client
│   └── websocket.ts  # WebSocket client
└── hooks/            # Custom React hooks
    ├── useBackendJob.ts
    └── use-toast.ts
```

---

### Vercel Serverless Functions

**Location:** `/api`

**Technology:** Node.js serverless functions

**Responsibilities:**
- Proxying external API calls (bypass CORS)
- Lightweight data transformations
- API key management (server-side only)
- Rate limiting enforcement

**Functions:**

**threat-intel.js**
- Unified endpoint for 9+ threat intelligence services
- Handles VirusTotal, AbuseIPDB, AlienVault, HIBP, etc.
- API key management via environment variables
- Response caching and error handling

**nmap.js**
- Port scanning via HackerTarget API
- Multiple scan types (nmap, DNS, WHOIS)
- Quota tracking and rate limit handling

**headers.js**
- HTTP header inspection
- CORS bypass for arbitrary URLs
- Timing information collection

**passivedns.js**
- Historical DNS record queries
- Mnemonic API integration

**archive.js**
- Wayback Machine snapshot retrieval
- CDX API integration

**Advantages:**
- No server maintenance
- Auto-scaling
- Geographic distribution
- Zero cold start (edge functions)

**Limitations:**
- 10 second timeout per request
- 50MB response size limit
- No persistent storage
- Read-only filesystem

---

### Backend Server (Express.js)

**Location:** `/backend`

**Technology Stack:**
- Node.js 20+ with TypeScript
- Express.js 4.18 for HTTP server
- Socket.io 4.7 for WebSocket
- Bull 4.12 for queue management
- Redis 4.6 for state storage
- Multer for file uploads

**Responsibilities:**
- Heavy file processing
- Long-running analysis tasks
- Job queue management
- WebSocket real-time updates
- File storage management
- Worker process coordination

**Core Services:**

**Queue Service** (`services/queue.ts`)
```typescript
- pythonQueue: Bull.Queue     // Python script execution
- pcapQueue: Bull.Queue        // PCAP analysis
- audioQueue: Bull.Queue       // Audio processing
- eventLogQueue: Bull.Queue    // Event log parsing
- redisClient: Redis.Client    // Caching layer
```

**Configuration:**
- 3 retry attempts with exponential backoff
- 100 completed jobs retained
- 50 failed jobs retained
- 2 minute job timeout

**WebSocket Service** (`services/websocket.ts`)
- Room-based job subscriptions
- Real-time progress updates
- Completion/failure notifications
- Automatic reconnection handling

**Storage Service** (`services/storage.ts`)
- Organized file system structure
- Automatic cleanup after 1 hour
- Result caching in JSON format

**Structure:**
```
storage/
├── uploads/
│   └── {jobId}/
│       └── original-file.ext
└── results/
    └── {jobId}/
        └── output.json
```

---

### Background Workers

**Location:** `/backend/src/workers`

**Process Model:** Separate Node.js processes per worker type

**Workers:**

**PCAP Worker** (`pcapWorker.ts`)
- Executes tshark for packet analysis
- Supports quick and full depth modes
- Parses JSON output from tshark
- Extracts protocols, IPs, conversations

**Audio Worker** (`audioWorker.ts`)
- Generates spectrograms using Python
- Extracts audio metadata
- Analyzes frequency spectrum
- Detects hidden data in audio

**Event Log Worker** (`eventLogWorker.ts`)
- Parses Windows EVTX files
- Extracts structured event data
- MITRE ATT&CK technique mapping
- CTF flag detection (Base64, Hex, ROT13)

**Worker Lifecycle:**
1. Poll queue for jobs
2. Download file from storage
3. Execute analysis tool/script
4. Emit progress via WebSocket
5. Save results to storage
6. Mark job complete/failed
7. Delete temporary files

---

### Redis Database

**Provider:** Railway (or self-hosted)

**Purpose:**
- Bull queue job storage
- Job status tracking
- Result caching (1 hour TTL)
- WebSocket connection state

**Data Structures:**

**Job Data:**
```
bull:{queueName}:{jobId}
{
  "data": {...},       // Job input
  "progress": 45,      // 0-100
  "returnvalue": {...}, // Result
  "attemptsMade": 0,
  "finishedOn": null
}
```

**Cache Data:**
```
cache:vt:{indicator}
{
  "malicious": 5,
  "score": 15,
  ...
}
TTL: 3600 seconds
```

---

## Data Flow

### File Upload Flow

```
1. User selects file in browser
   │
   ▼
2. Frontend validates size/type
   │
   ▼
3. POST to backend /api/v1/{service}/analyze
   │
   ▼
4. Backend creates unique jobId (UUID)
   │
   ▼
5. File saved to storage/uploads/{jobId}/
   │
   ▼
6. Job added to Bull queue
   │
   ▼
7. Frontend receives jobId, subscribes via WebSocket
   │
   ▼
8. Worker picks up job from queue
   │
   ▼
9. Worker processes file, emits progress
   │
   ▼
10. Result saved to storage/results/{jobId}/
    │
    ▼
11. Job marked complete, result sent via WebSocket
    │
    ▼
12. Frontend displays result
    │
    ▼
13. Files auto-deleted after 1 hour
```

### Threat Intel Query Flow

```
1. User inputs indicator (IP/domain/hash)
   │
   ▼
2. Frontend calls /api/threat-intel?service=X&query=Y
   │
   ▼
3. Vercel function checks if API key exists
   │
   ▼
4. Makes request to external API (VirusTotal, etc.)
   │
   ▼
5. Response returned to frontend
   │
   ▼
6. Frontend parses and displays result
```

### WebSocket Communication Flow

```
Client                          Server
  │                               │
  ├──── connect() ───────────────>│
  │<────── connected ──────────────┤
  │                               │
  ├──── join-job(jobId) ─────────>│
  │                          [Store socket in room]
  │                               │
  │<───── job-progress ────────────┤
  │   { progress: 25, message }   │
  │                               │
  │<───── job-progress ────────────┤
  │   { progress: 75, message }   │
  │                               │
  │<───── job-completed ───────────┤
  │   { result: {...} }           │
  │                               │
  ├──── leave-job(jobId) ────────>│
  │                               │
```

---

## Deployment

### Vercel (Frontend + Serverless)

**Build Configuration:**
```json
{
  "buildCommand": "npm run build",
  "outputDirectory": "dist",
  "framework": "vite"
}
```

**Environment Variables:**
```
VIRUSTOTAL_API_KEY
HIBP_API_KEY
ABUSEIPDB_API_KEY
ALIENVAULT_API_KEY
HACKERTARGET_API_KEY
REDIS_URL
VITE_BACKEND_ENABLED=true
VITE_BACKEND_WS_URL=wss://backend.railway.app
VITE_BACKEND_API_URL=https://backend.railway.app
```

**Deployment Trigger:**
- Automatic on push to main branch
- Preview deployments for PRs
- Instant rollback capability

---

### Railway (Backend + Redis)

**Dockerfile Configuration:**
```dockerfile
FROM node:20-slim
RUN apt-get update && apt-get install -y \
    python3 tshark wireshark-common
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build
EXPOSE 8080
CMD ["node", "dist/start.js"]
```

**Environment Variables:**
```
ALLOWED_ORIGINS=https://sectoolbox.cc
MAX_FILE_SIZE=2147483648
NODE_ENV=production
PORT=8080
REDIS_URL=redis://...
STORAGE_PATH=/app/storage
```

**Services:**
1. Backend API Server (Express)
2. Worker Processes (Bull)
3. Redis Database

**Resource Allocation:**
- 2GB RAM per service
- 2 vCPU per service
- 10GB storage volume

---

### DNS Configuration

```
sectoolbox.cc          A      76.76.21.21 (Vercel)
*.sectoolbox.cc       CNAME   cname.vercel-dns.com
```

---

## Scalability

### Horizontal Scaling

**Frontend:**
- Serverless by nature, scales infinitely
- Vercel CDN with 100+ edge locations
- Static assets cached globally

**Serverless Functions:**
- Auto-scale to 100+ concurrent executions
- Cold starts < 50ms (edge functions)
- No manual scaling required

**Backend:**
- Railway auto-scaling based on CPU/memory
- Multiple worker instances possible
- Load balancer distributes traffic

**Redis:**
- Railway managed Redis with replication
- Can upgrade to cluster mode for high traffic
- Automatic failover

### Vertical Scaling

**Current Limits:**
- 2GB file uploads
- 5 minute job timeout
- 50 concurrent jobs per queue

**Scalable To:**
- 10GB file uploads (increase storage)
- 30 minute job timeout (adjust Bull config)
- 500 concurrent jobs (add worker instances)

### Performance Optimizations

**Frontend:**
- Code splitting per route
- Lazy loading of heavy components
- Service worker for offline support
- Image optimization (WebP)

**Backend:**
- Connection pooling (Redis, Bull)
- Result caching (1 hour TTL)
- Compression middleware (gzip)
- Rate limiting per IP

**Database:**
- TTL on cached data
- Cleanup of completed jobs
- Index on job status fields

---

## Security Considerations

### Frontend Security

- Content Security Policy headers
- XSS protection via React sanitization
- No inline scripts or eval()
- HTTPS-only in production

### Backend Security

- Helmet.js security headers
- CORS restricted to allowed origins
- File type validation (magic bytes)
- File size limits enforced
- Input sanitization on all endpoints

### API Security

- API keys stored server-side only
- Rate limiting on all endpoints
- Request timeout enforcement
- No sensitive data in logs

### Data Security

- Files deleted after 1 hour
- No permanent storage of user data
- Redis password protected
- Network isolation (Railway private network)

---

## Monitoring and Logging

### Frontend Monitoring

- Error boundary catching
- Console logging in development
- Performance metrics (Core Web Vitals)

### Backend Monitoring

- Express error handling middleware
- Job failure tracking
- Redis connection monitoring
- Worker health checks

### Logging Strategy

**Production:**
- Error logs only
- Sanitized data (no sensitive info)
- Structured JSON format

**Development:**
- Verbose logging
- Request/response details
- WebSocket event tracking

---

## Technology Choices

### Why React?

- Large ecosystem
- Strong TypeScript support
- Component reusability
- Fast virtual DOM

### Why Vite?

- Instant dev server startup
- Lightning-fast HMR
- Optimized production builds
- Native ESM support

### Why Express?

- Mature and stable
- Extensive middleware ecosystem
- WebSocket integration
- Easy to deploy

### Why Bull + Redis?

- Reliable job queue
- Built-in retry logic
- Priority queues
- Job progress tracking
- Atomic operations

### Why Railway?

- Simple deployment
- Integrated Redis
- Automatic HTTPS
- Private networking
- Fair pricing

---

## Future Architecture Improvements

### Planned Enhancements

1. **Microservices Split**
   - Separate PCAP service
   - Dedicated Python execution service
   - Independent scaling per service

2. **Object Storage**
   - Move from filesystem to S3/R2
   - Better reliability
   - Lower costs at scale

3. **GraphQL API**
   - Replace REST with GraphQL
   - Better frontend data fetching
   - Reduced over-fetching

4. **Database Migration**
   - Add PostgreSQL for metadata
   - Keep Redis for caching only
   - Enable complex queries

5. **CDN for Results**
   - Cache processed results
   - Faster repeat analyses
   - Reduced backend load

---

## Conclusion

Sectoolbox's hybrid architecture balances performance, cost, and developer experience. The separation of concerns allows independent development and deployment of frontend and backend, while the queue-based worker system ensures reliable processing of heavy operations.

The architecture is designed to scale horizontally (more instances) and vertically (bigger instances) as needed, with clear upgrade paths for each component.
