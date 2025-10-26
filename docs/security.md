# Security

This document outlines Sectoolbox's security architecture, best practices, and threat mitigation strategies. Security is a core priority for a tool handling sensitive forensics data.

## Table of Contents

- [Security Overview](#security-overview)
- [Authentication and Authorization](#authentication-and-authorization)
- [Data Security](#data-security)
- [Network Security](#network-security)
- [Input Validation](#input-validation)
- [API Security](#api-security)
- [Infrastructure Security](#infrastructure-security)
- [Vulnerability Management](#vulnerability-management)
- [Incident Response](#incident-response)
- [Compliance](#compliance)

---

## Security Overview

### Security Principles

1. **Defense in Depth** - Multiple layers of security controls
2. **Least Privilege** - Minimal permissions for all components
3. **Secure by Default** - Security enabled out of the box
4. **Zero Trust** - Validate every request
5. **Privacy First** - No permanent data storage

### Threat Model

**Threats We Protect Against:**
- Malicious file uploads (malware, exploits)
- Cross-site scripting (XSS)
- Cross-site request forgery (CSRF)
- SQL injection (not applicable, no SQL database)
- Command injection
- Path traversal
- Denial of service (DoS)
- Man-in-the-middle attacks
- API abuse and rate limiting bypass

**Out of Scope:**
- Physical security (managed by hosting providers)
- Social engineering
- Insider threats (open-source, community-driven)

---

## Authentication and Authorization

### Current Model: Stateless API

Sectoolbox currently operates as a **public API** without user accounts or authentication. This design choice prioritizes:
- Ease of use
- Privacy (no account creation)
- Simplicity (no session management)

### API Key Management

External API integrations (VirusTotal, AbuseIPDB, etc.) use server-side API keys stored as environment variables.

**Best Practices:**
```bash
# NEVER commit API keys to version control
# Store in .env file (gitignored)
VIRUSTOTAL_API_KEY=your_key_here
HIBP_API_KEY=your_key_here

# Use Railway/Vercel secret management in production
```

**Key Rotation:**
- API keys should be rotated every 90 days
- Use different keys for development/production
- Monitor API usage for anomalies

### Future Authentication Plans

For enterprise deployments, consider adding:
- API token authentication
- OAuth2 integration
- Role-based access control (RBAC)
- User account management

---

## Data Security

### Data Lifecycle

```
1. Upload    → File received
2. Process   → Analysis performed
3. Store     → Results saved (1 hour)
4. Delete    → Automatic cleanup
```

### Data Retention Policy

**Uploaded Files:**
- Stored in `/storage/uploads/{jobId}/`
- **Automatic deletion after 1 hour**
- No backup or archival

**Analysis Results:**
- Stored in `/storage/results/{jobId}/`
- **Automatic deletion after 1 hour**
- Cached in Redis (1 hour TTL)

**Logs:**
- Error logs only in production
- No sensitive data logged
- Sanitized before logging

### Data Privacy

**What We Store:**
- Temporary file uploads (< 1 hour)
- Analysis results (< 1 hour)
- Job queue metadata (Redis)

**What We DON'T Store:**
- User accounts or profiles
- IP addresses (beyond request lifecycle)
- File contents after processing
- User behavior analytics

### Data Encryption

**In Transit:**
- HTTPS only (TLS 1.2+)
- WebSocket over TLS (wss://)
- No unencrypted connections allowed

**At Rest:**
- Railway/Vercel use encrypted volumes
- Redis password protected
- Environment variables encrypted

**Client-Side:**
- Pyodide runs entirely in browser
- No data sent to server for client-side analysis
- Local file processing when possible

### Automatic Cleanup

**Implementation:**
```typescript
// Runs every 15 minutes
const CLEANUP_INTERVAL = 15 * 60 * 1000;
const MAX_FILE_AGE = 60 * 60 * 1000; // 1 hour

function runCleanup() {
  // Find all jobs older than 1 hour
  // Delete uploads and results directories
  // Remove from Redis cache
}
```

**Why 1 Hour?**
- Balances user convenience with security
- Prevents indefinite storage of sensitive data
- Reduces storage costs
- Complies with data minimization principle

---

## Network Security

### CORS Configuration

**Backend Server:**
```typescript
app.use(cors({
  origin: process.env.ALLOWED_ORIGINS?.split(',') || '*',
  credentials: true
}));
```

**Production Configuration:**
```bash
ALLOWED_ORIGINS=https://sectoolbox.cc,https://www.sectoolbox.cc
```

**Development:**
```bash
ALLOWED_ORIGINS=http://localhost:3000,http://localhost:5173
```

### Security Headers

**Helmet.js Configuration:**
```typescript
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "wss:", "https:"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));
```

**Security Headers Added:**
- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: SAMEORIGIN`
- `X-XSS-Protection: 1; mode=block`
- `Strict-Transport-Security: max-age=31536000`
- `Referrer-Policy: strict-origin-when-cross-origin`

### Rate Limiting

**Implementation:**
```typescript
import rateLimit from 'express-rate-limit';

const uploadLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 10, // 10 requests per minute
  message: 'Too many uploads, please try again later',
  standardHeaders: true,
  legacyHeaders: false
});

app.post('/api/v1/*/upload', uploadLimiter, ...);
```

**Rate Limits:**
- File uploads: 10 per minute per IP
- Job status checks: 60 per minute per IP
- Serverless functions: 100 per minute per IP

### DDoS Protection

**Vercel:**
- Automatic DDoS protection
- Edge network absorbs attacks
- Rate limiting at edge

**Railway:**
- Connection limits
- Request size limits
- Timeout enforcement

---

## Input Validation

### File Upload Validation

**Size Validation:**
```typescript
const MAX_FILE_SIZE = 2 * 1024 * 1024 * 1024; // 2GB

function validateFileSize(size: number, maxSize: number = MAX_FILE_SIZE) {
  if (size > maxSize) {
    throw new Error(`File too large. Maximum: ${maxSize} bytes`);
  }
}
```

**File Type Validation:**
```typescript
function validateFileType(filename: string, allowedExtensions: string[]) {
  const ext = filename.split('.').pop()?.toLowerCase();
  if (!ext || !allowedExtensions.includes(ext)) {
    throw new Error(`Invalid file type. Allowed: ${allowedExtensions.join(', ')}`);
  }
}
```

**Magic Byte Validation:**
```typescript
// Verify file type by content, not just extension
import fileType from 'file-type';

async function verifyFileType(buffer: Buffer) {
  const type = await fileType.fromBuffer(buffer);
  // Compare with expected MIME type
}
```

**Filename Sanitization:**
```typescript
function sanitizeFilename(filename: string): string {
  // Remove dangerous characters
  return filename.replace(/[^a-zA-Z0-9._-]/g, '_');
}
```

### Parameter Validation

**Query Parameters:**
```typescript
// Validate indicator format
function validateIP(ip: string): boolean {
  const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return ipRegex.test(ip);
}

function validateDomain(domain: string): boolean {
  const domainRegex = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
  return domainRegex.test(domain);
}
```

**Request Body Validation:**
```typescript
// Use Zod for schema validation
import { z } from 'zod';

const PcapAnalysisSchema = z.object({
  depth: z.enum(['quick', 'full']).default('full'),
  filename: z.string().max(255)
});
```

### Path Traversal Prevention

**Storage Access:**
```typescript
import { join, normalize, resolve } from 'path';

function getJobPath(jobId: string): string {
  // Validate jobId is UUID
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  if (!uuidRegex.test(jobId)) {
    throw new Error('Invalid job ID');
  }

  const basePath = resolve('/app/storage/uploads');
  const jobPath = resolve(basePath, jobId);

  // Ensure path stays within base directory
  if (!jobPath.startsWith(basePath)) {
    throw new Error('Path traversal detected');
  }

  return jobPath;
}
```

### Command Injection Prevention

**Subprocess Execution:**
```typescript
import { spawn } from 'child_process';

// NEVER use shell: true
// NEVER concatenate user input into commands

// BAD:
exec(`tshark -r ${filename}`); // Vulnerable!

// GOOD:
spawn('tshark', ['-r', filename]); // Safe
```

**Python Script Execution:**
```typescript
// Whitelist allowed scripts
const ALLOWED_SCRIPTS = [
  'Forensics/analyze_pdf',
  'Forensics/extract_metadata',
  // ...
];

function executeScript(scriptId: string, filePath: string) {
  if (!ALLOWED_SCRIPTS.includes(scriptId)) {
    throw new Error('Script not allowed');
  }

  // Use array arguments, not string concatenation
  spawn('python3', [scriptPath, filePath]);
}
```

---

## API Security

### External API Integration

**API Key Storage:**
```bash
# Environment variables only
VIRUSTOTAL_API_KEY=abc123...
HIBP_API_KEY=def456...

# NEVER in code:
const apiKey = "abc123..."; // NO!
```

**Proxy Pattern:**
```javascript
// Client → Vercel Function → External API
// Benefits:
// 1. Hides API keys from client
// 2. Adds rate limiting
// 3. Enables caching
// 4. Centralizes error handling

export default async function handler(req, res) {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  const response = await fetch(externalAPI, {
    headers: { 'x-apikey': apiKey }
  });
  return res.json(await response.json());
}
```

### Request Authentication

**Job ID Verification:**
```typescript
// Jobs are identified by UUID
// No authorization check needed (public service)
// But validate UUID format

function verifyJobId(jobId: string): boolean {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(jobId);
}
```

### Timeout Enforcement

**Backend Requests:**
```typescript
const client = axios.create({
  timeout: 120000, // 2 minutes max
});
```

**Worker Jobs:**
```typescript
const job = await queue.add(data, {
  timeout: 300000, // 5 minutes max
});
```

---

## Infrastructure Security

### Environment Isolation

**Development:**
```
Backend:    http://localhost:8080
Redis:      redis://localhost:6379
Frontend:   http://localhost:5173
```

**Production:**
```
Backend:    https://backend.railway.app (private network)
Redis:      redis://...:6379 (password protected)
Frontend:   https://sectoolbox.cc (Vercel CDN)
```

### Network Segmentation

**Railway Private Network:**
- Backend and Redis communicate privately
- No public Redis access
- Firewall rules restrict traffic

**Vercel Edge Network:**
- Frontend served from CDN
- No direct backend access from client
- Serverless functions isolated

### Secret Management

**Railway Secrets:**
```bash
railway variables set REDIS_URL="redis://..."
railway variables set ALLOWED_ORIGINS="https://sectoolbox.cc"
```

**Vercel Secrets:**
```bash
vercel env add VIRUSTOTAL_API_KEY
vercel env add HIBP_API_KEY
```

**Best Practices:**
- Never commit secrets to Git
- Use different secrets per environment
- Rotate secrets regularly
- Audit secret access logs

### Container Security

**Dockerfile Hardening:**
```dockerfile
# Use official base images
FROM node:20-slim

# Run as non-root user
RUN useradd -m -u 1001 appuser
USER appuser

# Minimize installed packages
RUN apt-get update && apt-get install -y \
    python3 \
    tshark \
    && rm -rf /var/lib/apt/lists/*

# Don't expose unnecessary ports
EXPOSE 8080
```

---

## Vulnerability Management

### Dependency Scanning

**Automated Checks:**
```bash
# Check for known vulnerabilities
npm audit

# Fix automatically (if possible)
npm audit fix

# Update dependencies
npm update
```

**GitHub Dependabot:**
- Enabled on repository
- Automatic PR creation for updates
- Security advisories monitored

### Security Updates

**Priority Levels:**
- **Critical**: Patch within 24 hours
- **High**: Patch within 1 week
- **Medium**: Patch within 1 month
- **Low**: Patch in next release

### Known Limitations

**Current Limitations:**
1. No authentication system
2. No user account management
3. Public API (anyone can submit jobs)
4. Limited rate limiting

**Mitigation:**
- Short file retention (1 hour)
- File size limits (2GB)
- Rate limiting per IP
- Resource quotas on Railway

---

## Incident Response

### Security Incident Procedure

**1. Detection**
- Monitor error logs
- Review anomalous API usage
- Check rate limit triggers

**2. Assessment**
- Determine severity
- Identify affected systems
- Estimate impact

**3. Containment**
- Block malicious IPs
- Disable compromised API keys
- Take affected services offline if needed

**4. Eradication**
- Remove malicious files
- Patch vulnerabilities
- Update dependencies

**5. Recovery**
- Restore services
- Verify functionality
- Monitor for recurrence

**6. Post-Incident**
- Document findings
- Update security policies
- Implement preventive measures

### Reporting Security Issues

**How to Report:**
1. Email: security@sectoolbox.cc (preferred)
2. GitHub: Private security advisory
3. Discord: DM to administrators

**What to Include:**
- Vulnerability description
- Steps to reproduce
- Potential impact
- Suggested mitigation

**Response Timeline:**
- Acknowledgment: Within 24 hours
- Initial assessment: Within 48 hours
- Fix deployment: Within 1 week (critical)

---

## Compliance

### Data Protection

**GDPR Compliance:**
- No personal data collected
- No cookies or tracking
- No user accounts
- Automatic data deletion (1 hour)

**Data Minimization:**
- Only store what's necessary for processing
- Delete immediately after use
- No analytics or telemetry

### Open Source License

**MIT License:**
- Free to use, modify, distribute
- No warranty provided
- Users responsible for their deployments

### Responsible Disclosure

Sectoolbox follows responsible disclosure practices:
- 90-day disclosure window
- Coordinate with affected parties
- Public disclosure after fix deployed

---

## Security Checklist

### For Developers

- [ ] Never commit API keys or secrets
- [ ] Validate all user input
- [ ] Use parameterized queries (if SQL used)
- [ ] Sanitize file names
- [ ] Implement rate limiting
- [ ] Use HTTPS everywhere
- [ ] Enable security headers
- [ ] Keep dependencies updated
- [ ] Run security scans before deploy

### For Deployers

- [ ] Set strong Redis password
- [ ] Configure ALLOWED_ORIGINS correctly
- [ ] Use environment variables for secrets
- [ ] Enable automatic cleanup scheduler
- [ ] Set appropriate file size limits
- [ ] Configure rate limiting
- [ ] Monitor error logs
- [ ] Set up backup Redis (optional)
- [ ] Enable firewall rules

### For Users

- [ ] Don't upload sensitive files in production
- [ ] Use own instance for private data
- [ ] Rotate API keys regularly
- [ ] Monitor API usage quotas
- [ ] Report security issues responsibly

---

## Security Tools

### Recommended Tools

**Static Analysis:**
- ESLint with security plugins
- SonarQube for code quality
- npm audit for dependencies

**Dynamic Analysis:**
- OWASP ZAP for penetration testing
- Postman for API testing
- Burp Suite for traffic analysis

**Monitoring:**
- Sentry for error tracking
- LogDNA for log aggregation
- UptimeRobot for availability

---

## Conclusion

Security is an ongoing process, not a destination. Sectoolbox implements multiple layers of security controls to protect user data and prevent abuse. Regular audits, updates, and community feedback help maintain a secure platform.

For the latest security advisories and updates, check:
- GitHub Security Tab: https://github.com/sectoolbox/sectoolbox/security
- Discord Announcements: https://discord.gg/SvvKKMzE5Q
- Release Notes: https://github.com/sectoolbox/sectoolbox/releases

---

## Additional Resources

- OWASP Top 10: https://owasp.org/www-project-top-ten/
- CWE Top 25: https://cwe.mitre.org/top25/
- Node.js Security Best Practices: https://nodejs.org/en/docs/guides/security/
- Express Security Guide: https://expressjs.com/en/advanced/best-practice-security.html
