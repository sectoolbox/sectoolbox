# Deployment Guide

This guide provides step-by-step instructions for deploying Sectoolbox to production using Vercel (frontend + serverless functions) and Railway (backend + Redis).

## Table of Contents

- [Prerequisites](#prerequisites)
- [Architecture Overview](#architecture-overview)
- [Vercel Deployment](#vercel-deployment)
- [Railway Deployment](#railway-deployment)
- [Environment Configuration](#environment-configuration)
- [DNS Configuration](#dns-configuration)
- [Post-Deployment](#post-deployment)
- [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Required Accounts

1. **GitHub Account** - For repository hosting
2. **Vercel Account** - For frontend hosting (free tier available)
3. **Railway Account** - For backend hosting (5 USD credit included)

### Required Tools

```bash
# Install Git
git --version

# Install Node.js 20+
node --version

# Install Railway CLI (optional, for local testing)
npm install -g @railway/cli

# Install Vercel CLI (optional, for local testing)
npm install -g vercel
```

### API Keys

Obtain API keys for external services:

1. **VirusTotal** - https://www.virustotal.com/gui/join-us
2. **Have I Been Pwned** - https://haveibeenpwned.com/API/Key
3. **HackerTarget** (optional) - https://hackertarget.com/ip-tools/
4. **AbuseIPDB** (optional) - https://www.abuseipdb.com/api
5. **AlienVault OTX** (optional) - https://otx.alienvault.com/

---

## Architecture Overview

```
GitHub Repository
       ├─────────────┬─────────────┐
       │             │             │
   Vercel         Railway       Your DNS
  (Frontend)     (Backend)     (Optional)
       │             │             │
   CDN Edge      Private Net    Domain
  + Serverless   + Redis       sectoolbox.cc
```

**Vercel Hosts:**
- React frontend (static files)
- Serverless API functions (/api)

**Railway Hosts:**
- Express backend server
- Redis database
- Background workers

---

## Vercel Deployment

### Step 1: Fork Repository

1. Go to https://github.com/sectoolbox/sectoolbox
2. Click "Fork" button (top right)
3. Select your account
4. Wait for fork to complete

### Step 2: Connect to Vercel

1. Go to https://vercel.com/new
2. Click "Import Project"
3. Select "Import Git Repository"
4. Choose your forked repository
5. Click "Import"

### Step 3: Configure Build Settings

Vercel should auto-detect settings, but verify:

```
Framework Preset: Vite
Build Command: npm run build
Output Directory: dist
Install Command: npm install
```

### Step 4: Add Environment Variables

In Vercel dashboard, go to "Settings" → "Environment Variables":

**Required:**
```bash
# Threat Intel API Keys
VIRUSTOTAL_API_KEY=your_virustotal_key_here
HIBP_API_KEY=your_hibp_key_here

# Backend Connection (leave empty for now, will update after Railway)
VITE_BACKEND_API_URL=
VITE_BACKEND_WS_URL=
VITE_BACKEND_ENABLED=false
```

**Optional:**
```bash
ABUSEIPDB_API_KEY=your_abuseipdb_key_here
ALIENVAULT_API_KEY=your_alienvault_key_here
HACKERTARGET_API_KEY=your_hackertarget_key_here
```

### Step 5: Deploy

1. Click "Deploy" button
2. Wait for build to complete (2-3 minutes)
3. Vercel will provide a URL: `https://your-project.vercel.app`

---

## Railway Deployment

### Step 1: Create Railway Project

1. Go to https://railway.app/new
2. Click "Deploy from GitHub repo"
3. Select your forked repository
4. Click "Deploy Now"

### Step 2: Add Redis Database

1. In Railway dashboard, click "New"
2. Select "Database"
3. Choose "Redis"
4. Wait for provisioning (1 minute)

### Step 3: Configure Backend Service

1. Click on your backend service
2. Go to "Settings"
3. Set "Root Directory" to `backend`
4. Set "Start Command" to `npm start`

### Step 4: Add Environment Variables

In Railway dashboard, go to backend service → "Variables":

```bash
# Node Environment
NODE_ENV=production
PORT=8080

# Redis Connection (automatically provided by Railway)
REDIS_URL=${{Redis.REDIS_URL}}

# CORS Configuration
ALLOWED_ORIGINS=https://your-project.vercel.app

# File Storage
STORAGE_PATH=/app/storage
MAX_FILE_SIZE=2147483648

# Optional: Threat Intel Keys (if not using Vercel's)
VIRUSTOTAL_API_KEY=your_key_here
HIBP_API_KEY=your_key_here
```

### Step 5: Deploy

1. Railway auto-deploys on push to main branch
2. Wait for build to complete (5-7 minutes)
3. Railway provides a URL: `https://your-backend.railway.app`

### Step 6: Add Worker Service (Optional)

For better performance, run workers as separate service:

1. Click "New" → "Empty Service"
2. Connect same GitHub repo
3. Set "Root Directory" to `backend`
4. Set "Start Command" to `npm run start:worker`
5. Add same environment variables
6. Deploy

---

## Environment Configuration

### Update Vercel with Backend URL

1. Go to Vercel dashboard
2. Navigate to "Settings" → "Environment Variables"
3. Update these variables:

```bash
VITE_BACKEND_ENABLED=true
VITE_BACKEND_API_URL=https://your-backend.railway.app
VITE_BACKEND_WS_URL=wss://your-backend.railway.app
VITE_RAILWAY_API_URL=https://your-backend.railway.app
```

4. Redeploy frontend (Vercel → "Deployments" → "Redeploy")

### Update Railway with Frontend URL

1. Go to Railway dashboard
2. Update `ALLOWED_ORIGINS` variable:

```bash
ALLOWED_ORIGINS=https://your-project.vercel.app,https://your-domain.com
```

3. Railway will auto-redeploy

---

## DNS Configuration

### Using Vercel Domain

If using Vercel's free domain (`your-project.vercel.app`), skip this section.

### Using Custom Domain

#### Option 1: Vercel-Managed DNS

1. In Vercel dashboard, go to "Settings" → "Domains"
2. Add your domain: `sectoolbox.cc`
3. Follow Vercel's instructions to:
   - Update nameservers at your registrar
   - Wait for DNS propagation (up to 48 hours)

#### Option 2: External DNS Provider

Configure these DNS records at your provider:

```
Type    Name    Value                           TTL
A       @       76.76.21.21                     3600
CNAME   www     cname.vercel-dns.com            3600
CNAME   *       cname.vercel-dns.com            3600
```

Then in Vercel dashboard:
1. Go to "Settings" → "Domains"
2. Add domain: `sectoolbox.cc`
3. Vercel will verify DNS and provision SSL certificate

### Update Backend ALLOWED_ORIGINS

```bash
ALLOWED_ORIGINS=https://sectoolbox.cc,https://www.sectoolbox.cc
```

---

## Post-Deployment

### Verification Checklist

**Frontend:**
- [ ] Website loads at Vercel URL
- [ ] All pages accessible
- [ ] Client-side tools work (crypto, image analysis)
- [ ] No console errors

**Backend:**
- [ ] Health check: `https://backend.railway.app/health`
- [ ] Returns `{"status":"ok"}`
- [ ] WebSocket connection works
- [ ] File uploads successful

**Serverless Functions:**
- [ ] Threat intel lookups work
- [ ] Nmap scanning works (if API key provided)
- [ ] No CORS errors

**Integration:**
- [ ] PCAP upload → analysis → results
- [ ] Event log upload → parsing → display
- [ ] Audio upload → spectrogram generation
- [ ] WebSocket real-time updates working

### Performance Testing

```bash
# Test backend response time
curl -w "@curl-format.txt" -o /dev/null -s https://backend.railway.app/health

# Test frontend load time
curl -w "@curl-format.txt" -o /dev/null -s https://sectoolbox.cc

# Test file upload (with actual file)
curl -X POST https://backend.railway.app/api/v1/pcap/analyze \
  -F "file=@test.pcap" \
  -F "depth=full"
```

### Monitoring Setup

**Vercel Analytics:**
1. Enable in Vercel dashboard
2. View metrics: "Analytics" tab

**Railway Metrics:**
1. View in Railway dashboard
2. Monitor: CPU, Memory, Network

**External Monitoring:**
1. UptimeRobot: https://uptimerobot.com
2. Add monitors for:
   - Frontend: `https://sectoolbox.cc`
   - Backend: `https://backend.railway.app/health`

---

## Troubleshooting

### Frontend Issues

**Problem: Website shows "Failed to load"**
```bash
# Check Vercel build logs
# Ensure all dependencies installed
# Verify environment variables set
```

**Problem: "Backend not available"**
```bash
# Verify VITE_BACKEND_API_URL is correct
# Check VITE_BACKEND_ENABLED=true
# Redeploy frontend after changing env vars
```

**Problem: CORS errors in browser console**
```bash
# Update Railway ALLOWED_ORIGINS
# Must include exact protocol and domain
# No trailing slashes
```

---

### Backend Issues

**Problem: Build fails on Railway**
```bash
# Check Dockerfile syntax
# Verify all dependencies in package.json
# Check Python requirements.txt for errors
# Review Railway build logs
```

**Problem: 502 Bad Gateway**
```bash
# Check backend is running: /health endpoint
# Verify PORT=8080 in environment
# Check logs for startup errors
# Ensure Redis connection successful
```

**Problem: "Redis connection failed"**
```bash
# Verify REDIS_URL is set correctly
# Use Railway variable reference: ${{Redis.REDIS_URL}}
# Check Redis service is running
# Restart both Redis and backend
```

**Problem: Files not deleted after 1 hour**
```bash
# Check cleanup scheduler is running
# Review backend logs for cleanup messages
# Verify STORAGE_PATH is writable
# Check disk space on Railway
```

---

### Worker Issues

**Problem: Jobs stuck in "queued" status**
```bash
# Check worker process is running
# Verify worker connects to same Redis
# Check worker logs for errors
# Ensure tools installed (tshark, python3)
```

**Problem: "Command not found: tshark"**
```bash
# Verify Dockerfile includes tshark
# Check apt-get install succeeded
# Rebuild Docker image
```

**Problem: Python script execution fails**
```bash
# Check script exists in backend/src/scripts/pythonScripts/
# Verify requirements.txt includes dependencies
# Check Python script has execute permissions
# Review script output in worker logs
```

---

### Performance Issues

**Problem: Slow file uploads**
```bash
# Check file size (max 2GB)
# Verify network connection
# Test with smaller file first
# Check Railway region (choose closest)
```

**Problem: High memory usage**
```bash
# Monitor Railway metrics
# Increase memory allocation if needed
# Check for memory leaks in workers
# Implement request queuing
```

**Problem: Redis connection errors**
```bash
# Check Redis memory usage
# Increase Redis memory limit
# Clear old cache entries
# Review Redis logs
```

---

### SSL Certificate Issues

**Problem: "Your connection is not private"**
```bash
# Wait for Vercel SSL provisioning (up to 1 hour)
# Verify domain DNS is correct
# Check domain ownership verification
# Try incognito mode (may be cache issue)
```

**Problem: Mixed content warnings**
```bash
# Ensure all resources loaded via HTTPS
# Update http:// links to https://
# Check WebSocket using wss:// not ws://
```

---

## Scaling Considerations

### When to Scale

**Indicators:**
- Response time > 3 seconds
- Memory usage > 80%
- CPU usage > 70%
- Queue backlog growing

### Scaling Options

**Frontend (Vercel):**
- Auto-scales infinitely
- No action needed
- Consider Pro plan for:
  - Analytics
  - Faster builds
  - More team members

**Backend (Railway):**
- Vertical scaling: Increase memory/CPU
- Horizontal scaling: Multiple instances
- Load balancer: Railway Pro plan
- Separate worker instances

**Redis:**
- Upgrade to larger instance
- Enable persistence
- Add read replicas
- Consider Redis Cluster

---

## Backup and Recovery

### Database Backups

**Redis:**
```bash
# Railway provides automated backups (Pro plan)
# Manual backup:
railway run redis-cli BGSAVE
```

**Important:** Redis is used for cache and queues only. No permanent data stored.

### Configuration Backups

1. Export environment variables:
   - Vercel: Settings → Environment Variables → Export
   - Railway: Variables → Copy to clipboard

2. Store securely (password manager, encrypted file)

3. Document custom configurations

### Recovery Procedure

1. Redeploy from GitHub (automatic)
2. Restore environment variables
3. Verify services running
4. Test critical functionality

---

## Cost Estimates

### Free Tier Usage

**Vercel:**
- 100GB bandwidth/month
- Unlimited deploys
- 100 serverless function executions/day
- Custom domain included

**Railway:**
- 5 USD free credit
- ~500 hours of 1GB server/month
- Pay only for usage beyond credit

### Estimated Monthly Costs

**Light Usage** (< 1000 users/month):
- Vercel: $0 (free tier)
- Railway: $5-10
- Total: $5-10/month

**Medium Usage** (1000-10000 users/month):
- Vercel: $0-20 (may need Pro)
- Railway: $20-50
- Total: $20-70/month

**Heavy Usage** (> 10000 users/month):
- Vercel: $20 (Pro plan)
- Railway: $100-200
- Total: $120-220/month

---

## Security Hardening

### Production Checklist

- [ ] HTTPS only (enforce)
- [ ] API keys in environment variables (never in code)
- [ ] CORS properly configured
- [ ] Rate limiting enabled
- [ ] File size limits enforced
- [ ] Input validation on all endpoints
- [ ] Security headers configured (Helmet.js)
- [ ] Regular dependency updates
- [ ] Monitoring and alerting configured
- [ ] Backup procedure documented

### Security Headers

Verify these headers are present:

```bash
curl -I https://sectoolbox.cc
```

Expected headers:
```
strict-transport-security: max-age=31536000
x-content-type-options: nosniff
x-frame-options: SAMEORIGIN
x-xss-protection: 1; mode=block
```

---

## Maintenance

### Regular Tasks

**Weekly:**
- Review error logs
- Check disk space usage
- Monitor API quotas

**Monthly:**
- Update dependencies
- Review security advisories
- Check performance metrics
- Rotate API keys (if needed)

**Quarterly:**
- Full security audit
- Load testing
- Backup verification
- Documentation updates

---

## Support

### Getting Help

**Documentation:**
- GitHub: https://github.com/sectoolbox/sectoolbox/docs
- API Reference: /docs/api.md
- Architecture: /docs/architecture.md

**Community:**
- Discord: https://discord.gg/SvvKKMzE5Q
- GitHub Discussions: https://github.com/sectoolbox/sectoolbox/discussions

**Issues:**
- Bug reports: https://github.com/sectoolbox/sectoolbox/issues
- Feature requests: GitHub Discussions

---

## Next Steps

After successful deployment:

1. Configure custom domain (optional)
2. Set up monitoring and alerts
3. Create backup procedure
4. Document your configuration
5. Join community Discord
6. Consider contributing improvements

Congratulations on deploying Sectoolbox!
