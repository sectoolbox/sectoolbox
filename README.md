<div align="center">

# Sectoolbox

**Professional cybersecurity analysis toolkit for CTF competitions and security research**

[![React](https://img.shields.io/badge/React-19.1-61DAFB?logo=react)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.8-3178C6?logo=typescript)](https://www.typescriptlang.org/)
[![Vite](https://img.shields.io/badge/Vite-7.1-646CFF?logo=vite)](https://vitejs.dev)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

[Live Website](https://sectoolbox.cc/) • [Documentation](https://github.com/sectoolbox/sectoolbox/docs) • [Discord](https://discord.gg/SvvKKMzE5Q)

</div>

## Overview

Sectoolbox is a web-based security analysis platform designed for CTF players, security researchers, and penetration testers. Built with React and TypeScript, it delivers powerful forensics and exploitation tools directly in your browser with complete client-side processing.

## Main Tools
```
PCAP Analysis - Network packet capture parsing
USB PCAP - USB protocol analysis
Image Analysis - Steganography, EXIF, barcodes
Audio Analysis - Spectrograms, frequency analysis
Memory Forensics - Process analysis, credential hunting
Folder Scanner - Bulk file scanning
Crypto Tools - Encoding/decoding operations
Network - DNS, IP info, headers analysis
Threat Intel - VirusTotal, HIBP, AbuseIPDB integrations
Python Forensics - Full Python environment in browser
Digital Forensics - Disk image analysis
Dashboard - Quick file upload and tool directory
```

## Run locally?
> ### Go to [Getting Started](https://github.com/sectoolbox/sectoolbox/blob/main/docs/getting-started.md)


## Technical Stack

- **Frontend**: <kbd>React 19, TypeScript 5.8, Vite 7</kbd>
- **Backend**: <kbd>Node.js, Express, TypeScript</kbd>
- **UI Framework**: <kbd>Tailwind CSS, shadcn/ui</kbd>
- **Queue System**: <kbd>Bull with Redis</kbd>
- **Python Runtime**: <kbd>Pyodide 0.28.3 (Python 3.11 in WebAssembly)</kbd>
- **Code Editor**: <kbd>Monaco Editor</kbd>
- **Deployment**: 
  - Frontend + API Functions: <kbd>Vercel</kbd>
  - Backend + Redis: <kbd>Railway</kbd>


## Architecture

Sectoolbox uses a hybrid architecture optimized for both performance and deployment flexibility:

### **Frontend (Vercel)**
- React SPA served via Vercel's CDN
- Client-side analysis for lightweight operations
- WebAssembly (Pyodide) for in-browser Python execution

### **API Functions (Vercel Serverless)**
Located in `/api/`:
- `nmap.js` - Port scanning via HackerTarget API
- `threat-intel.js` - Threat intelligence lookups
- `passivedns.js` - DNS history queries
- `headers.js` - HTTP header analysis
- `archive.js` - Wayback Machine integration

### **Backend Server (Railway)**
Located in `/backend/`:
- Express server for heavy processing tasks
- Bull queue system with Redis for job management
- WebSocket support for real-time updates
- Workers for:
  - PCAP analysis (tshark integration)
  - Audio spectrogram generation
  - Python script execution

**Communication**: Frontend ↔ Backend API (REST + WebSocket) ↔ Redis ↔ Workers


## Project Structure

```
sectoolbox/
├── api/                      # Vercel serverless functions (HackerTarget, DNS, etc.)
├── backend/                  # Railway backend server
│   └── src/
│       ├── routes/           # API endpoints
│       ├── workers/          # Background job processors
│       ├── services/         # Queue, WebSocket, storage
│       └── utils/            # Shared utilities
├── src/                      # Frontend React application
│   ├── components/           # Reusable UI components
│   ├── pages/                # Application pages
│   ├── lib/                  # Analysis logic and utilities
│   ├── services/             # API client, WebSocket
│   └── hooks/                # React hooks
├── public/                   # Static assets
└── docs/                     # Documentation
```

## Community

- **Discord**: [Join our server](https://discord.gg/SvvKKMzE5Q)
- **GitHub Discussions**: [Ask questions](https://github.com/sectoolbox/sectoolbox/discussions)
- **Contributors**: [View contributors](https://github.com/sectoolbox/sectoolbox/graphs/contributors)

## Authors

- **Zeb** - [@zebbern](https://github.com/zebbern)
- **Kimmi** - [@Opkimmi](https://github.com/Opkimmi)

> **Built for the cybersecurity community with modern web technologies**

---

<div align="center">

### ⭐ Star us on GitHub if you find this project useful!⭐

</div>