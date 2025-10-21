<div align="center">

# Sectoolbox

**Professional cybersecurity analysis toolkit for CTF competitions and security research**

[![React](https://img.shields.io/badge/React-19.1-61DAFB?logo=react)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.8-3178C6?logo=typescript)](https://www.typescriptlang.org/)
[![Vite](https://img.shields.io/badge/Vite-7.1-646CFF?logo=vite)](https://vitejs.dev)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

[Live Website](https://sectoolbox.vercel.app/) • [Documentation|Adding Soon]() • [Discord](https://discord.gg/SvvKKMzE5Q)

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

## Technical Stack

- Frontend: <kbd>React 19, TypeScript 5.8</kbd>
- Build System: <kbd>Vite 7</kbd>
- UI Framework: <kbd>Tailwind CSS, shadcn/ui</kbd>
- Python Runtime: <kbd>Pyodide 0.28.3 (Python 3.11 in WebAssembly)</kbd>
- Code Editor: <kbd>Monaco Editor</kbd>
- Deployment: <kbd>Vercel with serverless functions</kbd>

### Prerequisites
```
- Node.js 18 or higher
- npm or yarn package manager
```

## Installation

```bash
# Clone repository
git clone https://github.com/sectoolbox/sectoolbox.git
cd sectoolbox

# Install dependencies
npm install

# Start development server
npm run dev

# Build for production
npm run build
```

Access the application at `http://localhost:5173`

## Project Structure

```
sectoolbox/
├── api/                  # Vercel serverless functions
├── src/
│   ├── components/       # Reusable UI components
│   ├── pages/            # Application pages
│   ├── lib/              # Analysis logic and utilities
│   └── data/             # Static data and scripts
├── public/               # Static assets
└── package.json
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