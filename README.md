<div align="center">

# Sectoolbox

**Professional cybersecurity analysis toolkit for CTF competitions and security research**

[![React](https://img.shields.io/badge/React-19.1-61DAFB?logo=react)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.8-3178C6?logo=typescript)](https://www.typescriptlang.org/)
[![Vite](https://img.shields.io/badge/Vite-7.1-646CFF?logo=vite)](https://vitejs.dev)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

[Live Website](https://sectoolbox.cc/) • [Documentation](docs/) • [Discord](https://discord.gg/SvvKKMzE5Q)

</div>

## Overview

Sectoolbox is a comprehensive web-based security analysis platform designed for CTF players, security researchers, and penetration testers. Built with modern web technologies, it delivers powerful forensics and exploitation tools directly in your browser with intelligent client-side and server-side processing.

## Features

### Analysis Tools

**Network Forensics:**
- PCAP Analysis - Deep packet inspection with tshark integration
- USB PCAP - USB protocol analysis and packet decoding
- Network Intelligence - DNS lookups, IP info, headers analysis

**File Analysis:**
- Image Analysis - Steganography detection, EXIF extraction, barcode scanning
- Audio Analysis - Spectrograms, frequency analysis, hidden data detection
- Memory Forensics - Process analysis, credential hunting, artifact extraction
- Event Log Analysis - Windows EVTX parsing with MITRE ATT&CK mapping

**Security Tools:**
- Threat Intelligence - VirusTotal, AbuseIPDB, AlienVault OTX, HIBP integrations
- Crypto Tools - Encoding/decoding, hash analysis, cipher identification
- Python Forensics - Full Python 3.11 environment in browser via WebAssembly
- Folder Scanner - Bulk file analysis and pattern detection

**Additional Features:**
- Real-time job processing with WebSocket updates
- Automated threat detection and IOC extraction
- CTF flag pattern recognition (HTB, picoCTF, etc.)
- Export results in multiple formats (JSON, CSV)

## Quick Start

### Try Online

Visit [sectoolbox.cc](https://sectoolbox.cc/) to use the platform instantly - no installation required.

### Run Locally

```bash
# Clone repository
git clone https://github.com/sectoolbox/sectoolbox.git
cd sectoolbox

# Install dependencies
npm install

# Start development server
npm run dev

# Visit http://localhost:5173
```

For detailed setup instructions, see [Getting Started](docs/getting-started.md).

### Deploy Your Own Instance

Deploy to production using Vercel and Railway:

```bash
# Deploy frontend to Vercel
vercel deploy

# Deploy backend to Railway
railway up
```

For complete deployment guide, see [Deployment Documentation](docs/deployment.md).


## Technical Stack

- **Frontend**: React 19, TypeScript 5.8, Vite 7
- **Backend**: Node.js, Express, TypeScript
- **UI Framework**: Tailwind CSS, shadcn/ui
- **Queue System**: Bull with Redis
- **Python Runtime**: Pyodide 0.28.3 (Python 3.11 in WebAssembly)
- **Code Editor**: Monaco Editor
- **Deployment**: 
  - Frontend + API Functions: Vercel
  - Backend + Redis: Railway

For detailed architecture information, see [Architecture Documentation](docs/architecture.md).

## Documentation

Comprehensive documentation is available in the `/docs` directory:

- **[Getting Started](docs/getting-started.md)** - Installation and setup guide
- **[API Reference](docs/api.md)** - Complete API documentation for all endpoints
- **[Architecture](docs/architecture.md)** - System architecture and design decisions
- **[Security](docs/security.md)** - Security practices and threat model
- **[Deployment](docs/deployment.md)** - Production deployment guide for Vercel and Railway
- **[Contributing](docs/contributing.md)** - Contribution guidelines and development standards

Additional documentation:
- [Adding File Upload Analysis Pages](docs/add_file_upload_analysis_page.md)
- [Adding Backend Tools](docs/add_tool_in_backend.md)
- [Event Log Automated Analysis](docs/eventlog_automated_analysis.md)
- [Environment Variables](docs/env_variables.md)

## Project Structure

```
sectoolbox/
├── api/                      # Vercel serverless functions
│   ├── threat-intel.js       # Threat intelligence integrations
│   ├── nmap.js               # Port scanning
│   ├── headers.js            # HTTP header analysis
│   ├── passivedns.js         # DNS history queries
│   └── archive.js            # Wayback Machine integration
├── backend/                  # Railway backend server
│   └── src/
│       ├── routes/           # REST API endpoints
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
- **Bug Reports**: [Open an issue](https://github.com/sectoolbox/sectoolbox/issues)
- **Contributors**: [View contributors](https://github.com/sectoolbox/sectoolbox/graphs/contributors)

## Contributing

We welcome contributions from the community. Before contributing, please review:

- [Contributing Guidelines](docs/contributing.md) - Development standards and PR process
- [Code of Conduct](docs/contributing.md#code-of-conduct) - Community standards
- [Security Policy](docs/security.md) - Reporting vulnerabilities

## Authors

- **Zeb** - [@zebbern](https://github.com/zebbern)
- **Kimmi** - [@Opkimmi](https://github.com/Opkimmi)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

Built for the cybersecurity community with modern web technologies.

Star us on GitHub if you find this project useful.