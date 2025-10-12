<div align="center">

# Sectoolbox

> Cybersecurity analysis toolkit for CTF competitions and security research

[![React](https://img.shields.io/badge/React-19.1-61DAFB?logo=react)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.8-3178C6?logo=typescript)](https://www.typescriptlang.org/)
[![Vite](https://img.shields.io/badge/Vite-7.1-646CFF?logo=vite)](https://vitejs.dev)

Sectoolbox is a web-based security analysis platform designed for CTF players, security researchers, and penetration testers. Built with modern React and TypeScript, it provides powerful forensics and exploitation tools directly in your browser with real-time analysis capabilities.

<img width="600" height="600" alt="{E03A6043-A370-4DEF-83C8-6FA26E429A7D}" src="https://github.com/user-attachments/assets/58957240-cff9-43a8-b14b-c4e11a27eff8" />

</div>

## Features

### Digital Forensics Suite
- **Image Analysis** - EXIF extraction, steganography detection, hex viewer, QR code scanning, bit plane analysis
- **Audio Analysis** - Spectral analysis, DTMF detection, hidden data extraction, waveform visualization
- **PCAP Analysis** - Network packet inspection, protocol analysis, traffic visualization, conversation tracking
- **USB PCAP Analysis** - USB traffic analysis, HID detection, data extraction
- **EVTX Analysis** - Windows Event Log parsing, security event investigation, threat detection
- **Memory Forensics** - Memory dump analysis, process inspection, network connections, DLL analysis
- **Folder Scanner** - Recursive file system analysis, entropy checking, file signature detection

### Network Analysis Tools
- **Shodan Integration** - IP intelligence and vulnerability scanning
- **Archive.org CDX** - Historical website snapshots with pagination and filtering
- **IPInfo.io** - Geolocation and network information
- **PassiveDNS** - Historical DNS records
- **crt.sh** - Certificate transparency logs
- **HTTP Headers** - Server header analysis and security assessment

### Web Exploitation Arsenal
- **240+ Attack Payloads** across 26 categories
- **Interactive Testing Tools** - Hash identifier, encoding chain builder, SQL injection tester
- **Payload Management** - Favorites system with localStorage persistence
- **Advanced Categories**:
  - SQL Injection, XSS, RCE, LFI/RFI, SSTI
  - XXE, CSRF, SSRF, NoSQL, GraphQL, JWT
  - Deserialization, HTTP Request Smuggling
  - OAuth/SAML, WebSocket, Prototype Pollution
  - Web Cache Poisoning, Race Conditions

### Cryptography Tools
- **Encoding/Decoding** - Base64, Hex, URL, HTML entities, Unicode, Binary
- **Hash Analysis** - MD5, SHA family, hash identification and cracking guidance
- **Classical Ciphers** - Caesar, Vigenere, ROT13, Atbash, Affine
- **Frequency Analysis** - Statistical cryptanalysis for encrypted text
- **Modern Crypto** - JWT decoder, RSA tools

### Advanced Features
- **Real-time Analysis** - Instant results as you work with live processing
- **Serverless Architecture** - Vercel serverless functions for CORS-free API access
- **Offline Capable** - All processing happens locally in your browser
- **Export Results** - Download analysis in multiple formats (JSON, CSV, text)
- **Responsive Design** - Works seamlessly on desktop, tablet, and mobile
- **Dark Mode** - Professional CTF-friendly interface with optimized contrast
- **No Backend Required** - Complete client-side processing for privacy
- **Search Functionality** - Quick tool search across all modules
- **Dropdown Navigation** - Organized tool categories for easy access

## Quick Start

### Prerequisites
- Node.js 18+ and npm

### Installation

```bash
# Clone the repository
git clone https://github.com/sectoolbox/sectoolbox.git
cd sectoolbox

# Install dependencies
npm install

# Start development server
npm run dev

# Build for Production
npm run build
npm run preview
```

Visit `http://localhost:5173` to access the application.

## Tech Stack

```
- Framework: React 19 + TypeScript 5.8
- Build Tool: Vite 7
- Styling: Tailwind CSS + shadcn/ui components
- Routing: React Router 7
- Charts: Recharts for data visualization
- Icons: Lucide React
- Image Processing: ExifReader, zbar-wasm for QR codes
- File Handling: JSZip, file-saver
- Deployment: Vercel with serverless functions
```

## Project Structure

```
sectoolbox/
├── api/                    # Vercel serverless functions
│   ├── archive.js         # Archive.org CDX proxy
│   ├── passivedns.js      # PassiveDNS proxy
│   └── headers.js         # HTTP headers proxy
├── src/
│   ├── components/        # Reusable UI components
│   │   ├── Layout.tsx     # Navigation and search
│   │   └── Footer.tsx     # Footer with links
│   ├── pages/            # Main application pages
│   │   ├── Dashboard.tsx
│   │   ├── ImageAnalysis.tsx
│   │   ├── AudioAnalysis.tsx
│   │   ├── PcapAnalysis.tsx
│   │   ├── USBPcapAnalysis.tsx
│   │   ├── DigitalForensics.tsx
│   │   ├── EVTXAnalysis.tsx
│   │   ├── MemoryForensics.tsx
│   │   ├── FolderScanner.tsx
│   │   ├── WebTools.tsx
│   │   ├── CryptoTools.tsx
│   │   └── Network.tsx
│   ├── lib/              # Utility functions and analysis logic
│   │   ├── forensics.ts
│   │   ├── pcapAnalysis.ts
│   │   ├── audioAnalysis.ts
│   │   ├── imageAnalysis.ts
│   │   └── toolsDatabase.ts
│   └── hooks/            # Custom React hooks
├── public/               # Static assets
└── package.json
```

## Community

Join our community:
- **Discord**: [https://discord.gg/SvvKKMzE5Q](https://discord.gg/SvvKKMzE5Q)
- **GitHub Discussions**: [sectoolbox/sectoolbox/discussions](https://github.com/sectoolbox/sectoolbox/discussions)
- **Contribute**: [https://github.com/sectoolbox/sectoolbox](https://github.com/sectoolbox/sectoolbox)

## Authors

- **Zeb** - Lead Developer - [@zebbern](https://github.com/zebbern)
- **Kimmi** - Frontend Engineer - [@Opkimmi](https://github.com/Opkimmi)

## Roadmap

- Binary analysis and reverse engineering tools
- Extended memory forensics with Volatility integration
- Custom payload builder
- Report generation system
- Plugin system for community extensions
- API documentation
- Website documentation

---

**Made for the cybersecurity community**

Star us on GitHub if you find this useful!
