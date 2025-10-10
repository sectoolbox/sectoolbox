# Sectoolbox

> Professional-grade cybersecurity analysis toolkit for CTF competitions and security research

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![React](https://img.shields.io/badge/React-19.1-61DAFB?logo=react)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.8-3178C6?logo=typescript)](https://www.typescriptlang.org/)
[![Vite](https://img.shields.io/badge/Vite-7.1-646CFF?logo=vite)](https://vitejs.dev)

Sectoolbox is a comprehensive web-based security analysis platform designed for CTF players, security researchers, and penetration testers. Built with modern React and TypeScript, it provides powerful forensics and exploitation tools directly in your browser with real-time analysis capabilities.

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
```

Visit `http://localhost:5173` to access the application.

### Build for Production

```bash
npm run build
npm run preview
```

## Usage Examples

### Digital Forensics
1. Navigate to **Digital Forensics** from the Analysis Tools menu
2. Choose your analysis type (General, EVTX, Memory)
3. Upload your file
4. View comprehensive analysis results with visualizations
5. Export findings in your preferred format

### Image Forensics
1. Select **Image** from the Analysis Tools dropdown
2. Upload your image file (JPEG, PNG, GIF, BMP)
3. View EXIF metadata and GPS coordinates
4. Analyze bit planes for hidden data
5. Extract embedded files and run steganography detection

### PCAP Analysis
1. Go to **PCAP** under Analysis Tools
2. Upload network capture file (.pcap, .pcapng)
3. Choose between general PCAP analysis or USB PCAP analysis
4. View packet details, protocol distribution, conversations
5. Analyze suspicious activity and export findings

### Web Exploitation
1. Access **Web** from Security Tools
2. Browse 240+ attack payloads organized by category
3. Use interactive tools for payload testing and encoding
4. Favorite commonly-used payloads for quick access
5. Test SQL injection, XSS, and other vulnerabilities

### Cryptography
1. Open **Cryptography** from Security Tools
2. Choose from encoding, hashing, or cipher operations
3. Paste or type your input
4. View instant results with multiple format options
5. Perform frequency analysis on encrypted text

### Network Intelligence
1. Navigate to **Network** under Analysis Tools
2. Enter domain or IP address
3. Gather intelligence from multiple sources (Shodan, IPInfo, PassiveDNS)
4. View historical website snapshots from Archive.org
5. Check SSL certificates via crt.sh

## Tech Stack

- **Framework**: React 19 + TypeScript 5.8
- **Build Tool**: Vite 7
- **Styling**: Tailwind CSS + shadcn/ui components
- **Routing**: React Router 7
- **Charts**: Recharts for data visualization
- **Icons**: Lucide React
- **Image Processing**: ExifReader, zbar-wasm for QR codes
- **File Handling**: JSZip, file-saver
- **Deployment**: Vercel with serverless functions

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

## Contributing

We welcome contributions! Here's how you can help:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Contribution Guidelines
- Write clean, documented code
- Follow existing code style and conventions
- Test your changes thoroughly across different browsers
- Update documentation as needed
- Add changelog entries for significant changes

## Bug Reports

Found a bug? Please report it on our [Issues page](https://github.com/sectoolbox/sectoolbox/issues/new) with:
- Clear description of the issue
- Steps to reproduce
- Expected vs actual behavior
- Screenshots if applicable
- Browser, OS, and version information

## Community

Join our community:
- **Discord**: [https://discord.gg/SvvKKMzE5Q](https://discord.gg/SvvKKMzE5Q)
- **GitHub Discussions**: [sectoolbox/sectoolbox/discussions](https://github.com/sectoolbox/sectoolbox/discussions)
- **Contribute**: [https://github.com/sectoolbox/sectoolbox](https://github.com/sectoolbox/sectoolbox)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Authors

- **Zeb** - Lead Developer - [@zebbern](https://github.com/zebbern)
- **Kimmi** - Frontend Engineer - [@Opkimmi](https://github.com/Opkimmi)

## Acknowledgments

- Built for the CTF and security research community
- Inspired by the need for accessible, browser-based security tools
- Thanks to all contributors and the open-source community

## Roadmap

- Password analysis and generation tools
- Binary analysis and reverse engineering tools
- Extended memory forensics with Volatility integration
- Keyboard shortcuts for power users
- PWA support for full offline capability
- Custom payload builder
- Report generation system
- API documentation
- Plugin system for community extensions

---

**Made for the cybersecurity community**

Star us on GitHub if you find this useful!
