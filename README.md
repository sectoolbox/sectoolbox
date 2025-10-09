# 🛡️ Sectoolbox

> Professional-grade cybersecurity analysis toolkit for CTF competitions and security research

[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![React](https://img.shields.io/badge/React-19.1-61DAFB?logo=react)](https://react.dev)
[![TypeScript](https://img.shields.io/badge/TypeScript-5.8-3178C6?logo=typescript)](https://www.typescriptlang.org/)
[![Vite](https://img.shields.io/badge/Vite-7.1-646CFF?logo=vite)](https://vitejs.dev)

Sectoolbox is a comprehensive web-based security analysis platform designed for CTF players, security researchers, and penetration testers. Built with modern React and TypeScript, it provides powerful forensics and exploitation tools directly in your browser.

## ✨ Features

### 🔍 Digital Forensics Suite
- **Image Analysis** - EXIF extraction, steganography detection, hex viewer, QR code scanning
- **Audio Analysis** - Spectral analysis, DTMF detection, hidden data extraction
- **PCAP Analysis** - Network packet inspection and protocol analysis
- **USB PCAP Analysis** - USB traffic analysis and forensics
- **EVTX Analysis** - Windows Event Log parsing and investigation
- **Folder Scanner** - Recursive file system analysis and entropy checking

### 🌐 Web Exploitation Arsenal
- **240+ Attack Payloads** across 26 categories
- **Interactive Testing Tools** - Hash identifier, encoding chain builder, SQL injection tester
- **Payload Management** - Favorites system, history tracking with localStorage
- **Advanced Categories**:
  - SQL Injection, XSS, RCE, LFI/RFI, SSTI
  - XXE, CSRF, SSRF, NoSQL, GraphQL, JWT
  - Deserialization, HTTP Request Smuggling
  - OAuth/SAML, WebSocket, Prototype Pollution
  - Web Cache Poisoning, Race Conditions

### 🔐 Cryptography Tools
- **Encoding/Decoding** - Base64, Hex, URL, HTML entities, Unicode
- **Hash Analysis** - MD5, SHA family, hash cracking guidance
- **Classical Ciphers** - Caesar, Vigenere, ROT13, Atbash
- **Frequency Analysis** - Statistical cryptanalysis tools

### 📊 Advanced Features
- **Real-time Analysis** - Instant results as you work
- **Offline Capable** - All processing happens locally in your browser
- **Export Results** - Download analysis in multiple formats
- **Responsive Design** - Works on desktop, tablet, and mobile
- **Dark Mode** - Professional CTF-friendly interface
- **No Backend Required** - Complete client-side processing

## 🚀 Quick Start

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

## 📖 Usage Examples

### Image Forensics
1. Navigate to the **Image** tab
2. Upload your image file
3. View EXIF metadata, analyze bit planes, check for steganography
4. Extract hidden data and embedded files

### Web Exploitation
1. Go to the **Web** tab
2. Browse 240+ attack payloads organized by category
3. Use interactive tools for payload testing
4. Favorite commonly-used payloads for quick access
5. View payload history to track your testing

### Cryptography
1. Access the **Cryptography** tab
2. Choose encoding/decoding operations
3. Analyze hashes and identify types
4. Solve classical cipher challenges
5. Perform frequency analysis on encrypted text

## 🛠️ Tech Stack

- **Framework**: React 19 + TypeScript
- **Build Tool**: Vite 7
- **Styling**: Tailwind CSS + shadcn/ui
- **Routing**: React Router 7
- **Charts**: Recharts
- **Icons**: Lucide React
- **Image Processing**: ExifReader, zbar-wasm
- **File Handling**: JSZip, file-saver

## 📁 Project Structure

```
sectoolbox/
├── src/
│   ├── components/      # Reusable UI components
│   ├── pages/          # Main application pages
│   │   ├── AudioAnalysis.tsx
│   │   ├── CryptoTools.tsx
│   │   ├── Dashboard.tsx
│   │   ├── DigitalForensics.tsx
│   │   ├── EVTXAnalysis.tsx
│   │   ├── FolderScanner.tsx
│   │   ├── ImageAnalysis.tsx
│   │   ├── PcapAnalysis.tsx
│   │   ├── USBPcapAnalysis.tsx
│   │   └── WebTools.tsx
│   ├── lib/            # Utility functions and analysis logic
│   └── hooks/          # Custom React hooks
├── public/             # Static assets
└── package.json
```

## 🤝 Contributing

We welcome contributions! Here's how you can help:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

### Contribution Guidelines
- Write clean, documented code
- Follow existing code style
- Test your changes thoroughly
- Update documentation as needed

## 🐛 Bug Reports

Found a bug? Please report it on our [Issues page](https://github.com/sectoolbox/sectoolbox/issues/new) with:
- Clear description of the issue
- Steps to reproduce
- Expected vs actual behavior
- Screenshots if applicable
- Browser and OS information

## 💬 Community

Join our community:
- **Discord**: [https://discord.gg/SvvKKMzE5Q](https://discord.gg/SvvKKMzE5Q)
- **GitHub Discussions**: [sectoolbox/sectoolbox/discussions](https://github.com/sectoolbox/sectoolbox/discussions)

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👥 Authors

- **Zeb** - Lead Developer - [@zebbern](https://github.com/zebbern)
- **Kimmi** - Frontend Engineer - [@Opkimmi](https://github.com/Opkimmi)

## 🙏 Acknowledgments

- Built for the CTF and security research community
- Inspired by the need for accessible, browser-based security tools
- Thanks to all contributors and users

## 📈 Roadmap

- [ ] Binary analysis tools
- [ ] Memory forensics capabilities
- [ ] Malware analysis sandbox
- [ ] Network tools (port scanner, DNS lookup)
- [ ] Password analysis tools
- [ ] Dark/Light theme toggle
- [ ] Keyboard shortcuts system
- [ ] PWA support for offline use

---

**Made with ❤️ for the cybersecurity community**

⭐ Star us on GitHub if you find this useful!
