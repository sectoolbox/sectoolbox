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

## Technical Stack
```
- Frontend: React 19, TypeScript 5.8
- Build System: Vite 7
- UI Framework: Tailwind CSS, shadcn/ui
- Python Runtime: Pyodide 0.28.3 (Python 3.11 in WebAssembly)
- Code Editor: Monaco Editor
- Deployment: Vercel with serverless functions
```

## Quick Start

### Prerequisites
- Node.js 18 or higher
- npm or yarn package manager

### Installation

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
├── api/                    # Vercel serverless functions
├── src/
│   ├── components/        # Reusable UI components
│   ├── pages/            # Application pages
│   ├── lib/              # Analysis logic and utilities
│   └── data/             # Static data and scripts
├── public/               # Static assets
└── package.json
```

## Key Capabilities

**Python Forensics Environment**
- Full Python 3.11 runtime in browser via WebAssembly
- 17 pre-built CTF scripts for common forensics tasks
- One-click package installation (pycryptodome, numpy, pillow, etc.)
- File browser with metadata analysis and hex viewer
- Shell-like helper functions (ls, cat, grep, hexdump)
- Multi-tab script editing with syntax highlighting

**Real-Time Analysis**
- Instant processing and results
- Live data visualization
- Interactive analysis tools
- Export results in multiple formats

## Community

- **Discord**: [Join our server](https://discord.gg/SvvKKMzE5Q)
- **GitHub Discussions**: [Ask questions](https://github.com/sectoolbox/sectoolbox/discussions)
- **Contributors**: [View contributors](https://github.com/sectoolbox/sectoolbox/graphs/contributors)

## Authors

- **Zeb** - [@zebbern](https://github.com/zebbern)
- **Kimmi** - [@Opkimmi](https://github.com/Opkimmi)

> **Built for the cybersecurity community with modern web technologies**

---

### Star us on GitHub if you find this project useful!
