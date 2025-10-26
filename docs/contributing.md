# Contributing to Sectoolbox

Thank you for considering contributing to Sectoolbox! This document provides guidelines and instructions for contributing to the project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Contributing Guidelines](#contributing-guidelines)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)
- [Community](#community)

---

## Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inspiring community for all. We pledge to make participation in our project a harassment-free experience for everyone, regardless of age, body size, disability, ethnicity, gender identity, level of experience, nationality, personal appearance, race, religion, or sexual identity and orientation.

### Our Standards

**Positive behavior includes:**
- Using welcoming and inclusive language
- Being respectful of differing viewpoints
- Gracefully accepting constructive criticism
- Focusing on what is best for the community
- Showing empathy towards other community members

**Unacceptable behavior includes:**
- Trolling, insulting comments, and personal attacks
- Public or private harassment
- Publishing others' private information without permission
- Other conduct which could reasonably be considered inappropriate

### Enforcement

Violations of the Code of Conduct may be reported to the project maintainers. All complaints will be reviewed and investigated promptly and fairly.

---

## Getting Started

### Ways to Contribute

**Code Contributions:**
- Bug fixes
- New features
- Performance improvements
- Code refactoring

**Non-Code Contributions:**
- Documentation improvements
- Bug reports
- Feature suggestions
- Community support
- Tutorial creation
- Translation

### First-Time Contributors

Look for issues labeled:
- `good first issue` - Simple tasks for beginners
- `help wanted` - Tasks where we need assistance
- `documentation` - Documentation improvements

---

## Development Setup

### Prerequisites

```bash
# Required
Node.js 20+
npm or yarn
Git

# Optional (for backend development)
Docker
Python 3.11+
Redis
```

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:

```bash
git clone https://github.com/YOUR_USERNAME/sectoolbox.git
cd sectoolbox
```

3. Add upstream remote:

```bash
git remote add upstream https://github.com/sectoolbox/sectoolbox.git
```

### Install Dependencies

**Frontend:**
```bash
npm install
```

**Backend:**
```bash
cd backend
npm install
pip install -r requirements.txt
```

### Environment Setup

Create `.env` file in root:

```bash
VITE_BACKEND_ENABLED=true
VITE_BACKEND_API_URL=http://localhost:8080
VITE_BACKEND_WS_URL=ws://localhost:8080
```

Create `.env` file in `backend/`:

```bash
NODE_ENV=development
PORT=8080
REDIS_URL=redis://localhost:6379
ALLOWED_ORIGINS=http://localhost:5173,http://localhost:3000
STORAGE_PATH=./storage
MAX_FILE_SIZE=2147483648
```

### Start Development Servers

**Frontend:**
```bash
npm run dev
# Runs on http://localhost:5173
```

**Backend:**
```bash
cd backend
npm run dev
# Runs on http://localhost:8080
```

**Redis (Docker):**
```bash
docker run -d -p 6379:6379 redis:latest
```

---

## Project Structure

```
sectoolbox/
├── src/                    # Frontend source code
│   ├── components/         # React components
│   │   ├── ui/             # Base UI components
│   │   ├── eventlogs/      # Event log components
│   │   └── pcap/           # PCAP components
│   ├── pages/              # Page components
│   ├── lib/                # Utility functions
│   ├── services/           # API clients
│   └── hooks/              # Custom React hooks
├── backend/                # Backend source code
│   └── src/
│       ├── routes/         # API endpoints
│       ├── workers/        # Background workers
│       ├── services/       # Core services
│       ├── utils/          # Utilities
│       └── scripts/        # Python scripts
├── api/                    # Vercel serverless functions
├── docs/                   # Documentation
├── public/                 # Static assets
└── .config/                # Build configurations
```

### Key Files

**Frontend:**
- `src/App.tsx` - Main app component with routing
- `src/main.tsx` - Entry point
- `src/services/api.ts` - Backend API client
- `src/services/websocket.ts` - WebSocket client

**Backend:**
- `backend/src/server.ts` - Express server
- `backend/src/services/queue.ts` - Bull queue setup
- `backend/src/services/websocket.ts` - WebSocket server
- `backend/src/workers/index.ts` - Worker process

---

## Contributing Guidelines

### Before You Start

1. Check existing issues and pull requests
2. Discuss major changes in GitHub Discussions first
3. Ensure your fork is up to date
4. Create a feature branch

### Branch Naming

Use descriptive branch names:

```bash
feature/add-pdf-analysis
fix/cors-error-threat-intel
docs/improve-deployment-guide
refactor/simplify-pcap-parser
```

### Commit Messages

Follow conventional commits format:

```
type(scope): description

[optional body]

[optional footer]
```

**Types:**
- `feat` - New feature
- `fix` - Bug fix
- `docs` - Documentation changes
- `style` - Code style changes (formatting)
- `refactor` - Code refactoring
- `test` - Adding/updating tests
- `chore` - Maintenance tasks

**Examples:**
```bash
feat(pcap): add support for pcapng format
fix(eventlogs): resolve CORS issue with threat intel API
docs(api): add examples for threat intel endpoints
refactor(frontend): simplify state management in PcapAnalysis
test(backend): add unit tests for validators
chore(deps): update dependencies to latest versions
```

### Making Changes

1. Create feature branch:
```bash
git checkout -b feature/your-feature-name
```

2. Make your changes

3. Test your changes:
```bash
npm run lint
npm run build
```

4. Commit changes:
```bash
git add .
git commit -m "feat: your descriptive message"
```

5. Push to your fork:
```bash
git push origin feature/your-feature-name
```

6. Create Pull Request on GitHub

---

## Pull Request Process

### Before Submitting

**Checklist:**
- [ ] Code follows project style guidelines
- [ ] All tests pass
- [ ] No console errors or warnings
- [ ] Documentation updated (if needed)
- [ ] Commit messages are clear and descriptive
- [ ] Branch is up to date with main
- [ ] Changes are focused and minimal

### PR Title

Use same format as commit messages:

```
feat(pcap): add TCP stream following
fix(security): resolve XSS vulnerability in search
docs(deployment): add Railway configuration steps
```

### PR Description

Include:

1. **What** - What changes were made
2. **Why** - Why these changes are needed
3. **How** - How the changes work
4. **Testing** - How to test the changes
5. **Screenshots** - For UI changes
6. **Related Issues** - Link to relevant issues

**Template:**
```markdown
## Description
Brief description of changes

## Motivation
Why these changes are needed

## Changes Made
- Change 1
- Change 2
- Change 3

## Testing Steps
1. Step 1
2. Step 2
3. Expected result

## Screenshots
(if applicable)

## Related Issues
Closes #123
Related to #456
```

### Review Process

1. Maintainers will review your PR
2. Address any requested changes
3. Once approved, PR will be merged
4. Celebrate your contribution!

**Review Timeline:**
- Initial review: 2-3 days
- Follow-up reviews: 1-2 days
- Merging: After approval

---

## Coding Standards

### TypeScript/JavaScript

**Style Guide:**
```typescript
// Use TypeScript for type safety
interface User {
  id: string;
  name: string;
}

// Prefer const over let
const userName = 'John';

// Use arrow functions
const greet = (name: string): string => {
  return `Hello, ${name}!`;
};

// Use async/await over promises
async function fetchData(): Promise<Data> {
  const response = await fetch(url);
  return response.json();
}

// Destructure when possible
const { id, name } = user;

// Use template literals
const message = `User ${name} has ID ${id}`;
```

**Naming Conventions:**
```typescript
// PascalCase for components and classes
class UserService {}
const UserProfile = () => {};

// camelCase for variables and functions
const userName = 'John';
function getUserById() {}

// UPPER_CASE for constants
const MAX_FILE_SIZE = 2147483648;

// Prefix booleans with is/has/should
const isLoading = true;
const hasError = false;
```

### React Components

```typescript
// Use functional components
import React from 'react';

interface Props {
  title: string;
  onClose: () => void;
}

export const Modal: React.FC<Props> = ({ title, onClose }) => {
  return (
    <div className="modal">
      <h2>{title}</h2>
      <button onClick={onClose}>Close</button>
    </div>
  );
};
```

### File Organization

```typescript
// Order: imports, types, component, exports

// 1. React imports
import React, { useState, useEffect } from 'react';

// 2. Third-party imports
import axios from 'axios';

// 3. Local imports
import { Button } from '@/components/ui/button';
import { api } from '@/services/api';

// 4. Types
interface Props {
  // ...
}

// 5. Component
export const Component: React.FC<Props> = (props) => {
  // ...
};
```

### CSS/Styling

**Use Tailwind utility classes:**
```tsx
<div className="flex items-center gap-2 p-4 bg-white rounded-lg shadow">
  <span className="text-lg font-semibold">Title</span>
</div>
```

**Group related utilities:**
```tsx
// Layout
<div className="flex flex-col items-center justify-center">
  
// Spacing
<div className="p-4 m-2 gap-3">
  
// Typography
<span className="text-lg font-bold text-gray-900">
```

### Python Scripts

```python
#!/usr/bin/env python3
"""
Module docstring explaining purpose
"""

import sys
import json
from typing import Dict, List, Any

def analyze_file(filepath: str) -> Dict[str, Any]:
    """
    Function docstring with parameters and return type
    
    Args:
        filepath: Path to the file to analyze
        
    Returns:
        Dictionary containing analysis results
    """
    # Implementation
    return {'data': [], 'metadata': {}}

def main() -> None:
    """Main entry point"""
    if len(sys.argv) < 2:
        print(json.dumps({'error': 'No file path provided'}))
        sys.exit(1)
    
    result = analyze_file(sys.argv[1])
    print(json.dumps(result, default=str))

if __name__ == '__main__':
    main()
```

---

## Testing

### Frontend Testing

```bash
# Run linter
npm run lint

# Build for production (catches type errors)
npm run build

# Manual testing
npm run dev
```

**Test Checklist:**
- [ ] Page loads without errors
- [ ] All interactive elements work
- [ ] No console warnings
- [ ] Responsive design works
- [ ] Accessibility (keyboard navigation)

### Backend Testing

```bash
# Run linter
cd backend
npm run lint

# Build TypeScript
npm run build

# Test API endpoints
curl http://localhost:8080/health
```

**Test Checklist:**
- [ ] API endpoints return correct status codes
- [ ] File uploads work correctly
- [ ] Job processing completes successfully
- [ ] WebSocket events fire properly
- [ ] Error handling works as expected

### Integration Testing

Test complete workflows:

1. **PCAP Analysis:**
   - Upload PCAP file
   - Verify job creation
   - Check WebSocket updates
   - Confirm result display

2. **Event Log Analysis:**
   - Upload EVTX file
   - Verify parsing completes
   - Check MITRE mappings
   - Test threat intel lookups

3. **Python Script Execution:**
   - Upload test file
   - Select script
   - Verify execution
   - Check result format

---

## Documentation

### When to Update Docs

Update documentation when you:
- Add new features
- Change API endpoints
- Modify configuration
- Add environment variables
- Change deployment process

### Documentation Standards

**API Documentation:**
```markdown
### Endpoint Name

**Endpoint:** `POST /api/v1/service/action`

Description of what the endpoint does.

#### Request

| Parameter | Type | Required | Description |
|-----------|------|----------|-------------|
| param1 | string | Yes | Description |

#### Example Request

\`\`\`bash
curl -X POST https://api.example.com/endpoint \
  -F "file=@test.pdf"
\`\`\`

#### Response

\`\`\`json
{
  "jobId": "uuid",
  "status": "queued"
}
\`\`\`
```

**Code Comments:**
```typescript
// Explain WHY, not WHAT
// Bad: Increment counter
count++;

// Good: Track number of retry attempts for rate limiting
retryCount++;

// Complex logic needs explanation
/**
 * Validates PCAP file format by checking magic number in first 4 bytes.
 * Supports both legacy pcap (0xA1B2C3D4) and pcapng (0x0A0D0D0A) formats.
 */
function validatePcapFormat(buffer: Buffer): boolean {
  // Implementation
}
```

---

## Community

### Communication Channels

**GitHub:**
- Issues - Bug reports and feature requests
- Discussions - General questions and ideas
- Pull Requests - Code contributions

**Discord:**
- Real-time chat
- Community support
- Development discussions
- Join: https://discord.gg/SvvKKMzE5Q

### Getting Help

**Before asking:**
1. Check documentation
2. Search existing issues
3. Review GitHub Discussions

**When asking:**
- Provide context
- Include error messages
- Share relevant code
- Describe what you tried

### Recognition

Contributors are recognized in:
- GitHub Contributors page
- Release notes
- README acknowledgments

---

## Release Process

### Versioning

We use Semantic Versioning (SemVer):

```
MAJOR.MINOR.PATCH

1.2.3
│ │ │
│ │ └─ Patch: Bug fixes
│ └─── Minor: New features (backward compatible)
└───── Major: Breaking changes
```

### Release Checklist

- [ ] All tests passing
- [ ] Documentation updated
- [ ] Changelog updated
- [ ] Version bumped
- [ ] Git tag created
- [ ] Deployed to production
- [ ] Release notes published

---

## License

By contributing to Sectoolbox, you agree that your contributions will be licensed under the MIT License.

---

## Questions?

If you have questions about contributing:

1. Check the [documentation](https://github.com/sectoolbox/sectoolbox/docs)
2. Ask in [GitHub Discussions](https://github.com/sectoolbox/sectoolbox/discussions)
3. Join our [Discord](https://discord.gg/SvvKKMzE5Q)

Thank you for contributing to Sectoolbox!
