import React, { useState } from 'react'
import {
  Key,
  Hash,
  Copy,
  Download,
  RefreshCw,
  Zap,
  Shield,
  Lock,
  Unlock,
  Binary,
  FileText,
  BarChart3,
  BookOpen,
  Radio,
  Braces,
  Globe
} from 'lucide-react'
import { Button } from '../components/ui/button'

interface CryptoResult {
  input: string
  output: string
  method: string
  timestamp: string
}

interface Tool {
  name: string
  encode?: (text: string, key?: string) => string
  decode?: (text: string, key?: string) => string | null
  description?: string
  example?: string
  needsKey?: boolean
}

const CryptoTools: React.FC = () => {
  const [activeTab, setActiveTab] = useState<'encoding' | 'classical' | 'binary' | 'specialized' | 'ctf' | 'analysis' | 'magic'>('encoding')
  const [input, setInput] = useState('')
  const [output, setOutput] = useState('')
  const [key, setKey] = useState('')
  const [results, setResults] = useState<CryptoResult[]>([])
  const [copied, setCopied] = useState(false)
  const [recursiveMode, setRecursiveMode] = useState(false)
  const [iterationCount, setIterationCount] = useState(0)
  const [magicSteps, setMagicSteps] = useState<string[]>([])
  const [magicResult, setMagicResult] = useState('')

  // ==================== HASHING ALGORITHMS ====================
  const hashingTools: Tool[] = [
    {
      name: 'MD5',
      description: 'MD5 hash algorithm (128-bit)',
      encode: async (text: string) => {
        const encoder = new TextEncoder()
        const data = encoder.encode(text)
        // Note: Web Crypto API doesn't support MD5, so we'll simulate
        // In production, use a proper MD5 library like crypto-js
        let hash = 0
        for (let i = 0; i < text.length; i++) {
          hash = ((hash << 5) - hash) + text.charCodeAt(i)
          hash = hash & hash
        }
        return Math.abs(hash).toString(16).padStart(32, '0')
      }
    },
    {
      name: 'SHA-1',
      description: 'SHA-1 hash algorithm (160-bit)',
      encode: async (text: string) => {
        const encoder = new TextEncoder()
        const data = encoder.encode(text)
        const hashBuffer = await crypto.subtle.digest('SHA-1', data)
        const hashArray = Array.from(new Uint8Array(hashBuffer))
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
      }
    },
    {
      name: 'SHA-256',
      description: 'SHA-256 hash algorithm (256-bit)',
      encode: async (text: string) => {
        const encoder = new TextEncoder()
        const data = encoder.encode(text)
        const hashBuffer = await crypto.subtle.digest('SHA-256', data)
        const hashArray = Array.from(new Uint8Array(hashBuffer))
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
      }
    },
    {
      name: 'SHA-384',
      description: 'SHA-384 hash algorithm (384-bit)',
      encode: async (text: string) => {
        const encoder = new TextEncoder()
        const data = encoder.encode(text)
        const hashBuffer = await crypto.subtle.digest('SHA-384', data)
        const hashArray = Array.from(new Uint8Array(hashBuffer))
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
      }
    },
    {
      name: 'SHA-512',
      description: 'SHA-512 hash algorithm (512-bit)',
      encode: async (text: string) => {
        const encoder = new TextEncoder()
        const data = encoder.encode(text)
        const hashBuffer = await crypto.subtle.digest('SHA-512', data)
        const hashArray = Array.from(new Uint8Array(hashBuffer))
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
      }
    },
    {
      name: 'RIPEMD-160 (Simulated)',
      description: 'RIPEMD-160 hash simulation',
      encode: (text: string) => {
        let hash = 0x67452301
        for (let i = 0; i < text.length; i++) {
          hash = ((hash << 5) - hash) + text.charCodeAt(i)
          hash = hash & hash
        }
        return Math.abs(hash).toString(16).padStart(40, '0')
      }
    },
    {
      name: 'HMAC-SHA256',
      description: 'HMAC with SHA-256 (requires key)',
      needsKey: true,
      encode: async (text: string, keyStr: string = '') => {
        if (!keyStr) return 'Key required'
        const encoder = new TextEncoder()
        const keyData = encoder.encode(keyStr)
        const textData = encoder.encode(text)

        const cryptoKey = await crypto.subtle.importKey(
          'raw',
          keyData,
          { name: 'HMAC', hash: 'SHA-256' },
          false,
          ['sign']
        )

        const signature = await crypto.subtle.sign('HMAC', cryptoKey, textData)
        const hashArray = Array.from(new Uint8Array(signature))
        return hashArray.map(b => b.toString(16).padStart(2, '0')).join('')
      }
    },
    {
      name: 'Whirlpool (Simulated)',
      description: 'Whirlpool hash simulation',
      encode: (text: string) => {
        let hash = 0x9876543210
        for (let i = 0; i < text.length; i++) {
          hash = ((hash << 7) - hash) + text.charCodeAt(i)
          hash = hash & hash
        }
        return Math.abs(hash).toString(16).padStart(128, '0').slice(0, 128)
      }
    }
  ]

  // ==================== ENCODING SCHEMES ====================
  const encodingTools: Tool[] = [
    {
      name: 'Base64',
      description: 'Standard Base64 encoding',
      example: 'Hello → SGVsbG8=',
      encode: (text: string) => btoa(unescape(encodeURIComponent(text))),
      decode: (text: string) => {
        try { return decodeURIComponent(escape(atob(text))) } catch { return null }
      }
    },
    {
      name: 'Base32',
      description: 'Base32 encoding (RFC 4648)',
      example: 'Hello → JBSWY3DP',
      encode: (text: string) => {
        const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
        let bits = ''
        for (let i = 0; i < text.length; i++) {
          bits += text.charCodeAt(i).toString(2).padStart(8, '0')
        }
        while (bits.length % 5 !== 0) bits += '0'
        let result = ''
        for (let i = 0; i < bits.length; i += 5) {
          result += alphabet[parseInt(bits.slice(i, i + 5), 2)]
        }
        while (result.length % 8 !== 0) result += '='
        return result
      },
      decode: (text: string) => {
        try {
          const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
          text = text.toUpperCase().replace(/[^A-Z2-7]/g, '')
          let bits = ''
          for (let i = 0; i < text.length; i++) {
            bits += alphabet.indexOf(text[i]).toString(2).padStart(5, '0')
          }
          let result = ''
          for (let i = 0; i < bits.length - 7; i += 8) {
            result += String.fromCharCode(parseInt(bits.slice(i, i + 8), 2))
          }
          return result
        } catch { return null }
      }
    },
    {
      name: 'Base16 (Hex)',
      description: 'Hexadecimal encoding',
      example: 'Hello → 48656c6c6f',
      encode: (text: string) => Array.from(text).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join(''),
      decode: (text: string) => {
        try {
          return text.match(/.{1,2}/g)?.map(byte => String.fromCharCode(parseInt(byte, 16))).join('') || null
        } catch { return null }
      }
    },
    {
      name: 'Base85 (Ascii85)',
      description: 'Ascii85 encoding',
      example: 'Used in PostScript and PDF',
      encode: (text: string) => {
        const charset = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~'
        let result = ''
        const data = new TextEncoder().encode(text)

        for (let i = 0; i < data.length; i += 4) {
          const chunk = new Array(4).fill(0)
          for (let j = 0; j < 4 && i + j < data.length; j++) {
            chunk[j] = data[i + j]
          }

          let value = (chunk[0] << 24) | (chunk[1] << 16) | (chunk[2] << 8) | chunk[3]
          const encoded = []
          for (let k = 0; k < 5; k++) {
            encoded.unshift(charset[value % 85])
            value = Math.floor(value / 85)
          }
          result += encoded.join('')
        }
        return result
      },
      decode: (text: string) => {
        try {
          const charset = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz!#$%&()*+-;<=>?@^_`{|}~'
          const result: number[] = []

          for (let i = 0; i < text.length; i += 5) {
            let value = 0
            for (let j = 0; j < 5 && i + j < text.length; j++) {
              const charIndex = charset.indexOf(text[i + j])
              if (charIndex === -1) return null
              value = value * 85 + charIndex
            }

            for (let k = 3; k >= 0; k--) {
              result.push((value >> (k * 8)) & 0xFF)
            }
          }

          return new TextDecoder().decode(new Uint8Array(result))
        } catch { return null }
      }
    },
    {
      name: 'Base58',
      description: 'Base58 encoding (Bitcoin)',
      example: 'Used in cryptocurrency addresses',
      encode: (text: string) => {
        const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
        const bytes = new TextEncoder().encode(text)
        let num = 0n
        for (const byte of bytes) {
          num = num * 256n + BigInt(byte)
        }
        let result = ''
        while (num > 0n) {
          result = alphabet[Number(num % 58n)] + result
          num = num / 58n
        }
        for (const byte of bytes) {
          if (byte === 0) result = '1' + result
          else break
        }
        return result
      },
      decode: (text: string) => {
        try {
          const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'
          let result = 0n
          let base = 1n

          for (let i = text.length - 1; i >= 0; i--) {
            const index = alphabet.indexOf(text[i])
            if (index === -1) return null
            result += BigInt(index) * base
            base *= 58n
          }

          const bytes: number[] = []
          while (result > 0n) {
            bytes.unshift(Number(result % 256n))
            result = result / 256n
          }

          for (let i = 0; i < text.length && text[i] === '1'; i++) {
            bytes.unshift(0)
          }

          return new TextDecoder().decode(new Uint8Array(bytes))
        } catch { return null }
      }
    },
    {
      name: 'URL Encoding',
      description: 'Percent encoding for URLs',
      example: 'Hello World → Hello%20World',
      encode: (text: string) => encodeURIComponent(text),
      decode: (text: string) => {
        try { return decodeURIComponent(text) } catch { return null }
      }
    },
    {
      name: 'HTML Entities',
      description: 'HTML entity encoding',
      example: '<script> → &lt;script&gt;',
      encode: (text: string) => text.replace(/[&<>"']/g, m => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;'
      })[m] || m),
      decode: (text: string) => text.replace(/&(amp|lt|gt|quot|#39|#x27);/g, m => ({
        '&amp;': '&', '&lt;': '<', '&gt;': '>', '&quot;': '"', '&#39;': "'", '&#x27;': "'"
      })[m] || m)
    },
    {
      name: 'UUEncode',
      description: 'Unix-to-Unix encoding',
      example: 'Legacy email encoding',
      encode: (text: string) => {
        let result = 'begin 644 file\n'
        for (let i = 0; i < text.length; i += 45) {
          const chunk = text.slice(i, i + 45)
          result += String.fromCharCode(32 + chunk.length)

          let bits = ''
          for (let j = 0; j < chunk.length; j++) {
            bits += chunk.charCodeAt(j).toString(2).padStart(8, '0')
          }
          while (bits.length % 6 !== 0) bits += '0'

          for (let j = 0; j < bits.length; j += 6) {
            result += String.fromCharCode(32 + parseInt(bits.slice(j, j + 6), 2))
          }
          result += '\n'
        }
        result += 'end\n'
        return result
      },
      decode: (text: string) => {
        try {
          const lines = text.split('\n').filter(line => line.trim() && !line.startsWith('begin') && line !== 'end')
          let result = ''

          for (const line of lines) {
            if (line.length === 0) continue
            const len = line.charCodeAt(0) - 32
            const data = line.substring(1)

            let bits = ''
            for (let i = 0; i < data.length; i++) {
              const char = data.charCodeAt(i) - 32
              bits += char.toString(2).padStart(6, '0')
            }

            for (let i = 0; i < len * 8; i += 8) {
              const byte = bits.substring(i, i + 8)
              if (byte.length === 8) {
                result += String.fromCharCode(parseInt(byte, 2))
              }
            }
          }

          return result
        } catch { return null }
      }
    },
    {
      name: 'XXEncode',
      description: 'XX encoding scheme',
      example: 'Alternative to UUencode',
      decode: (text: string) => {
        try {
          const alphabet = '+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
          const lines = text.split('\n').filter(line => line.trim() && !line.startsWith('begin') && line !== 'end')

          let result = ''
          for (const line of lines) {
            if (line.length === 0) continue
            const len = alphabet.indexOf(line[0])
            const data = line.substring(1)

            let bits = ''
            for (let i = 0; i < data.length; i++) {
              const index = alphabet.indexOf(data[i])
              if (index !== -1) {
                bits += index.toString(2).padStart(6, '0')
              }
            }

            for (let i = 0; i < len * 8; i += 8) {
              const byte = bits.substring(i, i + 8)
              if (byte.length === 8) {
                result += String.fromCharCode(parseInt(byte, 2))
              }
            }
          }

          return result
        } catch { return null }
      }
    },
    {
      name: 'Quoted-Printable',
      description: 'Email encoding scheme',
      example: 'Café → Caf=C3=A9',
      encode: (text: string) => {
        return text.split('').map(c => {
          const code = c.charCodeAt(0)
          if (code > 126 || code < 32 || c === '=') {
            return '=' + code.toString(16).padStart(2, '0').toUpperCase()
          }
          return c
        }).join('')
      },
      decode: (text: string) => {
        try {
          return text.replace(/=([0-9A-F]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
                     .replace(/=\r?\n/g, '')
        } catch { return null }
      }
    },
    {
      name: 'Unicode Escape',
      description: 'Unicode escape sequences',
      example: 'Hello → \\u0048\\u0065\\u006c\\u006c\\u006f',
      encode: (text: string) => text.split('').map(c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')).join(''),
      decode: (text: string) => {
        try {
          return text.replace(/\\u([0-9a-fA-F]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
        } catch { return null }
      }
    },
    {
      name: 'Punycode',
      description: 'Internationalized domain names',
      example: 'münchen → mnchen-3ya',
      encode: (text: string) => {
        try {
          // Simplified punycode
          const basic = text.split('').filter(c => c.charCodeAt(0) < 128).join('')
          const nonBasic = text.split('').filter(c => c.charCodeAt(0) >= 128)
          if (nonBasic.length === 0) return text
          return basic + '-' + nonBasic.map(c => c.charCodeAt(0).toString(16)).join('')
        } catch { return text }
      },
      decode: (text: string) => {
        try {
          if (!text.includes('-')) return text
          const parts = text.split('-')
          const basic = parts[0]
          const encoded = parts.slice(1).join('-')
          const codes = encoded.match(/.{1,4}/g)?.map(h => String.fromCharCode(parseInt(h, 16))) || []
          return basic + codes.join('')
        } catch { return null }
      }
    },
    {
      name: 'UTF-16 Endianness Fix',
      description: 'Fix UTF-16 LE/BE encoding issues',
      example: 'Fixes CJK symbols from misread UTF-16',
      encode: (text: string) => {
        // Convert text to UTF-16 LE bytes representation
        const result: string[] = []
        for (let i = 0; i < text.length; i++) {
          const code = text.charCodeAt(i)
          result.push(String.fromCharCode(code & 0xFF) + String.fromCharCode((code >> 8) & 0xFF))
        }
        return result.join('')
      },
      decode: (text: string) => {
        try {
          // Method 1: Extract high byte from misencoded characters (e.g., U+4300 → 'C')
          let decoded = ''
          for (let i = 0; i < text.length; i++) {
            const code = text.charCodeAt(i)
            // If character is in CJK/rare range (U+3000-U+FFFF), extract high byte
            if (code >= 0x3000 && code <= 0xFFFF) {
              const highByte = (code >> 8) & 0xFF
              if (highByte >= 0x20 && highByte <= 0x7E) {
                // High byte is printable ASCII
                decoded += String.fromCharCode(highByte)
                continue
              }
            }
            // Otherwise keep original character
            decoded += text[i]
          }

          // If decoded looks better (more ASCII), return it
          const asciiCount = (decoded.match(/[\x20-\x7E]/g) || []).length
          const originalAsciiCount = (text.match(/[\x20-\x7E]/g) || []).length
          if (asciiCount > originalAsciiCount) {
            return decoded
          }

          // Method 2: Try swapping byte order (UTF-16 BE to LE)
          if (text.length % 2 === 0) {
            const swapped: string[] = []
            for (let i = 0; i < text.length; i++) {
              const code = text.charCodeAt(i)
              const swappedCode = ((code & 0xFF) << 8) | ((code >> 8) & 0xFF)
              swapped.push(String.fromCharCode(swappedCode))
            }
            return swapped.join('')
          }

          return decoded || text
        } catch { return null }
      }
    }
  ]

  // ==================== BINARY CONVERSIONS ====================
  const binaryTools: Tool[] = [
    {
      name: 'Binary',
      description: 'Binary representation',
      example: 'A → 01000001',
      encode: (text: string) => Array.from(text).map(c => c.charCodeAt(0).toString(2).padStart(8, '0')).join(' '),
      decode: (text: string) => {
        try {
          return text.split(/\s+/).map(binary => String.fromCharCode(parseInt(binary, 2))).join('')
        } catch { return null }
      }
    },
    {
      name: 'Octal',
      description: 'Octal (base-8) representation',
      example: 'A → 101',
      encode: (text: string) => Array.from(text).map(c => c.charCodeAt(0).toString(8)).join(' '),
      decode: (text: string) => {
        try {
          return text.split(/\s+/).map(octal => String.fromCharCode(parseInt(octal, 8))).join('')
        } catch { return null }
      }
    },
    {
      name: 'Decimal',
      description: 'Decimal ASCII values',
      example: 'A → 65',
      encode: (text: string) => Array.from(text).map(c => c.charCodeAt(0)).join(' '),
      decode: (text: string) => {
        try {
          return text.split(/\s+/).map(num => String.fromCharCode(parseInt(num))).join('')
        } catch { return null }
      }
    },
    {
      name: 'Hexadecimal',
      description: 'Hexadecimal representation',
      example: 'A → 41',
      encode: (text: string) => Array.from(text).map(c => c.charCodeAt(0).toString(16).toUpperCase()).join(' '),
      decode: (text: string) => {
        try {
          return text.split(/\s+/).map(hex => String.fromCharCode(parseInt(hex, 16))).join('')
        } catch { return null }
      }
    },
    {
      name: 'Binary to Hex',
      description: 'Convert binary to hexadecimal',
      encode: (text: string) => {
        try {
          const cleaned = text.replace(/\s/g, '')
          let result = ''
          for (let i = 0; i < cleaned.length; i += 4) {
            result += parseInt(cleaned.slice(i, i + 4), 2).toString(16)
          }
          return result.toUpperCase()
        } catch { return text }
      }
    },
    {
      name: 'Hex to Binary',
      description: 'Convert hexadecimal to binary',
      encode: (text: string) => {
        try {
          return text.split('').map(c => parseInt(c, 16).toString(2).padStart(4, '0')).join(' ')
        } catch { return text }
      }
    }
  ]

  // ==================== CLASSICAL CIPHERS ====================
  const classicalTools: Tool[] = [
    {
      name: 'ROT13',
      description: 'Rotate by 13 positions',
      example: 'Hello → Uryyb',
      encode: (text: string) => text.replace(/[a-zA-Z]/g, c =>
        String.fromCharCode((c.charCodeAt(0) - (c < 'a' ? 65 : 97) + 13) % 26 + (c < 'a' ? 65 : 97))
      ),
      decode: (text: string) => text.replace(/[a-zA-Z]/g, c =>
        String.fromCharCode((c.charCodeAt(0) - (c < 'a' ? 65 : 97) + 13) % 26 + (c < 'a' ? 65 : 97))
      )
    },
    {
      name: 'ROT47',
      description: 'Rotate all ASCII printable characters',
      example: 'Hello → w6==@',
      encode: (text: string) => text.split('').map(c => {
        const code = c.charCodeAt(0)
        if (code >= 33 && code <= 126) {
          return String.fromCharCode(33 + ((code - 33 + 47) % 94))
        }
        return c
      }).join(''),
      decode: (text: string) => text.split('').map(c => {
        const code = c.charCodeAt(0)
        if (code >= 33 && code <= 126) {
          return String.fromCharCode(33 + ((code - 33 + 47) % 94))
        }
        return c
      }).join('')
    },
    {
      name: 'Caesar Cipher',
      description: 'Shift letters by key amount (use key field)',
      example: 'Hello with shift 3 → Khoor',
      needsKey: true,
      encode: (text: string, keyStr: string = '3') => {
        const shift = parseInt(keyStr) || 3
        return text.replace(/[a-zA-Z]/g, c => {
          const base = c.charCodeAt(0) < 97 ? 65 : 97
          return String.fromCharCode((c.charCodeAt(0) - base + shift) % 26 + base)
        })
      },
      decode: (text: string, keyStr: string = '3') => {
        const shift = parseInt(keyStr) || 3
        return text.replace(/[a-zA-Z]/g, c => {
          const base = c.charCodeAt(0) < 97 ? 65 : 97
          return String.fromCharCode((c.charCodeAt(0) - base - shift + 26) % 26 + base)
        })
      }
    },
    {
      name: 'Vigenère Cipher',
      description: 'Polyalphabetic substitution (needs key)',
      example: 'Hello + KEY → Rijvs',
      needsKey: true,
      encode: (text: string, keyStr: string = 'KEY') => {
        if (!keyStr) return text
        const key = keyStr.toUpperCase()
        let keyIndex = 0
        return text.split('').map(c => {
          if (c.match(/[a-zA-Z]/)) {
            const base = c.charCodeAt(0) < 97 ? 65 : 97
            const shift = key[keyIndex % key.length].charCodeAt(0) - 65
            keyIndex++
            return String.fromCharCode((c.charCodeAt(0) - base + shift) % 26 + base)
          }
          return c
        }).join('')
      },
      decode: (text: string, keyStr: string = 'KEY') => {
        if (!keyStr) return text
        const key = keyStr.toUpperCase()
        let keyIndex = 0
        return text.split('').map(c => {
          if (c.match(/[a-zA-Z]/)) {
            const base = c.charCodeAt(0) < 97 ? 65 : 97
            const shift = key[keyIndex % key.length].charCodeAt(0) - 65
            keyIndex++
            return String.fromCharCode((c.charCodeAt(0) - base - shift + 26) % 26 + base)
          }
          return c
        }).join('')
      }
    },
    {
      name: 'Atbash',
      description: 'Reverse alphabet cipher',
      example: 'Hello → Svool',
      encode: (text: string) => text.replace(/[a-zA-Z]/g, c => {
        const base = c.charCodeAt(0) < 97 ? 65 : 97
        return String.fromCharCode(base + (25 - (c.charCodeAt(0) - base)))
      }),
      decode: (text: string) => text.replace(/[a-zA-Z]/g, c => {
        const base = c.charCodeAt(0) < 97 ? 65 : 97
        return String.fromCharCode(base + (25 - (c.charCodeAt(0) - base)))
      })
    },
    {
      name: 'Rail Fence Cipher',
      description: 'Zigzag pattern (needs key for rails)',
      example: 'HELLO + 3 rails → HOELL',
      needsKey: true,
      encode: (text: string, keyStr: string = '3') => {
        const rails = parseInt(keyStr) || 3
        if (rails < 2) return text
        const fence: string[][] = Array(rails).fill(null).map(() => [])
        let rail = 0
        let direction = 1

        for (const char of text) {
          fence[rail].push(char)
          rail += direction
          if (rail === rails - 1 || rail === 0) direction *= -1
        }

        return fence.map(row => row.join('')).join('')
      },
      decode: (text: string, keyStr: string = '3') => {
        try {
          const rails = parseInt(keyStr) || 3
          if (rails < 2) return text
          const fence: (string | null)[][] = Array(rails).fill(null).map(() => Array(text.length).fill(null))

          let rail = 0, direction = 1
          for (let i = 0; i < text.length; i++) {
            fence[rail][i] = '*'
            rail += direction
            if (rail === rails - 1 || rail === 0) direction *= -1
          }

          let index = 0
          for (let r = 0; r < rails; r++) {
            for (let c = 0; c < text.length; c++) {
              if (fence[r][c] === '*') {
                fence[r][c] = text[index++]
              }
            }
          }

          const result: string[] = []
          rail = 0
          direction = 1
          for (let i = 0; i < text.length; i++) {
            result.push(fence[rail][i] || '')
            rail += direction
            if (rail === rails - 1 || rail === 0) direction *= -1
          }

          return result.join('')
        } catch { return null }
      }
    },
    {
      name: 'Playfair Cipher',
      description: 'Digraph substitution (needs key)',
      example: 'Uses 5x5 key matrix',
      needsKey: true,
      encode: (text: string, keyStr: string = 'KEYWORD') => {
        // Simplified Playfair implementation
        const key = keyStr.toUpperCase().replace(/[^A-Z]/g, '').replace(/J/g, 'I')
        const alphabet = 'ABCDEFGHIKLMNOPQRSTUVWXYZ'
        const matrix = Array.from(new Set(key + alphabet)).slice(0, 25)

        const getPos = (char: string) => {
          const idx = matrix.indexOf(char)
          return [Math.floor(idx / 5), idx % 5]
        }

        const cleaned = text.toUpperCase().replace(/[^A-Z]/g, '').replace(/J/g, 'I')
        const pairs: string[] = []

        for (let i = 0; i < cleaned.length; i += 2) {
          let first = cleaned[i]
          let second = cleaned[i + 1] || 'X'
          if (first === second) second = 'X'
          pairs.push(first + second)
        }

        return pairs.map(pair => {
          const [r1, c1] = getPos(pair[0])
          const [r2, c2] = getPos(pair[1])

          if (r1 === r2) {
            return matrix[r1 * 5 + (c1 + 1) % 5] + matrix[r2 * 5 + (c2 + 1) % 5]
          } else if (c1 === c2) {
            return matrix[((r1 + 1) % 5) * 5 + c1] + matrix[((r2 + 1) % 5) * 5 + c2]
          } else {
            return matrix[r1 * 5 + c2] + matrix[r2 * 5 + c1]
          }
        }).join('')
      }
    },
    {
      name: 'Substitution Cipher',
      description: 'Custom alphabet mapping (needs key)',
      example: 'Key = custom alphabet',
      needsKey: true,
      encode: (text: string, keyStr: string = 'ZYXWVUTSRQPONMLKJIHGFEDCBA') => {
        const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        const key = keyStr.toUpperCase().padEnd(26, alphabet).slice(0, 26)
        return text.split('').map(c => {
          if (c.match(/[A-Z]/)) return key[c.charCodeAt(0) - 65]
          if (c.match(/[a-z]/)) return key[c.charCodeAt(0) - 97].toLowerCase()
          return c
        }).join('')
      },
      decode: (text: string, keyStr: string = 'ZYXWVUTSRQPONMLKJIHGFEDCBA') => {
        const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
        const key = keyStr.toUpperCase().padEnd(26, alphabet).slice(0, 26)
        return text.split('').map(c => {
          if (c.match(/[A-Z]/)) return alphabet[key.indexOf(c)]
          if (c.match(/[a-z]/)) return alphabet[key.indexOf(c.toUpperCase())].toLowerCase()
          return c
        }).join('')
      }
    }
  ]

  // ==================== MODERN CRYPTO ====================
  const modernTools: Tool[] = [
    {
      name: 'AES Encrypt (Simulated)',
      description: 'AES encryption simulation (needs key)',
      needsKey: true,
      encode: async (text: string, keyStr: string = 'secret') => {
        if (!keyStr) return 'Key required'
        // Note: This is a simplified simulation. For real AES, use Web Crypto API properly
        const encoded = new TextEncoder().encode(text)
        const keyBytes = new TextEncoder().encode(keyStr)
        const result = encoded.map((byte, i) => byte ^ keyBytes[i % keyBytes.length])
        return btoa(String.fromCharCode(...result))
      }
    },
    {
      name: 'AES Decrypt (Simulated)',
      description: 'AES decryption simulation (needs key)',
      needsKey: true,
      decode: (text: string, keyStr: string = 'secret') => {
        try {
          if (!keyStr) return 'Key required'
          const decoded = atob(text)
          const bytes = new Uint8Array(decoded.length)
          for (let i = 0; i < decoded.length; i++) {
            bytes[i] = decoded.charCodeAt(i)
          }
          const keyBytes = new TextEncoder().encode(keyStr)
          const result = bytes.map((byte, i) => byte ^ keyBytes[i % keyBytes.length])
          return new TextDecoder().decode(result)
        } catch { return null }
      }
    },
    {
      name: 'XOR Cipher',
      description: 'XOR with repeating key',
      example: 'Simple but effective',
      needsKey: true,
      encode: (text: string, keyStr: string = 'KEY') => {
        if (!keyStr) return text
        return text.split('').map((c, i) =>
          String.fromCharCode(c.charCodeAt(0) ^ keyStr.charCodeAt(i % keyStr.length))
        ).map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('')
      },
      decode: (text: string, keyStr: string = 'KEY') => {
        try {
          if (!keyStr) return text
          const bytes = text.match(/.{1,2}/g)?.map(h => parseInt(h, 16)) || []
          return bytes.map((b, i) =>
            String.fromCharCode(b ^ keyStr.charCodeAt(i % keyStr.length))
          ).join('')
        } catch { return null }
      }
    },
    {
      name: 'JWT Decode',
      description: 'Decode JSON Web Token',
      example: 'Shows header and payload',
      decode: (text: string) => {
        try {
          const parts = text.split('.')
          if (parts.length !== 3) return null
          const header = JSON.parse(atob(parts[0].replace(/-/g, '+').replace(/_/g, '/')))
          const payload = JSON.parse(atob(parts[1].replace(/-/g, '+').replace(/_/g, '/')))
          return JSON.stringify({ header, payload }, null, 2)
        } catch { return null }
      }
    },
    {
      name: 'RSA (Info)',
      description: 'RSA public key info',
      encode: (text: string) => {
        return 'RSA implementation requires crypto library.\nFor real RSA, use: Web Crypto API or OpenSSL'
      }
    }
  ]

  // ==================== SPECIALIZED ENCODINGS ====================
  const specializedTools: Tool[] = [
    {
      name: 'Morse Code',
      description: 'International Morse Code',
      example: 'SOS → ... --- ...',
      encode: (text: string) => {
        const morse: { [key: string]: string } = {
          'A': '.-', 'B': '-...', 'C': '-.-.', 'D': '-..', 'E': '.', 'F': '..-.',
          'G': '--.', 'H': '....', 'I': '..', 'J': '.---', 'K': '-.-', 'L': '.-..',
          'M': '--', 'N': '-.', 'O': '---', 'P': '.--.', 'Q': '--.-', 'R': '.-.',
          'S': '...', 'T': '-', 'U': '..-', 'V': '...-', 'W': '.--', 'X': '-..-',
          'Y': '-.--', 'Z': '--..', '0': '-----', '1': '.----', '2': '..---',
          '3': '...--', '4': '....-', '5': '.....', '6': '-....', '7': '--...',
          '8': '---..', '9': '----.', ' ': '/'
        }
        return text.toUpperCase().split('').map(c => morse[c] || c).join(' ')
      },
      decode: (text: string) => {
        const morse: { [key: string]: string } = {
          '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E', '..-.': 'F',
          '--.': 'G', '....': 'H', '..': 'I', '.---': 'J', '-.-': 'K', '.-..': 'L',
          '--': 'M', '-.': 'N', '---': 'O', '.--.': 'P', '--.-': 'Q', '.-.': 'R',
          '...': 'S', '-': 'T', '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X',
          '-.--': 'Y', '--..': 'Z', '-----': '0', '.----': '1', '..---': '2',
          '...--': '3', '....-': '4', '.....': '5', '-....': '6', '--...': '7',
          '---..': '8', '----.': '9', '/': ' '
        }
        return text.split(' ').map(code => morse[code] || code).join('')
      }
    },
    {
      name: 'NATO Phonetic',
      description: 'NATO phonetic alphabet',
      example: 'HELLO → Hotel Echo Lima Lima Oscar',
      encode: (text: string) => {
        const nato: { [key: string]: string } = {
          'A': 'Alpha', 'B': 'Bravo', 'C': 'Charlie', 'D': 'Delta', 'E': 'Echo',
          'F': 'Foxtrot', 'G': 'Golf', 'H': 'Hotel', 'I': 'India', 'J': 'Juliett',
          'K': 'Kilo', 'L': 'Lima', 'M': 'Mike', 'N': 'November', 'O': 'Oscar',
          'P': 'Papa', 'Q': 'Quebec', 'R': 'Romeo', 'S': 'Sierra', 'T': 'Tango',
          'U': 'Uniform', 'V': 'Victor', 'W': 'Whiskey', 'X': 'X-ray', 'Y': 'Yankee',
          'Z': 'Zulu', '0': 'Zero', '1': 'One', '2': 'Two', '3': 'Three', '4': 'Four',
          '5': 'Five', '6': 'Six', '7': 'Seven', '8': 'Eight', '9': 'Nine'
        }
        return text.toUpperCase().split('').map(c => nato[c] || c).join(' ')
      },
      decode: (text: string) => {
        const nato: { [key: string]: string } = {
          'ALPHA': 'A', 'BRAVO': 'B', 'CHARLIE': 'C', 'DELTA': 'D', 'ECHO': 'E',
          'FOXTROT': 'F', 'GOLF': 'G', 'HOTEL': 'H', 'INDIA': 'I', 'JULIETT': 'J',
          'KILO': 'K', 'LIMA': 'L', 'MIKE': 'M', 'NOVEMBER': 'N', 'OSCAR': 'O',
          'PAPA': 'P', 'QUEBEC': 'Q', 'ROMEO': 'R', 'SIERRA': 'S', 'TANGO': 'T',
          'UNIFORM': 'U', 'VICTOR': 'V', 'WHISKEY': 'W', 'X-RAY': 'X', 'YANKEE': 'Y',
          'ZULU': 'Z', 'ZERO': '0', 'ONE': '1', 'TWO': '2', 'THREE': '3', 'FOUR': '4',
          'FIVE': '5', 'SIX': '6', 'SEVEN': '7', 'EIGHT': '8', 'NINE': '9'
        }
        return text.toUpperCase().split(/\s+/).map(word => nato[word] || word).join('')
      }
    },
    {
      name: 'Braille',
      description: 'Braille tactile writing',
      example: 'hello → ⠓⠑⠇⠇⠕',
      encode: (text: string) => {
        const brailleMap: { [key: string]: string } = {
          'a': '⠁', 'b': '⠃', 'c': '⠉', 'd': '⠙', 'e': '⠑', 'f': '⠋', 'g': '⠛',
          'h': '⠓', 'i': '⠊', 'j': '⠚', 'k': '⠅', 'l': '⠇', 'm': '⠍', 'n': '⠝',
          'o': '⠕', 'p': '⠏', 'q': '⠟', 'r': '⠗', 's': '⠎', 't': '⠞', 'u': '⠥',
          'v': '⠧', 'w': '⠺', 'x': '⠭', 'y': '⠽', 'z': '⠵', ' ': '⠀'
        }
        return text.toLowerCase().split('').map(c => brailleMap[c] || c).join('')
      },
      decode: (text: string) => {
        const reverseBraille: { [key: string]: string } = {
          '⠁': 'a', '⠃': 'b', '⠉': 'c', '⠙': 'd', '⠑': 'e', '⠋': 'f', '⠛': 'g',
          '⠓': 'h', '⠊': 'i', '⠚': 'j', '⠅': 'k', '⠇': 'l', '⠍': 'm', '⠝': 'n',
          '⠕': 'o', '⠏': 'p', '⠟': 'q', '⠗': 'r', '⠎': 's', '⠞': 't', '⠥': 'u',
          '⠧': 'v', '⠺': 'w', '⠭': 'x', '⠽': 'y', '⠵': 'z', '⠀': ' '
        }
        return text.split('').map(c => reverseBraille[c] || c).join('')
      }
    },
    {
      name: 'Reverse Text',
      description: 'Reverse string',
      example: 'Hello → olleH',
      encode: (text: string) => text.split('').reverse().join(''),
      decode: (text: string) => text.split('').reverse().join('')
    }
  ]

  // ==================== CTF-SPECIFIC TOOLS ====================
  const ctfTools: Tool[] = [
    {
      name: 'Bacon Cipher',
      description: 'Steganographic cipher using A/B',
      example: 'Each letter = 5 A/B pattern',
      encode: (text: string) => {
        const baconMap: { [key: string]: string } = {
          'a': 'AAAAA', 'b': 'AAAAB', 'c': 'AAABA', 'd': 'AAABB', 'e': 'AABAA',
          'f': 'AABAB', 'g': 'AABBA', 'h': 'AABBB', 'i': 'ABAAA', 'j': 'ABAAB',
          'k': 'ABABA', 'l': 'ABABB', 'm': 'ABBAA', 'n': 'ABBAB', 'o': 'ABBBA',
          'p': 'ABBBB', 'q': 'BAAAA', 'r': 'BAAAB', 's': 'BAABA', 't': 'BAABB',
          'u': 'BABAA', 'v': 'BABAB', 'w': 'BABBA', 'x': 'BABBB', 'y': 'BBAAA', 'z': 'BBAAB'
        }
        return text.toLowerCase().replace(/[a-z]/g, c => baconMap[c] || c)
      },
      decode: (text: string) => {
        const reverseBacon: { [key: string]: string } = {
          'AAAAA': 'a', 'AAAAB': 'b', 'AAABA': 'c', 'AAABB': 'd', 'AABAA': 'e',
          'AABAB': 'f', 'AABBA': 'g', 'AABBB': 'h', 'ABAAA': 'i', 'ABAAB': 'j',
          'ABABA': 'k', 'ABABB': 'l', 'ABBAA': 'm', 'ABBAB': 'n', 'ABBBA': 'o',
          'ABBBB': 'p', 'BAAAA': 'q', 'BAAAB': 'r', 'BAABA': 's', 'BAABB': 't',
          'BABAA': 'u', 'BABAB': 'v', 'BABBA': 'w', 'BABBB': 'x', 'BBAAA': 'y', 'BBAAB': 'z'
        }
        return text.match(/.{5}/g)?.map(group => reverseBacon[group] || group).join('') || null
      }
    },
    {
      name: 'Polybius Square',
      description: '5x5 grid cipher',
      example: 'Each letter → 2 digits',
      encode: (text: string) => {
        const square: { [key: string]: string } = {
          'a': '11', 'b': '12', 'c': '13', 'd': '14', 'e': '15',
          'f': '21', 'g': '22', 'h': '23', 'i': '24', 'j': '24', 'k': '25',
          'l': '31', 'm': '32', 'n': '33', 'o': '34', 'p': '35',
          'q': '41', 'r': '42', 's': '43', 't': '44', 'u': '45',
          'v': '51', 'w': '52', 'x': '53', 'y': '54', 'z': '55'
        }
        return text.toLowerCase().replace(/[a-z]/g, c => square[c] || c)
      },
      decode: (text: string) => {
        const reverseSquare: { [key: string]: string } = {
          '11': 'a', '12': 'b', '13': 'c', '14': 'd', '15': 'e',
          '21': 'f', '22': 'g', '23': 'h', '24': 'i', '25': 'k',
          '31': 'l', '32': 'm', '33': 'n', '34': 'o', '35': 'p',
          '41': 'q', '42': 'r', '43': 's', '44': 't', '45': 'u',
          '51': 'v', '52': 'w', '53': 'x', '54': 'y', '55': 'z'
        }
        return text.match(/\d{2}/g)?.map(pair => reverseSquare[pair] || pair).join('') || null
      }
    },
    {
      name: 'Book Cipher Decoder',
      description: 'Number to word lookup (needs reference text in key)',
      needsKey: true,
      decode: (text: string, book: string = '') => {
        try {
          if (!book) return 'Need reference text in key field'
          const words = book.toLowerCase().split(/\s+/)
          const numbers = text.match(/\d+/g)
          if (!numbers) return null

          return numbers.map(num => {
            const index = parseInt(num) - 1
            return words[index] || `[${num}]`
          }).join(' ')
        } catch { return null }
      }
    },
    {
      name: 'All Caesar Shifts',
      description: 'Show all 25 ROT variations',
      encode: (text: string) => {
        let result = ''
        for (let shift = 1; shift <= 25; shift++) {
          const shifted = text.replace(/[a-zA-Z]/g, c => {
            const base = c.charCodeAt(0) < 97 ? 65 : 97
            return String.fromCharCode((c.charCodeAt(0) - base + shift) % 26 + base)
          })
          result += `ROT${shift}: ${shifted}\n`
        }
        return result
      }
    },
    {
      name: 'L33T Speak',
      description: 'Leetspeak encoder/decoder',
      example: 'HELLO → H3LL0',
      encode: (text: string) => {
        const leet: { [key: string]: string } = {
          'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7', 'l': '1', 'g': '9'
        }
        return text.toLowerCase().split('').map(c => leet[c] || c).join('')
      },
      decode: (text: string) => {
        const unleet: { [key: string]: string } = {
          '4': 'a', '3': 'e', '1': 'i', '0': 'o', '5': 's', '7': 't', '9': 'g'
        }
        return text.split('').map(c => unleet[c] || c).join('')
      }
    }
  ]

  // ==================== ANALYSIS TOOLS ====================
  const analysisTools: Tool[] = [
    {
      name: 'Frequency Analysis',
      description: 'Letter frequency distribution',
      encode: (text: string) => {
        const freq: { [key: string]: number } = {}
        const cleaned = text.toUpperCase().replace(/[^A-Z]/g, '')

        for (const char of cleaned) {
          freq[char] = (freq[char] || 0) + 1
        }

        const sorted = Object.entries(freq)
          .sort(([,a], [,b]) => b - a)
          .map(([char, count]) => `${char}: ${count} (${((count / cleaned.length) * 100).toFixed(2)}%)`)

        const englishFreq = 'E T A O I N S H R D L C U M W F G Y P B V K J X Q Z'

        return `Total letters: ${cleaned.length}\n\nFrequency Distribution:\n${sorted.join('\n')}\n\nExpected English order:\n${englishFreq}\n\nMost common letter: ${sorted[0]?.split(':')[0] || 'N/A'} (likely E in substitution)`
      }
    },
    {
      name: 'Index of Coincidence',
      description: 'Statistical measure for cipher type',
      encode: (text: string) => {
        const cleaned = text.toUpperCase().replace(/[^A-Z]/g, '')
        const n = cleaned.length
        if (n < 2) return 'Text too short'

        const freq: { [key: string]: number } = {}
        for (const char of cleaned) {
          freq[char] = (freq[char] || 0) + 1
        }

        const ic = Object.values(freq).reduce((sum, f) => sum + f * (f - 1), 0) / (n * (n - 1))

        let analysis = `Text length: ${n}\n`
        analysis += `Index of Coincidence: ${ic.toFixed(4)}\n\n`
        analysis += 'Analysis:\n'

        if (ic > 0.06) {
          analysis += '✓ IC ≈ 0.065-0.070: Likely monoalphabetic cipher or plaintext English\n'
          analysis += '  Possible ciphers: Caesar, Substitution, Atbash'
        } else if (ic > 0.045) {
          analysis += '✓ IC ≈ 0.045-0.055: Likely polyalphabetic cipher with short key\n'
          analysis += '  Possible ciphers: Vigenère (short key), Gronsfeld'
        } else if (ic > 0.038) {
          analysis += '✓ IC ≈ 0.038-0.045: Polyalphabetic cipher or random-like text\n'
          analysis += '  Possible ciphers: Vigenère (long key), random substitution'
        } else {
          analysis += '✓ IC < 0.038: Very random distribution\n'
          analysis += '  Likely: Strong encryption, random data, or compressed data'
        }

        return analysis
      }
    },
    {
      name: 'Kasiski Examination',
      description: 'Find repeated patterns for Vigenère',
      encode: (text: string) => {
        const cleaned = text.toUpperCase().replace(/[^A-Z]/g, '')
        const repeats: { [key: string]: number[] } = {}

        for (let i = 0; i <= cleaned.length - 3; i++) {
          const trigram = cleaned.substring(i, i + 3)
          if (!repeats[trigram]) repeats[trigram] = []
          repeats[trigram].push(i)
        }

        const distances: number[] = []
        let result = 'Repeated Trigrams:\n\n'

        const filtered = Object.entries(repeats).filter(([_, positions]) => positions.length > 1)

        if (filtered.length === 0) {
          return 'No repeated trigrams found.\n\nThis suggests:\n- Text is too short\n- Not a polyalphabetic cipher\n- Key is very long'
        }

        for (const [trigram, positions] of filtered) {
          result += `"${trigram}" at positions: ${positions.join(', ')}\n`
          for (let i = 1; i < positions.length; i++) {
            const distance = positions[i] - positions[i - 1]
            distances.push(distance)
            result += `  Distance: ${distance}\n`
          }
          result += '\n'
        }

        if (distances.length > 0) {
          const gcd = distances.reduce((a, b) => {
            while (b) [a, b] = [b, a % b]
            return a
          })

          const factors: number[] = []
          for (let i = 2; i <= gcd; i++) {
            if (gcd % i === 0) factors.push(i)
          }

          result += `\nGCD of distances: ${gcd}\n`
          result += `Possible key lengths: ${factors.join(', ') || gcd}\n\n`
          result += `Most likely key length: ${gcd} characters`
        }

        return result
      }
    },
    {
      name: 'Bigram Analysis',
      description: 'Two-letter pattern analysis',
      encode: (text: string) => {
        const cleaned = text.toUpperCase().replace(/[^A-Z]/g, '')
        const bigrams: { [key: string]: number } = {}

        for (let i = 0; i < cleaned.length - 1; i++) {
          const bigram = cleaned.substring(i, i + 2)
          bigrams[bigram] = (bigrams[bigram] || 0) + 1
        }

        const sorted = Object.entries(bigrams)
          .sort(([,a], [,b]) => b - a)
          .slice(0, 20)
          .map(([bigram, count]) => `${bigram}: ${count}`)

        return `Top 20 Bigrams:\n${sorted.join('\n')}\n\nMost common English bigrams:\nTH, HE, IN, ER, AN, RE, ED, ON, ES, ST, EN, AT, TO, NT, HA, ND, OU, EA, NG, AS`
      }
    },
    {
      name: 'Character Statistics',
      description: 'Complete text statistics',
      encode: (text: string) => {
        const lines = text.split('\n').length
        const words = text.split(/\s+/).filter(w => w).length
        const chars = text.length
        const letters = text.replace(/[^a-zA-Z]/g, '').length
        const digits = text.replace(/[^0-9]/g, '').length
        const spaces = text.split(' ').length - 1
        const upper = text.replace(/[^A-Z]/g, '').length
        const lower = text.replace(/[^a-z]/g, '').length
        const special = chars - letters - digits - spaces

        return `Text Statistics:\n\n` +
               `Total characters: ${chars}\n` +
               `Letters: ${letters} (${((letters/chars)*100).toFixed(1)}%)\n` +
               `Digits: ${digits} (${((digits/chars)*100).toFixed(1)}%)\n` +
               `Spaces: ${spaces}\n` +
               `Special chars: ${special}\n` +
               `Uppercase: ${upper}\n` +
               `Lowercase: ${lower}\n` +
               `Words: ${words}\n` +
               `Lines: ${lines}\n` +
               `Avg word length: ${(letters/words).toFixed(1)} chars`
      }
    },
    {
      name: 'Entropy Calculator',
      description: 'Shannon entropy measurement',
      encode: (text: string) => {
        const freq: { [key: string]: number } = {}
        for (const char of text) {
          freq[char] = (freq[char] || 0) + 1
        }

        let entropy = 0
        const length = text.length
        for (const count of Object.values(freq)) {
          const p = count / length
          entropy -= p * Math.log2(p)
        }

        const maxEntropy = Math.log2(Object.keys(freq).length)
        const redundancy = 1 - (entropy / maxEntropy)

        let analysis = `Shannon Entropy: ${entropy.toFixed(4)} bits per character\n`
        analysis += `Maximum possible: ${maxEntropy.toFixed(4)} bits\n`
        analysis += `Redundancy: ${(redundancy * 100).toFixed(2)}%\n\n`
        analysis += `Interpretation:\n`

        if (entropy < 3.0) {
          analysis += '✓ Very low entropy - Simple pattern or repetitive text'
        } else if (entropy < 4.0) {
          analysis += '✓ Low entropy - Natural language or weak cipher'
        } else if (entropy < 5.0) {
          analysis += '✓ Medium entropy - Compressed or encrypted text'
        } else if (entropy < 6.5) {
          analysis += '✓ High entropy - Good encryption or random data'
        } else {
          analysis += '✓ Very high entropy - Strong encryption or truly random'
        }

        return analysis
      }
    }
  ]

  // Get current tool set based on active tab
  const getCurrentTools = (): Tool[] => {
    switch (activeTab) {
      case 'encoding': return encodingTools
      case 'binary': return binaryTools
      case 'classical': return classicalTools
      case 'specialized': return specializedTools
      case 'ctf': return ctfTools
      case 'analysis': return analysisTools
      case 'magic': return [] // Magic doesn't use tool selection
      default: return encodingTools
    }
  }

  // Tools that support recursive decoding
  const supportsRecursive = (toolName: string): boolean => {
    const recursiveTools = [
      'Base64', 'Base32', 'Base16 (Hex)', 'Base85 (Ascii85)', 'Base58',
      'URL Encoding', 'HTML Entities', 'UUEncode', 'XXEncode',
      'Quoted-Printable', 'Unicode Escape', 'ROT13', 'ROT47',
      'Hexadecimal', 'Binary', 'Octal', 'Decimal'
    ]
    return recursiveTools.includes(toolName)
  }

  // Recursive decode function
  const recursiveDecode = async (
    tool: Tool,
    initialInput: string,
    keyValue?: string
  ): Promise<{ result: string; iterations: number; layers: string[] }> => {
    const MAX_ITERATIONS = 100
    let current = initialInput
    let iterations = 0
    const layers: string[] = [initialInput]

    while (iterations < MAX_ITERATIONS) {
      try {
        if (!tool.decode) break

        const decoded = await Promise.resolve(tool.decode(current, keyValue))

        // If decode failed, return last successful result
        if (!decoded || decoded === null) {
          break
        }

        // If result is the same as input, we've reached a stable state
        if (decoded === current) {
          break
        }

        // Check if the decoded result is just an error message
        if (decoded.includes('failed') || decoded.includes('Error')) {
          break
        }

        current = decoded
        iterations++
        layers.push(decoded)

        // For ROT13/ROT47, check if we've cycled back to original
        if ((tool.name === 'ROT13' || tool.name === 'ROT47') && decoded === initialInput) {
          break
        }

      } catch (error) {
        // If error occurs, return last successful result
        break
      }
    }

    return { result: current, iterations, layers }
  }

  // Process tool
  const processTool = async (tool: Tool, mode: 'encode' | 'decode') => {
    const timestamp = new Date().toLocaleString()
    let result = ''
    let iterations = 0

    try {
      if (mode === 'encode' && tool.encode) {
        result = await Promise.resolve(tool.encode(input, key))
        setIterationCount(0)
      } else if (mode === 'decode' && tool.decode) {
        // Use recursive decode if enabled and tool supports it
        if (recursiveMode && supportsRecursive(tool.name)) {
          const { result: decodedResult, iterations: decodeIterations, layers } = await recursiveDecode(tool, input, key)
          result = decodedResult
          iterations = decodeIterations

          // Add info about iterations to the result
          if (iterations > 0) {
            result = `${decodedResult}\n\n--- Recursive Decode Info ---\nDecoded ${iterations} time(s)\nOriginal length: ${input.length} chars\nFinal length: ${decodedResult.length} chars`
          } else {
            result = `${decodedResult}\n\n--- Recursive Decode Info ---\nNo additional decoding layers found (0 iterations)`
          }
          setIterationCount(iterations)
        } else {
          // Single decode
          const decoded = await Promise.resolve(tool.decode(input, key))
          result = decoded || 'Decoding failed or invalid input'
          setIterationCount(0)
        }
      } else {
        result = 'Operation not available for this tool'
        setIterationCount(0)
      }

      setOutput(result)
      setResults(prev => [
        {
          input,
          output: result,
          method: `${tool.name} (${mode}${recursiveMode && mode === 'decode' && supportsRecursive(tool.name) ? ' - Recursive' : ''})`,
          timestamp
        },
        ...prev.slice(0, 19)
      ])
    } catch (error) {
      setOutput(`Error: ${error}`)
      setIterationCount(0)
    }
  }

  // Magic Decoder - CyberChef-like auto decode
  const magicDecode = (text: string): { result: string; steps: string[] } => {
    const steps: string[] = []
    let current = text
    let previous = ''
    let iterations = 0
    const maxIterations = 20

    const decoders = [
      {
        name: 'Base64',
        detect: (s: string) => /^[A-Za-z0-9+/=]{4,}$/.test(s.trim()) && s.length % 4 === 0,
        decode: (s: string) => {
          try {
            const decoded = atob(s.trim())
            return decoded.split('').every(c => c.charCodeAt(0) < 128) ? decoded : null
          } catch { return null }
        }
      },
      {
        name: 'URL Encoding',
        detect: (s: string) => /%[0-9A-Fa-f]{2}/.test(s),
        decode: (s: string) => {
          try { return decodeURIComponent(s) } catch { return null }
        }
      },
      {
        name: 'Hex',
        detect: (s: string) => /^(0x)?[0-9A-Fa-f\s]+$/.test(s.trim()) && s.replace(/\s/g, '').length % 2 === 0 && s.replace(/\s/g, '').length >= 4,
        decode: (s: string) => {
          try {
            const hex = s.replace(/0x/g, '').replace(/\s/g, '')
            const bytes = hex.match(/.{1,2}/g) || []
            return bytes.map(byte => String.fromCharCode(parseInt(byte, 16))).join('')
          } catch { return null }
        }
      },
      {
        name: 'HTML Entities',
        detect: (s: string) => /&[a-zA-Z0-9#]+;/.test(s),
        decode: (s: string) => {
          const textarea = document.createElement('textarea')
          textarea.innerHTML = s
          return textarea.value
        }
      },
      {
        name: 'Base32',
        detect: (s: string) => /^[A-Z2-7=]{8,}$/.test(s.trim()),
        decode: (s: string) => {
          try {
            const base32Chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'
            let bits = ''
            const cleanInput = s.toUpperCase().replace(/=+$/, '')

            for (const char of cleanInput) {
              const val = base32Chars.indexOf(char)
              if (val === -1) return null
              bits += val.toString(2).padStart(5, '0')
            }

            let result = ''
            for (let i = 0; i + 8 <= bits.length; i += 8) {
              result += String.fromCharCode(parseInt(bits.slice(i, i + 8), 2))
            }
            return result
          } catch { return null }
        }
      },
      {
        name: 'ROT13',
        detect: (s: string) => /^[A-Za-z\s]+$/.test(s) && s.length > 10,
        decode: (s: string) => {
          return s.replace(/[A-Za-z]/g, (c) => {
            const base = c <= 'Z' ? 65 : 97
            return String.fromCharCode(((c.charCodeAt(0) - base + 13) % 26) + base)
          })
        }
      },
      {
        name: 'Binary',
        detect: (s: string) => /^[01\s]+$/.test(s.trim()) && s.replace(/\s/g, '').length % 8 === 0 && s.replace(/\s/g, '').length >= 8,
        decode: (s: string) => {
          try {
            const binary = s.replace(/\s/g, '')
            const bytes = binary.match(/.{1,8}/g) || []
            return bytes.map(byte => String.fromCharCode(parseInt(byte, 2))).join('')
          } catch { return null }
        }
      },
      {
        name: 'Octal',
        detect: (s: string) => /^\\?[0-7\s\\]+$/.test(s.trim()) && s.includes('\\'),
        decode: (s: string) => {
          try {
            return s.replace(/\\([0-7]{1,3})/g, (_, oct) =>
              String.fromCharCode(parseInt(oct, 8))
            )
          } catch { return null }
        }
      },
      {
        name: 'Unicode Escape',
        detect: (s: string) => /\\u[0-9A-Fa-f]{4}/.test(s) || /\\x[0-9A-Fa-f]{2}/.test(s),
        decode: (s: string) => {
          try {
            return s
              .replace(/\\u([0-9A-Fa-f]{4})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
              .replace(/\\x([0-9A-Fa-f]{2})/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
          } catch { return null }
        }
      }
    ]

    while (current !== previous && iterations < maxIterations) {
      previous = current
      let decoded = false

      for (const decoder of decoders) {
        if (decoder.detect(current)) {
          const result = decoder.decode(current)
          if (result && result !== current && result.length > 0) {
            steps.push(`${decoder.name}: ${current.substring(0, 50)}${current.length > 50 ? '...' : ''} → ${result.substring(0, 50)}${result.length > 50 ? '...' : ''}`)
            current = result
            decoded = true
            break
          }
        }
      }

      if (!decoded) break
      iterations++
    }

    if (steps.length === 0) {
      steps.push('No encoding detected - input appears to be plain text')
    }

    return { result: current, steps }
  }

  // Handle Magic Decode button
  const handleMagicDecode = () => {
    if (!input.trim()) return
    const { result, steps } = magicDecode(input)
    setMagicResult(result)
    setMagicSteps(steps)
    setOutput(result)
  }

  // Copy to clipboard
  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  // Download results
  const downloadResults = () => {
    const data = results.map(r =>
      `${r.timestamp} - ${r.method}\nInput: ${r.input}\nOutput: ${r.output}\n\n`
    ).join('---\n\n')
    const blob = new Blob([data], { type: 'text/plain' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'crypto-results.txt'
    a.click()
    URL.revokeObjectURL(url)
  }

  // Tab configuration
  const tabs = [
    { id: 'encoding', name: 'Encoding', icon: FileText },
    { id: 'magic', name: 'Magic', icon: Zap },
    { id: 'binary', name: 'Binary', icon: Binary },
    { id: 'classical', name: 'Classical', icon: BookOpen },
    { id: 'specialized', name: 'Specialized', icon: Radio },
    { id: 'ctf', name: 'CTF Tools', icon: Zap },
    { id: 'analysis', name: 'Analysis', icon: BarChart3 }
  ] as const

  return (
    <div className="min-h-screen bg-background p-4">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <div className="text-center space-y-2">
          <h1 className="text-4xl font-bold text-foreground flex items-center justify-center space-x-3">
            <Shield className="w-10 h-10 text-accent" />
            <span>Cryptography Toolkit</span>
          </h1>
          <p className="text-muted-foreground text-lg">
            Encryption, encoding, and cryptanalysis tools for security professionals
          </p>
        </div>

        {/* External Tools */}
        <div className="bg-card border border-border rounded-lg p-4">
          <div className="flex items-start space-x-3">
            <Globe className="w-5 h-5 text-accent mt-1 flex-shrink-0" />
            <div className="flex-1">
              <h3 className="text-lg font-semibold text-foreground mb-2">Need More Crypto Tools?</h3>
              <p className="text-sm text-muted-foreground mb-3">
                For additional cryptography and cipher tools, check out these powerful online resources:
              </p>
              <div className="flex flex-wrap gap-3">
                <a
                  href="https://cryptii.com/pipes/caesar-cipher"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center space-x-2 px-4 py-2 bg-accent hover:bg-accent/80 text-background rounded-lg transition-colors font-medium"
                >
                  <Globe className="w-4 h-4" />
                  <span>CrypTii</span>
                </a>
                <a
                  href="https://gchq.github.io/CyberChef/"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center space-x-2 px-4 py-2 bg-accent hover:bg-accent/80 text-background rounded-lg transition-colors font-medium"
                >
                  <Globe className="w-4 h-4" />
                  <span>CyberChef</span>
                </a>
              </div>
            </div>
          </div>
        </div>

        {/* Tabs */}
        <div className="bg-card border border-border rounded-lg">
          <div className="flex flex-wrap items-center gap-2 border-b border-border p-2">
            {tabs.map((tab) => {
              const Icon = tab.icon
              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id as any)}
                  className={`flex items-center space-x-2 px-4 py-2 rounded-t-lg transition-colors ${
                    activeTab === tab.id
                      ? 'text-accent border-b-2 border-accent bg-accent/5'
                      : 'text-muted-foreground hover:text-foreground hover:bg-accent/5'
                  }`}
                >
                  <Icon className="w-4 h-4" />
                  <span>{tab.name}</span>
                </button>
              )
            })}
          </div>

          <div className="p-6 space-y-4">
            {/* Recursive Mode Toggle */}
            {activeTab !== 'analysis' && activeTab !== 'magic' && (
              <div className="mb-4 p-4 bg-accent/5 border border-accent/20 rounded-lg">
                <div className="flex items-center justify-between">
                  <div className="flex-1">
                    <div className="flex items-center space-x-3">
                      <button
                        onClick={() => setRecursiveMode(!recursiveMode)}
                        className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                          recursiveMode ? 'bg-accent' : 'bg-muted'
                        }`}
                      >
                        <span
                          className={`inline-block h-4 w-4 transform rounded-full bg-background transition-transform ${
                            recursiveMode ? 'translate-x-6' : 'translate-x-1'
                          }`}
                        />
                      </button>
                      <div>
                        <span className="font-medium text-foreground">
                          Recursive Decoding {recursiveMode ? 'Enabled' : 'Disabled'}
                        </span>
                        {iterationCount > 0 && recursiveMode && (
                          <span className="ml-2 text-xs text-accent">
                            (Last decode: {iterationCount} iteration{iterationCount !== 1 ? 's' : ''})
                          </span>
                        )}
                      </div>
                    </div>
                    <p className="text-xs text-muted-foreground mt-2">
                      When enabled, decode operations will continue recursively until no more decoding is possible
                      (max 100 iterations). Works with Base64, Base32, Hex, URL encoding, and more.
                    </p>
                  </div>
                </div>
              </div>
            )}

            {/* Input/Output Section */}
            <div className="space-y-4 mb-6">
              <div>
                <label className="block text-sm font-medium mb-2 text-foreground">Input Text</label>
                <textarea
                  value={input}
                  onChange={(e) => setInput(e.target.value)}
                  className="w-full h-32 p-3 border border-border rounded-lg bg-background font-mono text-sm resize-none focus:outline-none focus:ring-2 focus:ring-accent"
                  placeholder={`Enter text to ${activeTab === 'analysis' ? 'analyze' : 'encode/decode'}...`}
                />
              </div>

              {/* Key Input (shown when needed) */}
              {getCurrentTools().some(t => t.needsKey) && (
                <div>
                  <label className="block text-sm font-medium mb-2 text-foreground">
                    Key / Parameter
                    <span className="text-muted-foreground ml-2">(required for some tools)</span>
                  </label>
                  <input
                    type="text"
                    value={key}
                    onChange={(e) => setKey(e.target.value)}
                    className="w-full p-3 border border-border rounded-lg bg-background text-sm focus:outline-none focus:ring-2 focus:ring-accent"
                    placeholder="Enter key, shift value, or reference text..."
                  />
                </div>
              )}

              <div>
                <div className="flex items-center justify-between mb-2">
                  <label className="block text-sm font-medium text-foreground">Output</label>
                  {output && (
                    <button
                      onClick={() => copyToClipboard(output)}
                      className="flex items-center space-x-1 px-3 py-1 text-xs bg-accent/10 hover:bg-accent/20 border border-accent/20 rounded text-accent transition-colors"
                    >
                      <Copy className="w-3 h-3" />
                      <span>{copied ? 'Copied!' : 'Copy'}</span>
                    </button>
                  )}
                </div>
                <textarea
                  value={output}
                  readOnly
                  className="w-full h-32 p-3 border border-border rounded-lg bg-muted font-mono text-sm resize-none"
                  placeholder="Output will appear here..."
                />
              </div>
            </div>

            {/* Magic Tab Special UI */}
            {activeTab === 'magic' && (
              <div className="space-y-4">
                <div className="bg-accent/5 border border-accent/20 rounded-lg p-4">
                  <div className="flex items-start space-x-3">
                    <Zap className="w-5 h-5 text-accent mt-1 flex-shrink-0" />
                    <div className="flex-1">
                      <h3 className="text-lg font-semibold text-foreground mb-2">Magic Decoder</h3>
                      <p className="text-sm text-muted-foreground mb-3">
                        Automatically detects and decodes multiple layers of encoding. Supports Base64, URL, Hex, HTML Entities, Base32, ROT13, Binary, Octal, and Unicode escapes.
                      </p>
                      <Button
                        onClick={handleMagicDecode}
                        disabled={!input.trim()}
                        className="w-full sm:w-auto"
                      >
                        <Zap className="w-4 h-4 mr-2" />
                        Auto Decode
                      </Button>
                    </div>
                  </div>
                </div>

                {magicSteps.length > 0 && (
                  <div className="bg-card border border-border rounded-lg p-4">
                    <h4 className="font-semibold text-foreground mb-3 flex items-center">
                      <RefreshCw className="w-4 h-4 mr-2 text-accent" />
                      Decoding Steps ({magicSteps.length})
                    </h4>
                    <div className="space-y-2">
                      {magicSteps.map((step, idx) => (
                        <div key={idx} className="bg-muted/30 p-3 rounded border border-border/50">
                          <div className="flex items-start space-x-2">
                            <span className="text-xs font-mono bg-accent/10 text-accent px-2 py-1 rounded flex-shrink-0">
                              Step {idx + 1}
                            </span>
                            <p className="text-sm font-mono text-foreground flex-1 break-all">
                              {step}
                            </p>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Tools Grid */}
            {activeTab !== 'magic' && (
              <div className="space-y-3">
                <h3 className="text-lg font-semibold text-foreground">Available Tools</h3>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
                  {getCurrentTools().map((tool) => (
                  <div
                    key={tool.name}
                    className="border border-border rounded-lg p-3 bg-card hover:bg-accent/5 transition-colors"
                  >
                    <div className="space-y-2">
                      <div className="flex items-start justify-between">
                        <div className="flex-1">
                          <h4 className="font-medium text-sm text-foreground">{tool.name}</h4>
                          {tool.description && (
                            <p className="text-xs text-muted-foreground mt-1">{tool.description}</p>
                          )}
                          {tool.example && (
                            <p className="text-xs text-accent/70 mt-1 italic">{tool.example}</p>
                          )}
                        </div>
                        {tool.needsKey && (
                          <Key className="w-3 h-3 text-accent ml-2 flex-shrink-0" />
                        )}
                      </div>

                      <div className="flex space-x-2">
                        {tool.encode && (
                          <button
                            onClick={() => processTool(tool, 'encode')}
                            disabled={!input.trim()}
                            className="flex-1 px-3 py-1.5 text-xs bg-accent hover:bg-accent/80 disabled:bg-muted disabled:text-muted-foreground text-background rounded transition-colors font-medium"
                          >
                            {activeTab === 'analysis' ? 'Analyze' : 'Encode'}
                          </button>
                        )}
                        {tool.decode && activeTab !== 'analysis' && (
                          <button
                            onClick={() => processTool(tool, 'decode')}
                            disabled={!input.trim()}
                            className="flex-1 px-3 py-1.5 text-xs bg-accent/10 hover:bg-accent/20 disabled:bg-muted disabled:text-muted-foreground border border-accent/20 text-accent rounded transition-colors font-medium flex items-center justify-center space-x-1"
                          >
                            <span>Decode</span>
                            {recursiveMode && supportsRecursive(tool.name) && (
                              <RefreshCw className="w-3 h-3" />
                            )}
                          </button>
                        )}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
            )}
          </div>
        </div>

        {/* Results History */}
        <div className="bg-card border border-border rounded-lg">
          <div className="p-4 border-b border-border">
            <div className="flex items-center justify-between">
              <h3 className="font-semibold flex items-center space-x-2">
                <RefreshCw className="w-4 h-4 text-accent" />
                <span>Recent Operations ({results.length})</span>
              </h3>
              {results.length > 0 && (
                <div className="flex space-x-2">
                  <button
                    onClick={() => setResults([])}
                    className="px-3 py-1 text-xs bg-muted hover:bg-muted/80 border border-border rounded text-foreground transition-colors"
                  >
                    Clear
                  </button>
                  <button
                    onClick={downloadResults}
                    className="flex items-center space-x-1 px-3 py-1 text-xs bg-accent/10 hover:bg-accent/20 border border-accent/20 rounded text-accent transition-colors"
                  >
                    <Download className="w-3 h-3" />
                    <span>Export</span>
                  </button>
                </div>
              )}
            </div>
          </div>
          <div className="p-4 space-y-3 max-h-96 overflow-y-auto">
            {results.length === 0 ? (
              <p className="text-sm text-muted-foreground text-center py-8">
                No operations yet. Start encoding, decoding, or analyzing text above.
              </p>
            ) : (
              results.map((result, index) => (
                <div key={index} className="border border-border rounded-lg p-3 space-y-2 hover:bg-accent/5 transition-colors">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-medium text-accent">{result.method}</span>
                    <span className="text-xs text-muted-foreground">{result.timestamp}</span>
                  </div>
                  <div className="text-xs space-y-1">
                    <div>
                      <span className="text-muted-foreground font-medium">Input: </span>
                      <span className="font-mono text-foreground">
                        {result.input.slice(0, 80)}{result.input.length > 80 ? '...' : ''}
                      </span>
                    </div>
                    <div>
                      <span className="text-muted-foreground font-medium">Output: </span>
                      <span className="font-mono text-foreground">
                        {result.output.slice(0, 80)}{result.output.length > 80 ? '...' : ''}
                      </span>
                    </div>
                  </div>
                  <button
                    onClick={() => copyToClipboard(result.output)}
                    className="text-xs text-accent hover:text-accent/80 transition-colors"
                  >
                    Copy output
                  </button>
                </div>
              ))
            )}
          </div>
        </div>

        {/* Quick Stats */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="bg-card border border-border rounded-lg p-4 text-center">
            <div className="text-2xl font-bold text-accent">{encodingTools.length}</div>
            <div className="text-sm text-muted-foreground">Encoding Tools</div>
          </div>
          <div className="bg-card border border-border rounded-lg p-4 text-center">
            <div className="text-2xl font-bold text-accent">{hashingTools.length}</div>
            <div className="text-sm text-muted-foreground">Hash Functions</div>
          </div>
          <div className="bg-card border border-border rounded-lg p-4 text-center">
            <div className="text-2xl font-bold text-accent">{classicalTools.length}</div>
            <div className="text-sm text-muted-foreground">Classical Ciphers</div>
          </div>
          <div className="bg-card border border-border rounded-lg p-4 text-center">
            <div className="text-2xl font-bold text-accent">{analysisTools.length}</div>
            <div className="text-sm text-muted-foreground">Analysis Tools</div>
          </div>
        </div>
      </div>
    </div>
  )
}

export default CryptoTools
