/**
 * Multi-Stage Decoding Utilities for CTF and Forensics
 * Supports various encoding schemes with automatic detection
 */

import { toast } from 'react-hot-toast';

export interface DecodingResult {
  type: string;
  decoded: string;
  success: boolean;
  encoding: string;
  confidence: number; // 0-100
}

// ========== BASE64 ==========

export const decodeBase64 = (input: string): DecodingResult => {
  try {
    const decoded = atob(input);
    const confidence = isReadable(decoded) ? 90 : 50;
    
    return {
      type: 'Base64',
      decoded,
      success: true,
      encoding: 'base64',
      confidence,
    };
  } catch (error) {
    return {
      type: 'Base64',
      decoded: '',
      success: false,
      encoding: 'base64',
      confidence: 0,
    };
  }
};

// ========== HEX ==========

export const decodeHex = (input: string): DecodingResult => {
  try {
    const cleaned = input.replace(/0x|\\x| /g, '');
    const decoded = cleaned.match(/.{1,2}/g)
      ?.map(byte => String.fromCharCode(parseInt(byte, 16)))
      .join('') || '';
    
    const confidence = isReadable(decoded) ? 85 : 40;
    
    return {
      type: 'Hex',
      decoded,
      success: decoded.length > 0,
      encoding: 'hex',
      confidence,
    };
  } catch (error) {
    return {
      type: 'Hex',
      decoded: '',
      success: false,
      encoding: 'hex',
      confidence: 0,
    };
  }
};

// ========== URL ENCODING ==========

export const decodeURL = (input: string): DecodingResult => {
  try {
    const decoded = decodeURIComponent(input);
    const confidence = decoded !== input ? 80 : 20;
    
    return {
      type: 'URL',
      decoded,
      success: true,
      encoding: 'url',
      confidence,
    };
  } catch (error) {
    return {
      type: 'URL',
      decoded: '',
      success: false,
      encoding: 'url',
      confidence: 0,
    };
  }
};

// ========== HTML ENTITIES ==========

export const decodeHTML = (input: string): DecodingResult => {
  try {
    const textarea = document.createElement('textarea');
    textarea.innerHTML = input;
    const decoded = textarea.value;
    const confidence = decoded !== input ? 75 : 20;
    
    return {
      type: 'HTML',
      decoded,
      success: true,
      encoding: 'html',
      confidence,
    };
  } catch (error) {
    return {
      type: 'HTML',
      decoded: '',
      success: false,
      encoding: 'html',
      confidence: 0,
    };
  }
};

// ========== ROT13 / CAESAR CIPHER ==========

export const decodeROT13 = (input: string): DecodingResult => {
  const decoded = input.replace(/[a-zA-Z]/g, (char) => {
    const start = char <= 'Z' ? 65 : 97;
    return String.fromCharCode(((char.charCodeAt(0) - start + 13) % 26) + start);
  });
  
  const confidence = isReadable(decoded) ? 70 : 30;
  
  return {
    type: 'ROT13',
    decoded,
    success: true,
    encoding: 'rot13',
    confidence,
  };
};

export const decodeCaesar = (input: string, shift: number): DecodingResult => {
  const decoded = input.replace(/[a-zA-Z]/g, (char) => {
    const start = char <= 'Z' ? 65 : 97;
    return String.fromCharCode(((char.charCodeAt(0) - start - shift + 26) % 26) + start);
  });
  
  const confidence = isReadable(decoded) ? 70 : 30;
  
  return {
    type: `Caesar (shift ${shift})`,
    decoded,
    success: true,
    encoding: `caesar-${shift}`,
    confidence,
  };
};

export const tryAllCaesarShifts = (input: string): DecodingResult[] => {
  const results: DecodingResult[] = [];
  
  for (let shift = 1; shift < 26; shift++) {
    const result = decodeCaesar(input, shift);
    if (result.confidence > 50) {
      results.push(result);
    }
  }
  
  return results.sort((a, b) => b.confidence - a.confidence);
};

// ========== BINARY ==========

export const decodeBinary = (input: string): DecodingResult => {
  try {
    const cleaned = input.replace(/[^01]/g, '');
    const decoded = cleaned.match(/.{1,8}/g)
      ?.map(byte => String.fromCharCode(parseInt(byte, 2)))
      .join('') || '';
    
    const confidence = isReadable(decoded) ? 80 : 35;
    
    return {
      type: 'Binary',
      decoded,
      success: decoded.length > 0,
      encoding: 'binary',
      confidence,
    };
  } catch (error) {
    return {
      type: 'Binary',
      decoded: '',
      success: false,
      encoding: 'binary',
      confidence: 0,
    };
  }
};

// ========== MORSE CODE ==========

const MORSE_CODE: Record<string, string> = {
  '.-': 'A', '-...': 'B', '-.-.': 'C', '-..': 'D', '.': 'E',
  '..-.': 'F', '--.': 'G', '....': 'H', '..': 'I', '.---': 'J',
  '-.-': 'K', '.-..': 'L', '--': 'M', '-.': 'N', '---': 'O',
  '.--.': 'P', '--.-': 'Q', '.-.': 'R', '...': 'S', '-': 'T',
  '..-': 'U', '...-': 'V', '.--': 'W', '-..-': 'X', '-.--': 'Y',
  '--..': 'Z', '-----': '0', '.----': '1', '..---': '2', '...--': '3',
  '....-': '4', '.....': '5', '-....': '6', '--...': '7', '---..': '8',
  '----.': '9',
};

export const decodeMorse = (input: string): DecodingResult => {
  try {
    const words = input.trim().split(/\s{3,}/);
    const decoded = words.map(word => {
      const letters = word.split(/\s+/);
      return letters.map(letter => MORSE_CODE[letter] || '?').join('');
    }).join(' ');
    
    const unknownCount = (decoded.match(/\?/g) || []).length;
    const confidence = unknownCount === 0 ? 85 : Math.max(20, 85 - unknownCount * 10);
    
    return {
      type: 'Morse Code',
      decoded,
      success: unknownCount < decoded.length / 2,
      encoding: 'morse',
      confidence,
    };
  } catch (error) {
    return {
      type: 'Morse Code',
      decoded: '',
      success: false,
      encoding: 'morse',
      confidence: 0,
    };
  }
};

// ========== BASE32 ==========

export const decodeBase32 = (input: string): DecodingResult => {
  try {
    // Simple Base32 decoder
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
    const cleaned = input.toUpperCase().replace(/[^A-Z2-7=]/g, '');
    
    let bits = '';
    for (const char of cleaned) {
      if (char === '=') break;
      const value = alphabet.indexOf(char);
      if (value >= 0) {
        bits += value.toString(2).padStart(5, '0');
      }
    }
    
    const decoded = bits.match(/.{1,8}/g)
      ?.map(byte => String.fromCharCode(parseInt(byte, 2)))
      .join('') || '';
    
    const confidence = isReadable(decoded) ? 75 : 30;
    
    return {
      type: 'Base32',
      decoded,
      success: decoded.length > 0,
      encoding: 'base32',
      confidence,
    };
  } catch (error) {
    return {
      type: 'Base32',
      decoded: '',
      success: false,
      encoding: 'base32',
      confidence: 0,
    };
  }
};

// ========== REVERSED STRING ==========

export const decodeReverse = (input: string): DecodingResult => {
  const decoded = input.split('').reverse().join('');
  const confidence = isReadable(decoded) ? 60 : 25;
  
  return {
    type: 'Reversed',
    decoded,
    success: true,
    encoding: 'reverse',
    confidence,
  };
};

// ========== MULTI-STAGE DECODING ==========

export const tryAllDecodings = (input: string, maxDepth = 3): DecodingResult[] => {
  const results: DecodingResult[] = [];
  const visited = new Set<string>();
  
  const tryDecode = (text: string, depth: number, history: string[] = []) => {
    if (depth > maxDepth || visited.has(text)) return;
    visited.add(text);
    
    const decoders = [
      () => decodeBase64(text),
      () => decodeHex(text),
      () => decodeURL(text),
      () => decodeHTML(text),
      () => decodeROT13(text),
      () => decodeBinary(text),
      () => decodeBase32(text),
      () => decodeReverse(text),
    ];
    
    for (const decoder of decoders) {
      const result = decoder();
      if (result.success && result.decoded !== text && result.confidence > 40) {
        const fullResult: DecodingResult = {
          ...result,
          type: [...history, result.type].join(' → '),
        };
        results.push(fullResult);
        
        // Try decoding the result again
        if (depth < maxDepth) {
          tryDecode(result.decoded, depth + 1, [...history, result.type]);
        }
      }
    }
  };
  
  tryDecode(input, 0);
  
  return results.sort((a, b) => b.confidence - a.confidence);
};

// ========== AUTOMATIC DETECTION ==========

export const detectEncoding = (input: string): string[] => {
  const encodings: string[] = [];
  
  // Base64 pattern
  if (/^[A-Za-z0-9+/]+={0,2}$/.test(input) && input.length % 4 === 0) {
    encodings.push('base64');
  }
  
  // Hex pattern
  if (/^(0x)?[0-9a-fA-F]+$/.test(input.replace(/\s/g, ''))) {
    encodings.push('hex');
  }
  
  // URL encoding
  if (/%[0-9A-Fa-f]{2}/.test(input)) {
    encodings.push('url');
  }
  
  // HTML entities
  if (/&[a-z]+;|&#\d+;/i.test(input)) {
    encodings.push('html');
  }
  
  // Binary
  if (/^[01\s]+$/.test(input)) {
    encodings.push('binary');
  }
  
  // Morse code
  if (/^[\.\- ]+$/.test(input)) {
    encodings.push('morse');
  }
  
  // Base32
  if (/^[A-Z2-7=]+$/.test(input)) {
    encodings.push('base32');
  }
  
  return encodings;
};

// ========== HELPER FUNCTIONS ==========

const isReadable = (text: string): boolean => {
  if (!text) return false;
  
  // Check if text contains mostly printable ASCII characters
  const printable = text.split('').filter(c => {
    const code = c.charCodeAt(0);
    return (code >= 32 && code <= 126) || code === 10 || code === 13;
  }).length;
  
  const ratio = printable / text.length;
  
  // Check for common English words
  const commonWords = ['the', 'and', 'is', 'in', 'to', 'of', 'flag', 'ctf'];
  const lowerText = text.toLowerCase();
  const wordMatches = commonWords.filter(word => lowerText.includes(word)).length;
  
  return ratio > 0.8 || wordMatches > 0;
};

// ========== EXPORT ALL DECODERS ==========

export const getAllDecoders = () => [
  { name: 'Base64', decode: decodeBase64 },
  { name: 'Hex', decode: decodeHex },
  { name: 'URL', decode: decodeURL },
  { name: 'HTML', decode: decodeHTML },
  { name: 'ROT13', decode: decodeROT13 },
  { name: 'Binary', decode: decodeBinary },
  { name: 'Morse', decode: decodeMorse },
  { name: 'Base32', decode: decodeBase32 },
  { name: 'Reverse', decode: decodeReverse },
];

// ========== COPY DECODED TO CLIPBOARD ==========

export const copyDecoded = (decoded: string, type: string) => {
  navigator.clipboard.writeText(decoded);
  toast.success(`${type} decoded value copied!`);
};
