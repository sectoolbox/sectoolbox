/**
 * Formatting utilities - Pure synchronous functions
 * These can be copied to frontend if needed
 */

/**
 * Format bytes to human-readable size
 * @param bytes - Number of bytes
 * @param decimals - Decimal places (default: 2)
 * @returns Formatted string like "1.5 MB"
 */
export function formatBytes(bytes: number, decimals: number = 2): string {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(decimals))} ${sizes[i]}`;
}

/**
 * Format duration in seconds to readable string
 * @param seconds - Duration in seconds
 * @returns Formatted string like "2:30" or "1:05:30"
 */
export function formatDuration(seconds: number): string {
  if (seconds < 0) return '0:00';
  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = Math.floor(seconds % 60);
  
  if (hours > 0) {
    return `${hours}:${minutes.toString().padStart(2, '0')}:${secs.toString().padStart(2, '0')}`;
  }
  return `${minutes}:${secs.toString().padStart(2, '0')}`;
}

/**
 * Convert hex string to ASCII
 * @param hex - Hexadecimal string (with or without colons/spaces)
 * @returns ASCII string with non-printable chars replaced by '.'
 */
export function hexToAscii(hex: string): string {
  if (!hex) return '';
  const cleaned = hex.replace(/[:|\s]/g, '');
  const bytes = cleaned.match(/.{1,2}/g) || [];
  
  return bytes
    .map(byte => {
      const code = parseInt(byte, 16);
      if (code === 10 || code === 13 || code === 9) return String.fromCharCode(code);
      if (code >= 32 && code <= 126) return String.fromCharCode(code);
      return '.';
    })
    .join('');
}

/**
 * Convert ASCII string to hex
 * @param str - ASCII string
 * @param separator - Optional separator between bytes
 * @returns Hexadecimal string
 */
export function asciiToHex(str: string, separator: string = ''): string {
  return Array.from(str)
    .map(char => char.charCodeAt(0).toString(16).padStart(2, '0'))
    .join(separator);
}

/**
 * Truncate string with ellipsis
 * @param str - String to truncate
 * @param maxLength - Maximum length
 * @param ellipsis - Ellipsis string (default: '...')
 * @returns Truncated string
 */
export function truncateString(str: string, maxLength: number, ellipsis: string = '...'): string {
  if (str.length <= maxLength) return str;
  return str.slice(0, maxLength - ellipsis.length) + ellipsis;
}
