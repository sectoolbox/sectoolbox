/**
 * Shared formatting utilities for frontend
 */

/**
 * Format bytes to human-readable size
 */
export function formatBytes(bytes: number, decimals: number = 2): string {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB', 'PB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}

/**
 * Convert hex string to ASCII
 * Used for PCAP stream extraction and packet analysis
 */
export function hexToAscii(hex: string): string {
  if (!hex) {
    return '';
  }

  const cleaned = hex.replace(/:/g, '').replace(/\s/g, '');
  const bytes = cleaned.match(/.{1,2}/g) || [];

  const result = bytes
    .map(byte => {
      const code = parseInt(byte, 16);
      // Keep all printable characters and newlines/tabs
      if (code === 10 || code === 13 || code === 9) return String.fromCharCode(code);
      if (code >= 32 && code <= 126) return String.fromCharCode(code);
      return '.';
    })
    .join('');

  return result;
}

/**
 * Format file size (alias for formatBytes)
 */
export function formatFileSize(bytes: number): string {
  return formatBytes(bytes);
}
