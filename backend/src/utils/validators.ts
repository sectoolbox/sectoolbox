export function validateFileSize(size: number, maxSize: number = 2 * 1024 * 1024 * 1024): void {
  if (size > maxSize) {
    throw new Error(`File too large. Maximum size: ${formatBytes(maxSize)}`);
  }
}

export function validateFileType(filename: string, allowedExtensions: string[]): void {
  const ext = filename.split('.').pop()?.toLowerCase();
  if (!ext || !allowedExtensions.includes(ext)) {
    throw new Error(`Invalid file type. Allowed: ${allowedExtensions.join(', ')}`);
  }
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}

export function sanitizeFilename(filename: string): string {
  return filename.replace(/[^a-zA-Z0-9._-]/g, '_');
}
