/**
 * Validation utilities - Pure synchronous functions
 * These can be copied to frontend if needed
 */

import { formatBytes } from './formatting.js';

/**
 * Validate file size against maximum
 * @param size - File size in bytes
 * @param maxSize - Maximum allowed size (default: 2GB)
 * @throws Error if file exceeds maximum size
 */
export function validateFileSize(size: number, maxSize: number = 2 * 1024 * 1024 * 1024): void {
  if (size <= 0) {
    throw new Error('Invalid file size');
  }
  if (size > maxSize) {
    throw new Error(`File too large. Maximum size: ${formatBytes(maxSize)}`);
  }
}

/**
 * Validate file type against allowed extensions
 * @param filename - File name with extension
 * @param allowedExtensions - Array of allowed extensions (without dots)
 * @throws Error if file type not allowed
 */
export function validateFileType(filename: string, allowedExtensions: readonly string[] | string[]): void {
  const ext = filename.split('.').pop()?.toLowerCase();
  if (!ext || !allowedExtensions.includes(ext)) {
    throw new Error(`Invalid file type. Allowed: ${allowedExtensions.join(', ')}`);
  }
}

/**
 * Sanitize filename for safe filesystem use
 * @param filename - Original filename
 * @returns Sanitized filename with only safe characters
 */
export function sanitizeFilename(filename: string): string {
  return filename.replace(/[^a-zA-Z0-9._-]/g, '_');
}

/**
 * Generate unique filename with timestamp
 * @param originalFilename - Original filename
 * @returns Unique filename with timestamp prefix
 */
export function generateUniqueFilename(originalFilename: string): string {
  const sanitized = sanitizeFilename(originalFilename);
  return `${Date.now()}_${sanitized}`;
}

/**
 * Check if value is a valid UUID v4
 * @param value - String to validate
 * @returns True if valid UUID v4
 */
export function isValidUUID(value: string): boolean {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(value);
}
