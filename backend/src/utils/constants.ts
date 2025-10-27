/**
 * Shared constants - Single source of truth
 * Copy this file to frontend if needed for consistency
 */

/**
 * File size limits in bytes
 */
export const FILE_SIZE_LIMITS = {
  PCAP: 2 * 1024 * 1024 * 1024, // 2GB
  AUDIO: 500 * 1024 * 1024, // 500MB
  IMAGE: 100 * 1024 * 1024, // 100MB
  EVTX: 1.5 * 1024 * 1024 * 1024, // 1.5GB
  MEMORY_DUMP: 4 * 1024 * 1024 * 1024, // 4GB
  DEFAULT: 500 * 1024 * 1024, // 500MB
} as const;

/**
 * Allowed file extensions by type
 */
export const ALLOWED_EXTENSIONS = {
  PCAP: ['pcap', 'pcapng', 'cap'],
  AUDIO: ['wav', 'mp3', 'ogg', 'flac', 'm4a', 'aac'],
  IMAGE: ['jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'tiff', 'svg'],
  EVTX: ['evtx'],
  MEMORY: ['raw', 'mem', 'dmp', 'vmem', 'dump'],
  ARCHIVE: ['zip', 'rar', '7z', 'tar', 'gz', 'bz2'],
} as const;

/**
 * WebSocket event names
 */
export const WS_EVENTS = {
  JOIN_JOB: 'join-job',
  LEAVE_JOB: 'leave-job',
  JOB_PROGRESS: 'job-progress',
  JOB_COMPLETED: 'job-completed',
  JOB_FAILED: 'job-failed',
} as const;

/**
 * Job status types
 */
export const JOB_STATUS = {
  QUEUED: 'queued',
  PROCESSING: 'processing',
  COMPLETED: 'completed',
  FAILED: 'failed',
} as const;

/**
 * Common CTF flag patterns
 */
export const CTF_FLAG_PATTERNS = {
  HTB: /HTB\{[^}]+\}/gi,
  PICOCTF: /picoCTF\{[^}]+\}/gi,
  FLAG: /flag\{[^}]+\}/gi,
  GENERIC: /[A-Z]{2,10}\{[^}]+\}/g,
} as const;
