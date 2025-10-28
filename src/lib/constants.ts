/**
 * Frontend constants - Single source of truth for UI values
 */

/**
 * Event log severity level colors
 * Used consistently across all EventLog components
 */
export const SEVERITY_COLORS = {
  CRITICAL: {
    text: 'text-red-500',
    bg: 'bg-red-500/20',
    border: 'border-red-500/50',
    rowBg: 'bg-red-950/30',
    rowBorder: 'border-red-900/50',
  },
  ERROR: {
    text: 'text-red-400',
    bg: 'bg-red-400/20',
    border: 'border-red-400/50',
    rowBg: 'bg-red-950/20',
    rowBorder: 'border-red-900/30',
  },
  WARNING: {
    text: 'text-yellow-400',
    bg: 'bg-yellow-500/20',
    border: 'border-yellow-500/50',
    rowBg: 'bg-yellow-950/20',
    rowBorder: 'border-yellow-900/30',
  },
  INFORMATION: {
    text: 'text-blue-400',
    bg: 'bg-blue-500/20',
    border: 'border-blue-500/50',
    rowBg: 'bg-background',
    rowBorder: 'border-border',
  },
  DEFAULT: {
    text: 'text-muted-foreground',
    bg: 'bg-muted/20',
    border: 'border-muted',
    rowBg: 'bg-background',
    rowBorder: 'border-border',
  },
} as const;

/**
 * Get severity colors by level name
 */
export const getSeverityColors = (levelName: string) => {
  const normalized = levelName.toUpperCase();
  if (normalized in SEVERITY_COLORS) {
    return SEVERITY_COLORS[normalized as keyof typeof SEVERITY_COLORS];
  }
  return SEVERITY_COLORS.DEFAULT;
};

/**
 * File size limits (same as backend)
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
