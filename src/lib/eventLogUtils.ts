/**
 * Event Log Analysis Utilities
 * Comprehensive helper functions for event log analysis
 */

import { toast } from 'react-hot-toast';

// ========== COPY TO CLIPBOARD ==========

export const copyToClipboard = async (text: string, label?: string) => {
  try {
    await navigator.clipboard.writeText(text);
    toast.success(`${label || 'Text'} copied to clipboard`);
    return true;
  } catch (error) {
    toast.error('Failed to copy to clipboard');
    return false;
  }
};

export const copyEventToClipboard = async (event: any) => {
  const formatted = JSON.stringify(event, null, 2);
  return copyToClipboard(formatted, 'Event data');
};

export const copyIOCsToClipboard = async (iocs: any) => {
  const lines: string[] = [];
  
  if (iocs.ips?.length) lines.push(`IPs:\n${iocs.ips.join('\n')}`);
  if (iocs.domains?.length) lines.push(`Domains:\n${iocs.domains.join('\n')}`);
  if (iocs.users?.length) lines.push(`Users:\n${iocs.users.join('\n')}`);
  if (iocs.processes?.length) lines.push(`Processes:\n${iocs.processes.join('\n')}`);
  if (iocs.files?.length) lines.push(`Files:\n${iocs.files.join('\n')}`);
  if (iocs.hashes?.length) lines.push(`Hashes:\n${iocs.hashes.join('\n')}`);
  
  return copyToClipboard(lines.join('\n\n'), 'All IOCs');
};

// ========== BOOKMARKING SYSTEM ==========

interface Bookmark {
  id: string;
  recordId: number;
  eventId: number;
  timestamp: string;
  note?: string;
  tags?: string[];
  createdAt: string;
}

const BOOKMARKS_KEY = 'sectoolbox_eventlog_bookmarks';

export const getBookmarks = (): Bookmark[] => {
  try {
    const stored = localStorage.getItem(BOOKMARKS_KEY);
    return stored ? JSON.parse(stored) : [];
  } catch {
    return [];
  }
};

export const addBookmark = (event: any, note?: string, tags?: string[]): Bookmark => {
  const bookmarks = getBookmarks();
  const bookmark: Bookmark = {
    id: `${event.recordId}-${Date.now()}`,
    recordId: event.recordId,
    eventId: event.eventId,
    timestamp: event.timestamp,
    note,
    tags,
    createdAt: new Date().toISOString(),
  };
  
  bookmarks.push(bookmark);
  localStorage.setItem(BOOKMARKS_KEY, JSON.stringify(bookmarks));
  toast.success('Event bookmarked');
  return bookmark;
};

export const removeBookmark = (id: string) => {
  const bookmarks = getBookmarks().filter(b => b.id !== id);
  localStorage.setItem(BOOKMARKS_KEY, JSON.stringify(bookmarks));
  toast.success('Bookmark removed');
};

export const isBookmarked = (recordId: number): boolean => {
  return getBookmarks().some(b => b.recordId === recordId);
};

export const updateBookmark = (id: string, updates: Partial<Bookmark>) => {
  const bookmarks = getBookmarks().map(b => 
    b.id === id ? { ...b, ...updates } : b
  );
  localStorage.setItem(BOOKMARKS_KEY, JSON.stringify(bookmarks));
  toast.success('Bookmark updated');
};

// ========== SEARCH HISTORY ==========

const SEARCH_HISTORY_KEY = 'sectoolbox_eventlog_search_history';
const MAX_HISTORY = 20;

export const getSearchHistory = (): string[] => {
  try {
    const stored = localStorage.getItem(SEARCH_HISTORY_KEY);
    return stored ? JSON.parse(stored) : [];
  } catch {
    return [];
  }
};

export const addToSearchHistory = (query: string) => {
  if (!query.trim()) return;
  
  let history = getSearchHistory();
  // Remove if exists
  history = history.filter(q => q !== query);
  // Add to front
  history.unshift(query);
  // Limit size
  history = history.slice(0, MAX_HISTORY);
  
  localStorage.setItem(SEARCH_HISTORY_KEY, JSON.stringify(history));
};

export const clearSearchHistory = () => {
  localStorage.removeItem(SEARCH_HISTORY_KEY);
  toast.success('Search history cleared');
};

// ========== SAVED FILTERS ==========

export interface SavedFilter {
  id: string;
  name: string;
  description?: string;
  filters: {
    searchQuery?: string;
    useRegex?: boolean;
    searchField?: string;
    levelFilter?: string;
    timeRange?: string;
    eventIds?: number[];
    providers?: string[];
  };
  createdAt: string;
}

const FILTERS_KEY = 'sectoolbox_eventlog_saved_filters';

export const getSavedFilters = (): SavedFilter[] => {
  try {
    const stored = localStorage.getItem(FILTERS_KEY);
    return stored ? JSON.parse(stored) : [];
  } catch {
    return [];
  }
};

export const saveFilter = (name: string, filters: any, description?: string): SavedFilter => {
  const savedFilters = getSavedFilters();
  const filter: SavedFilter = {
    id: `filter-${Date.now()}`,
    name,
    description,
    filters,
    createdAt: new Date().toISOString(),
  };
  
  savedFilters.push(filter);
  localStorage.setItem(FILTERS_KEY, JSON.stringify(savedFilters));
  toast.success('Filter saved');
  return filter;
};

export const deleteFilter = (id: string) => {
  const filters = getSavedFilters().filter(f => f.id !== id);
  localStorage.setItem(FILTERS_KEY, JSON.stringify(filters));
  toast.success('Filter deleted');
};

export const updateFilter = (id: string, updates: Partial<SavedFilter>) => {
  const filters = getSavedFilters().map(f => 
    f.id === id ? { ...f, ...updates } : f
  );
  localStorage.setItem(FILTERS_KEY, JSON.stringify(filters));
  toast.success('Filter updated');
};

// ========== EVENT TAGGING ==========

interface EventTag {
  recordId: number;
  tags: string[];
}

const TAGS_KEY = 'sectoolbox_eventlog_tags';

export const getEventTags = (recordId: number): string[] => {
  try {
    const stored = localStorage.getItem(TAGS_KEY);
    const allTags: EventTag[] = stored ? JSON.parse(stored) : [];
    return allTags.find(t => t.recordId === recordId)?.tags || [];
  } catch {
    return [];
  }
};

export const addTagToEvent = (recordId: number, tag: string) => {
  try {
    const stored = localStorage.getItem(TAGS_KEY);
    let allTags: EventTag[] = stored ? JSON.parse(stored) : [];
    
    const existing = allTags.find(t => t.recordId === recordId);
    if (existing) {
      if (!existing.tags.includes(tag)) {
        existing.tags.push(tag);
      }
    } else {
      allTags.push({ recordId, tags: [tag] });
    }
    
    localStorage.setItem(TAGS_KEY, JSON.stringify(allTags));
    toast.success('Tag added');
  } catch (error) {
    toast.error('Failed to add tag');
  }
};

export const removeTagFromEvent = (recordId: number, tag: string) => {
  try {
    const stored = localStorage.getItem(TAGS_KEY);
    let allTags: EventTag[] = stored ? JSON.parse(stored) : [];
    
    const existing = allTags.find(t => t.recordId === recordId);
    if (existing) {
      existing.tags = existing.tags.filter(t => t !== tag);
      if (existing.tags.length === 0) {
        allTags = allTags.filter(t => t.recordId !== recordId);
      }
    }
    
    localStorage.setItem(TAGS_KEY, JSON.stringify(allTags));
    toast.success('Tag removed');
  } catch (error) {
    toast.error('Failed to remove tag');
  }
};

// ========== STATISTICS CALCULATIONS ==========

export const calculateStatistics = (events: any[]) => {
  const stats = {
    total: events.length,
    byLevel: {} as Record<string, number>,
    byProvider: {} as Record<string, number>,
    byHour: {} as Record<string, number>,
    topEventIds: {} as Record<number, number>,
    timeRange: {
      start: '',
      end: '',
    },
    averageEventsPerHour: 0,
    criticalCount: 0,
    errorCount: 0,
    warningCount: 0,
  };

  events.forEach(event => {
    // Level distribution
    const level = event.levelName || 'Unknown';
    stats.byLevel[level] = (stats.byLevel[level] || 0) + 1;
    
    // Provider distribution
    const provider = event.provider || 'Unknown';
    stats.byProvider[provider] = (stats.byProvider[provider] || 0) + 1;
    
    // Event ID frequency
    const eventId = event.eventId;
    stats.topEventIds[eventId] = (stats.topEventIds[eventId] || 0) + 1;
    
    // Hourly distribution
    if (event.timestamp) {
      try {
        const date = new Date(event.timestamp);
        const hour = date.toISOString().slice(0, 13);
        stats.byHour[hour] = (stats.byHour[hour] || 0) + 1;
      } catch {}
    }
    
    // Count by severity
    if (level === 'Critical') stats.criticalCount++;
    if (level === 'Error') stats.errorCount++;
    if (level === 'Warning') stats.warningCount++;
  });

  // Calculate time range
  const timestamps = events
    .map(e => e.timestamp)
    .filter(Boolean)
    .sort();
  
  if (timestamps.length > 0) {
    stats.timeRange.start = timestamps[0];
    stats.timeRange.end = timestamps[timestamps.length - 1];
    
    // Calculate average events per hour
    const start = new Date(timestamps[0]).getTime();
    const end = new Date(timestamps[timestamps.length - 1]).getTime();
    const hours = (end - start) / (1000 * 60 * 60);
    stats.averageEventsPerHour = hours > 0 ? events.length / hours : 0;
  }

  return stats;
};

// ========== ANOMALY DETECTION ==========

export const detectAnomalies = (events: any[]) => {
  const hourly = {} as Record<string, number>;
  
  events.forEach(event => {
    if (event.timestamp) {
      try {
        const hour = new Date(event.timestamp).toISOString().slice(0, 13);
        hourly[hour] = (hourly[hour] || 0) + 1;
      } catch {}
    }
  });

  const counts = Object.values(hourly);
  if (counts.length === 0) return [];

  const mean = counts.reduce((a, b) => a + b, 0) / counts.length;
  const stdDev = Math.sqrt(
    counts.reduce((sum, count) => sum + Math.pow(count - mean, 2), 0) / counts.length
  );

  const threshold = mean + (2 * stdDev); // 2 standard deviations

  const anomalies = Object.entries(hourly)
    .filter(([_, count]) => count > threshold)
    .map(([hour, count]) => ({
      hour,
      count,
      expected: Math.round(mean),
      deviation: Math.round(((count - mean) / mean) * 100),
    }))
    .sort((a, b) => b.count - a.count);

  return anomalies;
};

// ========== EXPORT UTILITIES ==========

export const exportToCSV = (events: any[], filename = 'events.csv') => {
  if (events.length === 0) {
    toast.error('No events to export');
    return;
  }

  const headers = ['Record ID', 'Event ID', 'Level', 'Provider', 'Computer', 'Timestamp', 'Channel'];
  const rows = events.map(event => [
    event.recordId,
    event.eventId,
    event.levelName,
    event.provider,
    event.computer,
    event.timestamp,
    event.channel || '',
  ]);

  const csv = [
    headers.join(','),
    ...rows.map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(','))
  ].join('\n');

  downloadFile(csv, filename, 'text/csv');
  toast.success('Exported to CSV');
};

export const exportToJSON = (data: any, filename = 'events.json') => {
  const json = JSON.stringify(data, null, 2);
  downloadFile(json, filename, 'application/json');
  toast.success('Exported to JSON');
};

const downloadFile = (content: string, filename: string, mimeType: string) => {
  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
};

// ========== KEYBOARD SHORTCUTS ==========

export const setupKeyboardShortcuts = (handlers: {
  onSearch?: () => void;
  onExport?: () => void;
  onBookmark?: () => void;
  onRefresh?: () => void;
  onHelp?: () => void;
}) => {
  const handleKeyPress = (e: KeyboardEvent) => {
    // Ctrl/Cmd + K = Search
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
      e.preventDefault();
      handlers.onSearch?.();
    }
    // Ctrl/Cmd + E = Export
    if ((e.ctrlKey || e.metaKey) && e.key === 'e') {
      e.preventDefault();
      handlers.onExport?.();
    }
    // Ctrl/Cmd + B = Bookmark
    if ((e.ctrlKey || e.metaKey) && e.key === 'b') {
      e.preventDefault();
      handlers.onBookmark?.();
    }
    // Ctrl/Cmd + R = Refresh
    if ((e.ctrlKey || e.metaKey) && e.key === 'r') {
      e.preventDefault();
      handlers.onRefresh?.();
    }
    // ? = Help
    if (e.key === '?' && !e.ctrlKey && !e.metaKey) {
      e.preventDefault();
      handlers.onHelp?.();
    }
  };

  window.addEventListener('keydown', handleKeyPress);
  return () => window.removeEventListener('keydown', handleKeyPress);
};

// ========== FORMATTING UTILITIES ==========

export const formatTimestamp = (timestamp: string) => {
  try {
    return new Date(timestamp).toLocaleString();
  } catch {
    return timestamp;
  }
};

export const formatBytes = (bytes: number) => {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const sizes = ['Bytes', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return Math.round(bytes / Math.pow(k, i) * 100) / 100 + ' ' + sizes[i];
};

export const formatDuration = (start: string, end: string) => {
  try {
    const diff = new Date(end).getTime() - new Date(start).getTime();
    const hours = Math.floor(diff / (1000 * 60 * 60));
    const minutes = Math.floor((diff % (1000 * 60 * 60)) / (1000 * 60));
    return `${hours}h ${minutes}m`;
  } catch {
    return 'Unknown';
  }
};
