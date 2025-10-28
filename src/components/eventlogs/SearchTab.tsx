import React, { useState, useMemo } from 'react';
import { Search, Filter, Clock, ChevronDown, ChevronRight } from 'lucide-react';
import { Card } from '../ui/card';

interface SearchTabProps {
  events: any[];
}

export const SearchTab: React.FC<SearchTabProps> = ({ events }) => {
  const [searchQuery, setSearchQuery] = useState('');
  const [useRegex, setUseRegex] = useState(false);
  const [searchField, setSearchField] = useState<'all' | 'eventId' | 'provider' | 'computer' | 'data'>('all');
  const [levelFilter, setLevelFilter] = useState<string>('all');
  const [timeRange, setTimeRange] = useState<'all' | '1h' | '24h' | '7d' | 'custom'>('all');
  const [expandedEvents, setExpandedEvents] = useState<Set<number>>(new Set());

  const toggleEvent = (recordId: number) => {
    setExpandedEvents(prev => {
      const next = new Set(prev);
      if (next.has(recordId)) {
        next.delete(recordId);
      } else {
        next.add(recordId);
      }
      return next;
    });
  };

  // Helper to find and extract matching content from event data
  const findMatchInEventData = (event: any, query: string, isRegex: boolean): { matched: boolean; matchedText?: string; field?: string } => {
    if (!event.data || !query) return { matched: false };
    
    try {
      if (isRegex) {
        const regex = new RegExp(query, 'i');
        for (const [key, value] of Object.entries(event.data)) {
          const valueStr = String(value);
          if (regex.test(valueStr)) {
            // Extract context around match (50 chars before and after)
            const match = valueStr.match(regex);
            if (match) {
              const matchIndex = match.index || 0;
              const start = Math.max(0, matchIndex - 50);
              const end = Math.min(valueStr.length, matchIndex + match[0].length + 50);
              const context = valueStr.substring(start, end);
              return { 
                matched: true, 
                matchedText: context,
                field: key
              };
            }
          }
        }
      } else {
        const lowerQuery = query.toLowerCase();
        for (const [key, value] of Object.entries(event.data)) {
          const valueStr = String(value);
          const lowerValue = valueStr.toLowerCase();
          if (lowerValue.includes(lowerQuery)) {
            // Extract context around match (50 chars before and after)
            const matchIndex = lowerValue.indexOf(lowerQuery);
            const start = Math.max(0, matchIndex - 50);
            const end = Math.min(valueStr.length, matchIndex + lowerQuery.length + 50);
            const context = valueStr.substring(start, end);
            return { 
              matched: true, 
              matchedText: context,
              field: key
            };
          }
        }
      }
    } catch (e) {
      return { matched: false };
    }
    
    return { matched: false };
  };

  const filteredResults = useMemo(() => {
    if (!searchQuery && levelFilter === 'all' && timeRange === 'all') {
      return events;
    }

    return events.filter(event => {
      // Level filter
      if (levelFilter !== 'all' && event.levelName !== levelFilter) return false;

      // Time filter
      if (timeRange !== 'all' && timeRange !== 'custom') {
        const eventTime = new Date(event.timestamp).getTime();
        const now = Date.now();
        const ranges = {
          '1h': 60 * 60 * 1000,
          '24h': 24 * 60 * 60 * 1000,
          '7d': 7 * 24 * 60 * 60 * 1000,
        };
        if (now - eventTime > ranges[timeRange]) return false;
      }

      // Search query
      if (!searchQuery) return true;

      try {
        if (useRegex) {
          const regex = new RegExp(searchQuery, 'i');
          if (searchField === 'all') {
            return regex.test(String(event.eventId)) ||
                   regex.test(event.provider || '') ||
                   regex.test(event.computer || '') ||
                   regex.test(JSON.stringify(event.data || {}));
          } else if (searchField === 'eventId') {
            return regex.test(String(event.eventId));
          } else if (searchField === 'provider') {
            return regex.test(event.provider || '');
          } else if (searchField === 'computer') {
            return regex.test(event.computer || '');
          } else if (searchField === 'data') {
            return regex.test(JSON.stringify(event.data || {}));
          }
        } else {
          const query = searchQuery.toLowerCase();
          if (searchField === 'all') {
            return String(event.eventId).toLowerCase().includes(query) ||
                   (event.provider || '').toLowerCase().includes(query) ||
                   (event.computer || '').toLowerCase().includes(query) ||
                   JSON.stringify(event.data || {}).toLowerCase().includes(query);
          } else if (searchField === 'eventId') {
            return String(event.eventId).toLowerCase().includes(query);
          } else if (searchField === 'provider') {
            return (event.provider || '').toLowerCase().includes(query);
          } else if (searchField === 'computer') {
            return (event.computer || '').toLowerCase().includes(query);
          } else if (searchField === 'data') {
            return JSON.stringify(event.data || {}).toLowerCase().includes(query);
          }
        }
      } catch (e) {
        return false;
      }

      return true;
    });
  }, [events, searchQuery, useRegex, searchField, levelFilter, timeRange]);

  return (
    <div className="space-y-4">
      {/* Search Filters */}
      <Card className="p-4">
        <div className="space-y-4">
          {/* Search Input */}
          <div>
            <label className="text-sm font-medium mb-2 block">Search Query</label>
            <div className="flex gap-2">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
                <input
                  type="text"
                  placeholder="Enter search term or regex pattern..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="w-full pl-10 pr-3 py-2 bg-card border border-border rounded text-sm"
                />
              </div>
              <label className="flex items-center gap-2 px-3 py-2 bg-card border border-border rounded cursor-pointer hover:bg-muted/50">
                <input
                  type="checkbox"
                  checked={useRegex}
                  onChange={(e) => setUseRegex(e.target.checked)}
                  className="rounded"
                />
                <span className="text-sm">Regex</span>
              </label>
            </div>
          </div>

          {/* Filters */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <div>
              <label className="text-sm font-medium mb-2 block flex items-center gap-2">
                <Filter className="w-4 h-4" />
                Search Field
              </label>
              <select
                value={searchField}
                onChange={(e) => setSearchField(e.target.value as any)}
                className="w-full px-3 py-2 bg-card border border-border rounded text-sm"
              >
                <option value="all">All Fields</option>
                <option value="eventId">Event ID Only</option>
                <option value="provider">Provider Only</option>
                <option value="computer">Computer Only</option>
                <option value="data">Event Data Only</option>
              </select>
            </div>

            <div>
              <label className="text-sm font-medium mb-2 block flex items-center gap-2">
                <Filter className="w-4 h-4" />
                Level
              </label>
              <select
                value={levelFilter}
                onChange={(e) => setLevelFilter(e.target.value)}
                className="w-full px-3 py-2 bg-card border border-border rounded text-sm"
              >
                <option value="all">All Levels</option>
                <option value="Critical">Critical</option>
                <option value="Error">Error</option>
                <option value="Warning">Warning</option>
                <option value="Information">Information</option>
              </select>
            </div>

            <div>
              <label className="text-sm font-medium mb-2 block flex items-center gap-2">
                <Clock className="w-4 h-4" />
                Time Range
              </label>
              <select
                value={timeRange}
                onChange={(e) => setTimeRange(e.target.value as any)}
                className="w-full px-3 py-2 bg-card border border-border rounded text-sm"
              >
                <option value="all">All Time</option>
                <option value="1h">Last Hour</option>
                <option value="24h">Last 24 Hours</option>
                <option value="7d">Last 7 Days</option>
              </select>
            </div>
          </div>
        </div>
      </Card>

      {/* Results */}
      <Card className="p-4">
        <div className="flex items-center justify-between mb-4">
          <h3 className="font-semibold">Search Results</h3>
          <span className="text-sm text-muted-foreground">
            {filteredResults.length.toLocaleString()} events found
          </span>
        </div>

        <div className="space-y-2 max-h-[600px] overflow-y-auto">
          {filteredResults.length === 0 ? (
            <div className="text-center py-8 text-muted-foreground">
              <Search className="w-12 h-12 mx-auto mb-3 opacity-50" />
              <p>No events match your search criteria</p>
            </div>
          ) : (
            filteredResults.slice(0, 100).map((event) => {
              const isExpanded = expandedEvents.has(event.recordId);
              const matchResult = searchQuery && searchField === 'data' ? findMatchInEventData(event, searchQuery, useRegex) : { matched: false };
              
              return (
                <div key={event.recordId} className="border border-border rounded overflow-hidden">
                  <div 
                    className="p-3 bg-muted/5 cursor-pointer hover:bg-muted/10 transition-colors"
                    onClick={() => toggleEvent(event.recordId)}
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex items-center gap-2">
                        {isExpanded ? (
                          <ChevronDown className="w-4 h-4 text-muted-foreground flex-shrink-0 mt-0.5" />
                        ) : (
                          <ChevronRight className="w-4 h-4 text-muted-foreground flex-shrink-0 mt-0.5" />
                        )}
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 mb-1 flex-wrap">
                            <span className="font-mono text-sm font-semibold text-accent">
                              Event {event.eventId}
                            </span>
                            <span className={`px-2 py-0.5 rounded text-xs font-medium ${
                              event.levelName === 'Critical' ? 'bg-red-500/20 text-red-400' :
                              event.levelName === 'Error' ? 'bg-red-400/20 text-red-300' :
                              event.levelName === 'Warning' ? 'bg-yellow-500/20 text-yellow-400' :
                              'bg-blue-500/20 text-blue-400'
                            }`}>
                              {event.levelName}
                            </span>
                          </div>
                          <div className="text-sm text-muted-foreground mb-1">
                            {event.provider} • {event.computer}
                          </div>
                          <div className="text-xs text-muted-foreground">
                            {new Date(event.timestamp).toLocaleString()}
                          </div>
                          {matchResult.matched && matchResult.matchedText && (
                            <div className="mt-2 p-2 bg-green-500/10 border border-green-500/30 rounded">
                              <div className="text-xs font-semibold text-green-400 mb-1">
                                Match found in: {matchResult.field}
                              </div>
                              <div className="text-xs font-mono text-muted-foreground break-all">
                                ...{matchResult.matchedText}...
                              </div>
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>

                  {isExpanded && (
                    <div className="border-t border-border p-4 bg-muted/5 space-y-3">
                      {/* Basic Info */}
                      <div className="grid grid-cols-2 gap-3 text-xs">
                        <div>
                          <span className="text-muted-foreground">Record ID:</span>
                          <span className="ml-2 font-mono">{event.recordId}</span>
                        </div>
                        <div>
                          <span className="text-muted-foreground">Event ID:</span>
                          <span className="ml-2 font-mono">{event.eventId}</span>
                        </div>
                        <div>
                          <span className="text-muted-foreground">Level:</span>
                          <span className="ml-2">{event.levelName} ({event.level})</span>
                        </div>
                        <div>
                          <span className="text-muted-foreground">Channel:</span>
                          <span className="ml-2">{event.channel || 'N/A'}</span>
                        </div>
                        <div className="col-span-2">
                          <span className="text-muted-foreground">Provider:</span>
                          <span className="ml-2">{event.provider}</span>
                        </div>
                        <div className="col-span-2">
                          <span className="text-muted-foreground">Computer:</span>
                          <span className="ml-2">{event.computer}</span>
                        </div>
                      </div>

                      {/* Event Data */}
                      {event.data && Object.keys(event.data).length > 0 && (
                        <div>
                          <div className="text-xs font-semibold text-muted-foreground mb-2">Event Data:</div>
                          <div className="bg-card border border-border rounded p-2 space-y-1 max-h-64 overflow-y-auto">
                            {Object.entries(event.data).map(([key, value]) => (
                              <div key={key} className="text-xs">
                                <span className="text-muted-foreground font-medium">{key}:</span>
                                <span className="ml-2 font-mono break-all">{String(value)}</span>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Raw XML */}
                      {event.rawXml && (
                        <details className="mt-3">
                          <summary className="text-xs font-semibold text-muted-foreground cursor-pointer hover:text-foreground">
                            View Raw XML
                          </summary>
                          <pre className="mt-2 bg-card border border-border rounded p-2 text-xs font-mono overflow-x-auto max-h-64 overflow-y-auto">
                            {event.rawXml}
                          </pre>
                        </details>
                      )}
                    </div>
                  )}
                </div>
              );
            })
          )}
          {filteredResults.length > 100 && (
            <div className="text-center text-sm text-muted-foreground py-3">
              Showing first 100 of {filteredResults.length.toLocaleString()} results
            </div>
          )}
        </div>
      </Card>
    </div>
  );
};
