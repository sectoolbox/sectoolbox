import React, { useState, useMemo } from 'react';
import { ChevronDown, ChevronRight, AlertCircle, Info, AlertTriangle, XCircle } from 'lucide-react';
import { Card } from '../ui/card';

interface EventsTabProps {
  events: any[];
}

export const EventsTab: React.FC<EventsTabProps> = ({ events }) => {
  const [expandedEvents, setExpandedEvents] = useState<Set<number>>(new Set());
  const [filterLevel, setFilterLevel] = useState<string>('all');
  const [filterEventId, setFilterEventId] = useState<string>('');
  const [filterProvider, setFilterProvider] = useState<string>('');
  const [currentPage, setCurrentPage] = useState(1);
  const itemsPerPage = 50;

  // Filter events
  const filteredEvents = useMemo(() => {
    return events.filter(event => {
      if (filterLevel !== 'all' && event.levelName !== filterLevel) return false;
      if (filterEventId && !String(event.eventId).includes(filterEventId)) return false;
      if (filterProvider && !event.provider?.toLowerCase().includes(filterProvider.toLowerCase())) return false;
      return true;
    });
  }, [events, filterLevel, filterEventId, filterProvider]);

  // Paginate
  const totalPages = Math.ceil(filteredEvents.length / itemsPerPage);
  const paginatedEvents = useMemo(() => {
    const start = (currentPage - 1) * itemsPerPage;
    return filteredEvents.slice(start, start + itemsPerPage);
  }, [filteredEvents, currentPage]);

  const toggleEvent = (recordId: number) => {
    const newExpanded = new Set(expandedEvents);
    if (newExpanded.has(recordId)) {
      newExpanded.delete(recordId);
    } else {
      newExpanded.add(recordId);
    }
    setExpandedEvents(newExpanded);
  };

  const getLevelIcon = (levelName: string) => {
    switch (levelName) {
      case 'Critical':
        return <XCircle className="w-4 h-4 text-red-500" />;
      case 'Error':
        return <AlertCircle className="w-4 h-4 text-red-400" />;
      case 'Warning':
        return <AlertTriangle className="w-4 h-4 text-yellow-500" />;
      case 'Information':
        return <Info className="w-4 h-4 text-blue-400" />;
      default:
        return <Info className="w-4 h-4 text-muted-foreground" />;
    }
  };

  const getLevelColor = (levelName: string) => {
    switch (levelName) {
      case 'Critical':
        return 'bg-red-500/20 text-red-400 border-red-500/50';
      case 'Error':
        return 'bg-red-400/20 text-red-300 border-red-400/50';
      case 'Warning':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50';
      case 'Information':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/50';
      default:
        return 'bg-muted/20 text-muted-foreground border-muted';
    }
  };

  const getRowBgColor = (levelName: string) => {
    switch (levelName) {
      case 'Critical':
        return 'bg-red-950/30 border-red-900/50';
      case 'Error':
        return 'bg-red-950/20 border-red-900/30';
      case 'Warning':
        return 'bg-yellow-950/20 border-yellow-900/30';
      case 'Information':
        return 'bg-blue-950/10 border-blue-900/20';
      default:
        return 'bg-card border-border';
    }
  };

  return (
    <div className="space-y-4">
      {/* Filters */}
      <Card className="p-4">
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div>
            <label className="text-sm font-medium mb-2 block">Level</label>
            <select
              value={filterLevel}
              onChange={(e) => setFilterLevel(e.target.value)}
              className="w-full px-3 py-2 bg-card border border-border rounded text-sm"
            >
              <option value="all">All Levels</option>
              <option value="Critical">Critical</option>
              <option value="Error">Error</option>
              <option value="Warning">Warning</option>
              <option value="Information">Information</option>
              <option value="Verbose">Verbose</option>
            </select>
          </div>
          
          <div>
            <label className="text-sm font-medium mb-2 block">Event ID</label>
            <input
              type="text"
              placeholder="Filter by Event ID..."
              value={filterEventId}
              onChange={(e) => setFilterEventId(e.target.value)}
              className="w-full px-3 py-2 bg-card border border-border rounded text-sm"
            />
          </div>

          <div>
            <label className="text-sm font-medium mb-2 block">Provider</label>
            <input
              type="text"
              placeholder="Filter by Provider..."
              value={filterProvider}
              onChange={(e) => setFilterProvider(e.target.value)}
              className="w-full px-3 py-2 bg-card border border-border rounded text-sm"
            />
          </div>
        </div>

        <div className="mt-3 text-sm text-muted-foreground">
          Showing {paginatedEvents.length} of {filteredEvents.length} events
          {filteredEvents.length !== events.length && ` (filtered from ${events.length} total)`}
        </div>
      </Card>

      {/* Events List */}
      <div className="space-y-2">
        {paginatedEvents.map((event) => {
          const isExpanded = expandedEvents.has(event.recordId);
          
          return (
            <Card key={event.recordId} className={`overflow-hidden border-2 ${getRowBgColor(event.levelName)}`}>
              <div
                className="p-4 cursor-pointer hover:bg-muted/5 transition-colors"
                onClick={() => toggleEvent(event.recordId)}
              >
                <div className="flex items-start gap-3">
                  {isExpanded ? (
                    <ChevronDown className="w-5 h-5 text-muted-foreground flex-shrink-0 mt-0.5" />
                  ) : (
                    <ChevronRight className="w-5 h-5 text-muted-foreground flex-shrink-0 mt-0.5" />
                  )}

                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-3 flex-wrap mb-2">
                      {getLevelIcon(event.levelName)}
                      
                      <span className={`px-2 py-1 rounded text-xs font-medium border ${getLevelColor(event.levelName)}`}>
                        {event.levelName}
                      </span>

                      <span className="font-mono text-sm font-semibold text-accent">
                        Event ID: {event.eventId}
                      </span>

                      <span className="text-xs text-muted-foreground">
                        Record #{event.recordId}
                      </span>

                      <span className="text-xs text-muted-foreground">
                        {new Date(event.timestamp).toLocaleString()}
                      </span>
                    </div>

                    <div className="text-sm mb-1">
                      <span className="text-muted-foreground">Provider:</span>{' '}
                      <span className="font-medium">{event.provider}</span>
                    </div>

                    {event.computer && (
                      <div className="text-sm text-muted-foreground">
                        Computer: {event.computer}
                      </div>
                    )}
                  </div>
                </div>
              </div>

              {/* Expanded Details */}
              {isExpanded && (
                <div className="border-t border-border bg-muted/5 p-4 space-y-3">
                  {/* Event Data Fields */}
                  {event.data && Object.keys(event.data).length > 0 && (
                    <div>
                      <div className="text-sm font-semibold mb-2">Event Data:</div>
                      <div className="bg-card rounded border border-border p-3 space-y-1">
                        {Object.entries(event.data).map(([key, value]: [string, any]) => (
                          <div key={key} className="text-xs font-mono">
                            <span className="text-muted-foreground">{key}:</span>{' '}
                            <span className="text-foreground">{String(value)}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Additional Info */}
                  <div className="grid grid-cols-2 gap-3 text-xs">
                    {event.channel && (
                      <div>
                        <span className="text-muted-foreground">Channel:</span>{' '}
                        <span className="font-mono">{event.channel}</span>
                      </div>
                    )}
                    {event.userId && (
                      <div>
                        <span className="text-muted-foreground">User ID:</span>{' '}
                        <span className="font-mono">{event.userId}</span>
                      </div>
                    )}
                    {event.task !== undefined && (
                      <div>
                        <span className="text-muted-foreground">Task:</span>{' '}
                        <span className="font-mono">{event.task}</span>
                      </div>
                    )}
                    {event.keywords && (
                      <div>
                        <span className="text-muted-foreground">Keywords:</span>{' '}
                        <span className="font-mono">{event.keywords}</span>
                      </div>
                    )}
                  </div>

                  {/* Raw XML (collapsed by default) */}
                  {event.rawXml && (
                    <details className="text-xs">
                      <summary className="cursor-pointer text-muted-foreground hover:text-foreground">
                        View Raw XML
                      </summary>
                      <pre className="mt-2 bg-card p-2 rounded border border-border overflow-x-auto text-xs">
                        {event.rawXml}
                      </pre>
                    </details>
                  )}
                </div>
              )}
            </Card>
          );
        })}
      </div>

      {/* Pagination */}
      {totalPages > 1 && (
        <div className="flex items-center justify-center gap-2">
          <button
            onClick={() => setCurrentPage(p => Math.max(1, p - 1))}
            disabled={currentPage === 1}
            className="px-3 py-1 rounded border border-border disabled:opacity-50 disabled:cursor-not-allowed hover:bg-muted"
          >
            Previous
          </button>
          
          <span className="text-sm text-muted-foreground">
            Page {currentPage} of {totalPages}
          </span>
          
          <button
            onClick={() => setCurrentPage(p => Math.min(totalPages, p + 1))}
            disabled={currentPage === totalPages}
            className="px-3 py-1 rounded border border-border disabled:opacity-50 disabled:cursor-not-allowed hover:bg-muted"
          >
            Next
          </button>
        </div>
      )}
    </div>
  );
};
