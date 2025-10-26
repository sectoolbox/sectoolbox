import React, { useState } from 'react';
import { Search, Zap, Filter, Download } from 'lucide-react';
import { Button } from '../ui/button';

interface ExplorerTabProps {
  packets: any[];
  onJumpToPacket: (frameNumber: number) => void;
  onApplyFilter: (filter: string) => void;
}

export const ExplorerTab: React.FC<ExplorerTabProps> = ({
  packets,
  onJumpToPacket,
  onApplyFilter
}) => {
  const [searchMode, setSearchMode] = useState<'simple' | 'advanced' | 'regex'>('simple');
  const [searchTerm, setSearchTerm] = useState('');
  const [searchField, setSearchField] = useState('all');
  const [searchResults, setSearchResults] = useState<any[]>([]);

  // Advanced filter builder
  const [filterConditions, setFilterConditions] = useState<Array<{
    field: string;
    operator: string;
    value: string;
    logic: 'AND' | 'OR';
  }>>([{ field: 'protocol', operator: 'equals', value: '', logic: 'AND' }]);

  const performSearch = () => {
    if (!searchTerm) {
      setSearchResults([]);
      return;
    }

    const results: any[] = [];

    if (searchMode === 'simple') {
      // Search across relevant fields only
      packets.forEach(pkt => {
        const matchedFields = findMatchedFields(pkt, searchTerm, searchField);
        if (matchedFields.length > 0) {
          results.push({
            packet: pkt,
            matchedIn: matchedFields
          });
        }
      });
    } else if (searchMode === 'regex') {
      // Regex search - only search in actual packet content (payload, info, visible fields)
      try {
        const regex = new RegExp(searchTerm, 'gi');
        packets.forEach(pkt => {
          const matchedFields: string[] = [];
          
          // Search in visible/important fields only, not entire JSON
          if (pkt.info && regex.test(pkt.info)) matchedFields.push('info');
          if (pkt.payload && regex.test(pkt.payload)) matchedFields.push('payload');
          if (pkt.source && regex.test(pkt.source)) matchedFields.push('source');
          if (pkt.destination && regex.test(pkt.destination)) matchedFields.push('destination');
          if (pkt.protocol && regex.test(pkt.protocol)) matchedFields.push('protocol');
          
          // Search in layers data if available
          if (pkt.layers) {
            const layersStr = JSON.stringify(pkt.layers);
            if (regex.test(layersStr)) matchedFields.push('layers');
          }
          
          if (matchedFields.length > 0) {
            results.push({
              packet: pkt,
              matchedIn: matchedFields
            });
          }
        });
      } catch (e) {
        // Invalid regex
      }
    }

    setSearchResults(results);
  };

  const applyAdvancedFilter = () => {
    const filterParts: string[] = [];

    filterConditions.forEach((cond, idx) => {
      let part = '';
      if (idx > 0) part += ' ' + cond.logic + ' ';

      if (cond.operator === 'equals') {
        part += cond.field + ' == ' + cond.value;
      } else if (cond.operator === 'contains') {
        part += cond.field + ' contains ' + cond.value;
      } else if (cond.operator === 'gt') {
        part += cond.field + ' > ' + cond.value;
      } else if (cond.operator === 'lt') {
        part += cond.field + ' < ' + cond.value;
      }

      filterParts.push(part);
    });

    const filterString = filterParts.join('');
    onApplyFilter(filterString);
  };

  const addFilterCondition = () => {
    setFilterConditions([...filterConditions, { field: 'protocol', operator: 'equals', value: '', logic: 'AND' }]);
  };

  const updateFilterCondition = (index: number, field: string, value: any) => {
    const newConditions = [...filterConditions];
    newConditions[index] = { ...newConditions[index], [field]: value };
    setFilterConditions(newConditions);
  };

  const removeFilterCondition = (index: number) => {
    setFilterConditions(filterConditions.filter((_, i) => i !== index));
  };

  // Quick search presets
  const quickSearches = [
    { label: 'Find Flags', search: 'CTF\\{|flag\\{|FLAG\\{', mode: 'regex' as const },
    { label: 'Find Credentials', search: 'password|username|auth|token', mode: 'regex' as const },
    { label: 'Find Base64', search: '[A-Za-z0-9+/]{20,}={0,2}', mode: 'regex' as const },
    { label: 'Find IPs', search: '\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}', mode: 'regex' as const },
    { label: 'Find URLs', search: 'http', mode: 'simple' as const },
    { label: 'Find Secrets', search: 'secret|key|api|token', mode: 'regex' as const }
  ];

  const runQuickSearch = (search: string, mode: 'simple' | 'regex') => {
    setSearchTerm(search);
    setSearchMode(mode);
    setTimeout(() => performSearch(), 100);
  };

  return (
    <div className="space-y-6 p-4">
      {/* Search Mode Selector */}
      <div className="flex gap-2 bg-muted/20 p-1 rounded-lg w-fit">
        <button
          onClick={() => setSearchMode('simple')}
          className={'px-4 py-2 rounded text-sm font-medium ' + (searchMode === 'simple' ? 'bg-accent text-background' : 'hover:bg-muted')}
        >
          Simple Search
        </button>
        <button
          onClick={() => setSearchMode('advanced')}
          className={'px-4 py-2 rounded text-sm font-medium ' + (searchMode === 'advanced' ? 'bg-accent text-background' : 'hover:bg-muted')}
        >
          Advanced Filter
        </button>
        <button
          onClick={() => setSearchMode('regex')}
          className={'px-4 py-2 rounded text-sm font-medium ' + (searchMode === 'regex' ? 'bg-accent text-background' : 'hover:bg-muted')}
        >
          Regex Search
        </button>
      </div>

      {/* Simple/Regex Search */}
      {(searchMode === 'simple' || searchMode === 'regex') && (
        <div className="space-y-4">
          <div className="flex gap-2">
            {searchMode === 'simple' && (
              <select
                value={searchField}
                onChange={(e) => setSearchField(e.target.value)}
                className="px-3 py-2 bg-card border border-border rounded text-sm"
              >
                <option value="all">All Fields</option>
                <option value="source">Source IP</option>
                <option value="destination">Destination IP</option>
                <option value="protocol">Protocol</option>
                <option value="info">Info</option>
                <option value="payload">Payload</option>
              </select>
            )}
            <input
              type="text"
              placeholder={searchMode === 'regex' ? 'Enter regex pattern...' : 'Enter search term...'}
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && performSearch()}
              className="flex-1 px-3 py-2 bg-card border border-border rounded text-sm"
            />
            <Button onClick={performSearch}>
              <Search className="w-4 h-4 mr-2" />
              Search
            </Button>
          </div>

          {/* Quick Search Buttons */}
          <div>
            <div className="text-sm font-medium mb-2 text-muted-foreground">Quick Searches:</div>
            <div className="flex gap-2 flex-wrap">
              {quickSearches.map((qs, idx) => (
                <Button
                  key={idx}
                  size="sm"
                  variant="outline"
                  onClick={() => runQuickSearch(qs.search, qs.mode)}
                >
                  <Zap className="w-3 h-3 mr-1" />
                  {qs.label}
                </Button>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Advanced Filter Builder */}
      {searchMode === 'advanced' && (
        <div className="space-y-4">
          <div className="bg-card border border-border rounded-lg p-4 space-y-3">
            <div className="font-semibold mb-2">Filter Builder</div>
            {filterConditions.map((condition, idx) => (
              <div key={idx} className="flex gap-2 items-center">
                {idx > 0 && (
                  <select
                    value={condition.logic}
                    onChange={(e) => updateFilterCondition(idx, 'logic', e.target.value)}
                    className="px-2 py-1 bg-background border border-border rounded text-sm"
                  >
                    <option value="AND">AND</option>
                    <option value="OR">OR</option>
                  </select>
                )}
                <select
                  value={condition.field}
                  onChange={(e) => updateFilterCondition(idx, 'field', e.target.value)}
                  className="px-3 py-2 bg-background border border-border rounded text-sm flex-1"
                >
                  <option value="protocol">Protocol</option>
                  <option value="ip.src">Source IP</option>
                  <option value="ip.dst">Destination IP</option>
                  <option value="tcp.port">TCP Port</option>
                  <option value="udp.port">UDP Port</option>
                  <option value="http.host">HTTP Host</option>
                  <option value="dns.qry.name">DNS Query</option>
                  <option value="frame.len">Packet Length</option>
                </select>
                <select
                  value={condition.operator}
                  onChange={(e) => updateFilterCondition(idx, 'operator', e.target.value)}
                  className="px-3 py-2 bg-background border border-border rounded text-sm"
                >
                  <option value="equals">equals</option>
                  <option value="contains">contains</option>
                  <option value="gt">greater than</option>
                  <option value="lt">less than</option>
                </select>
                <input
                  type="text"
                  value={condition.value}
                  onChange={(e) => updateFilterCondition(idx, 'value', e.target.value)}
                  placeholder="value"
                  className="px-3 py-2 bg-background border border-border rounded text-sm flex-1"
                />
                {filterConditions.length > 1 && (
                  <Button size="sm" variant="destructive" onClick={() => removeFilterCondition(idx)}>
                    ✕
                  </Button>
                )}
              </div>
            ))}

            <div className="flex gap-2">
              <Button size="sm" variant="outline" onClick={addFilterCondition}>
                + Add Condition
              </Button>
              <Button size="sm" onClick={applyAdvancedFilter}>
                <Filter className="w-4 h-4 mr-2" />
                Apply Filter
              </Button>
              <Button size="sm" variant="outline" onClick={() => setFilterConditions([{ field: 'protocol', operator: 'equals', value: '', logic: 'AND' }])}>
                Clear
              </Button>
            </div>
          </div>
        </div>
      )}

      {/* Search Results */}
      {searchResults.length > 0 && (
        <div className="bg-card border border-border rounded-lg overflow-hidden">
          <div className="bg-muted/50 px-4 py-3 border-b flex items-center justify-between">
            <h3 className="font-semibold">Search Results ({searchResults.length})</h3>
            <Button size="sm" variant="outline">
              <Download className="w-3 h-3 mr-1" />
              Export Results
            </Button>
          </div>
          <div className="max-h-96 overflow-auto">
            {searchResults.map((result, idx) => {
              // Get the actual matched content to display
              const getMatchedContent = () => {
                for (const field of result.matchedIn) {
                  const content = result.packet[field];
                  if (content) return { field, content: String(content) };
                }
                return { field: 'info', content: result.packet.info || 'No content' };
              };
              
              const { field, content } = getMatchedContent();
              
              return (
                <div key={idx} className="border-b last:border-b-0 p-3 hover:bg-muted/10">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-accent">Frame {result.packet.index}</span>
                      <span className="text-xs px-2 py-1 bg-accent/20 rounded">{result.packet.protocol}</span>
                      <span className="text-xs text-muted-foreground">
                        {result.packet.source} → {result.packet.destination}
                      </span>
                    </div>
                    <Button size="sm" variant="outline" onClick={() => onJumpToPacket(result.packet.index)}>
                      Jump
                    </Button>
                  </div>
                  <div className="text-xs text-muted-foreground mb-1">
                    Matched in: {result.matchedIn.join(', ')}
                  </div>
                  <div className="text-xs font-mono bg-muted/20 p-2 rounded">
                    <div className="text-muted-foreground mb-1">{field}:</div>
                    <div className="line-clamp-2 break-all">{content}</div>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {searchResults.length === 0 && searchTerm && (
        <div className="bg-card border border-border rounded-lg p-8 text-center">
          <Search className="w-12 h-12 mx-auto mb-4 text-muted-foreground opacity-50" />
          <p className="text-muted-foreground">No packets match your search criteria</p>
        </div>
      )}
    </div>
  );
};

function findMatchedFields(packet: any, searchTerm: string, searchField?: string): string[] {
  const matched: string[] = [];
  const term = searchTerm.toLowerCase();

  // If specific field selected, only search that field
  if (searchField && searchField !== 'all') {
    const value = packet[searchField];
    if (value && String(value).toLowerCase().includes(term)) {
      matched.push(searchField);
    }
    return matched.length > 0 ? matched : [];
  }

  // Otherwise search all relevant fields
  const fieldsToSearch = ['source', 'destination', 'protocol', 'info', 'payload'];
  fieldsToSearch.forEach(field => {
    const value = packet[field];
    if (value && String(value).toLowerCase().includes(term)) {
      matched.push(field);
    }
  });

  return matched.length > 0 ? matched : [];
}
