import React, { useState } from 'react';
import { Globe, Database, Network, Download, ExternalLink, ChevronDown, ChevronRight } from 'lucide-react';
import { Button } from '../ui/button';

interface StreamsTabProps {
  httpSessions: any[];
  dnsQueries: any[];
  conversations: any[];
  onFollowStream: (stream: any) => void;
  onJumpToPacket: (frameNumber: number) => void;
}

export const StreamsTab: React.FC<StreamsTabProps> = ({
  httpSessions,
  dnsQueries,
  conversations,
  onFollowStream,
  onJumpToPacket
}) => {
  const [activeView, setActiveView] = useState<'http' | 'dns' | 'tcp'>('http');
  const [expandedHosts, setExpandedHosts] = useState<Set<string>>(new Set());
  const [searchTerm, setSearchTerm] = useState('');

  // Group HTTP by host
  const httpByHost = new Map<string, any[]>();
  httpSessions.forEach(session => {
    const host = session.host || session.destination || 'Unknown';
    if (!httpByHost.has(host)) httpByHost.set(host, []);
    httpByHost.get(host)!.push(session);
  });

  const toggleHost = (host: string) => {
    const newExpanded = new Set(expandedHosts);
    if (newExpanded.has(host)) {
      newExpanded.delete(host);
    } else {
      newExpanded.add(host);
    }
    setExpandedHosts(newExpanded);
  };

  const exportHttpAsCurl = (session: any) => {
    const curl = `curl -X ${session.method || 'GET'} '${session.fullUri || session.uri}' \\
  ${session.host ? `-H 'Host: ${session.host}' \\` : ''}
  ${session.userAgent ? `-H 'User-Agent: ${session.userAgent}' \\` : ''}
  ${session.cookie ? `-H 'Cookie: ${session.cookie}' \\` : ''}
  ${session.authorization ? `-H 'Authorization: ${session.authorization}' \\` : ''}`;

    navigator.clipboard.writeText(curl);
  };

  return (
    <div className="space-y-4 p-4">
      {/* View Selector */}
      <div className="flex gap-2 bg-muted/20 p-1 rounded-lg w-fit">
        <button
          onClick={() => setActiveView('http')}
          className={`px-4 py-2 rounded text-sm font-medium transition-colors ${
            activeView === 'http' ? 'bg-accent text-background' : 'hover:bg-muted'
          }`}
        >
          <Globe className="w-4 h-4 inline mr-2" />
          HTTP ({httpSessions.length})
        </button>
        <button
          onClick={() => setActiveView('dns')}
          className={`px-4 py-2 rounded text-sm font-medium transition-colors ${
            activeView === 'dns' ? 'bg-accent text-background' : 'hover:bg-muted'
          }`}
        >
          <Database className="w-4 h-4 inline mr-2" />
          DNS ({dnsQueries.length})
        </button>
        <button
          onClick={() => setActiveView('tcp')}
          className={`px-4 py-2 rounded text-sm font-medium transition-colors ${
            activeView === 'tcp' ? 'bg-accent text-background' : 'hover:bg-muted'
          }`}
        >
          <Network className="w-4 h-4 inline mr-2" />
          TCP Streams ({conversations.length})
        </button>
      </div>

      {/* Search */}
      <input
        type="text"
        placeholder={`Search ${activeView.toUpperCase()} sessions...`}
        value={searchTerm}
        onChange={(e) => setSearchTerm(e.target.value)}
        className="w-full px-3 py-2 bg-card border border-border rounded text-sm"
      />

      {/* HTTP View */}
      {activeView === 'http' && (
        <div className="space-y-3">
          {Array.from(httpByHost.entries())
            .filter(([host]) => !searchTerm || host.toLowerCase().includes(searchTerm.toLowerCase()))
            .map(([host, sessions]) => {
              const isExpanded = expandedHosts.has(host);

              return (
                <div key={host} className="bg-card border border-border rounded-lg overflow-hidden">
                  <div
                    className="px-4 py-3 bg-muted/20 cursor-pointer flex items-center justify-between"
                    onClick={() => toggleHost(host)}
                  >
                    <div className="flex items-center gap-2">
                      {isExpanded ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                      <Globe className="w-4 h-4 text-accent" />
                      <span className="font-semibold">{host}</span>
                      <span className="text-xs text-muted-foreground">({sessions.length} requests)</span>
                    </div>
                    <Button size="sm" variant="ghost" onClick={(e) => { e.stopPropagation(); }}>
                      Export All
                    </Button>
                  </div>

                  {isExpanded && (
                    <div className="p-4 space-y-3">
                      {sessions.map((session, idx) => (
                        <div key={idx} className="border border-border rounded-lg p-3 space-y-2">
                          <div className="flex items-start justify-between">
                            <div className="flex items-center gap-2">
                              <span className={`px-2 py-1 rounded text-xs font-mono ${
                                session.method === 'GET' ? 'bg-green-400/20 text-green-400' :
                                session.method === 'POST' ? 'bg-blue-400/20 text-blue-400' :
                                session.method === 'PUT' ? 'bg-yellow-400/20 text-yellow-400' :
                                'bg-purple-400/20 text-purple-400'
                              }`}>
                                {session.method || 'RESPONSE'}
                              </span>
                              <span className="font-mono text-sm">{session.uri || session.url}</span>
                              {session.statusCode && (
                                <span className={`px-2 py-1 rounded text-xs ${
                                  session.statusCode.startsWith('2') ? 'bg-green-400/20 text-green-400' :
                                  session.statusCode.startsWith('3') ? 'bg-blue-400/20 text-blue-400' :
                                  session.statusCode.startsWith('4') ? 'bg-yellow-400/20 text-yellow-400' :
                                  'bg-red-400/20 text-red-400'
                                }`}>
                                  {session.statusCode}
                                </span>
                              )}
                            </div>
                            <span className="text-xs text-muted-foreground">
                              Frame {session.frameNumber}
                            </span>
                          </div>

                          {/* HTTP Details */}
                          <div className="text-xs space-y-1 bg-muted/20 p-2 rounded font-mono">
                            {session.host && <div>Host: {session.host}</div>}
                            {session.userAgent && <div className="truncate">User-Agent: {session.userAgent}</div>}
                            {session.cookie && <div className="truncate">Cookie: {session.cookie}</div>}
                            {session.authorization && (
                              <div className="text-red-400">⚠️ Authorization: {session.authorization.substring(0, 50)}...</div>
                            )}
                            {session.contentType && <div>Content-Type: {session.contentType}</div>}
                            {session.contentLength && <div>Content-Length: {session.contentLength}</div>}
                          </div>

                          {/* Actions */}
                          <div className="flex gap-2">
                            <Button size="sm" variant="outline" onClick={() => onJumpToPacket(session.frameNumber)}>
                              Jump to Frame
                            </Button>
                            <Button size="sm" variant="outline" onClick={() => exportHttpAsCurl(session)}>
                              Copy as cURL
                            </Button>
                            {session.tcpStream !== undefined && (
                              <Button size="sm" variant="outline" onClick={() => onFollowStream({ tcpStream: session.tcpStream })}>
                                Follow Stream
                              </Button>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              );
            })}
        </div>
      )}

      {/* DNS View */}
      {activeView === 'dns' && (
        <div className="space-y-2">
          {dnsQueries
            .filter(dns => !searchTerm || dns.query?.toLowerCase().includes(searchTerm.toLowerCase()))
            .map((dns, idx) => (
              <div key={idx} className="bg-card border border-border rounded-lg p-3">
                <div className="flex items-start justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <Database className="w-4 h-4 text-yellow-400" />
                    <span className="font-mono text-sm font-semibold">{dns.query}</span>
                  </div>
                  <span className="text-xs text-muted-foreground">Frame {dns.frameNumber}</span>
                </div>

                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div>
                    <span className="text-muted-foreground">Source:</span>
                    <span className="ml-2 font-mono">{dns.source}</span>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Type:</span>
                    <span className="ml-2 font-mono">{dns.type || 'A'}</span>
                  </div>
                  {dns.answer && (
                    <div className="col-span-2">
                      <span className="text-muted-foreground">Answer:</span>
                      <span className="ml-2 font-mono text-accent">{dns.answer}</span>
                    </div>
                  )}
                  <div className="col-span-2">
                    <span className="text-muted-foreground">Time:</span>
                    <span className="ml-2 font-mono">{new Date(dns.timestamp).toLocaleString()}</span>
                  </div>
                </div>

                <div className="mt-2">
                  <Button size="sm" variant="outline" onClick={() => onJumpToPacket(dns.frameNumber)}>
                    Jump to Frame
                  </Button>
                </div>
              </div>
            ))}
        </div>
      )}

      {/* TCP Streams View */}
      {activeView === 'tcp' && (
        <div className="space-y-2">
          {conversations
            .filter(conv => !searchTerm || conv.source?.toLowerCase().includes(searchTerm.toLowerCase()) || conv.destination?.toLowerCase().includes(searchTerm.toLowerCase()))
            .map((conv, idx) => (
              <div key={idx} className="bg-card border border-border rounded-lg p-4">
                <div className="flex items-start justify-between mb-3">
                  <div>
                    <div className="flex items-center gap-2 mb-1">
                      <Network className="w-4 h-4 text-accent" />
                      <span className="font-mono text-sm font-semibold">
                        {conv.source}:{conv.srcPort || 0} ↔ {conv.destination}:{conv.destPort || 0}
                      </span>
                    </div>
                    <div className="text-xs text-muted-foreground">
                      Protocols: {conv.protocols.join(', ')}
                    </div>
                  </div>
                </div>

                <div className="grid grid-cols-3 gap-4 mb-3 text-sm">
                  <div>
                    <div className="text-muted-foreground text-xs">Packets</div>
                    <div className="font-mono font-semibold">{conv.packets}</div>
                  </div>
                  <div>
                    <div className="text-muted-foreground text-xs">Bytes</div>
                    <div className="font-mono font-semibold">{(conv.bytes / 1024).toFixed(1)} KB</div>
                  </div>
                  <div>
                    <div className="text-muted-foreground text-xs">Duration</div>
                    <div className="font-mono font-semibold">
                      {conv.duration ? `${(conv.duration / 1000).toFixed(2)}s` : 'N/A'}
                    </div>
                  </div>
                </div>

                <Button size="sm" className="w-full" onClick={() => onFollowStream(conv)}>
                  Follow TCP Stream
                </Button>
              </div>
            ))}
        </div>
      )}
    </div>
  );
};
