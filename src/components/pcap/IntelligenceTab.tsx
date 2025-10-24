import React, { useState } from 'react';
import { AlertTriangle, CheckCircle, Shield, TrendingUp, Users, Globe, Clock, Database, Copy, ExternalLink } from 'lucide-react';
import { Button } from '../ui/button';
import { Finding } from '../../lib/pcapIntelligence';

interface IntelligenceTabProps {
  findings: Finding[];
  packets: any[];
  httpSessions: any[];
  dnsQueries: any[];
  conversations: any[];
  stats: {
    totalPackets: number;
    timespan: string;
    protocols: any[];
    hosts: number;
    dataTransfer: number;
  };
  onJumpToPacket: (frameNumber: number) => void;
  onApplyFilter: (filter: string) => void;
}

export const IntelligenceTab: React.FC<IntelligenceTabProps> = ({
  findings,
  packets,
  httpSessions,
  dnsQueries,
  conversations,
  stats,
  onJumpToPacket,
  onApplyFilter
}) => {
  const [expandedFindings, setExpandedFindings] = useState<Set<string>>(new Set());

  const criticalFindings = findings.filter(f => f.severity === 'critical');
  const warningFindings = findings.filter(f => f.severity === 'warning');
  const infoFindings = findings.filter(f => f.severity === 'info');

  const toggleFinding = (id: string) => {
    const newExpanded = new Set(expandedFindings);
    if (newExpanded.has(id)) {
      newExpanded.delete(id);
    } else {
      newExpanded.add(id);
    }
    setExpandedFindings(newExpanded);
  };

  const getSeverityIcon = (severity: string) => {
    if (severity === 'critical') return <AlertTriangle className="w-5 h-5 text-red-400" />;
    if (severity === 'warning') return <Shield className="w-5 h-5 text-yellow-400" />;
    return <CheckCircle className="w-5 h-5 text-blue-400" />;
  };

  const getSeverityBg = (severity: string) => {
    if (severity === 'critical') return 'border-red-400/30 bg-red-400/5';
    if (severity === 'warning') return 'border-yellow-400/30 bg-yellow-400/5';
    return 'border-blue-400/30 bg-blue-400/5';
  };

  return (
    <div className="space-y-6 p-6">
      {/* Summary Stats */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <div className="bg-card border border-border rounded-lg p-4">
          <Database className="w-6 h-6 mb-2 text-accent" />
          <div className="text-2xl font-bold text-accent">{stats.totalPackets.toLocaleString()}</div>
          <div className="text-xs text-muted-foreground">Total Packets</div>
        </div>
        <div className="bg-card border border-border rounded-lg p-4">
          <Clock className="w-6 h-6 mb-2 text-blue-400" />
          <div className="text-2xl font-bold text-blue-400">{stats.timespan}</div>
          <div className="text-xs text-muted-foreground">Capture Duration</div>
        </div>
        <div className="bg-card border border-border rounded-lg p-4">
          <Globe className="w-6 h-6 mb-2 text-green-400" />
          <div className="text-2xl font-bold text-green-400">{stats.hosts}</div>
          <div className="text-xs text-muted-foreground">Unique Hosts</div>
        </div>
        <div className="bg-card border border-border rounded-lg p-4">
          <TrendingUp className="w-6 h-6 mb-2 text-purple-400" />
          <div className="text-2xl font-bold text-purple-400">{stats.protocols.length}</div>
          <div className="text-xs text-muted-foreground">Protocols</div>
        </div>
        <div className="bg-card border border-border rounded-lg p-4">
          <Database className="w-6 h-6 mb-2 text-cyan-400" />
          <div className="text-2xl font-bold text-cyan-400">{(stats.dataTransfer / 1024 / 1024).toFixed(1)} MB</div>
          <div className="text-xs text-muted-foreground">Total Data</div>
        </div>
      </div>

      {/* Top Protocols Quick View */}
      <div className="bg-card border border-border rounded-lg p-4">
        <h3 className="font-semibold mb-3">Protocol Distribution</h3>
        <div className="flex gap-2 flex-wrap">
          {stats.protocols.slice(0, 10).map((proto, idx) => (
            <button
              key={idx}
              onClick={() => onApplyFilter(`protocol == ${proto.name}`)}
              className="px-3 py-2 bg-muted/20 hover:bg-accent/20 border border-border rounded-lg text-sm"
            >
              <div className="font-mono font-semibold">{proto.name}</div>
              <div className="text-xs text-muted-foreground">{proto.count} packets ({proto.percentage}%)</div>
            </button>
          ))}
        </div>
      </div>

      {/* Critical Findings - SHOW ALL DATA */}
      {criticalFindings.length > 0 && (
        <div className="bg-card border border-red-400/30 rounded-lg overflow-hidden">
          <div className="bg-red-500/10 px-4 py-3 border-b border-red-500/30">
            <h3 className="font-semibold text-red-400 flex items-center gap-2">
              <AlertTriangle className="w-5 h-5" />
              CRITICAL FINDINGS ({criticalFindings.length})
            </h3>
          </div>
          <div className="p-4 space-y-4">
            {criticalFindings.map(finding => {
              const isExpanded = expandedFindings.has(finding.id);

              return (
                <div key={finding.id} className={`border rounded-lg overflow-hidden ${getSeverityBg(finding.severity)}`}>
                  <div
                    className="p-4 cursor-pointer hover:bg-muted/10"
                    onClick={() => toggleFinding(finding.id)}
                  >
                    <div className="flex items-start justify-between mb-2">
                      <div className="flex items-center gap-2 flex-1">
                        {getSeverityIcon(finding.severity)}
                        <div>
                          <div className="font-semibold">{finding.title}</div>
                          <div className="text-xs text-muted-foreground mt-1">{finding.description}</div>
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs px-2 py-1 bg-background/50 rounded">{finding.category}</span>
                        <span className="text-xs text-muted-foreground">{isExpanded ? 'Click to collapse' : 'Click to expand'}</span>
                      </div>
                    </div>

                    {/* Show preview of evidence even when collapsed */}
                    {!isExpanded && finding.evidence.length > 0 && (
                      <div className="mt-2">
                        <div className="text-xs font-mono bg-background/30 px-3 py-2 rounded border border-border/50">
                          {finding.evidence[0]}
                        </div>
                      </div>
                    )}
                  </div>

                  {/* Full Details When Expanded */}
                  {isExpanded && (
                    <div className="px-4 pb-4 space-y-3 border-t border-border/30">
                      {/* Auto-extracted value (decoded, etc) */}
                      {finding.autoExtracted && (
                        <div>
                          <div className="text-xs font-semibold text-accent mb-2 mt-3">EXTRACTED VALUE:</div>
                          <div className="bg-accent/10 border border-accent/30 rounded p-3">
                            <div className="font-mono text-sm break-all">{finding.autoExtracted}</div>
                          </div>
                          <Button
                            size="sm"
                            variant="outline"
                            className="mt-2"
                            onClick={() => navigator.clipboard.writeText(finding.autoExtracted!)}
                          >
                            <Copy className="w-3 h-3 mr-1" />
                            Copy Extracted Value
                          </Button>
                        </div>
                      )}

                      {/* All Evidence */}
                      <div>
                        <div className="text-xs font-semibold text-muted-foreground mb-2">EVIDENCE ({finding.evidence.length}):</div>
                        <div className="space-y-2">
                          {finding.evidence.map((ev, i) => (
                            <div key={i} className="bg-background/50 border border-border/50 rounded p-3">
                              <div className="font-mono text-xs break-all">{ev}</div>
                              <Button
                                size="sm"
                                variant="ghost"
                                className="mt-2"
                                onClick={() => navigator.clipboard.writeText(ev)}
                              >
                                <Copy className="w-3 h-3 mr-1" />
                                Copy
                              </Button>
                            </div>
                          ))}
                        </div>
                      </div>

                      {/* Related Frames */}
                      {finding.frames.length > 0 && (
                        <div>
                          <div className="text-xs font-semibold text-muted-foreground mb-2">RELATED FRAMES:</div>
                          <div className="flex gap-2 flex-wrap">
                            {finding.frames.slice(0, 10).map((frame, i) => (
                              <Button
                                key={i}
                                size="sm"
                                variant="outline"
                                onClick={() => onJumpToPacket(frame)}
                              >
                                Frame {frame}
                              </Button>
                            ))}
                            {finding.frames.length > 10 && (
                              <span className="text-xs text-muted-foreground self-center">
                                +{finding.frames.length - 10} more frames
                              </span>
                            )}
                          </div>
                        </div>
                      )}

                      {/* Actions */}
                      <div className="flex gap-2 pt-2 border-t border-border/30">
                        {finding.frames.length > 0 && (
                          <Button size="sm" onClick={() => onJumpToPacket(finding.frames[0])}>
                            Jump to Packets Tab
                          </Button>
                        )}
                        <Button size="sm" variant="outline" onClick={() => onApplyFilter(`frame.number == ${finding.frames[0]}`)}>
                          Apply Filter
                        </Button>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* Warnings - SHOW ALL DATA */}
      {warningFindings.length > 0 && (
        <div className="bg-card border border-yellow-400/30 rounded-lg overflow-hidden">
          <div className="bg-yellow-500/10 px-4 py-3 border-b border-yellow-500/30">
            <h3 className="font-semibold text-yellow-400 flex items-center gap-2">
              <Shield className="w-5 h-5" />
              WARNINGS ({warningFindings.length})
            </h3>
          </div>
          <div className="p-4 space-y-3 max-h-96 overflow-auto">
            {warningFindings.map(finding => {
              const isExpanded = expandedFindings.has(finding.id);

              return (
                <div key={finding.id} className={`border rounded-lg ${getSeverityBg(finding.severity)}`}>
                  <div
                    className="p-3 cursor-pointer hover:bg-muted/10"
                    onClick={() => toggleFinding(finding.id)}
                  >
                    <div className="flex items-start justify-between">
                      <div className="flex-1">
                        <div className="font-semibold text-sm">{finding.title}</div>
                        <div className="text-xs text-muted-foreground mt-1">{finding.description}</div>
                        <div className="text-xs font-mono bg-background/30 px-2 py-1 rounded mt-2 break-all">
                          {finding.evidence[0]}
                        </div>
                      </div>
                      <span className="text-xs px-2 py-1 bg-background/50 rounded ml-2">{finding.category}</span>
                    </div>
                  </div>

                  {isExpanded && finding.evidence.length > 1 && (
                    <div className="px-3 pb-3 space-y-2 border-t border-border/30">
                      {finding.evidence.slice(1).map((ev, i) => (
                        <div key={i} className="text-xs font-mono bg-background/30 px-2 py-1 rounded break-all mt-2">
                          {ev}
                        </div>
                      ))}
                      {finding.frames.length > 0 && (
                        <Button size="sm" variant="outline" onClick={() => onJumpToPacket(finding.frames[0])} className="mt-2">
                          Jump to Frame {finding.frames[0]}
                        </Button>
                      )}
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}

      {/* HTTP Sessions Overview - SHOW ACTUAL REQUESTS */}
      {httpSessions.length > 0 && (
        <div className="bg-card border border-border rounded-lg overflow-hidden">
          <div className="bg-muted/20 px-4 py-3 border-b border-border flex items-center justify-between">
            <h3 className="font-semibold">HTTP Traffic ({httpSessions.length} requests)</h3>
            <Button size="sm" variant="outline">
              View All in Streams Tab
            </Button>
          </div>
          <div className="p-4 space-y-2 max-h-64 overflow-auto">
            {httpSessions.slice(0, 10).map((session, idx) => (
              <div key={idx} className="border border-border rounded p-3 space-y-2">
                <div className="flex items-center gap-2">
                  <span className={`px-2 py-1 rounded text-xs font-mono font-semibold ${
                    session.method === 'GET' ? 'bg-green-400/20 text-green-400' :
                    session.method === 'POST' ? 'bg-blue-400/20 text-blue-400' :
                    'bg-purple-400/20 text-purple-400'
                  }`}>
                    {session.method || 'RESP'}
                  </span>
                  <span className="font-mono text-sm flex-1 truncate">{session.uri || session.url}</span>
                  {session.statusCode && (
                    <span className="px-2 py-1 rounded text-xs bg-muted">{session.statusCode}</span>
                  )}
                </div>

                {/* Show full details */}
                <div className="text-xs space-y-1 font-mono bg-muted/20 p-2 rounded">
                  {session.host && <div><span className="text-muted-foreground">Host:</span> {session.host}</div>}
                  {session.source && <div><span className="text-muted-foreground">From:</span> {session.source}</div>}
                  {session.destination && <div><span className="text-muted-foreground">To:</span> {session.destination}</div>}
                  {session.userAgent && <div className="truncate"><span className="text-muted-foreground">User-Agent:</span> {session.userAgent}</div>}
                  {session.cookie && (
                    <div className="break-all">
                      <span className="text-muted-foreground">Cookie:</span>
                      <div className="bg-yellow-400/10 px-2 py-1 rounded mt-1">{session.cookie}</div>
                    </div>
                  )}
                  {session.authorization && (
                    <div className="break-all">
                      <span className="text-red-400">Authorization (CLEARTEXT):</span>
                      <div className="bg-red-400/10 px-2 py-1 rounded mt-1">{session.authorization}</div>
                    </div>
                  )}
                </div>

                <div className="flex gap-2">
                  <Button size="sm" variant="outline" onClick={() => onJumpToPacket(session.frameNumber)}>
                    Frame {session.frameNumber}
                  </Button>
                  <Button
                    size="sm"
                    variant="outline"
                    onClick={() => {
                      const curl = `curl -X ${session.method || 'GET'} '${session.fullUri || session.uri}'`;
                      navigator.clipboard.writeText(curl);
                    }}
                  >
                    <Copy className="w-3 h-3 mr-1" />
                    Copy as cURL
                  </Button>
                </div>
              </div>
            ))}
            {httpSessions.length > 10 && (
              <div className="text-center text-sm text-muted-foreground pt-2">
                Showing 10 of {httpSessions.length} HTTP requests. View all in Streams tab.
              </div>
            )}
          </div>
        </div>
      )}

      {/* DNS Queries Overview - SHOW ACTUAL QUERIES */}
      {dnsQueries.length > 0 && (
        <div className="bg-card border border-border rounded-lg overflow-hidden">
          <div className="bg-muted/20 px-4 py-3 border-b border-border">
            <h3 className="font-semibold">DNS Queries ({dnsQueries.length} lookups)</h3>
          </div>
          <div className="p-4 space-y-2 max-h-64 overflow-auto">
            {dnsQueries.slice(0, 15).map((dns, idx) => (
              <div key={idx} className="flex items-center justify-between p-2 bg-muted/20 rounded">
                <div className="flex-1">
                  <div className="font-mono text-sm font-semibold">{dns.query}</div>
                  {dns.answer && (
                    <div className="font-mono text-xs text-accent mt-1">→ {dns.answer}</div>
                  )}
                  <div className="text-xs text-muted-foreground mt-1">
                    From: {dns.source} | Type: {dns.type || 'A'}
                  </div>
                </div>
                <Button size="sm" variant="outline" onClick={() => onJumpToPacket(dns.frameNumber)}>
                  Frame {dns.frameNumber}
                </Button>
              </div>
            ))}
            {dnsQueries.length > 15 && (
              <div className="text-center text-sm text-muted-foreground pt-2">
                Showing 15 of {dnsQueries.length} DNS queries. View all in Streams tab.
              </div>
            )}
          </div>
        </div>
      )}

      {/* Top Conversations - SHOW ACTUAL DATA */}
      {conversations.length > 0 && (
        <div className="bg-card border border-border rounded-lg overflow-hidden">
          <div className="bg-muted/20 px-4 py-3 border-b border-border">
            <h3 className="font-semibold">Top Conversations ({conversations.length} total)</h3>
          </div>
          <div className="p-4 space-y-2 max-h-64 overflow-auto">
            {conversations
              .sort((a, b) => b.packets - a.packets)
              .slice(0, 10)
              .map((conv, idx) => (
                <div key={idx} className="border border-border rounded p-3">
                  <div className="font-mono text-sm font-semibold mb-2">
                    {conv.source}:{conv.srcPort || 0} ↔ {conv.destination}:{conv.destPort || 0}
                  </div>
                  <div className="grid grid-cols-3 gap-3 text-xs">
                    <div>
                      <span className="text-muted-foreground">Packets:</span>
                      <div className="font-mono font-semibold">{conv.packets}</div>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Bytes:</span>
                      <div className="font-mono font-semibold">{(conv.bytes / 1024).toFixed(1)} KB</div>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Protocols:</span>
                      <div className="font-mono text-xs">{conv.protocols.join(', ')}</div>
                    </div>
                  </div>
                </div>
              ))}
          </div>
        </div>
      )}

      {/* Pattern Findings */}
      {infoFindings.length > 0 && (
        <div className="bg-card border border-border rounded-lg overflow-hidden">
          <div className="bg-blue-500/10 px-4 py-3 border-b border-blue-500/30">
            <h3 className="font-semibold text-blue-400 flex items-center gap-2">
              <TrendingUp className="w-5 h-5" />
              PATTERNS DETECTED ({infoFindings.length})
            </h3>
          </div>
          <div className="p-4 space-y-2 max-h-64 overflow-auto">
            {infoFindings.map(finding => (
              <div key={finding.id} className="flex items-center justify-between p-3 bg-muted/10 border border-border rounded">
                <div className="flex-1">
                  <div className="font-medium text-sm">{finding.title}</div>
                  <div className="text-xs text-muted-foreground mt-1">{finding.description}</div>
                  <div className="text-xs font-mono mt-2">{finding.evidence[0]}</div>
                </div>
                {finding.frames.length > 0 && (
                  <Button size="sm" variant="ghost" onClick={() => onJumpToPacket(finding.frames[0])}>
                    View
                  </Button>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* No Findings */}
      {findings.length === 0 && (
        <div className="bg-card border border-border rounded-lg p-8 text-center">
          <CheckCircle className="w-12 h-12 mx-auto mb-4 text-green-400" />
          <h3 className="text-lg font-semibold text-green-400 mb-2">No Issues Detected</h3>
          <p className="text-sm text-muted-foreground">
            No flags, credentials, or security issues found. Traffic appears normal.
          </p>
          <p className="text-sm text-muted-foreground mt-2">
            Use Packets, Streams, or Explorer tabs for detailed analysis.
          </p>
        </div>
      )}
    </div>
  );
};
