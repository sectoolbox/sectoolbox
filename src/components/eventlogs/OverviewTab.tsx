import React, { useState } from 'react';
import { Activity, AlertTriangle, Shield, Users, Server, Hash, ChevronDown, ChevronRight, Eye, FileSearch, Flag, Copy, ExternalLink, Target } from 'lucide-react';
import { Card } from '../ui/card';
import { Button } from '../ui/button';
import { Badge } from '../ui/badge';
import { toast } from 'react-hot-toast';
import { getTechniquesForEvent, getTacticColor } from '@/lib/mitreAttack';
import { tryAllDecodings } from '@/lib/decoders';
import { AnomalyDetection } from './AnomalyDetection';
import { EventCorrelationView } from './EventCorrelationView';

interface OverviewTabProps {
  analysis: {
    topEventIds?: Array<{ eventId: number; count: number }>;
    levelDistribution?: Record<string, number>;
    topProviders?: Array<{ provider: string; count: number }>;
    topComputers?: Array<{ computer: string; count: number }>;
    topUsers?: Array<{ user: string; count: number }>;
    timeline?: Array<{ date: string; count: number }>;
  };
  iocs?: {
    ips?: string[];
    domains?: string[];
    users?: string[];
    processes?: string[];
    files?: string[];
    hashes?: string[];
  };
  threats?: Array<{
    type: string;
    severity: string;
    description: string;
    eventId: number;
    timestamp: string;
    recordId?: number;
    details?: any;
  }>;
  flags?: Array<{
    type: string;
    pattern: string;
    value: string;
    decoded?: string;
    field: string;
    eventId: number;
    timestamp: string;
    context?: string;
  }>;
  events?: any[];
  metadata?: any;
}

export const OverviewTab: React.FC<OverviewTabProps> = ({ analysis, iocs, threats, flags, events, metadata }) => {
  const [expandedThreats, setExpandedThreats] = useState<Set<number>>(new Set());
  const [expandedIOCs, setExpandedIOCs] = useState<Set<string>>(new Set());
  const [expandedFlags, setExpandedFlags] = useState<Set<number>>(new Set());

  const toggleThreat = (index: number) => {
    const newExpanded = new Set(expandedThreats);
    if (newExpanded.has(index)) {
      newExpanded.delete(index);
    } else {
      newExpanded.add(index);
    }
    setExpandedThreats(newExpanded);
  };

  const toggleIOC = (category: string) => {
    const newExpanded = new Set(expandedIOCs);
    if (newExpanded.has(category)) {
      newExpanded.delete(category);
    } else {
      newExpanded.add(category);
    }
    setExpandedIOCs(newExpanded);
  };

  const findEventByIdAndTime = (eventId: number, timestamp: string) => {
    if (!events) return null;
    return events.find(e => 
      e.eventId === eventId && 
      new Date(e.timestamp).getTime() === new Date(timestamp).getTime()
    );
  };
  const getSeverityColor = (severity: string) => {
    switch (severity.toLowerCase()) {
      case 'critical':
        return 'bg-red-500/20 text-red-400 border-red-500/50';
      case 'high':
        return 'bg-orange-500/20 text-orange-400 border-orange-500/50';
      case 'medium':
        return 'bg-yellow-500/20 text-yellow-400 border-yellow-500/50';
      case 'low':
        return 'bg-blue-500/20 text-blue-400 border-blue-500/50';
      default:
        return 'bg-muted/20 text-muted-foreground border-muted';
    }
  };

  const getLevelColor = (level: string) => {
    switch (level) {
      case 'Critical':
        return 'bg-red-500';
      case 'Error':
        return 'bg-red-400';
      case 'Warning':
        return 'bg-yellow-500';
      case 'Information':
        return 'bg-blue-500';
      default:
        return 'bg-muted';
    }
  };

  return (
    <div className="space-y-6">
      {/* Overview Summary Cards */}
      {metadata && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Card className="p-4">
            <div className="text-sm text-muted-foreground mb-1">Total Events</div>
            <div className="text-2xl font-bold text-accent">{metadata.totalEvents?.toLocaleString()}</div>
          </Card>
          <Card className="p-4">
            <div className="text-sm text-muted-foreground mb-1">Threats Detected</div>
            <div className="text-2xl font-bold text-red-400">{threats?.length || 0}</div>
          </Card>
          <Card className="p-4">
            <div className="text-sm text-muted-foreground mb-1">IOCs Found</div>
            <div className="text-2xl font-bold text-yellow-400">
              {(iocs?.ips?.length || 0) + (iocs?.domains?.length || 0) + (iocs?.users?.length || 0)}
            </div>
          </Card>
          <Card className="p-4">
            <div className="text-sm text-muted-foreground mb-1">File Size</div>
            <div className="text-2xl font-bold">{((metadata.filesize || 0) / 1024 / 1024).toFixed(1)} MB</div>
          </Card>
        </div>
      )}

      {/* Threats Section */}
      {threats && threats.length > 0 && (
        <Card className="p-4">
          <div className="flex items-center gap-2 mb-4">
            <AlertTriangle className="w-5 h-5 text-red-400" />
            <h3 className="text-lg font-semibold">Detected Threats</h3>
            <span className="ml-auto px-2 py-1 bg-red-500/20 text-red-400 rounded text-sm font-medium">
              {threats.length} found
            </span>
          </div>
          
          <div className="space-y-3">
            {threats.map((threat, idx) => {
              const isExpanded = expandedThreats.has(idx);
              const relatedEvent = findEventByIdAndTime(threat.eventId, threat.timestamp);
              const mitreTechniques = getTechniquesForEvent(threat.eventId);
              
              return (
                <div key={idx} className="border border-border rounded overflow-hidden">
                  <div 
                    className="p-3 bg-muted/5 cursor-pointer hover:bg-muted/10 transition-colors"
                    onClick={() => toggleThreat(idx)}
                  >
                    <div className="flex items-start gap-3">
                      <div className="mt-0.5">
                        {isExpanded ? (
                          <ChevronDown className="w-5 h-5 text-muted-foreground" />
                        ) : (
                          <ChevronRight className="w-5 h-5 text-muted-foreground" />
                        )}
                      </div>
                      <Shield className="w-4 h-4 text-muted-foreground mt-0.5" />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1 flex-wrap">
                          <span className="font-medium">{threat.type}</span>
                          <span className={`px-2 py-0.5 rounded text-xs font-medium border ${getSeverityColor(threat.severity)}`}>
                            {threat.severity}
                          </span>
                          <span className="text-xs text-muted-foreground ml-auto">
                            Event ID: {threat.eventId}
                          </span>
                        </div>
                        <p className="text-sm text-muted-foreground mb-1">{threat.description}</p>
                        
                        {/* MITRE ATT&CK Techniques */}
                        {mitreTechniques.length > 0 && (
                          <div className="flex flex-wrap gap-1 mt-2">
                            {mitreTechniques.map((tech, techIdx) => (
                              <a
                                key={techIdx}
                                href={`https://attack.mitre.org/techniques/${tech.id}/`}
                                target="_blank"
                                rel="noopener noreferrer"
                                className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium hover:opacity-80 transition-opacity"
                                style={{ 
                                  backgroundColor: getTacticColor(tech.tactic) + '33',
                                  borderColor: getTacticColor(tech.tactic),
                                  color: getTacticColor(tech.tactic),
                                  borderWidth: '1px'
                                }}
                                onClick={(e) => e.stopPropagation()}
                              >
                                <Target className="w-3 h-3" />
                                {tech.id} {tech.name}
                                <ExternalLink className="w-3 h-3" />
                              </a>
                            ))}
                          </div>
                        )}
                        
                        {/* Show threat details if available */}
                        {threat.details && (
                          <p className="text-sm font-mono bg-muted/30 px-2 py-1 rounded mt-1">
                            {threat.details}
                          </p>
                        )}
                        <p className="text-xs text-muted-foreground mt-1">
                          {new Date(threat.timestamp).toLocaleString()}
                        </p>
                      </div>
                    </div>
                  </div>

                  {/* Expanded Threat Details */}
                  {isExpanded && relatedEvent && (
                    <div className="border-t border-border bg-muted/5 p-4 space-y-3">
                      <div>
                        <div className="text-sm font-semibold mb-2 flex items-center gap-2">
                          <Eye className="w-4 h-4" />
                          Related Event Details
                        </div>
                        
                        <div className="grid grid-cols-2 gap-3 mb-3">
                          <div className="text-xs">
                            <span className="text-muted-foreground">Provider:</span>{' '}
                            <span className="font-mono">{relatedEvent.provider}</span>
                          </div>
                          <div className="text-xs">
                            <span className="text-muted-foreground">Computer:</span>{' '}
                            <span className="font-mono">{relatedEvent.computer}</span>
                          </div>
                          <div className="text-xs">
                            <span className="text-muted-foreground">Record ID:</span>{' '}
                            <span className="font-mono">#{relatedEvent.recordId}</span>
                          </div>
                          <div className="text-xs">
                            <span className="text-muted-foreground">Level:</span>{' '}
                            <span className="font-mono">{relatedEvent.levelName}</span>
                          </div>
                        </div>

                        {relatedEvent.data && Object.keys(relatedEvent.data).length > 0 && (
                          <div>
                            <div className="text-xs font-semibold mb-2 flex items-center gap-2">
                              <FileSearch className="w-3 h-3" />
                              Event Data
                            </div>
                            <div className="bg-card rounded border border-border p-3 space-y-1 max-h-48 overflow-y-auto">
                              {Object.entries(relatedEvent.data).map(([key, value]: [string, any]) => (
                                <div key={key} className="text-xs font-mono">
                                  <span className="text-muted-foreground">{key}:</span>{' '}
                                  <span className="text-foreground break-all">{String(value)}</span>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>

                      <div className="pt-2 border-t border-border">
                        <Button 
                          size="sm" 
                          variant="outline"
                          onClick={(e) => {
                            e.stopPropagation();
                            // Could add functionality to jump to event in Events tab
                          }}
                        >
                          View Full Event
                        </Button>
                      </div>
                    </div>
                  )}

                  {isExpanded && !relatedEvent && (
                    <div className="border-t border-border bg-muted/5 p-4">
                      <p className="text-xs text-muted-foreground">
                        Related event data not available
                      </p>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </Card>
      )}

      {/* IOCs Section */}
      {iocs && (
        <Card className="p-4">
          <div className="flex items-center gap-2 mb-4">
            <Hash className="w-5 h-5 text-accent" />
            <h3 className="text-lg font-semibold">Indicators of Compromise (IOCs)</h3>
            <span className="ml-auto text-sm text-muted-foreground">
              {(iocs.ips?.length || 0) + (iocs.domains?.length || 0) + (iocs.users?.length || 0) + (iocs.processes?.length || 0) + (iocs.files?.length || 0) + (iocs.hashes?.length || 0)} total
            </span>
          </div>

          <div className="space-y-3">
            {/* IP Addresses */}
            {iocs.ips && iocs.ips.length > 0 && (
              <div className="border border-border rounded overflow-hidden">
                <div 
                  className="flex items-center justify-between p-3 bg-muted/5 cursor-pointer hover:bg-muted/10 transition-colors"
                  onClick={() => toggleIOC('ips')}
                >
                  <div className="flex items-center gap-2">
                    {expandedIOCs.has('ips') ? (
                      <ChevronDown className="w-4 h-4 text-muted-foreground" />
                    ) : (
                      <ChevronRight className="w-4 h-4 text-muted-foreground" />
                    )}
                    <span className="text-sm font-semibold">IP Addresses</span>
                  </div>
                  <span className="text-xs px-2 py-1 bg-blue-500/20 text-blue-400 rounded font-medium">
                    {iocs.ips.length}
                  </span>
                </div>
                {expandedIOCs.has('ips') && (
                  <div className="border-t border-border p-3 bg-muted/5">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs text-muted-foreground">Click any IP to copy</span>
                      <Button
                        size="sm"
                        variant="outline"
                        className="h-7 text-xs"
                        onClick={(e) => {
                          e.stopPropagation();
                          navigator.clipboard.writeText(iocs.ips!.join('\n'));
                          toast.success(`Copied ${iocs.ips!.length} IPs to clipboard`);
                        }}
                      >
                        <Copy className="w-3 h-3 mr-1" />
                        Copy All
                      </Button>
                    </div>
                    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-2">
                      {iocs.ips.map((ip, idx) => (
                        <div 
                          key={idx} 
                          className="text-xs font-mono bg-card px-2 py-1 rounded border border-border hover:bg-muted/50 transition-colors cursor-pointer"
                          onClick={(e) => {
                            e.stopPropagation();
                            navigator.clipboard.writeText(ip);
                            toast.success('IP copied');
                          }}
                        >
                          {ip}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Domains */}
            {iocs.domains && iocs.domains.length > 0 && (
              <div className="border border-border rounded overflow-hidden">
                <div 
                  className="flex items-center justify-between p-3 bg-muted/5 cursor-pointer hover:bg-muted/10 transition-colors"
                  onClick={() => toggleIOC('domains')}
                >
                  <div className="flex items-center gap-2">
                    {expandedIOCs.has('domains') ? (
                      <ChevronDown className="w-4 h-4 text-muted-foreground" />
                    ) : (
                      <ChevronRight className="w-4 h-4 text-muted-foreground" />
                    )}
                    <span className="text-sm font-semibold">Domains</span>
                  </div>
                  <span className="text-xs px-2 py-1 bg-purple-500/20 text-purple-400 rounded font-medium">
                    {iocs.domains.length}
                  </span>
                </div>
                {expandedIOCs.has('domains') && (
                  <div className="border-t border-border p-3 bg-muted/5">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs text-muted-foreground">Click any domain to copy</span>
                      <Button
                        size="sm"
                        variant="outline"
                        className="h-7 text-xs"
                        onClick={(e) => {
                          e.stopPropagation();
                          navigator.clipboard.writeText(iocs.domains!.join('\n'));
                          toast.success(`Copied ${iocs.domains!.length} domains to clipboard`);
                        }}
                      >
                        <Copy className="w-3 h-3 mr-1" />
                        Copy All
                      </Button>
                    </div>
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
                      {iocs.domains.map((domain, idx) => (
                        <div 
                          key={idx} 
                          className="text-xs font-mono bg-card px-2 py-1 rounded border border-border hover:bg-muted/50 transition-colors break-all cursor-pointer"
                          onClick={(e) => {
                            e.stopPropagation();
                            navigator.clipboard.writeText(domain);
                            toast.success('Domain copied');
                          }}
                        >
                          {domain}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Users */}
            {iocs.users && iocs.users.length > 0 && (
              <div className="border border-border rounded overflow-hidden">
                <div 
                  className="flex items-center justify-between p-3 bg-muted/5 cursor-pointer hover:bg-muted/10 transition-colors"
                  onClick={() => toggleIOC('users')}
                >
                  <div className="flex items-center gap-2">
                    {expandedIOCs.has('users') ? (
                      <ChevronDown className="w-4 h-4 text-muted-foreground" />
                    ) : (
                      <ChevronRight className="w-4 h-4 text-muted-foreground" />
                    )}
                    <span className="text-sm font-semibold">Users</span>
                  </div>
                  <span className="text-xs px-2 py-1 bg-green-500/20 text-green-400 rounded font-medium">
                    {iocs.users.length}
                  </span>
                </div>
                {expandedIOCs.has('users') && (
                  <div className="border-t border-border p-3 bg-muted/5">
                    <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                      {iocs.users.map((user, idx) => (
                        <div key={idx} className="text-xs font-mono bg-card px-2 py-1 rounded border border-border hover:bg-muted/50 transition-colors">
                          {user}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Processes */}
            {iocs.processes && iocs.processes.length > 0 && (
              <div className="border border-border rounded overflow-hidden">
                <div 
                  className="flex items-center justify-between p-3 bg-muted/5 cursor-pointer hover:bg-muted/10 transition-colors"
                  onClick={() => toggleIOC('processes')}
                >
                  <div className="flex items-center gap-2">
                    {expandedIOCs.has('processes') ? (
                      <ChevronDown className="w-4 h-4 text-muted-foreground" />
                    ) : (
                      <ChevronRight className="w-4 h-4 text-muted-foreground" />
                    )}
                    <span className="text-sm font-semibold">Processes</span>
                  </div>
                  <span className="text-xs px-2 py-1 bg-yellow-500/20 text-yellow-400 rounded font-medium">
                    {iocs.processes.length}
                  </span>
                </div>
                {expandedIOCs.has('processes') && (
                  <div className="border-t border-border p-3 bg-muted/5">
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-xs text-muted-foreground">Process executions with command lines</span>
                      <Button
                        size="sm"
                        variant="outline"
                        className="h-7 text-xs"
                        onClick={(e) => {
                          e.stopPropagation();
                          const processData = iocs.processes!.map(processName => {
                            // Find the event with this process to get CommandLine
                            const event = events?.find(e => 
                              e.event_id === 4688 && 
                              (e.data?.NewProcessName === processName || 
                               e.data?.ProcessName === processName ||
                               e.data?.Image === processName)
                            );
                            const cmdLine = event?.data?.CommandLine || '';
                            return cmdLine ? `${processName}\n  Command: ${cmdLine}` : processName;
                          }).join('\n\n');
                          navigator.clipboard.writeText(processData);
                          toast.success(`Copied ${iocs.processes!.length} processes to clipboard`);
                        }}
                      >
                        <Copy className="w-3 h-3 mr-1" />
                        Copy All
                      </Button>
                    </div>
                    <div className="space-y-2">
                      {iocs.processes.map((processName, idx) => {
                        // Find the event with this process to get CommandLine
                        const event = events?.find(e => 
                          e.event_id === 4688 && 
                          (e.data?.NewProcessName === processName || 
                           e.data?.ProcessName === processName ||
                           e.data?.Image === processName)
                        );
                        const commandLine = event?.data?.CommandLine || '';
                        
                        return (
                          <div 
                            key={idx} 
                            className="text-xs bg-card px-3 py-2 rounded border border-border hover:bg-muted/50 transition-colors cursor-pointer"
                            onClick={(e) => {
                              e.stopPropagation();
                              const copyText = commandLine ? `${processName}\nCommand: ${commandLine}` : processName;
                              navigator.clipboard.writeText(copyText);
                              toast.success('Process copied');
                            }}
                          >
                            <div className="font-mono font-semibold text-yellow-400 mb-1 break-all">
                              {processName}
                            </div>
                            {commandLine && (
                              <div className="font-mono text-muted-foreground break-all pl-2 border-l-2 border-yellow-500/30">
                                <span className="text-yellow-500/70">Command:</span> {commandLine}
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Files */}
            {iocs.files && iocs.files.length > 0 && (
              <div className="border border-border rounded overflow-hidden">
                <div 
                  className="flex items-center justify-between p-3 bg-muted/5 cursor-pointer hover:bg-muted/10 transition-colors"
                  onClick={() => toggleIOC('files')}
                >
                  <div className="flex items-center gap-2">
                    {expandedIOCs.has('files') ? (
                      <ChevronDown className="w-4 h-4 text-muted-foreground" />
                    ) : (
                      <ChevronRight className="w-4 h-4 text-muted-foreground" />
                    )}
                    <span className="text-sm font-semibold">Files</span>
                  </div>
                  <span className="text-xs px-2 py-1 bg-orange-500/20 text-orange-400 rounded font-medium">
                    {iocs.files.length}
                  </span>
                </div>
                {expandedIOCs.has('files') && (
                  <div className="border-t border-border p-3 bg-muted/5">
                    <div className="space-y-1">
                      {iocs.files.map((file, idx) => (
                        <div key={idx} className="text-xs font-mono bg-card px-2 py-1 rounded border border-border hover:bg-muted/50 transition-colors break-all">
                          {file}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Hashes */}
            {iocs.hashes && iocs.hashes.length > 0 && (
              <div className="border border-border rounded overflow-hidden">
                <div 
                  className="flex items-center justify-between p-3 bg-muted/5 cursor-pointer hover:bg-muted/10 transition-colors"
                  onClick={() => toggleIOC('hashes')}
                >
                  <div className="flex items-center gap-2">
                    {expandedIOCs.has('hashes') ? (
                      <ChevronDown className="w-4 h-4 text-muted-foreground" />
                    ) : (
                      <ChevronRight className="w-4 h-4 text-muted-foreground" />
                    )}
                    <span className="text-sm font-semibold">Hashes</span>
                  </div>
                  <span className="text-xs px-2 py-1 bg-red-500/20 text-red-400 rounded font-medium">
                    {iocs.hashes.length}
                  </span>
                </div>
                {expandedIOCs.has('hashes') && (
                  <div className="border-t border-border p-3 bg-muted/5">
                    <div className="space-y-1">
                      {iocs.hashes.map((hash, idx) => (
                        <div key={idx} className="text-xs font-mono bg-card px-2 py-1 rounded border border-border hover:bg-muted/50 transition-colors break-all">
                          {hash}
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>

          {(!iocs.ips?.length && !iocs.domains?.length && !iocs.users?.length && 
            !iocs.processes?.length && !iocs.files?.length && !iocs.hashes?.length) && (
            <p className="text-sm text-muted-foreground text-center py-4">No IOCs detected in this log file.</p>
          )}
        </Card>
      )}

      {/* CTF Flags Section */}
      {flags && flags.length > 0 && (
        <Card className="p-4">
          <div className="flex items-center gap-2 mb-4">
            <Flag className="w-5 h-5 text-green-500" />
            <h3 className="text-lg font-semibold">CTF Flags & Encoded Data</h3>
            <span className="ml-auto text-sm text-muted-foreground">
              {flags.length} found
            </span>
          </div>

          <div className="space-y-3">
            {flags.map((flag, idx) => {
              const isExpanded = expandedFlags.has(idx);
              const additionalDecodings = flag.value && !flag.decoded ? tryAllDecodings(flag.value).filter(d => d.success && d.confidence > 70) : [];
              
              return (
                <div key={idx} className="border border-border rounded overflow-hidden">
                  <div 
                    className="flex items-center justify-between p-3 bg-muted/5 cursor-pointer hover:bg-muted/10 transition-colors"
                    onClick={() => {
                      const newExpanded = new Set(expandedFlags);
                      if (newExpanded.has(idx)) {
                        newExpanded.delete(idx);
                      } else {
                        newExpanded.add(idx);
                      }
                      setExpandedFlags(newExpanded);
                    }}
                  >
                    <div className="flex items-center gap-2 flex-1 min-w-0">
                      {isExpanded ? (
                        <ChevronDown className="w-4 h-4 text-muted-foreground flex-shrink-0" />
                      ) : (
                        <ChevronRight className="w-4 h-4 text-muted-foreground flex-shrink-0" />
                      )}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1 flex-wrap">
                          <span className={`px-2 py-1 rounded text-xs font-medium ${
                            flag.type === 'CTF Flag' ? 'bg-green-500/20 text-green-400' :
                            flag.type === 'Base64 Encoded' ? 'bg-blue-500/20 text-blue-400' :
                            'bg-purple-500/20 text-purple-400'
                          }`}>
                            {flag.type}
                          </span>
                          <span className="text-xs text-muted-foreground">{flag.pattern}</span>
                          {additionalDecodings.length > 0 && (
                            <Badge className="bg-yellow-500/20 text-yellow-400">
                              +{additionalDecodings.length} more encodings detected
                            </Badge>
                          )}
                        </div>
                        <div className="text-sm font-mono break-all">
                          {flag.decoded ? (
                            <span className="text-green-400">
                              {flag.decoded.length > 80 ? flag.decoded.substring(0, 80) + '...' : flag.decoded}
                            </span>
                          ) : (
                            flag.value.length > 80 ? flag.value.substring(0, 80) + '...' : flag.value
                          )}
                        </div>
                      </div>
                    </div>
                    <Button
                      size="sm"
                      variant="ghost"
                      onClick={(e) => {
                        e.stopPropagation();
                        navigator.clipboard.writeText(flag.decoded || flag.value);
                        toast.success('Copied to clipboard');
                      }}
                    >
                      <Copy className="w-4 h-4" />
                    </Button>
                  </div>

                  {isExpanded && (
                    <div className="border-t border-border p-4 bg-muted/5 space-y-3">
                      {/* Full Value */}
                      <div>
                        <div className="text-xs font-semibold text-muted-foreground mb-2 flex items-center justify-between">
                          <span>Full Value:</span>
                          <Button
                            size="sm"
                            variant="outline"
                            className="h-6 text-xs"
                            onClick={() => {
                              navigator.clipboard.writeText(flag.value);
                              toast.success('Copied to clipboard');
                            }}
                          >
                            <Copy className="w-3 h-3 mr-1" />
                            Copy
                          </Button>
                        </div>
                        <div className="bg-card border border-border rounded p-2">
                          <pre className="text-xs font-mono break-all whitespace-pre-wrap">{flag.value}</pre>
                        </div>
                      </div>

                      {/* Decoded Value (from Python) */}
                      {flag.decoded && (
                        <div>
                          <div className="text-xs font-semibold text-muted-foreground mb-2 flex items-center justify-between">
                            <span>Decoded ({flag.pattern}):</span>
                            <Button
                              size="sm"
                              variant="outline"
                              className="h-6 text-xs"
                              onClick={() => {
                                navigator.clipboard.writeText(flag.decoded!);
                                toast.success('Copied decoded value');
                              }}
                            >
                              <Copy className="w-3 h-3 mr-1" />
                              Copy
                            </Button>
                          </div>
                          <div className="bg-green-500/10 border border-green-500/30 rounded p-2">
                            <pre className="text-xs font-mono break-all whitespace-pre-wrap text-green-400">{flag.decoded}</pre>
                          </div>
                        </div>
                      )}

                      {/* Additional Decodings */}
                      {additionalDecodings.length > 0 && (
                        <div>
                          <div className="text-xs font-semibold text-muted-foreground mb-2">
                            Additional Possible Decodings:
                          </div>
                          <div className="space-y-2">
                            {additionalDecodings.map((decoding, decIdx) => (
                              <div key={decIdx} className="bg-card border border-border rounded p-2">
                                <div className="flex items-center justify-between mb-1">
                                  <div className="flex items-center gap-2">
                                    <Badge variant="outline" className="text-xs">{decoding.type}</Badge>
                                    <span className="text-xs text-muted-foreground">
                                      Confidence: {decoding.confidence}%
                                    </span>
                                  </div>
                                  <Button
                                    size="sm"
                                    variant="ghost"
                                    className="h-6"
                                    onClick={() => {
                                      navigator.clipboard.writeText(decoding.decoded);
                                      toast.success(`Copied ${decoding.type} decoded value`);
                                    }}
                                  >
                                    <Copy className="w-3 h-3" />
                                  </Button>
                                </div>
                                <pre className="text-xs font-mono break-all whitespace-pre-wrap">{decoding.decoded}</pre>
                              </div>
                            ))}
                          </div>
                        </div>
                      )}

                      {/* Context */}
                      {flag.context && (
                        <div>
                          <div className="text-xs font-semibold text-muted-foreground mb-2">Context:</div>
                          <div className="bg-card border border-border rounded p-2">
                            <pre className="text-xs font-mono break-all whitespace-pre-wrap">{flag.context}</pre>
                          </div>
                        </div>
                      )}

                      {/* Metadata */}
                      <div className="grid grid-cols-2 gap-3 text-xs pt-2 border-t border-border">
                        <div>
                          <span className="text-muted-foreground">Field:</span>
                          <span className="ml-2 font-mono">{flag.field}</span>
                        </div>
                        <div>
                          <span className="text-muted-foreground">Event ID:</span>
                          <span className="ml-2 font-mono">{flag.eventId}</span>
                        </div>
                        <div className="col-span-2">
                          <span className="text-muted-foreground">Time:</span>
                          <span className="ml-2 text-xs">{new Date(flag.timestamp).toLocaleString()}</span>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </Card>
      )}

      {/* Statistics */}
      {analysis && (
        <>
          {/* Level Distribution */}
          {analysis.levelDistribution && (
            <Card className="p-4">
              <div className="flex items-center gap-2 mb-4">
                <Activity className="w-5 h-5 text-accent" />
                <h3 className="text-lg font-semibold">Event Level Distribution</h3>
              </div>

              <div className="space-y-3">
                {Object.entries(analysis.levelDistribution).map(([level, count]) => {
                  const total = Object.values(analysis.levelDistribution || {}).reduce((a, b) => a + b, 0);
                  const percentage = ((count / total) * 100).toFixed(1);
                  
                  return (
                    <div key={level}>
                      <div className="flex items-center justify-between mb-1">
                        <span className="text-sm font-medium">{level}</span>
                        <span className="text-sm text-muted-foreground">
                          {count.toLocaleString()} ({percentage}%)
                        </span>
                      </div>
                      <div className="w-full bg-muted/20 rounded-full h-2">
                        <div
                          className={`${getLevelColor(level)} h-2 rounded-full transition-all`}
                          style={{ width: `${percentage}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            </Card>
          )}

          {/* Top Event IDs */}
          {analysis.topEventIds && analysis.topEventIds.length > 0 && (
            <Card className="p-4">
              <div className="flex items-center gap-2 mb-4">
                <Activity className="w-5 h-5 text-accent" />
                <h3 className="text-lg font-semibold">Top Event IDs</h3>
              </div>

              <div className="space-y-2">
                {analysis.topEventIds.slice(0, 10).map(({ eventId, count }, idx) => (
                  <div key={idx} className="flex items-center justify-between p-2 bg-muted/5 rounded">
                    <span className="font-mono font-medium">Event ID: {eventId}</span>
                    <span className="text-sm text-muted-foreground">{count.toLocaleString()} occurrences</span>
                  </div>
                ))}
              </div>
            </Card>
          )}

          {/* Top Providers */}
          {analysis.topProviders && analysis.topProviders.length > 0 && (
            <Card className="p-4">
              <div className="flex items-center gap-2 mb-4">
                <Server className="w-5 h-5 text-accent" />
                <h3 className="text-lg font-semibold">Top Event Providers</h3>
              </div>

              <div className="space-y-2">
                {analysis.topProviders.slice(0, 10).map(({ provider, count }, idx) => (
                  <div key={idx} className="flex items-center justify-between p-2 bg-muted/5 rounded">
                    <span className="text-sm truncate">{provider}</span>
                    <span className="text-sm text-muted-foreground ml-2">{count.toLocaleString()}</span>
                  </div>
                ))}
              </div>
            </Card>
          )}

          {/* Top Computers */}
          {analysis.topComputers && analysis.topComputers.length > 0 && (
            <Card className="p-4">
              <div className="flex items-center gap-2 mb-4">
                <Server className="w-5 h-5 text-accent" />
                <h3 className="text-lg font-semibold">Top Computers</h3>
              </div>

              <div className="space-y-2">
                {analysis.topComputers.slice(0, 10).map(({ computer, count }, idx) => (
                  <div key={idx} className="flex items-center justify-between p-2 bg-muted/5 rounded">
                    <span className="text-sm font-mono">{computer}</span>
                    <span className="text-sm text-muted-foreground">{count.toLocaleString()}</span>
                  </div>
                ))}
              </div>
            </Card>
          )}

          {/* Top Users */}
          {analysis.topUsers && analysis.topUsers.length > 0 && (
            <Card className="p-4">
              <div className="flex items-center gap-2 mb-4">
                <Users className="w-5 h-5 text-accent" />
                <h3 className="text-lg font-semibold">Top Users</h3>
              </div>

              <div className="space-y-2">
                {analysis.topUsers.slice(0, 10).map(({ user, count }, idx) => (
                  <div key={idx} className="flex items-center justify-between p-2 bg-muted/5 rounded">
                    <span className="text-sm font-mono">{user}</span>
                    <span className="text-sm text-muted-foreground">{count.toLocaleString()}</span>
                  </div>
                ))}
              </div>
            </Card>
          )}
        </>
      )}

      {/* Anomaly Detection */}
      {events && events.length > 0 && (
        <div>
          <h2 className="text-xl font-semibold mb-3">Anomaly Detection</h2>
          <AnomalyDetection events={events} />
        </div>
      )}

      {/* Event Correlation */}
      {events && events.length > 0 && (
        <div>
          <h2 className="text-xl font-semibold mb-3">Event Correlation</h2>
          <EventCorrelationView events={events} />
        </div>
      )}
    </div>
  );
};
