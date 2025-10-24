import React from 'react';
import { AlertTriangle, CheckCircle, Flag, Key, Shield, TrendingUp, Users, Globe, Clock, Database } from 'lucide-react';
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
  const criticalFindings = findings.filter(f => f.severity === 'critical');
  const warningFindings = findings.filter(f => f.severity === 'warning');
  const infoFindings = findings.filter(f => f.severity === 'info');

  const getSeverityIcon = (severity: string) => {
    if (severity === 'critical') return <AlertTriangle className="w-5 h-5 text-red-400" />;
    if (severity === 'warning') return <Shield className="w-5 h-5 text-yellow-400" />;
    return <CheckCircle className="w-5 h-5 text-blue-400" />;
  };

  const getSeverityColor = (severity: string) => {
    if (severity === 'critical') return 'border-red-400/30 bg-red-400/5';
    if (severity === 'warning') return 'border-yellow-400/30 bg-yellow-400/5';
    return 'border-blue-400/30 bg-blue-400/5';
  };

  return (
    <div className="space-y-6 p-6">
      {/* Quick Stats Overview */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <div className="bg-card border border-border rounded-lg p-4 text-center">
          <Database className="w-6 h-6 mx-auto mb-2 text-accent" />
          <div className="text-2xl font-bold text-accent">{stats.totalPackets.toLocaleString()}</div>
          <div className="text-xs text-muted-foreground">Total Packets</div>
        </div>
        <div className="bg-card border border-border rounded-lg p-4 text-center">
          <Clock className="w-6 h-6 mx-auto mb-2 text-blue-400" />
          <div className="text-2xl font-bold text-blue-400">{stats.timespan}</div>
          <div className="text-xs text-muted-foreground">Duration</div>
        </div>
        <div className="bg-card border border-border rounded-lg p-4 text-center">
          <Globe className="w-6 h-6 mx-auto mb-2 text-green-400" />
          <div className="text-2xl font-bold text-green-400">{stats.hosts}</div>
          <div className="text-xs text-muted-foreground">Unique Hosts</div>
        </div>
        <div className="bg-card border border-border rounded-lg p-4 text-center">
          <TrendingUp className="w-6 h-6 mx-auto mb-2 text-purple-400" />
          <div className="text-2xl font-bold text-purple-400">{stats.protocols.length}</div>
          <div className="text-xs text-muted-foreground">Protocols</div>
        </div>
        <div className="bg-card border border-border rounded-lg p-4 text-center">
          <Database className="w-6 h-6 mx-auto mb-2 text-cyan-400" />
          <div className="text-2xl font-bold text-cyan-400">{(stats.dataTransfer / 1024 / 1024).toFixed(1)} MB</div>
          <div className="text-xs text-muted-foreground">Data Transfer</div>
        </div>
      </div>

      {/* Critical Findings */}
      {criticalFindings.length > 0 && (
        <div className="bg-card border border-border rounded-lg overflow-hidden">
          <div className="bg-red-500/10 border-b border-red-500/30 px-4 py-3">
            <h3 className="font-semibold text-red-400 flex items-center gap-2">
              <AlertTriangle className="w-5 h-5" />
              Critical Findings ({criticalFindings.length})
            </h3>
          </div>
          <div className="p-4 space-y-3">
            {criticalFindings.map(finding => (
              <div key={finding.id} className={`border rounded-lg p-4 ${getSeverityColor(finding.severity)}`}>
                <div className="flex items-start justify-between mb-2">
                  <div className="flex items-center gap-2">
                    {getSeverityIcon(finding.severity)}
                    <span className="font-semibold">{finding.title}</span>
                  </div>
                  <span className="text-xs px-2 py-1 bg-muted rounded">{finding.category}</span>
                </div>
                <p className="text-sm text-muted-foreground mb-3">{finding.description}</p>
                <div className="space-y-1 mb-3">
                  {finding.evidence.map((ev, i) => (
                    <div key={i} className="text-xs font-mono bg-background/50 px-2 py-1 rounded">
                      {ev}
                    </div>
                  ))}
                  {finding.autoExtracted && (
                    <div className="text-xs font-mono bg-accent/10 px-2 py-1 rounded text-accent">
                      Decoded: {finding.autoExtracted}
                    </div>
                  )}
                </div>
                <div className="flex gap-2">
                  {finding.frames.length > 0 && (
                    <Button size="sm" variant="outline" onClick={() => onJumpToPacket(finding.frames[0])}>
                      Jump to Frame {finding.frames[0]}
                    </Button>
                  )}
                  <Button size="sm" variant="outline" onClick={() => onApplyFilter(`frame.number == ${finding.frames[0]}`)}>
                    Filter
                  </Button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Warning Findings */}
      {warningFindings.length > 0 && (
        <div className="bg-card border border-border rounded-lg overflow-hidden">
          <div className="bg-yellow-500/10 border-b border-yellow-500/30 px-4 py-3">
            <h3 className="font-semibold text-yellow-400 flex items-center gap-2">
              <Shield className="w-5 h-5" />
              Warnings ({warningFindings.length})
            </h3>
          </div>
          <div className="p-4 space-y-3 max-h-96 overflow-auto">
            {warningFindings.map(finding => (
              <div key={finding.id} className={`border rounded-lg p-3 ${getSeverityColor(finding.severity)}`}>
                <div className="flex items-start justify-between mb-2">
                  <span className="font-medium text-sm">{finding.title}</span>
                  <span className="text-xs px-2 py-1 bg-muted rounded">{finding.category}</span>
                </div>
                <p className="text-xs text-muted-foreground mb-2">{finding.description}</p>
                <div className="text-xs font-mono bg-background/50 px-2 py-1 rounded mb-2">
                  {finding.evidence[0]}
                </div>
                {finding.frames.length > 0 && (
                  <Button size="sm" variant="outline" onClick={() => onJumpToPacket(finding.frames[0])}>
                    View Frame {finding.frames[0]}
                  </Button>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Pattern Findings */}
      {infoFindings.length > 0 && (
        <div className="bg-card border border-border rounded-lg overflow-hidden">
          <div className="bg-blue-500/10 border-b border-blue-500/30 px-4 py-3">
            <h3 className="font-semibold text-blue-400 flex items-center gap-2">
              <TrendingUp className="w-5 h-5" />
              Patterns Detected ({infoFindings.length})
            </h3>
          </div>
          <div className="p-4 space-y-2 max-h-64 overflow-auto">
            {infoFindings.map(finding => (
              <div key={finding.id} className="flex items-center justify-between p-2 bg-muted/20 rounded">
                <div className="flex-1">
                  <span className="text-sm font-medium">{finding.title}</span>
                  <p className="text-xs text-muted-foreground">{finding.evidence[0]}</p>
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
            Traffic appears normal. Use other tabs for detailed analysis.
          </p>
        </div>
      )}
    </div>
  );
};
