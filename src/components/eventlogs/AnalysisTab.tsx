import React from 'react';
import { Activity, AlertTriangle, Shield, Users, Server, Hash } from 'lucide-react';
import { Card } from '../ui/card';

interface AnalysisTabProps {
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
  }>;
}

export const AnalysisTab: React.FC<AnalysisTabProps> = ({ analysis, iocs, threats }) => {
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
            {threats.map((threat, idx) => (
              <div key={idx} className="border border-border rounded p-3 bg-muted/5">
                <div className="flex items-start gap-3">
                  <Shield className="w-4 h-4 text-muted-foreground mt-0.5" />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-medium">{threat.type}</span>
                      <span className={`px-2 py-0.5 rounded text-xs font-medium border ${getSeverityColor(threat.severity)}`}>
                        {threat.severity}
                      </span>
                      <span className="text-xs text-muted-foreground ml-auto">
                        Event ID: {threat.eventId}
                      </span>
                    </div>
                    <p className="text-sm text-muted-foreground mb-1">{threat.description}</p>
                    <p className="text-xs text-muted-foreground">
                      {new Date(threat.timestamp).toLocaleString()}
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* IOCs Section */}
      {iocs && (
        <Card className="p-4">
          <div className="flex items-center gap-2 mb-4">
            <Hash className="w-5 h-5 text-accent" />
            <h3 className="text-lg font-semibold">Indicators of Compromise (IOCs)</h3>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {iocs.ips && iocs.ips.length > 0 && (
              <div>
                <div className="text-sm font-semibold mb-2 text-muted-foreground">IP Addresses</div>
                <div className="bg-muted/20 rounded p-2 space-y-1 max-h-32 overflow-y-auto">
                  {iocs.ips.map((ip, idx) => (
                    <div key={idx} className="text-xs font-mono">{ip}</div>
                  ))}
                </div>
              </div>
            )}

            {iocs.domains && iocs.domains.length > 0 && (
              <div>
                <div className="text-sm font-semibold mb-2 text-muted-foreground">Domains</div>
                <div className="bg-muted/20 rounded p-2 space-y-1 max-h-32 overflow-y-auto">
                  {iocs.domains.map((domain, idx) => (
                    <div key={idx} className="text-xs font-mono">{domain}</div>
                  ))}
                </div>
              </div>
            )}

            {iocs.users && iocs.users.length > 0 && (
              <div>
                <div className="text-sm font-semibold mb-2 text-muted-foreground">Users</div>
                <div className="bg-muted/20 rounded p-2 space-y-1 max-h-32 overflow-y-auto">
                  {iocs.users.map((user, idx) => (
                    <div key={idx} className="text-xs font-mono">{user}</div>
                  ))}
                </div>
              </div>
            )}

            {iocs.processes && iocs.processes.length > 0 && (
              <div>
                <div className="text-sm font-semibold mb-2 text-muted-foreground">Processes</div>
                <div className="bg-muted/20 rounded p-2 space-y-1 max-h-32 overflow-y-auto">
                  {iocs.processes.map((process, idx) => (
                    <div key={idx} className="text-xs font-mono">{process}</div>
                  ))}
                </div>
              </div>
            )}

            {iocs.files && iocs.files.length > 0 && (
              <div>
                <div className="text-sm font-semibold mb-2 text-muted-foreground">Files</div>
                <div className="bg-muted/20 rounded p-2 space-y-1 max-h-32 overflow-y-auto">
                  {iocs.files.map((file, idx) => (
                    <div key={idx} className="text-xs font-mono break-all">{file}</div>
                  ))}
                </div>
              </div>
            )}

            {iocs.hashes && iocs.hashes.length > 0 && (
              <div>
                <div className="text-sm font-semibold mb-2 text-muted-foreground">Hashes</div>
                <div className="bg-muted/20 rounded p-2 space-y-1 max-h-32 overflow-y-auto">
                  {iocs.hashes.map((hash, idx) => (
                    <div key={idx} className="text-xs font-mono break-all">{hash}</div>
                  ))}
                </div>
              </div>
            )}
          </div>

          {(!iocs.ips?.length && !iocs.domains?.length && !iocs.users?.length && 
            !iocs.processes?.length && !iocs.files?.length && !iocs.hashes?.length) && (
            <p className="text-sm text-muted-foreground">No IOCs detected in this log file.</p>
          )}
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
    </div>
  );
};
