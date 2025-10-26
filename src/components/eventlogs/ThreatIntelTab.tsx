import React, { useState, useMemo } from 'react';
import { Shield, Loader2, CheckCircle2, XCircle, AlertCircle } from 'lucide-react';
import { Card } from '../ui/card';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import { toast } from 'react-hot-toast';
import {
  checkIndicatorAll,
  getAggregatedScore,
  type ThreatIntelResult,
} from '@/lib/threatIntel';

interface ThreatIntelTabProps {
  iocs?: {
    ips?: string[];
    domains?: string[];
    hashes?: string[];
  };
}

export const ThreatIntelTab: React.FC<ThreatIntelTabProps> = ({ iocs }) => {
  const [checkedIndicators, setCheckedIndicators] = useState<Map<string, ThreatIntelResult[]>>(new Map());
  const [checking, setChecking] = useState<Set<string>>(new Set());

  const allIndicators = useMemo(() => {
    const indicators: { value: string; type: 'ip' | 'domain' | 'hash' }[] = [];
    
    iocs?.ips?.forEach(ip => indicators.push({ value: ip, type: 'ip' }));
    iocs?.domains?.forEach(domain => indicators.push({ value: domain, type: 'domain' }));
    iocs?.hashes?.forEach(hash => indicators.push({ value: hash, type: 'hash' }));
    
    return indicators;
  }, [iocs]);

  const handleCheck = async (indicator: string, type: 'ip' | 'domain' | 'hash') => {
    setChecking(prev => new Set(prev).add(indicator));

    try {
      const results = await checkIndicatorAll(indicator, type);
      setCheckedIndicators(prev => new Map(prev).set(indicator, results));
      
      const { consensus } = getAggregatedScore(results);
      if (consensus === 'malicious') {
        toast.error(`${indicator} flagged as MALICIOUS!`);
      } else if (consensus === 'suspicious') {
        toast(`${indicator} marked as suspicious`, { icon: '⚠️' });
      } else if (consensus === 'clean') {
        toast.success(`${indicator} appears clean`);
      }
    } catch (error: any) {
      toast.error(`Failed to check ${indicator}: ${error.message}`);
    } finally {
      setChecking(prev => {
        const next = new Set(prev);
        next.delete(indicator);
        return next;
      });
    }
  };

  const handleCheckAll = async () => {
    for (const indicator of allIndicators.slice(0, 10)) {
      if (!checkedIndicators.has(indicator.value)) {
        await handleCheck(indicator.value, indicator.type);
        // Wait 1 second between checks to respect rate limits
        await new Promise(resolve => setTimeout(resolve, 1000));
      }
    }
  };

  const getStatusIcon = (consensus: string) => {
    switch (consensus) {
      case 'malicious':
        return <XCircle className="w-5 h-5 text-red-500" />;
      case 'suspicious':
        return <AlertCircle className="w-5 h-5 text-yellow-500" />;
      case 'clean':
        return <CheckCircle2 className="w-5 h-5 text-green-500" />;
      default:
        return <Shield className="w-5 h-5 text-muted-foreground" />;
    }
  };

  const getStatusColor = (consensus: string) => {
    switch (consensus) {
      case 'malicious':
        return 'text-red-500';
      case 'suspicious':
        return 'text-yellow-500';
      case 'clean':
        return 'text-green-500';
      default:
        return 'text-muted-foreground';
    }
  };

  if (!iocs || allIndicators.length === 0) {
    return (
      <Card className="p-8 text-center">
        <Shield className="w-16 h-16 mx-auto mb-4 text-muted-foreground opacity-50" />
        <h3 className="text-lg font-semibold mb-2">No IOCs to Check</h3>
        <p className="text-sm text-muted-foreground">
          No indicators of compromise found in this log file.
        </p>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <Card className="p-6">
        <div className="flex items-center justify-between mb-4">
          <div>
            <h3 className="text-lg font-semibold">Threat Intelligence Lookup</h3>
            <p className="text-sm text-muted-foreground">
              Check IOCs against VirusTotal, AbuseIPDB, and AlienVault OTX (API keys stored securely in environment variables)
            </p>
          </div>
          <Button
            size="sm"
            onClick={handleCheckAll}
            disabled={checkedIndicators.size === allIndicators.length}
          >
            Check All (First 10)
          </Button>
        </div>
      </Card>

      {/* Summary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <Card className="p-4">
          <p className="text-sm text-muted-foreground mb-1">Total IOCs</p>
          <p className="text-2xl font-bold">{allIndicators.length}</p>
        </Card>
        <Card className="p-4">
          <p className="text-sm text-muted-foreground mb-1">Checked</p>
          <p className="text-2xl font-bold">{checkedIndicators.size}</p>
        </Card>
        <Card className="p-4">
          <p className="text-sm text-muted-foreground mb-1">Malicious</p>
          <p className="text-2xl font-bold text-red-500">
            {Array.from(checkedIndicators.values()).filter(
              results => getAggregatedScore(results).consensus === 'malicious'
            ).length}
          </p>
        </Card>
        <Card className="p-4">
          <p className="text-sm text-muted-foreground mb-1">Suspicious</p>
          <p className="text-2xl font-bold text-yellow-500">
            {Array.from(checkedIndicators.values()).filter(
              results => getAggregatedScore(results).consensus === 'suspicious'
            ).length}
          </p>
        </Card>
      </div>

      {/* IOC List */}
      <Card className="p-6">
        <h3 className="text-lg font-semibold mb-4">Indicators</h3>
        <div className="space-y-2">
          {allIndicators.map((indicator) => {
            const results = checkedIndicators.get(indicator.value);
            const isChecking = checking.has(indicator.value);
            const aggregated = results ? getAggregatedScore(results) : null;

            return (
              <div
                key={indicator.value}
                className="flex items-center justify-between p-3 border border-border rounded-lg hover:bg-muted/50 transition-colors"
              >
                <div className="flex items-center gap-3 flex-1 min-w-0">
                  {aggregated ? (
                    getStatusIcon(aggregated.consensus)
                  ) : (
                    <Shield className="w-5 h-5 text-muted-foreground" />
                  )}
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-sm truncate">{indicator.value}</span>
                      <Badge variant="outline" className="text-xs">
                        {indicator.type}
                      </Badge>
                    </div>
                    {aggregated && (
                      <div className="flex items-center gap-2 mt-1">
                        <span className={`text-xs font-medium ${getStatusColor(aggregated.consensus)}`}>
                          {aggregated.consensus.toUpperCase()}
                        </span>
                        <span className="text-xs text-muted-foreground">
                          Score: {aggregated.averageScore}/100
                        </span>
                      </div>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  {isChecking ? (
                    <Button size="sm" disabled>
                      <Loader2 className="w-4 h-4 animate-spin" />
                    </Button>
                  ) : results ? (
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => {
                        // Show detailed results
                        // Results received
                      }}
                    >
                      Details
                    </Button>
                  ) : (
                    <Button
                      size="sm"
                      onClick={() => handleCheck(indicator.value, indicator.type)}
                    >
                      Check
                    </Button>
                  )}
                </div>
              </div>
            );
          })}
        </div>
      </Card>

      {/* Results Details */}
      {Array.from(checkedIndicators.entries()).map(([indicator, results]) => {
        const aggregated = getAggregatedScore(results);
        return (
          <Card key={indicator} className="p-6">
            <div className="flex items-center justify-between mb-4">
              <h4 className="font-semibold font-mono">{indicator}</h4>
              <Badge className={getStatusColor(aggregated.consensus)}>
                {aggregated.consensus}
              </Badge>
            </div>
            <div className="space-y-3">
              {results.map((result, idx) => (
                <div key={idx} className="p-3 border border-border rounded">
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <span className="font-semibold text-sm">{result.source}</span>
                      {result.isMalicious && (
                        <Badge variant="destructive" className="text-xs">Malicious</Badge>
                      )}
                    </div>
                    <Badge variant="outline">{result.score}/100</Badge>
                  </div>
                  {result.error ? (
                    <p className="text-xs text-red-500">{result.error}</p>
                  ) : (
                    <div className="text-xs text-muted-foreground space-y-1">
                      {result.details.lastAnalysisStats && (
                        <p>
                          Malicious: {result.details.lastAnalysisStats.malicious} / 
                          Suspicious: {result.details.lastAnalysisStats.suspicious}
                        </p>
                      )}
                      {result.details.abuseConfidenceScore !== undefined && (
                        <p>Abuse Confidence: {result.details.abuseConfidenceScore}%</p>
                      )}
                      {result.details.pulseCount !== undefined && (
                        <p>Threat Pulses: {result.details.pulseCount}</p>
                      )}
                      {result.details.tags && result.details.tags.length > 0 && (
                        <p>Tags: {result.details.tags.slice(0, 3).join(', ')}</p>
                      )}
                    </div>
                  )}
                </div>
              ))}
            </div>
          </Card>
        );
      })}
    </div>
  );
};
