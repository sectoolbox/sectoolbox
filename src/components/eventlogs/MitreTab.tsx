import React, { useState, useMemo } from 'react';
import { Shield, ExternalLink, AlertTriangle, TrendingUp } from 'lucide-react';
import { Card } from '../ui/card';
import { Badge } from '../ui/badge';
import { Button } from '../ui/button';
import {
  getTechniquesForEvent,
  getTacticsForEvents,
  getTechniquesFrequency,
  generateAttackPath,
  getAllTactics,
  getTacticColor,
} from '@/lib/mitreAttack';

interface MitreTabProps {
  events: any[];
}

export const MitreTab: React.FC<MitreTabProps> = ({ events }) => {
  const [selectedTactic, setSelectedTactic] = useState<string | null>(null);

  const tactics = useMemo(() => getTacticsForEvents(events), [events]);
  const techniques = useMemo(() => getTechniquesFrequency(events), [events]);
  const attackPath = useMemo(() => generateAttackPath(events), [events]);

  const sortedTechniques = useMemo(() => {
    return Array.from(techniques.entries())
      .sort((a, b) => b[1].count - a[1].count);
  }, [techniques]);

  const filteredTechniques = selectedTactic
    ? sortedTechniques.filter(([_, data]) => data.technique.tactic === selectedTactic)
    : sortedTechniques;

  if (tactics.size === 0) {
    return (
      <Card className="p-8 text-center">
        <Shield className="w-16 h-16 mx-auto mb-4 text-muted-foreground opacity-50" />
        <h3 className="text-lg font-semibold mb-2">No MITRE ATT&CK Techniques Detected</h3>
        <p className="text-sm text-muted-foreground">
          No events in this log file map to known MITRE ATT&CK techniques.
        </p>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      {/* Header Stats */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Card className="p-4">
          <div className="flex items-center gap-3">
            <Shield className="w-8 h-8 text-blue-500" />
            <div>
              <p className="text-sm text-muted-foreground">Unique Tactics</p>
              <p className="text-2xl font-bold">{tactics.size}</p>
            </div>
          </div>
        </Card>
        <Card className="p-4">
          <div className="flex items-center gap-3">
            <AlertTriangle className="w-8 h-8 text-yellow-500" />
            <div>
              <p className="text-sm text-muted-foreground">Unique Techniques</p>
              <p className="text-2xl font-bold">{techniques.size}</p>
            </div>
          </div>
        </Card>
        <Card className="p-4">
          <div className="flex items-center gap-3">
            <TrendingUp className="w-8 h-8 text-red-500" />
            <div>
              <p className="text-sm text-muted-foreground">Attack Phases</p>
              <p className="text-2xl font-bold">{attackPath.length}</p>
            </div>
          </div>
        </Card>
      </div>

      {/* Attack Path */}
      {attackPath.length > 0 && (
        <Card className="p-6">
          <h3 className="text-lg font-semibold mb-4 flex items-center gap-2">
            <TrendingUp className="w-5 h-5" />
            Attack Kill Chain
          </h3>
          <div className="space-y-3">
            {attackPath.map((phase, idx) => (
              <div key={idx} className="relative">
                {idx > 0 && (
                  <div className="absolute left-6 -top-3 w-0.5 h-3 bg-border" />
                )}
                <div className="flex items-start gap-4">
                  <div
                    className="w-12 h-12 rounded-full flex items-center justify-center text-white font-bold flex-shrink-0"
                    style={{ backgroundColor: getTacticColor(phase.tactic) }}
                  >
                    {idx + 1}
                  </div>
                  <div className="flex-1">
                    <h4 className="font-semibold mb-1">{phase.tactic}</h4>
                    <div className="flex flex-wrap gap-2 mb-2">
                      {phase.techniques.map((tech) => (
                        <Badge key={tech.id} variant="outline" className="text-xs">
                          {tech.id}: {tech.name}
                        </Badge>
                      ))}
                    </div>
                    <p className="text-xs text-muted-foreground">
                      {phase.eventCount} events • {phase.timestamp && new Date(phase.timestamp).toLocaleString()}
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </Card>
      )}

      {/* Tactic Filter */}
      <Card className="p-4">
        <h3 className="text-lg font-semibold mb-4">Filter by Tactic</h3>
        <div className="flex flex-wrap gap-2">
          <Button
            variant={selectedTactic === null ? 'default' : 'outline'}
            size="sm"
            onClick={() => setSelectedTactic(null)}
          >
            All Tactics
          </Button>
          {Array.from(tactics.entries())
            .sort((a, b) => b[1] - a[1])
            .map(([tactic, count]) => (
              <Button
                key={tactic}
                variant={selectedTactic === tactic ? 'default' : 'outline'}
                size="sm"
                onClick={() => setSelectedTactic(tactic)}
                style={{
                  borderColor: selectedTactic === tactic ? getTacticColor(tactic) : undefined,
                  backgroundColor: selectedTactic === tactic ? getTacticColor(tactic) : undefined,
                }}
              >
                {tactic} ({count})
              </Button>
            ))}
        </div>
      </Card>

      {/* Techniques List */}
      <Card className="p-6">
        <h3 className="text-lg font-semibold mb-4">
          Detected Techniques {selectedTactic && `- ${selectedTactic}`}
        </h3>
        <div className="space-y-3">
          {filteredTechniques.map(([techId, data]) => (
            <div
              key={techId}
              className="p-4 border border-border rounded-lg hover:bg-muted/50 transition-colors"
            >
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-2">
                    <Badge
                      variant="outline"
                      style={{
                        borderColor: getTacticColor(data.technique.tactic),
                        color: getTacticColor(data.technique.tactic),
                      }}
                    >
                      {data.technique.tactic}
                    </Badge>
                    <h4 className="font-semibold">
                      {data.technique.id}: {data.technique.name}
                    </h4>
                    <Badge className="ml-auto">{data.count} events</Badge>
                  </div>
                  <p className="text-sm text-muted-foreground mb-3">
                    {data.technique.description}
                  </p>
                  <div className="flex items-center gap-4 text-xs text-muted-foreground">
                    <span>
                      Platforms: {data.technique.platforms.join(', ')}
                    </span>
                    {data.technique.dataSource && (
                      <span>
                        Data Source: {data.technique.dataSource}
                      </span>
                    )}
                  </div>
                </div>
                <Button
                  variant="ghost"
                  size="sm"
                  className="flex-shrink-0"
                  onClick={() => window.open(data.technique.url, '_blank')}
                >
                  <ExternalLink className="w-4 h-4 mr-1" />
                  MITRE
                </Button>
              </div>
            </div>
          ))}
        </div>
      </Card>

      {/* Tactic Matrix */}
      <Card className="p-6">
        <h3 className="text-lg font-semibold mb-4">MITRE ATT&CK Tactic Coverage</h3>
        <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
          {getAllTactics().map((tactic) => {
            const count = tactics.get(tactic) || 0;
            const isDetected = count > 0;
            return (
              <div
                key={tactic}
                className={`p-3 rounded-lg border ${
                  isDetected
                    ? 'border-accent bg-accent/10'
                    : 'border-border bg-muted/20 opacity-50'
                }`}
                style={{
                  borderColor: isDetected ? getTacticColor(tactic) : undefined,
                }}
              >
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-semibold truncate">{tactic}</span>
                  {isDetected && (
                    <Badge variant="secondary" className="text-xs">
                      {count}
                    </Badge>
                  )}
                </div>
                <div
                  className="h-1 rounded-full"
                  style={{
                    backgroundColor: isDetected ? getTacticColor(tactic) : '#3f3f46',
                    opacity: isDetected ? 1 : 0.3,
                  }}
                />
              </div>
            );
          })}
        </div>
      </Card>
    </div>
  );
};
