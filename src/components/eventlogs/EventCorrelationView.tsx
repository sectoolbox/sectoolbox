import React, { useState } from 'react';
import { Users, Activity, GitBranch, ChevronDown, ChevronRight } from 'lucide-react';
import { Card } from '../ui/card';

interface EventCorrelationViewProps {
  events: any[];
}

interface CorrelatedGroup {
  type: 'user-session' | 'process-chain' | 'attack-sequence';
  title: string;
  description: string;
  events: any[];
  metadata?: Record<string, any>;
}

export const EventCorrelationView: React.FC<EventCorrelationViewProps> = ({ events }) => {
  const [expandedGroups, setExpandedGroups] = useState<Set<number>>(new Set());

  const correlateEvents = (): CorrelatedGroup[] => {
    const groups: CorrelatedGroup[] = [];

    // Group by user sessions (same logon ID)
    const logonIdMap = new Map<string, any[]>();
    events.forEach(event => {
      const logonId = event.logon_id || event.subject_logon_id;
      if (logonId && logonId !== '0x0' && logonId !== '-') {
        if (!logonIdMap.has(logonId)) {
          logonIdMap.set(logonId, []);
        }
        logonIdMap.get(logonId)!.push(event);
      }
    });

    logonIdMap.forEach((sessionEvents, logonId) => {
      if (sessionEvents.length >= 3) { // Only show meaningful sessions
        const user = sessionEvents[0].target_user_name || sessionEvents[0].subject_user_name || 'Unknown';
        groups.push({
          type: 'user-session',
          title: `User Session: ${user}`,
          description: `Logon ID: ${logonId} | ${sessionEvents.length} events`,
          events: sessionEvents.sort((a, b) => 
            new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
          ),
          metadata: {
            user,
            logonId,
            startTime: sessionEvents[0].timestamp,
            endTime: sessionEvents[sessionEvents.length - 1].timestamp
          }
        });
      }
    });

    // Group by process chains (parent-child process relationships)
    const processIdMap = new Map<string, any[]>();
    events.filter(e => e.event_id === 4688).forEach(event => {
      const processId = event.new_process_id || event.process_id;
      if (processId) {
        if (!processIdMap.has(processId)) {
          processIdMap.set(processId, []);
        }
        processIdMap.get(processId)!.push(event);
      }
    });

    // Find process chains (where a process spawns children)
    events.filter(e => e.event_id === 4688).forEach(event => {
      const parentProcessId = event.parent_process_id || event.creator_process_id;
      const children = Array.from(processIdMap.values()).filter(group =>
        group.some(e => e.parent_process_id === parentProcessId)
      );

      if (children.length > 0 && parentProcessId) {
        const allChainEvents = [event, ...children.flat()];
        if (allChainEvents.length >= 2) {
          groups.push({
            type: 'process-chain',
            title: `Process Chain: ${event.process_name || 'Unknown'}`,
            description: `Parent PID: ${parentProcessId} | ${allChainEvents.length} processes`,
            events: allChainEvents.sort((a, b) =>
              new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
            ),
            metadata: {
              parentProcess: event.process_name,
              parentProcessId: parentProcessId
            }
          });
        }
      }
    });

    // Detect attack sequences (failed login → successful login → privilege escalation)
    const failedLogins = events.filter(e => e.event_id === 4625);
    const successLogins = events.filter(e => e.event_id === 4624);
    const privEsc = events.filter(e => e.event_id === 4672);

    failedLogins.forEach(failed => {
      const targetUser = failed.target_user_name;
      const failedTime = new Date(failed.timestamp).getTime();

      // Look for successful login within 10 minutes
      const relatedSuccess = successLogins.find(success =>
        success.target_user_name === targetUser &&
        Math.abs(new Date(success.timestamp).getTime() - failedTime) < 10 * 60 * 1000
      );

      if (relatedSuccess) {
        const successTime = new Date(relatedSuccess.timestamp).getTime();
        // Look for privilege escalation within 5 minutes of success
        const relatedPrivEsc = privEsc.find(priv =>
          (priv.target_user_name === targetUser || priv.subject_user_name === targetUser) &&
          Math.abs(new Date(priv.timestamp).getTime() - successTime) < 5 * 60 * 1000
        );

        if (relatedPrivEsc) {
          groups.push({
            type: 'attack-sequence',
            title: `Potential Attack Sequence: ${targetUser}`,
            description: 'Failed login → Successful login → Privilege escalation',
            events: [failed, relatedSuccess, relatedPrivEsc].sort((a, b) =>
              new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
            ),
            metadata: {
              user: targetUser,
              pattern: 'failed-success-privesc'
            }
          });
        }
      }
    });

    return groups.slice(0, 20); // Limit to prevent overwhelming UI
  };

  const correlatedGroups = correlateEvents();

  const toggleGroup = (index: number) => {
    const newExpanded = new Set(expandedGroups);
    if (newExpanded.has(index)) {
      newExpanded.delete(index);
    } else {
      newExpanded.add(index);
    }
    setExpandedGroups(newExpanded);
  };

  const getGroupIcon = (type: CorrelatedGroup['type']) => {
    switch (type) {
      case 'user-session': return Users;
      case 'process-chain': return GitBranch;
      case 'attack-sequence': return Activity;
    }
  };

  const getGroupColor = (type: CorrelatedGroup['type']) => {
    switch (type) {
      case 'user-session': return 'bg-blue-950/20 border-blue-900/30 text-blue-500';
      case 'process-chain': return 'bg-purple-950/20 border-purple-900/30 text-purple-500';
      case 'attack-sequence': return 'bg-red-950/30 border-red-900/50 text-red-500';
    }
  };

  if (correlatedGroups.length === 0) {
    return (
      <Card className="p-6">
        <p className="text-muted-foreground text-center">No correlated event groups found</p>
      </Card>
    );
  }

  return (
    <div className="space-y-3">
      {correlatedGroups.map((group, index) => {
        const Icon = getGroupIcon(group.type);
        const isExpanded = expandedGroups.has(index);

        return (
          <Card key={index} className={`border-2 ${getGroupColor(group.type)}`}>
            <div
              className="p-4 cursor-pointer hover:bg-muted/5 transition-colors"
              onClick={() => toggleGroup(index)}
            >
              <div className="flex items-start gap-3">
                {isExpanded ? (
                  <ChevronDown className="w-5 h-5 flex-shrink-0 mt-0.5" />
                ) : (
                  <ChevronRight className="w-5 h-5 flex-shrink-0 mt-0.5" />
                )}
                <Icon className="w-5 h-5 flex-shrink-0 mt-0.5" />
                <div className="flex-1">
                  <h3 className="font-semibold mb-1">{group.title}</h3>
                  <p className="text-sm text-muted-foreground">{group.description}</p>
                </div>
              </div>
            </div>

            {isExpanded && (
              <div className="border-t border-border bg-muted/5 p-4 space-y-2">
                {group.events.map((event, eventIndex) => (
                  <div key={eventIndex} className="bg-card rounded border border-border p-3">
                    <div className="flex items-center gap-3 flex-wrap text-sm">
                      <span className="font-mono text-accent">ID: {event.event_id}</span>
                      <span className="text-muted-foreground">
                        {new Date(event.timestamp).toLocaleString()}
                      </span>
                      {event.process_name && (
                        <span className="text-muted-foreground">Process: {event.process_name}</span>
                      )}
                      {(event.target_user_name || event.subject_user_name) && (
                        <span className="text-muted-foreground">
                          User: {event.target_user_name || event.subject_user_name}
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </Card>
        );
      })}
    </div>
  );
};
