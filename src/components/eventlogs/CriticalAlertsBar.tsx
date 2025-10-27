import React from 'react';
import { AlertTriangle, Shield, User, Terminal, Activity } from 'lucide-react';
import { Card } from '../ui/card';
import { Button } from '../ui/button';

interface CriticalAlert {
  type: 'failed-login' | 'account-created' | 'privilege-escalation' | 'suspicious-process' | 'lateral-movement';
  severity: 'critical' | 'high' | 'medium';
  count: number;
  description: string;
  eventIds: number[];
}

interface CriticalAlertsBarProps {
  events: any[];
  onJumpToEvent?: (eventId: number) => void;
}

export const CriticalAlertsBar: React.FC<CriticalAlertsBarProps> = ({ events, onJumpToEvent }) => {
  const detectCriticalAlerts = (): CriticalAlert[] => {
    const alerts: CriticalAlert[] = [];

    // Failed logins (Event ID 4625)
    const failedLogins = events.filter(e => e.event_id === 4625 || e.event_id === 4771);
    if (failedLogins.length > 0) {
      alerts.push({
        type: 'failed-login',
        severity: failedLogins.length > 10 ? 'critical' : 'high',
        count: failedLogins.length,
        description: `${failedLogins.length} failed login attempt${failedLogins.length > 1 ? 's' : ''}`,
        eventIds: [4625, 4771]
      });
    }

    // Account creation (Event ID 4720, 4722, 4728)
    const accountEvents = events.filter(e => [4720, 4722, 4728].includes(e.event_id));
    if (accountEvents.length > 0) {
      alerts.push({
        type: 'account-created',
        severity: 'high',
        count: accountEvents.length,
        description: `${accountEvents.length} account modification${accountEvents.length > 1 ? 's' : ''}`,
        eventIds: [4720, 4722, 4728]
      });
    }

    // Privilege escalation (Event ID 4672, 4673, 4674)
    const privEsc = events.filter(e => [4672, 4673, 4674].includes(e.event_id));
    if (privEsc.length > 0) {
      alerts.push({
        type: 'privilege-escalation',
        severity: 'critical',
        count: privEsc.length,
        description: `${privEsc.length} privilege escalation event${privEsc.length > 1 ? 's' : ''}`,
        eventIds: [4672, 4673, 4674]
      });
    }

    // Suspicious PowerShell/CMD execution (Event ID 4688 with specific keywords)
    const suspiciousProcesses = events.filter(e => {
      if (e.event_id !== 4688) return false;
      const processName = e.process_name?.toLowerCase() || '';
      const commandLine = e.command_line?.toLowerCase() || '';
      return processName.includes('powershell') || 
             processName.includes('cmd') || 
             commandLine.includes('invoke-') ||
             commandLine.includes('downloadstring') ||
             commandLine.includes('iex');
    });
    if (suspiciousProcesses.length > 0) {
      alerts.push({
        type: 'suspicious-process',
        severity: 'critical',
        count: suspiciousProcesses.length,
        description: `${suspiciousProcesses.length} suspicious process execution${suspiciousProcesses.length > 1 ? 's' : ''}`,
        eventIds: [4688]
      });
    }

    // Lateral movement indicators (Event ID 4624 Type 3, 4648)
    const lateralMovement = events.filter(e => 
      (e.event_id === 4624 && e.logon_type === 3) || e.event_id === 4648
    );
    if (lateralMovement.length > 5) { // Only alert if more than 5 to reduce noise
      alerts.push({
        type: 'lateral-movement',
        severity: 'high',
        count: lateralMovement.length,
        description: `${lateralMovement.length} potential lateral movement event${lateralMovement.length > 1 ? 's' : ''}`,
        eventIds: [4624, 4648]
      });
    }

    return alerts;
  };

  const alerts = detectCriticalAlerts();

  if (alerts.length === 0) {
    return null;
  }

  const getAlertIcon = (type: CriticalAlert['type']) => {
    switch (type) {
      case 'failed-login': return Shield;
      case 'account-created': return User;
      case 'privilege-escalation': return AlertTriangle;
      case 'suspicious-process': return Terminal;
      case 'lateral-movement': return Activity;
    }
  };

  const getSeverityColor = (severity: CriticalAlert['severity']) => {
    switch (severity) {
      case 'critical': return 'bg-red-500/10 border-red-500 text-red-500';
      case 'high': return 'bg-orange-500/10 border-orange-500 text-orange-500';
      case 'medium': return 'bg-yellow-500/10 border-yellow-500 text-yellow-500';
    }
  };

  return (
    <Card className="p-4 bg-red-950/20 border-red-900/50">
      <div className="flex items-start gap-3 mb-3">
        <AlertTriangle className="w-5 h-5 text-red-500 flex-shrink-0 mt-0.5" />
        <div className="flex-1">
          <h3 className="font-semibold text-red-500 mb-1">Critical Security Alerts Detected</h3>
          <p className="text-sm text-muted-foreground">
            {alerts.length} type{alerts.length > 1 ? 's' : ''} of suspicious activity detected in this log file
          </p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
        {alerts.map((alert, index) => {
          const Icon = getAlertIcon(alert.type);
          return (
            <div
              key={index}
              className={`p-3 rounded-lg border-2 ${getSeverityColor(alert.severity)} transition-all hover:scale-[1.02]`}
            >
              <div className="flex items-start justify-between gap-2 mb-2">
                <Icon className="w-5 h-5 flex-shrink-0" />
                <span className="text-2xl font-bold">{alert.count}</span>
              </div>
              <p className="text-sm font-medium mb-2">{alert.description}</p>
              <Button
                variant="outline"
                size="sm"
                className="w-full text-xs"
                onClick={() => onJumpToEvent?.(alert.eventIds[0])}
              >
                View Events
              </Button>
            </div>
          );
        })}
      </div>
    </Card>
  );
};
