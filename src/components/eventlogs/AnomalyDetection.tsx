import React from 'react';
import { AlertTriangle, Clock, Link2, Activity } from 'lucide-react';
import { Card } from '../ui/card';

interface AnomalyDetectionProps {
  events: any[];
}

interface Anomaly {
  type: 'odd-hour-login' | 'unusual-process' | 'rapid-events' | 'lateral-movement';
  severity: 'high' | 'medium' | 'low';
  description: string;
  affectedEvents: any[];
  timestamp?: string;
}

export const AnomalyDetection: React.FC<AnomalyDetectionProps> = ({ events }) => {
  const detectAnomalies = (): Anomaly[] => {
    const anomalies: Anomaly[] = [];

    // Detect odd-hour logins (between 11 PM and 5 AM)
    const oddHourLogins = events.filter(e => {
      if (e.event_id !== 4624) return false;
      const hour = new Date(e.timestamp).getHours();
      return hour >= 23 || hour <= 5;
    });
    if (oddHourLogins.length > 0) {
      anomalies.push({
        type: 'odd-hour-login',
        severity: 'high',
        description: `${oddHourLogins.length} login(s) detected during unusual hours (11PM-5AM)`,
        affectedEvents: oddHourLogins,
        timestamp: oddHourLogins[0].timestamp
      });
    }

    // Detect unusual process chains (suspicious parent-child relationships)
    const suspiciousProcessChains = events.filter(e => {
      if (e.event_id !== 4688) return false;
      const processName = e.process_name?.toLowerCase() || '';
      const parentProcess = e.parent_process_name?.toLowerCase() || '';
      
      // Office apps spawning cmd/powershell
      const officeApps = ['winword.exe', 'excel.exe', 'powerpnt.exe', 'outlook.exe'];
      const shells = ['cmd.exe', 'powershell.exe', 'wscript.exe', 'cscript.exe'];
      
      const parentIsOffice = officeApps.some(app => parentProcess.includes(app));
      const childIsShell = shells.some(shell => processName.includes(shell));
      
      return parentIsOffice && childIsShell;
    });
    if (suspiciousProcessChains.length > 0) {
      anomalies.push({
        type: 'unusual-process',
        severity: 'high',
        description: `${suspiciousProcessChains.length} suspicious process chain(s) detected (Office → Shell)`,
        affectedEvents: suspiciousProcessChains
      });
    }

    // Detect rapid failed login attempts (brute force)
    const failedLogins = events.filter(e => e.event_id === 4625);
    if (failedLogins.length > 5) {
      // Group by time windows (5 min intervals)
      const timeWindows = new Map<number, any[]>();
      failedLogins.forEach(event => {
        const windowKey = Math.floor(new Date(event.timestamp).getTime() / (5 * 60 * 1000));
        if (!timeWindows.has(windowKey)) {
          timeWindows.set(windowKey, []);
        }
        timeWindows.get(windowKey)!.push(event);
      });

      timeWindows.forEach((windowEvents, _) => {
        if (windowEvents.length >= 5) {
          anomalies.push({
            type: 'rapid-events',
            severity: 'high',
            description: `${windowEvents.length} failed login attempts in 5-minute window (potential brute force)`,
            affectedEvents: windowEvents,
            timestamp: windowEvents[0].timestamp
          });
        }
      });
    }

    // Detect lateral movement patterns (multiple logon Type 3 from same source)
    const networkLogons = events.filter(e => e.event_id === 4624 && e.logon_type === 3);
    const sourceIpMap = new Map<string, any[]>();
    networkLogons.forEach(event => {
      const sourceIp = event.source_network_address || event.ip_address;
      if (sourceIp && sourceIp !== '-') {
        if (!sourceIpMap.has(sourceIp)) {
          sourceIpMap.set(sourceIp, []);
        }
        sourceIpMap.get(sourceIp)!.push(event);
      }
    });

    sourceIpMap.forEach((ipEvents, ip) => {
      if (ipEvents.length >= 10) {
        anomalies.push({
          type: 'lateral-movement',
          severity: 'medium',
          description: `${ipEvents.length} network logons from ${ip} (potential lateral movement)`,
          affectedEvents: ipEvents
        });
      }
    });

    return anomalies;
  };

  const anomalies = detectAnomalies();

  if (anomalies.length === 0) {
    return (
      <Card className="p-6 bg-green-950/20 border-green-900/30">
        <div className="flex items-center gap-3">
          <Activity className="w-6 h-6 text-green-500" />
          <div>
            <h3 className="font-semibold text-green-500">No Anomalies Detected</h3>
            <p className="text-sm text-muted-foreground">Event patterns appear normal</p>
          </div>
        </div>
      </Card>
    );
  }

  const getAnomalyIcon = (type: Anomaly['type']) => {
    switch (type) {
      case 'odd-hour-login': return Clock;
      case 'unusual-process': return AlertTriangle;
      case 'rapid-events': return Activity;
      case 'lateral-movement': return Link2;
    }
  };

  const getSeverityColor = (severity: Anomaly['severity']) => {
    switch (severity) {
      case 'high': return 'bg-red-950/30 border-red-900/50 text-red-500';
      case 'medium': return 'bg-orange-950/30 border-orange-900/50 text-orange-500';
      case 'low': return 'bg-yellow-950/30 border-yellow-900/50 text-yellow-500';
    }
  };

  return (
    <div className="space-y-3">
      <Card className="p-4 bg-orange-950/20 border-orange-900/50">
        <div className="flex items-center gap-3">
          <AlertTriangle className="w-5 h-5 text-orange-500" />
          <div>
            <h3 className="font-semibold text-orange-500">Anomalies Detected</h3>
            <p className="text-sm text-muted-foreground">
              {anomalies.length} unusual pattern{anomalies.length > 1 ? 's' : ''} found in event logs
            </p>
          </div>
        </div>
      </Card>

      <div className="grid grid-cols-1 gap-3">
        {anomalies.map((anomaly, index) => {
          const Icon = getAnomalyIcon(anomaly.type);
          return (
            <Card key={index} className={`p-4 border-2 ${getSeverityColor(anomaly.severity)}`}>
              <div className="flex items-start gap-3">
                <Icon className="w-5 h-5 flex-shrink-0 mt-0.5" />
                <div className="flex-1">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="font-semibold">{anomaly.description}</span>
                    <span className="text-xs px-2 py-0.5 rounded bg-background/50 uppercase">
                      {anomaly.severity}
                    </span>
                  </div>
                  {anomaly.timestamp && (
                    <p className="text-xs text-muted-foreground">
                      First occurrence: {new Date(anomaly.timestamp).toLocaleString()}
                    </p>
                  )}
                  <p className="text-xs text-muted-foreground mt-1">
                    Affected events: {anomaly.affectedEvents.length}
                  </p>
                </div>
              </div>
            </Card>
          );
        })}
      </div>
    </div>
  );
};
