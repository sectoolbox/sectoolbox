import React from 'react';
import { Shield, UserPlus, ArrowUpCircle, Terminal, Network, TrendingUp } from 'lucide-react';
import { Card } from '../ui/card';

interface QuickStatsCardsProps {
  events: any[];
}

interface Stat {
  label: string;
  value: number;
  icon: React.ElementType;
  color: string;
  bgColor: string;
  description: string;
}

export const QuickStatsCards: React.FC<QuickStatsCardsProps> = ({ events }) => {
  const calculateStats = (): Stat[] => {
    // Failed logins (Event ID 4625, 4771)
    const failedLogins = events.filter(e => e.event_id === 4625 || e.event_id === 4771).length;

    // New accounts created (Event ID 4720)
    const newAccounts = events.filter(e => e.event_id === 4720).length;

    // Privilege escalations (Event ID 4672, 4673, 4674)
    const privEscalations = events.filter(e => [4672, 4673, 4674].includes(e.event_id)).length;

    // Suspicious PowerShell executions (Event ID 4688 with PowerShell)
    const suspiciousPowerShell = events.filter(e => {
      if (e.event_id !== 4688) return false;
      const processName = e.process_name?.toLowerCase() || '';
      const commandLine = e.command_line?.toLowerCase() || '';
      return processName.includes('powershell') && (
        commandLine.includes('invoke-') ||
        commandLine.includes('downloadstring') ||
        commandLine.includes('iex') ||
        commandLine.includes('-enc') ||
        commandLine.includes('-w hidden')
      );
    }).length;

    // Network connections (Event ID 5156, 4688 with network tools)
    const networkConnections = events.filter(e => {
      if (e.event_id === 5156) return true;
      if (e.event_id === 4688) {
        const processName = e.process_name?.toLowerCase() || '';
        return processName.includes('net.exe') || 
               processName.includes('ping') || 
               processName.includes('nslookup');
      }
      return false;
    }).length;

    // Process creations (Event ID 4688)
    const processCreations = events.filter(e => e.event_id === 4688).length;

    return [
      {
        label: 'Failed Logins',
        value: failedLogins,
        icon: Shield,
        color: 'text-red-500',
        bgColor: 'bg-red-500/10',
        description: 'Authentication failures'
      },
      {
        label: 'New Accounts',
        value: newAccounts,
        icon: UserPlus,
        color: 'text-orange-500',
        bgColor: 'bg-orange-500/10',
        description: 'Account creations'
      },
      {
        label: 'Privilege Escalations',
        value: privEscalations,
        icon: ArrowUpCircle,
        color: 'text-purple-500',
        bgColor: 'bg-purple-500/10',
        description: 'Elevated privileges'
      },
      {
        label: 'Suspicious PowerShell',
        value: suspiciousPowerShell,
        icon: Terminal,
        color: 'text-yellow-500',
        bgColor: 'bg-yellow-500/10',
        description: 'Potential malicious scripts'
      },
      {
        label: 'Network Activity',
        value: networkConnections,
        icon: Network,
        color: 'text-blue-500',
        bgColor: 'bg-blue-500/10',
        description: 'Network connections/tools'
      },
      {
        label: 'Process Creations',
        value: processCreations,
        icon: TrendingUp,
        color: 'text-green-500',
        bgColor: 'bg-green-500/10',
        description: 'New processes spawned'
      }
    ];
  };

  const stats = calculateStats();

  return (
    <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
      {stats.map((stat, index) => {
        const Icon = stat.icon;
        return (
          <Card 
            key={index} 
            className={`p-4 ${stat.bgColor} border-2 border-border hover:border-accent/50 transition-all cursor-pointer hover:scale-[1.02]`}
          >
            <div className="flex items-start justify-between mb-2">
              <Icon className={`w-5 h-5 ${stat.color}`} />
              <span className={`text-2xl font-bold ${stat.color}`}>
                {stat.value}
              </span>
            </div>
            <div className="text-sm font-semibold mb-1">{stat.label}</div>
            <div className="text-xs text-muted-foreground">{stat.description}</div>
          </Card>
        );
      })}
    </div>
  );
};
