/**
 * MITRE ATT&CK Framework Integration
 * Maps Windows Event IDs to MITRE ATT&CK techniques
 */

export interface MitreTechnique {
  id: string;
  name: string;
  tactic: string;
  description: string;
  url: string;
  platforms: string[];
  dataSource?: string;
}

export interface MitreMapping {
  eventId: number;
  techniques: MitreTechnique[];
  description: string;
}

// ========== MITRE ATT&CK MAPPINGS ==========

export const MITRE_MAPPINGS: MitreMapping[] = [
  // Authentication & Account Management
  {
    eventId: 4625,
    description: 'Failed login attempt',
    techniques: [
      {
        id: 'T1110',
        name: 'Brute Force',
        tactic: 'Credential Access',
        description: 'Adversaries may use brute force techniques to gain access',
        url: 'https://attack.mitre.org/techniques/T1110',
        platforms: ['Windows', 'Linux', 'macOS'],
        dataSource: 'Authentication logs',
      },
      {
        id: 'T1078',
        name: 'Valid Accounts',
        tactic: 'Defense Evasion',
        description: 'Adversaries may obtain and abuse credentials',
        url: 'https://attack.mitre.org/techniques/T1078',
        platforms: ['Windows', 'Linux', 'macOS'],
        dataSource: 'Authentication logs',
      },
    ],
  },
  {
    eventId: 4624,
    description: 'Successful logon',
    techniques: [
      {
        id: 'T1078',
        name: 'Valid Accounts',
        tactic: 'Initial Access',
        description: 'Adversaries may obtain and abuse credentials',
        url: 'https://attack.mitre.org/techniques/T1078',
        platforms: ['Windows', 'Linux', 'macOS'],
        dataSource: 'Authentication logs',
      },
    ],
  },
  {
    eventId: 4672,
    description: 'Special privileges assigned to new logon',
    techniques: [
      {
        id: 'T1078.001',
        name: 'Valid Accounts: Default Accounts',
        tactic: 'Privilege Escalation',
        description: 'Adversaries may obtain and abuse credentials of default accounts',
        url: 'https://attack.mitre.org/techniques/T1078/001',
        platforms: ['Windows'],
        dataSource: 'Authentication logs',
      },
    ],
  },
  {
    eventId: 4740,
    description: 'Account was locked out',
    techniques: [
      {
        id: 'T1110',
        name: 'Brute Force',
        tactic: 'Credential Access',
        description: 'Multiple failed login attempts leading to lockout',
        url: 'https://attack.mitre.org/techniques/T1110',
        platforms: ['Windows'],
        dataSource: 'Authentication logs',
      },
    ],
  },
  
  // Process Execution
  {
    eventId: 4688,
    description: 'A new process has been created',
    techniques: [
      {
        id: 'T1059',
        name: 'Command and Scripting Interpreter',
        tactic: 'Execution',
        description: 'Adversaries may abuse command and script interpreters',
        url: 'https://attack.mitre.org/techniques/T1059',
        platforms: ['Windows', 'Linux', 'macOS'],
        dataSource: 'Process monitoring',
      },
      {
        id: 'T1204',
        name: 'User Execution',
        tactic: 'Execution',
        description: 'An adversary may rely upon user actions to execute malicious code',
        url: 'https://attack.mitre.org/techniques/T1204',
        platforms: ['Windows', 'Linux', 'macOS'],
        dataSource: 'Process monitoring',
      },
    ],
  },
  
  // PowerShell
  {
    eventId: 4103,
    description: 'PowerShell module loaded',
    techniques: [
      {
        id: 'T1059.001',
        name: 'PowerShell',
        tactic: 'Execution',
        description: 'Adversaries may abuse PowerShell commands and scripts',
        url: 'https://attack.mitre.org/techniques/T1059/001',
        platforms: ['Windows'],
        dataSource: 'PowerShell logs',
      },
    ],
  },
  {
    eventId: 4104,
    description: 'PowerShell script block executed',
    techniques: [
      {
        id: 'T1059.001',
        name: 'PowerShell',
        tactic: 'Execution',
        description: 'Adversaries may abuse PowerShell commands and scripts',
        url: 'https://attack.mitre.org/techniques/T1059/001',
        platforms: ['Windows'],
        dataSource: 'PowerShell logs',
      },
      {
        id: 'T1027',
        name: 'Obfuscated Files or Information',
        tactic: 'Defense Evasion',
        description: 'Adversaries may attempt to make executable code difficult to discover',
        url: 'https://attack.mitre.org/techniques/T1027',
        platforms: ['Windows', 'Linux', 'macOS'],
        dataSource: 'PowerShell logs',
      },
    ],
  },
  
  // Service Installation
  {
    eventId: 7045,
    description: 'A service was installed in the system',
    techniques: [
      {
        id: 'T1543.003',
        name: 'Create or Modify System Process: Windows Service',
        tactic: 'Persistence',
        description: 'Adversaries may create or modify Windows services',
        url: 'https://attack.mitre.org/techniques/T1543/003',
        platforms: ['Windows'],
        dataSource: 'Service creation',
      },
      {
        id: 'T1569.002',
        name: 'System Services: Service Execution',
        tactic: 'Execution',
        description: 'Adversaries may abuse the Windows service control manager',
        url: 'https://attack.mitre.org/techniques/T1569/002',
        platforms: ['Windows'],
        dataSource: 'Service creation',
      },
    ],
  },
  
  // Scheduled Tasks
  {
    eventId: 4698,
    description: 'A scheduled task was created',
    techniques: [
      {
        id: 'T1053.005',
        name: 'Scheduled Task/Job: Scheduled Task',
        tactic: 'Persistence',
        description: 'Adversaries may abuse task scheduling functionality',
        url: 'https://attack.mitre.org/techniques/T1053/005',
        platforms: ['Windows'],
        dataSource: 'Scheduled task creation',
      },
    ],
  },
  
  // Registry Modification
  {
    eventId: 4657,
    description: 'A registry value was modified',
    techniques: [
      {
        id: 'T1112',
        name: 'Modify Registry',
        tactic: 'Defense Evasion',
        description: 'Adversaries may interact with Windows Registry',
        url: 'https://attack.mitre.org/techniques/T1112',
        platforms: ['Windows'],
        dataSource: 'Registry monitoring',
      },
    ],
  },
  
  // WMI
  {
    eventId: 5857,
    description: 'WMI activity',
    techniques: [
      {
        id: 'T1047',
        name: 'Windows Management Instrumentation',
        tactic: 'Execution',
        description: 'Adversaries may abuse WMI to execute malicious commands',
        url: 'https://attack.mitre.org/techniques/T1047',
        platforms: ['Windows'],
        dataSource: 'WMI activity',
      },
    ],
  },
  
  // Security Policy Changes
  {
    eventId: 4719,
    description: 'System audit policy was changed',
    techniques: [
      {
        id: 'T1562.002',
        name: 'Impair Defenses: Disable Windows Event Logging',
        tactic: 'Defense Evasion',
        description: 'Adversaries may disable Windows event logging',
        url: 'https://attack.mitre.org/techniques/T1562/002',
        platforms: ['Windows'],
        dataSource: 'Windows event logs',
      },
    ],
  },
  
  // Kerberos
  {
    eventId: 4768,
    description: 'Kerberos TGT requested',
    techniques: [
      {
        id: 'T1558.003',
        name: 'Steal or Forge Kerberos Tickets: Kerberoasting',
        tactic: 'Credential Access',
        description: 'Adversaries may abuse Kerberos ticket system',
        url: 'https://attack.mitre.org/techniques/T1558/003',
        platforms: ['Windows'],
        dataSource: 'Kerberos logs',
      },
    ],
  },
  {
    eventId: 4769,
    description: 'Kerberos service ticket requested',
    techniques: [
      {
        id: 'T1558.003',
        name: 'Steal or Forge Kerberos Tickets: Kerberoasting',
        tactic: 'Credential Access',
        description: 'Adversaries may abuse Kerberos ticket system',
        url: 'https://attack.mitre.org/techniques/T1558/003',
        platforms: ['Windows'],
        dataSource: 'Kerberos logs',
      },
    ],
  },
  {
    eventId: 4771,
    description: 'Kerberos pre-authentication failed',
    techniques: [
      {
        id: 'T1110',
        name: 'Brute Force',
        tactic: 'Credential Access',
        description: 'Failed Kerberos authentication may indicate password spraying',
        url: 'https://attack.mitre.org/techniques/T1110',
        platforms: ['Windows'],
        dataSource: 'Kerberos logs',
      },
    ],
  },
  
  // Sysmon Events
  {
    eventId: 1,
    description: 'Process creation (Sysmon)',
    techniques: [
      {
        id: 'T1059',
        name: 'Command and Scripting Interpreter',
        tactic: 'Execution',
        description: 'Adversaries may abuse command and script interpreters',
        url: 'https://attack.mitre.org/techniques/T1059',
        platforms: ['Windows'],
        dataSource: 'Process monitoring',
      },
    ],
  },
  {
    eventId: 3,
    description: 'Network connection (Sysmon)',
    techniques: [
      {
        id: 'T1071',
        name: 'Application Layer Protocol',
        tactic: 'Command and Control',
        description: 'Adversaries may communicate using application layer protocols',
        url: 'https://attack.mitre.org/techniques/T1071',
        platforms: ['Windows', 'Linux', 'macOS'],
        dataSource: 'Network monitoring',
      },
    ],
  },
  {
    eventId: 8,
    description: 'CreateRemoteThread (Sysmon)',
    techniques: [
      {
        id: 'T1055',
        name: 'Process Injection',
        tactic: 'Defense Evasion',
        description: 'Adversaries may inject code into processes',
        url: 'https://attack.mitre.org/techniques/T1055',
        platforms: ['Windows', 'Linux', 'macOS'],
        dataSource: 'Process monitoring',
      },
    ],
  },
  {
    eventId: 10,
    description: 'Process accessed (Sysmon)',
    techniques: [
      {
        id: 'T1003',
        name: 'OS Credential Dumping',
        tactic: 'Credential Access',
        description: 'Adversaries may attempt to dump credentials',
        url: 'https://attack.mitre.org/techniques/T1003',
        platforms: ['Windows', 'Linux', 'macOS'],
        dataSource: 'Process monitoring',
      },
    ],
  },
  {
    eventId: 11,
    description: 'File created (Sysmon)',
    techniques: [
      {
        id: 'T1105',
        name: 'Ingress Tool Transfer',
        tactic: 'Command and Control',
        description: 'Adversaries may transfer tools or files to victim systems',
        url: 'https://attack.mitre.org/techniques/T1105',
        platforms: ['Windows', 'Linux', 'macOS'],
        dataSource: 'File monitoring',
      },
    ],
  },
  {
    eventId: 13,
    description: 'Registry value set (Sysmon)',
    techniques: [
      {
        id: 'T1112',
        name: 'Modify Registry',
        tactic: 'Defense Evasion',
        description: 'Adversaries may interact with Windows Registry',
        url: 'https://attack.mitre.org/techniques/T1112',
        platforms: ['Windows'],
        dataSource: 'Registry monitoring',
      },
      {
        id: 'T1547.001',
        name: 'Boot or Logon Autostart Execution: Registry Run Keys',
        tactic: 'Persistence',
        description: 'Adversaries may achieve persistence via registry run keys',
        url: 'https://attack.mitre.org/techniques/T1547/001',
        platforms: ['Windows'],
        dataSource: 'Registry monitoring',
      },
    ],
  },
  {
    eventId: 22,
    description: 'DNS query (Sysmon)',
    techniques: [
      {
        id: 'T1071.004',
        name: 'Application Layer Protocol: DNS',
        tactic: 'Command and Control',
        description: 'Adversaries may communicate using DNS',
        url: 'https://attack.mitre.org/techniques/T1071/004',
        platforms: ['Windows', 'Linux', 'macOS'],
        dataSource: 'DNS logs',
      },
    ],
  },
];

// ========== HELPER FUNCTIONS ==========

export const getTechniquesForEvent = (eventId: number): MitreTechnique[] => {
  const mapping = MITRE_MAPPINGS.find(m => m.eventId === eventId);
  return mapping?.techniques || [];
};

export const getTacticsForEvents = (events: any[]): Map<string, number> => {
  const tactics = new Map<string, number>();
  
  events.forEach(event => {
    const techniques = getTechniquesForEvent(event.eventId);
    techniques.forEach(tech => {
      tactics.set(tech.tactic, (tactics.get(tech.tactic) || 0) + 1);
    });
  });
  
  return tactics;
};

export const getTechniquesFrequency = (events: any[]): Map<string, { technique: MitreTechnique; count: number; eventIds: number[] }> => {
  const frequency = new Map<string, { technique: MitreTechnique; count: number; eventIds: number[] }>();
  
  events.forEach(event => {
    const techniques = getTechniquesForEvent(event.eventId);
    techniques.forEach(tech => {
      const existing = frequency.get(tech.id);
      if (existing) {
        existing.count++;
        if (!existing.eventIds.includes(event.eventId)) {
          existing.eventIds.push(event.eventId);
        }
      } else {
        frequency.set(tech.id, { technique: tech, count: 1, eventIds: [event.eventId] });
      }
    });
  });
  
  return frequency;
};

export const getAllTactics = (): string[] => {
  return [
    'Reconnaissance',
    'Resource Development',
    'Initial Access',
    'Execution',
    'Persistence',
    'Privilege Escalation',
    'Defense Evasion',
    'Credential Access',
    'Discovery',
    'Lateral Movement',
    'Collection',
    'Command and Control',
    'Exfiltration',
    'Impact',
  ];
};

export const getTacticColor = (tactic: string): string => {
  const colors: Record<string, string> = {
    'Reconnaissance': '#9c27b0',
    'Resource Development': '#673ab7',
    'Initial Access': '#3f51b5',
    'Execution': '#2196f3',
    'Persistence': '#03a9f4',
    'Privilege Escalation': '#00bcd4',
    'Defense Evasion': '#009688',
    'Credential Access': '#4caf50',
    'Discovery': '#8bc34a',
    'Lateral Movement': '#cddc39',
    'Collection': '#ffeb3b',
    'Command and Control': '#ffc107',
    'Exfiltration': '#ff9800',
    'Impact': '#ff5722',
  };
  
  return colors[tactic] || '#9e9e9e';
};

export const generateAttackPath = (events: any[]): {
  phase: string;
  tactic: string;
  techniques: MitreTechnique[];
  eventCount: number;
  timestamp?: string;
}[] => {
  const tactics = getTacticsForEvents(events);
  const allTactics = getAllTactics();
  
  const path = allTactics
    .filter(tactic => tactics.has(tactic))
    .map(tactic => {
      const relevantEvents = events.filter(event => {
        const techniques = getTechniquesForEvent(event.eventId);
        return techniques.some(t => t.tactic === tactic);
      });
      
      const techniques = Array.from(
        new Map(
          relevantEvents.flatMap(e => getTechniquesForEvent(e.eventId))
            .filter(t => t.tactic === tactic)
            .map(t => [t.id, t])
        ).values()
      );
      
      return {
        phase: tactic,
        tactic,
        techniques,
        eventCount: relevantEvents.length,
        timestamp: relevantEvents[0]?.timestamp,
      };
    });
  
  return path;
};
