import React from 'react';
import { AlertTriangle, Shield, Search, ArrowUp } from 'lucide-react';
import { Button } from '../ui/button';

interface QuickJumpButtonsProps {
  events: any[];
  onJumpTo: (targetType: 'threat' | 'critical' | 'suspicious') => void;
}

export const QuickJumpButtons: React.FC<QuickJumpButtonsProps> = ({ events, onJumpTo }) => {
  // Count different event types
  const threatCount = events.filter(e => 
    [4625, 4720, 4672, 4673, 4674].includes(e.event_id)
  ).length;

  const criticalCount = events.filter(e => 
    e.levelName === 'Critical' || e.levelName === 'Error'
  ).length;

  const suspiciousCount = events.filter(e => {
    if (e.event_id !== 4688) return false;
    const processName = e.process_name?.toLowerCase() || '';
    const commandLine = e.command_line?.toLowerCase() || '';
    return processName.includes('powershell') && (
      commandLine.includes('invoke-') ||
      commandLine.includes('downloadstring') ||
      commandLine.includes('iex')
    );
  }).length;

  if (threatCount === 0 && criticalCount === 0 && suspiciousCount === 0) {
    return null;
  }

  return (
    <div className="fixed bottom-6 right-6 flex flex-col gap-2 z-50">
      {threatCount > 0 && (
        <Button
          onClick={() => onJumpTo('threat')}
          className="shadow-lg hover:scale-105 transition-all bg-red-600 hover:bg-red-700"
          size="lg"
        >
          <Shield className="w-4 h-4 mr-2" />
          Jump to Threats ({threatCount})
          <ArrowUp className="w-4 h-4 ml-2" />
        </Button>
      )}

      {criticalCount > 0 && (
        <Button
          onClick={() => onJumpTo('critical')}
          className="shadow-lg hover:scale-105 transition-all bg-orange-600 hover:bg-orange-700"
          size="lg"
        >
          <AlertTriangle className="w-4 h-4 mr-2" />
          Jump to Critical ({criticalCount})
          <ArrowUp className="w-4 h-4 ml-2" />
        </Button>
      )}

      {suspiciousCount > 0 && (
        <Button
          onClick={() => onJumpTo('suspicious')}
          className="shadow-lg hover:scale-105 transition-all bg-yellow-600 hover:bg-yellow-700"
          size="lg"
        >
          <Search className="w-4 h-4 mr-2" />
          Jump to Suspicious ({suspiciousCount})
          <ArrowUp className="w-4 h-4 ml-2" />
        </Button>
      )}
    </div>
  );
};
