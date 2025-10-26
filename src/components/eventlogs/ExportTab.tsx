import React, { useState } from 'react';
import { FileJson, FileText, FileCode } from 'lucide-react';
import { Button } from '../ui/button';
import { Card } from '../ui/card';

interface ExportTabProps {
  events: any[];
  analysis?: any;
  iocs?: any;
  threats?: any;
  metadata?: any;
}

export const ExportTab: React.FC<ExportTabProps> = ({ events, analysis, iocs, threats, metadata }) => {
  const [exporting, setExporting] = useState(false);

  const exportJSON = () => {
    setExporting(true);
    try {
      const data = {
        metadata,
        events,
        analysis,
        iocs,
        threats,
        exportedAt: new Date().toISOString()
      };
      
      const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `eventlog-export-${Date.now()}.json`;
      a.click();
      URL.revokeObjectURL(url);
    } finally {
      setExporting(false);
    }
  };

  const exportCSV = () => {
    setExporting(true);
    try {
      // CSV Headers
      const headers = ['RecordID', 'EventID', 'Level', 'Provider', 'Timestamp', 'Computer', 'UserID'];
      
      // CSV Rows
      const rows = events.map(event => [
        event.recordId || '',
        event.eventId || '',
        event.levelName || '',
        event.provider || '',
        event.timestamp || '',
        event.computer || '',
        event.userId || ''
      ]);

      // Combine headers and rows
      const csvContent = [
        headers.join(','),
        ...rows.map(row => row.map(cell => `"${String(cell).replace(/"/g, '""')}"`).join(','))
      ].join('\n');

      const blob = new Blob([csvContent], { type: 'text/csv' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `eventlog-export-${Date.now()}.csv`;
      a.click();
      URL.revokeObjectURL(url);
    } finally {
      setExporting(false);
    }
  };

  const exportHTML = () => {
    setExporting(true);
    try {
      const html = `
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <title>Event Log Analysis Report</title>
  <style>
    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      max-width: 1200px;
      margin: 40px auto;
      padding: 20px;
      background: #0a0a0a;
      color: #e0e0e0;
    }
    h1, h2 { color: #6366f1; }
    .section { margin: 30px 0; padding: 20px; background: #1a1a1a; border-radius: 8px; border: 1px solid #333; }
    .event { margin: 10px 0; padding: 15px; background: #0f0f0f; border-radius: 6px; border: 1px solid #333; }
    .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-size: 12px; font-weight: 600; }
    .badge.critical { background: rgba(239, 68, 68, 0.2); color: #ef4444; border: 1px solid rgba(239, 68, 68, 0.5); }
    .badge.error { background: rgba(248, 113, 113, 0.2); color: #f87171; border: 1px solid rgba(248, 113, 113, 0.5); }
    .badge.warning { background: rgba(234, 179, 8, 0.2); color: #eab308; border: 1px solid rgba(234, 179, 8, 0.5); }
    .badge.info { background: rgba(59, 130, 246, 0.2); color: #3b82f6; border: 1px solid rgba(59, 130, 246, 0.5); }
    .meta { color: #9ca3af; font-size: 14px; }
    table { width: 100%; border-collapse: collapse; }
    th, td { padding: 10px; text-align: left; border-bottom: 1px solid #333; }
    th { background: #1a1a1a; font-weight: 600; }
    code { background: #1a1a1a; padding: 2px 6px; border-radius: 4px; font-family: monospace; }
  </style>
</head>
<body>
  <h1>Windows Event Log Analysis Report</h1>
  
  ${metadata ? `
  <div class="section">
    <h2>Summary</h2>
    <p><strong>Filename:</strong> ${metadata.filename}</p>
    <p><strong>Total Events:</strong> ${metadata.totalEvents?.toLocaleString()}</p>
    <p><strong>File Size:</strong> ${(metadata.filesize / 1024 / 1024).toFixed(2)} MB</p>
    <p><strong>Generated:</strong> ${new Date().toLocaleString()}</p>
  </div>
  ` : ''}

  ${threats && threats.length > 0 ? `
  <div class="section">
    <h2>Threats (${threats.length})</h2>
    ${threats.map((threat: any) => `
      <div class="event">
        <div>
          <span class="badge ${threat.severity.toLowerCase()}">${threat.severity}</span>
          <strong>${threat.type}</strong>
        </div>
        <p class="meta">${threat.description}</p>
        <p class="meta">Event ID: ${threat.eventId} | ${new Date(threat.timestamp).toLocaleString()}</p>
      </div>
    `).join('')}
  </div>
  ` : ''}

  ${analysis?.levelDistribution ? `
  <div class="section">
    <h2>Event Level Distribution</h2>
    <table>
      <tr><th>Level</th><th>Count</th><th>Percentage</th></tr>
      ${Object.entries(analysis.levelDistribution).map(([level, count]: [string, any]) => {
        const total = Object.values(analysis.levelDistribution).reduce((a: number, b: any) => a + b, 0);
        const percentage = ((count / total) * 100).toFixed(1);
        return `<tr><td>${level}</td><td>${count.toLocaleString()}</td><td>${percentage}%</td></tr>`;
      }).join('')}
    </table>
  </div>
  ` : ''}

  ${analysis?.topEventIds && analysis.topEventIds.length > 0 ? `
  <div class="section">
    <h2>Top Event IDs</h2>
    <table>
      <tr><th>Event ID</th><th>Count</th></tr>
      ${analysis.topEventIds.slice(0, 10).map((item: any) => 
        `<tr><td><code>${item.eventId}</code></td><td>${item.count.toLocaleString()}</td></tr>`
      ).join('')}
    </table>
  </div>
  ` : ''}

  ${iocs && (iocs.ips?.length || iocs.domains?.length || iocs.users?.length) ? `
  <div class="section">
    <h2>Indicators of Compromise (IOCs)</h2>
    ${iocs.ips?.length ? `<p><strong>IP Addresses:</strong> ${iocs.ips.slice(0, 20).join(', ')}</p>` : ''}
    ${iocs.domains?.length ? `<p><strong>Domains:</strong> ${iocs.domains.slice(0, 20).join(', ')}</p>` : ''}
    ${iocs.users?.length ? `<p><strong>Users:</strong> ${iocs.users.slice(0, 20).join(', ')}</p>` : ''}
    ${iocs.processes?.length ? `<p><strong>Processes:</strong> ${iocs.processes.slice(0, 20).join(', ')}</p>` : ''}
  </div>
  ` : ''}

  <div class="section">
    <h2>Events (${events.length} total)</h2>
    ${events.slice(0, 100).map(event => `
      <div class="event">
        <div>
          <span class="badge ${event.levelName?.toLowerCase() || 'info'}">${event.levelName}</span>
          <strong>Event ID: ${event.eventId}</strong>
          <span class="meta"> | Record #${event.recordId}</span>
        </div>
        <p class="meta">${event.provider} | ${new Date(event.timestamp).toLocaleString()}</p>
        ${event.computer ? `<p class="meta">Computer: ${event.computer}</p>` : ''}
      </div>
    `).join('')}
    ${events.length > 100 ? '<p class="meta"><em>Showing first 100 events. Export JSON for full data.</em></p>' : ''}
  </div>

  <footer class="meta" style="text-align: center; margin-top: 40px; padding-top: 20px; border-top: 1px solid #333;">
    <p>Generated by SecToolbox Event Log Analyzer</p>
  </footer>
</body>
</html>`;

      const blob = new Blob([html], { type: 'text/html' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `eventlog-report-${Date.now()}.html`;
      a.click();
      URL.revokeObjectURL(url);
    } finally {
      setExporting(false);
    }
  };

  return (
    <div className="space-y-6">
      <Card className="p-6">
        <h3 className="text-lg font-semibold mb-4">Export Event Log Analysis</h3>
        <p className="text-sm text-muted-foreground mb-6">
          Export the complete analysis including events, statistics, IOCs, and detected threats.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <Button
            onClick={exportJSON}
            disabled={exporting}
            className="h-auto py-6 flex-col gap-2"
            variant="outline"
          >
            <FileJson className="w-8 h-8" />
            <div>
              <div className="font-semibold">Export JSON</div>
              <div className="text-xs text-muted-foreground">Complete data structure</div>
            </div>
          </Button>

          <Button
            onClick={exportCSV}
            disabled={exporting}
            className="h-auto py-6 flex-col gap-2"
            variant="outline"
          >
            <FileText className="w-8 h-8" />
            <div>
              <div className="font-semibold">Export CSV</div>
              <div className="text-xs text-muted-foreground">Events in spreadsheet format</div>
            </div>
          </Button>

          <Button
            onClick={exportHTML}
            disabled={exporting}
            className="h-auto py-6 flex-col gap-2"
            variant="outline"
          >
            <FileCode className="w-8 h-8" />
            <div>
              <div className="font-semibold">Export HTML Report</div>
              <div className="text-xs text-muted-foreground">Formatted analysis report</div>
            </div>
          </Button>
        </div>
      </Card>

      <Card className="p-6">
        <h4 className="font-semibold mb-3">Export Information</h4>
        <div className="space-y-2 text-sm text-muted-foreground">
          <p><strong>JSON:</strong> Complete raw data including all events, analysis, IOCs, and threats. Best for programmatic processing or importing into other tools.</p>
          <p><strong>CSV:</strong> Events in comma-separated format. Compatible with Excel, Google Sheets, and database imports. Includes basic event fields only.</p>
          <p><strong>HTML Report:</strong> Human-readable formatted report with styling. View in any browser. Includes summary, threats, statistics, and first 100 events.</p>
        </div>
      </Card>

      {metadata && (
        <Card className="p-6">
          <h4 className="font-semibold mb-3">Current Analysis Summary</h4>
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <span className="text-muted-foreground">Total Events:</span>{' '}
              <span className="font-mono font-medium">{metadata.totalEvents?.toLocaleString()}</span>
            </div>
            {metadata.filename && (
              <div>
                <span className="text-muted-foreground">Filename:</span>{' '}
                <span className="font-mono font-medium">{metadata.filename}</span>
              </div>
            )}
            {metadata.filesize && (
              <div>
                <span className="text-muted-foreground">File Size:</span>{' '}
                <span className="font-mono font-medium">{(metadata.filesize / 1024 / 1024).toFixed(2)} MB</span>
              </div>
            )}
            {threats && (
              <div>
                <span className="text-muted-foreground">Threats Found:</span>{' '}
                <span className="font-mono font-medium text-red-400">{threats.length}</span>
              </div>
            )}
          </div>
        </Card>
      )}
    </div>
  );
};
