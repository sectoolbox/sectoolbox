import React, { useState } from 'react';
import { X, Download, Copy } from 'lucide-react';
import { Button } from '../ui/button';
import toast from 'react-hot-toast';

interface FollowStreamModalProps {
  packets: any[];
  stream: any; // Backend stream data from tshark
  onClose: () => void;
}

export const FollowStreamModal: React.FC<FollowStreamModalProps> = ({
  packets,
  stream,
  onClose
}) => {
  const [viewMode, setViewMode] = useState<'ascii' | 'hex' | 'http' | 'raw'>('ascii');

  if (!stream) return null;

  const renderContent = () => {
    // If we have backend stream data (from tshark follow command)
    if (stream.clientData !== undefined && stream.serverData !== undefined) {
      if (viewMode === 'http' || viewMode === 'ascii') {
        return (
          <div className="space-y-4">
            <div>
              <div className="text-sm font-semibold mb-2 text-red-400">Client → Server (Request):</div>
              <div className="bg-red-500/10 border border-red-500/30 rounded p-3 font-mono text-xs">
                <pre className="whitespace-pre-wrap">{stream.clientData || 'No client data'}</pre>
              </div>
            </div>
            <div>
              <div className="text-sm font-semibold mb-2 text-blue-400">Server → Client (Response):</div>
              <div className="bg-blue-500/10 border border-blue-500/30 rounded p-3 font-mono text-xs">
                <pre className="whitespace-pre-wrap">{stream.serverData || 'No server data'}</pre>
              </div>
            </div>
          </div>
        );
      } else if (viewMode === 'raw') {
        return (
          <div className="font-mono text-xs">
            <pre className="whitespace-pre-wrap">{stream.rawOutput || 'No raw data'}</pre>
          </div>
        );
      } else if (viewMode === 'hex') {
        return (
          <div className="font-mono text-xs space-y-4">
            <div>
              <div className="text-sm font-semibold mb-2 text-red-400">Client → Server:</div>
              <div className="bg-red-500/10 rounded p-3">
                <pre className="whitespace-pre-wrap">{formatAsHex(stream.clientData)}</pre>
              </div>
            </div>
            <div>
              <div className="text-sm font-semibold mb-2 text-blue-400">Server → Client:</div>
              <div className="bg-blue-500/10 rounded p-3">
                <pre className="whitespace-pre-wrap">{formatAsHex(stream.serverData)}</pre>
              </div>
            </div>
          </div>
        );
      }
    }

    // Fallback: If backend data not available, show combined data
    if (stream.combined && Array.isArray(stream.combined)) {
      return (
        <div className="font-mono text-xs space-y-2">
          {stream.combined.map((item: any, idx: number) => (
            <div key={idx}>
              <div className={`text-xs mb-1 ${item.direction === 'client' ? 'text-red-400' : 'text-blue-400'}`}>
                {item.direction === 'client' ? '→ Client' : '← Server'}
              </div>
              <div className={`p-2 rounded ${item.direction === 'client' ? 'bg-red-500/10' : 'bg-blue-500/10'}`}>
                <pre className="whitespace-pre-wrap">{item.data}</pre>
              </div>
            </div>
          ))}
        </div>
      );
    }

    return (
      <div className="text-center text-muted-foreground py-12">
        <p>No stream data available</p>
      </div>
    );
  };

  const downloadStream = () => {
    const content = stream.clientData + '\n\n' + stream.serverData || stream.rawOutput || '';
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `tcp-stream-${stream.streamId}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const copyStream = () => {
    const content = stream.clientData + '\n\n' + stream.serverData || stream.rawOutput || '';
    navigator.clipboard.writeText(content);
    toast.success('Stream copied to clipboard!');
  };

  return (
    <div className="fixed inset-0 bg-background/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-card border border-border rounded-lg w-full max-w-5xl max-h-[90vh] flex flex-col">
        {/* Header */}
        <div className="px-6 py-4 border-b border-border flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold">Follow TCP Stream {stream.streamId}</h2>
            <p className="text-sm text-muted-foreground">
              {stream.node0 || 'Node 0'} ↔ {stream.node1 || 'Node 1'}
            </p>
            {stream.totalBytes && (
              <p className="text-xs text-muted-foreground mt-1">
                Total: {stream.totalBytes} bytes
              </p>
            )}
          </div>
          <Button variant="ghost" size="sm" onClick={onClose}>
            <X className="w-4 h-4" />
          </Button>
        </div>

        {/* View Mode Selector */}
        <div className="px-6 py-3 border-b border-border flex items-center justify-between">
          <div className="flex gap-2">
            <Button
              size="sm"
              variant={viewMode === 'ascii' ? 'default' : 'outline'}
              onClick={() => setViewMode('ascii')}
            >
              ASCII
            </Button>
            <Button
              size="sm"
              variant={viewMode === 'hex' ? 'default' : 'outline'}
              onClick={() => setViewMode('hex')}
            >
              Hex
            </Button>
            <Button
              size="sm"
              variant={viewMode === 'http' ? 'default' : 'outline'}
              onClick={() => setViewMode('http')}
            >
              HTTP
            </Button>
            <Button
              size="sm"
              variant={viewMode === 'raw' ? 'default' : 'outline'}
              onClick={() => setViewMode('raw')}
            >
              Raw
            </Button>
          </div>
          <div className="flex gap-2">
            <Button size="sm" variant="outline" onClick={copyStream}>
              <Copy className="w-3 h-3 mr-1" />
              Copy
            </Button>
            <Button size="sm" variant="outline" onClick={downloadStream}>
              <Download className="w-3 h-3 mr-1" />
              Save
            </Button>
          </div>
        </div>

        {/* Stream Content */}
        <div className="flex-1 overflow-auto p-6 bg-background">
          {renderContent()}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-border flex items-center justify-between">
          <div className="text-sm text-muted-foreground">
            TCP Stream {stream.streamId}
            {stream.totalBytes && ` | ${stream.totalBytes} bytes`}
          </div>
          <Button variant="outline" onClick={onClose}>
            Close
          </Button>
        </div>
      </div>
    </div>
  );
};

function formatAsHex(text: string): string {
  if (!text) return '';

  const lines: string[] = [];
  for (let i = 0; i < text.length; i += 16) {
    const chunk = text.substr(i, 16);
    const hex = chunk.split('').map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join(' ');
    const ascii = chunk.split('').map(c => (c.charCodeAt(0) >= 32 && c.charCodeAt(0) <= 126) ? c : '.').join('');
    lines.push(`${i.toString(16).padStart(4, '0')}  ${hex.padEnd(47, ' ')}  ${ascii}`);
  }
  return lines.join('\n');
}
