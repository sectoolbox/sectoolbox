import React, { useState, useMemo } from 'react';
import { X, Download, Copy, ChevronLeft, ChevronRight } from 'lucide-react';
import { Button } from '../ui/button';

interface FollowStreamModalProps {
  packets: any[];
  stream: { tcpStream?: number; source?: string; destination?: string } | null;
  onClose: () => void;
}

export const FollowStreamModal: React.FC<FollowStreamModalProps> = ({
  packets,
  stream,
  onClose
}) => {
  const [viewMode, setViewMode] = useState<'ascii' | 'hex' | 'raw' | 'http'>('ascii');

  if (!stream) return null;

  // Filter packets for this stream
  const streamPackets = useMemo(() => {
    if (stream.tcpStream !== undefined) {
      return packets.filter(pkt => pkt.tcpStream === stream.tcpStream);
    } else if (stream.source && stream.destination) {
      return packets.filter(pkt =>
        (pkt.source === stream.source && pkt.destination === stream.destination) ||
        (pkt.source === stream.destination && pkt.destination === stream.source)
      );
    }
    return [];
  }, [packets, stream]);

  // Reconstruct stream data
  const streamData = useMemo(() => {
    const clientToServer: string[] = [];
    const serverToClient: string[] = [];

    streamPackets
      .sort((a, b) => a.index - b.index)
      .forEach(pkt => {
        const isClientToServer = pkt.source === stream.source || pkt.source === streamPackets[0]?.source;
        const data = extractPayload(pkt);

        if (data) {
          if (isClientToServer) {
            clientToServer.push(data);
          } else {
            serverToClient.push(data);
          }
        }
      });

    return {
      client: clientToServer.join(''),
      server: serverToClient.join(''),
      combined: streamPackets.map(pkt => ({
        direction: pkt.source === streamPackets[0]?.source ? 'client' : 'server',
        data: extractPayload(pkt),
        frame: pkt.index
      }))
    };
  }, [streamPackets, stream]);

  const renderContent = () => {
    if (viewMode === 'ascii') {
      return (
        <div className="font-mono text-xs space-y-2">
          {streamData.combined.map((item, idx) => (
            item.data && (
              <div key={idx}>
                <div className={`text-xs mb-1 ${item.direction === 'client' ? 'text-red-400' : 'text-blue-400'}`}>
                  {item.direction === 'client' ? '→ Client to Server' : '← Server to Client'} (Frame {item.frame})
                </div>
                <div className={`p-2 rounded ${item.direction === 'client' ? 'bg-red-500/10' : 'bg-blue-500/10'}`}>
                  <pre className="whitespace-pre-wrap break-all">{item.data}</pre>
                </div>
              </div>
            )
          ))}
        </div>
      );
    } else if (viewMode === 'hex') {
      return (
        <div className="font-mono text-xs space-y-2">
          {streamData.combined.map((item, idx) => (
            item.data && (
              <div key={idx}>
                <div className={`text-xs mb-1 ${item.direction === 'client' ? 'text-red-400' : 'text-blue-400'}`}>
                  {item.direction === 'client' ? '→ Client' : '← Server'} (Frame {item.frame})
                </div>
                <div className={`p-2 rounded ${item.direction === 'client' ? 'bg-red-500/10' : 'bg-blue-500/10'}`}>
                  {formatAsHex(item.data)}
                </div>
              </div>
            )
          ))}
        </div>
      );
    } else if (viewMode === 'http') {
      // Try to parse as HTTP
      return (
        <div className="space-y-4">
          <div>
            <div className="text-sm font-semibold mb-2 text-red-400">Client → Server (Request):</div>
            <div className="bg-red-500/10 border border-red-500/30 rounded p-3 font-mono text-xs">
              <pre className="whitespace-pre-wrap">{streamData.client || 'No request data'}</pre>
            </div>
          </div>
          <div>
            <div className="text-sm font-semibold mb-2 text-blue-400">Server → Client (Response):</div>
            <div className="bg-blue-500/10 border border-blue-500/30 rounded p-3 font-mono text-xs">
              <pre className="whitespace-pre-wrap">{streamData.server || 'No response data'}</pre>
            </div>
          </div>
        </div>
      );
    } else {
      // Raw
      return (
        <div className="font-mono text-xs">
          <pre className="whitespace-pre-wrap break-all">
            {streamData.combined.map(item => item.data).join('\n')}
          </pre>
        </div>
      );
    }
  };

  const downloadStream = () => {
    const content = streamData.combined.map(item => item.data).join('\n');
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `stream-${stream.tcpStream || 0}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const copyStream = () => {
    const content = streamData.combined.map(item => item.data).join('\n');
    navigator.clipboard.writeText(content);
  };

  return (
    <div className="fixed inset-0 bg-background/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-card border border-border rounded-lg w-full max-w-5xl max-h-[90vh] flex flex-col">
        {/* Header */}
        <div className="px-6 py-4 border-b border-border flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold">Follow TCP Stream {stream.tcpStream}</h2>
            <p className="text-sm text-muted-foreground">
              {streamPackets[0]?.source}:{streamPackets[0]?.srcPort} ↔ {streamPackets[0]?.destination}:{streamPackets[0]?.destPort}
            </p>
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
          {streamPackets.length > 0 ? (
            renderContent()
          ) : (
            <div className="text-center text-muted-foreground py-12">
              <Network className="w-12 h-12 mx-auto mb-4 opacity-50" />
              <p>No stream data available</p>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3 border-t border-border flex items-center justify-between">
          <div className="text-sm text-muted-foreground">
            {streamPackets.length} packets in stream | {(streamData.combined.reduce((sum, item) => sum + (item.data?.length || 0), 0) / 1024).toFixed(1)} KB
          </div>
          <Button variant="outline" onClick={onClose}>
            Close
          </Button>
        </div>
      </div>
    </div>
  );
};

function extractPayload(packet: any): string | null {
  // Try to extract text payload from packet
  if (packet.data) {
    try {
      // If data is hex string, convert to ASCII
      const hex = packet.data.replace(/:/g, '').replace(/\s/g, '');
      const bytes = hex.match(/.{1,2}/g);
      if (bytes) {
        return bytes
          .map((byte: string) => {
            const code = parseInt(byte, 16);
            return code >= 32 && code <= 126 ? String.fromCharCode(code) : '.';
          })
          .join('');
      }
    } catch (e) {
      // Fallback
    }
  }

  // Try from raw layers
  if (packet.rawLayers?.tcp?.['tcp.payload']) {
    return packet.rawLayers.tcp['tcp.payload'];
  }

  return null;
}

function formatAsHex(text: string): string {
  const lines: string[] = [];
  for (let i = 0; i < text.length; i += 16) {
    const chunk = text.substr(i, 16);
    const hex = chunk.split('').map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join(' ');
    lines.push(`${i.toString(16).padStart(4, '0')}  ${hex.padEnd(47, ' ')}  ${chunk}`);
  }
  return lines.join('\n');
}
