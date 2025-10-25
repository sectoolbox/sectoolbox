import React, { useState, useMemo } from 'react';
import { X, Download, Copy, ChevronUp, ChevronDown, Search } from 'lucide-react';
import { Button } from '../ui/button';
import toast from 'react-hot-toast';

interface FollowStreamModalProps {
  packets: any[];
  stream: any; // Backend stream data
  onClose: () => void;
  allStreams?: number[]; // Array of all available stream IDs
  onNavigateStream?: (streamId: number) => void;
}

export const FollowStreamModal: React.FC<FollowStreamModalProps> = ({
  packets,
  stream,
  onClose,
  allStreams = [],
  onNavigateStream
}) => {
  // Wireshark-like settings
  const [showAs, setShowAs] = useState<'ascii' | 'ebcdic' | 'hex' | 'c-array' | 'raw' | 'yaml'>('ascii');
  const [streamFilter, setStreamFilter] = useState<'entire' | 'client-to-server' | 'server-to-client' | 'conversation-flow' | 'timeline-all'>('conversation-flow');
  const [showDeltaTimes, setShowDeltaTimes] = useState(false);
  const [findTerm, setFindTerm] = useState('');

  if (!stream) return null;

  // Get current stream data based on filter
  const displayData = useMemo(() => {
    if (!stream) return '';

    if (streamFilter === 'entire') {
      return stream.entireConversation || '';
    } else if (streamFilter === 'client-to-server') {
      return stream.clientToServer || '';
    } else if (streamFilter === 'server-to-client') {
      return stream.serverToClient || '';
    }

    return '';
  }, [stream, streamFilter]);

  const clientBytes = stream.clientToServer?.length || 0;
  const serverBytes = stream.serverToClient?.length || 0;
  const totalBytes = stream.totalBytes || stream.entireConversation?.length || 0;

  // Format data based on "Show As" mode
  const formatData = (data: string) => {
    if (!data) return 'No data';

    switch (showAs) {
      case 'ascii':
        return data;

      case 'ebcdic':
        // EBCDIC conversion (simplified)
        return data.split('').map(c => {
          const code = c.charCodeAt(0);
          return code >= 32 && code <= 126 ? c : '.';
        }).join('');

      case 'hex':
        return data.split('').map((c, i) => {
          const hex = c.charCodeAt(0).toString(16).padStart(2, '0').toUpperCase();
          return (i % 16 === 0 ? '\n' : '') + hex + ' ';
        }).join('').trim();

      case 'c-array':
        const cArray = data.split('').map((c, i) => {
          const hex = c.charCodeAt(0).toString(16).padStart(2, '0');
          const comma = i < data.length - 1 ? ',' : '';
          const newline = i % 12 === 11 ? '\n  ' : '';
          return `0x${hex}${comma}${newline}`;
        }).join('');
        return `char data[${data.length}] = {\n  ${cArray}\n};`;

      case 'raw':
        return data;

      case 'yaml':
        return `stream_${stream.streamId}:\n  client_to_server: |\n    ${stream.clientToServer?.replace(/\n/g, '\n    ')}\n  server_to_client: |\n    ${stream.serverToClient?.replace(/\n/g, '\n    ')}`;

      default:
        return data;
    }
  };

  const downloadStream = () => {
    const content = displayData;
    const blob = new Blob([content], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `tcp-stream-${stream.streamId}-${streamFilter}.txt`;
    a.click();
    URL.revokeObjectURL(url);
    toast.success('Stream downloaded!');
  };

  const copyStream = () => {
    navigator.clipboard.writeText(displayData);
    toast.success('Stream copied to clipboard!');
  };

  const currentStreamIndex = allStreams.indexOf(stream.streamId);
  const hasPrevStream = currentStreamIndex > 0;
  const hasNextStream = currentStreamIndex < allStreams.length - 1;

  const node0 = stream.node0 || 'Unknown';
  const node1 = stream.node1 || 'Unknown';

  const renderContent = () => {
    // TIMELINE VIEW - Show ALL streams chronologically
    if (streamFilter === 'timeline-all') {
      // Extract all TCP payloads from ALL packets
      const allPayloads: any[] = [];

      packets.forEach(pkt => {
        const tcpPayloadHex = pkt.rawLayers?.tcp?.['tcp.payload'] || pkt.layers?.tcp?.['tcp.payload'];

        if (tcpPayloadHex && pkt.tcpStream !== null && pkt.tcpStream !== undefined) {
          const asciiData = hexToAscii(tcpPayloadHex);

          if (asciiData.length > 0) {
            allPayloads.push({
              streamId: pkt.tcpStream,
              frame: pkt.frame || pkt.index,
              timestamp: pkt.timestamp,
              source: pkt.source,
              destination: pkt.destination,
              srcPort: pkt.srcPort,
              dstPort: pkt.dstPort,
              data: asciiData,
              length: asciiData.length,
              protocol: pkt.protocol
            });
          }
        }
      });

      // Sort by timestamp
      allPayloads.sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime());

      if (allPayloads.length === 0) {
        return (
          <div className="text-center text-muted-foreground py-12">
            <p>No TCP payload data found in any stream</p>
          </div>
        );
      }

      // Display timeline
      return (
        <div className="space-y-2">
          {allPayloads.map((payload, idx) => {
            const delta = idx > 0
              ? (new Date(payload.timestamp).getTime() - new Date(allPayloads[idx - 1].timestamp).getTime()) / 1000
              : 0;

            // Get color based on stream ID
            const streamColors = ['bg-red-500/10 border-red-500/30', 'bg-blue-500/10 border-blue-500/30', 'bg-green-500/10 border-green-500/30', 'bg-purple-500/10 border-purple-500/30', 'bg-yellow-500/10 border-yellow-500/30', 'bg-cyan-500/10 border-cyan-500/30'];
            const streamColor = streamColors[payload.streamId % streamColors.length];

            return (
              <div key={idx}>
                {/* Time marker */}
                {showDeltaTimes && idx > 0 && delta > 0.5 && (
                  <div className="text-xs text-muted-foreground text-center py-1 border-t border-dashed border-border mt-2">
                    +{delta.toFixed(3)}s
                  </div>
                )}

                {/* Payload card */}
                <div className={`border ${streamColor} rounded p-3`}>
                  <div className="flex items-center justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <span className="px-2 py-1 bg-accent/20 text-accent rounded text-xs font-bold">
                        STREAM {payload.streamId}
                      </span>
                      <span className="text-xs text-muted-foreground">Frame {payload.frame}</span>
                      <span className="text-xs font-mono">
                        {payload.source}:{payload.srcPort || '?'} → {payload.destination}:{payload.dstPort || '?'}
                      </span>
                    </div>
                    <div className="flex items-center gap-2 text-xs text-muted-foreground">
                      {showDeltaTimes && idx > 0 && <span>+{delta.toFixed(3)}s</span>}
                      <span>{payload.length} bytes</span>
                    </div>
                  </div>
                  <pre className="whitespace-pre-wrap break-all text-foreground text-xs font-mono">
                    {formatData(payload.data)}
                  </pre>
                </div>
              </div>
            );
          })}

          <div className="text-center text-sm text-muted-foreground mt-4 pt-4 border-t border-border">
            Timeline: {allPayloads.length} packets with payload from {allStreams.length} streams
          </div>
        </div>
      );
    }

    if (totalBytes === 0) {
      return (
        <div className="text-center text-muted-foreground py-12">
          <p className="text-lg font-semibold mb-2">No Stream Data Available</p>
          <p className="text-sm">This TCP stream has no payload data or stream ID {stream.streamId} not found.</p>
          <p className="text-xs mt-2">The stream may only contain TCP handshake/ACK packets without application data.</p>
        </div>
      );
    }

    // CONVERSATION FLOW - Show entire conversation chronologically with color coding
    if (streamFilter === 'conversation-flow' && stream.payloads && Array.isArray(stream.payloads) && stream.payloads.length > 0) {
      return (
        <div className="font-mono text-xs space-y-2">
          {stream.payloads.map((payload: any, idx: number) => {
            const delta = idx > 0
              ? (new Date(payload.timestamp).getTime() - new Date(stream.payloads[idx - 1].timestamp).getTime()) / 1000
              : 0;

            return (
              <div key={idx} className={`border ${payload.direction === 'client' ? 'border-red-500/30 bg-red-500/5' : 'border-blue-500/30 bg-blue-500/5'} rounded p-3`}>
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <span className={`px-2 py-1 rounded text-xs font-semibold ${payload.direction === 'client' ? 'bg-red-500/20 text-red-400' : 'bg-blue-500/20 text-blue-400'}`}>
                      {payload.direction === 'client' ? 'CLIENT → SERVER' : 'SERVER → CLIENT'}
                    </span>
                    <span className="text-xs text-muted-foreground">Frame {payload.frame}</span>
                  </div>
                  <div className="flex items-center gap-3 text-xs text-muted-foreground">
                    {showDeltaTimes && idx > 0 && <span>+{delta.toFixed(3)}s</span>}
                    <span>{payload.length} bytes</span>
                  </div>
                </div>
                <pre className="whitespace-pre-wrap break-all text-foreground">{formatData(payload.data)}</pre>
              </div>
            );
          })}
        </div>
      );
    }

    // Show with delta times (legacy - kept for compatibility)
    if (showDeltaTimes && stream.payloads && Array.isArray(stream.payloads) && stream.payloads.length > 0) {
      return (
        <div className="font-mono text-xs space-y-2">
          {stream.payloads.map((payload: any, idx: number) => {
            const delta = idx > 0
              ? (new Date(payload.timestamp).getTime() - new Date(stream.payloads[idx - 1].timestamp).getTime()) / 1000
              : 0;

            return (
              <div key={idx} className={`${payload.direction === 'client' ? 'bg-red-500/10' : 'bg-blue-500/10'} rounded p-2`}>
                <div className="flex items-center justify-between mb-1">
                  <span className={`text-xs font-semibold ${payload.direction === 'client' ? 'text-red-400' : 'text-blue-400'}`}>
                    {payload.direction === 'client' ? 'Client → Server' : 'Server → Client'} (Frame {payload.frame})
                  </span>
                  <span className="text-xs text-muted-foreground">
                    +{delta.toFixed(3)}s | {payload.length} bytes
                  </span>
                </div>
                <pre className="whitespace-pre-wrap break-all">{payload.data}</pre>
              </div>
            );
          })}
        </div>
      );
    }

    // Regular view (entire conversation or filtered)
    const formatted = formatData(displayData);

    if (streamFilter === 'entire' && showAs === 'ascii') {
      // Show client/server separated for better readability
      return (
        <div className="space-y-4">
          <div>
            <div className="text-sm font-semibold mb-2 text-red-400 flex items-center justify-between">
              <span>Client → Server ({node0} → {node1})</span>
              <span>{clientBytes} bytes</span>
            </div>
            <div className="bg-red-500/10 border border-red-500/30 rounded p-4 font-mono text-xs max-h-96 overflow-auto">
              <pre className="whitespace-pre-wrap break-all">{stream.clientToServer || 'No client data'}</pre>
            </div>
          </div>
          <div>
            <div className="text-sm font-semibold mb-2 text-blue-400 flex items-center justify-between">
              <span>Server → Client ({node1} → {node0})</span>
              <span>{serverBytes} bytes</span>
            </div>
            <div className="bg-blue-500/10 border border-blue-500/30 rounded p-4 font-mono text-xs max-h-96 overflow-auto">
              <pre className="whitespace-pre-wrap break-all">{stream.serverToClient || 'No server data'}</pre>
            </div>
          </div>
        </div>
      );
    }

    return (
      <div className="font-mono text-xs p-4 bg-muted/20 rounded">
        <pre className="whitespace-pre-wrap break-all">{formatted}</pre>
      </div>
    );
  };

  return (
    <div className="fixed inset-0 bg-background/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-card border border-border rounded-lg w-full max-w-6xl max-h-[90vh] flex flex-col shadow-2xl">
        {/* Header */}
        <div className="px-6 py-4 border-b border-border">
          <div className="flex items-center justify-between">
            <div className="flex-1">
              <h2 className="text-lg font-semibold">Follow TCP Stream</h2>
              <div className="flex items-center gap-4 mt-2 text-sm text-muted-foreground">
                <span className="font-mono">{node0} ↔ {node1}</span>
                <span>Stream {stream.streamId}</span>
                <span>{totalBytes} bytes total</span>
              </div>
            </div>
            <Button variant="ghost" size="sm" onClick={onClose}>
              <X className="w-4 h-4" />
            </Button>
          </div>
        </div>

        {/* Controls */}
        <div className="px-6 py-3 border-b border-border space-y-3">
          {/* Stream Direction Filter */}
          <div className="flex items-center gap-3">
            <label className="text-sm font-medium min-w-[80px]">View:</label>
            <select
              value={streamFilter}
              onChange={(e) => setStreamFilter(e.target.value as any)}
              className="flex-1 px-3 py-2 bg-background border border-border rounded text-sm"
            >
              <option value="conversation-flow">Conversation Flow (This stream, {totalBytes} bytes)</option>
              <option value="timeline-all">Timeline View (ALL streams chronological)</option>
              <option value="entire">Entire conversation (Combined, {totalBytes} bytes)</option>
              <option value="client-to-server">Client → Server only ({node0} → {node1}, {clientBytes} bytes)</option>
              <option value="server-to-client">Server → Client only ({node1} → {node0}, {serverBytes} bytes)</option>
            </select>
          </div>

          {/* Show As Format */}
          <div className="flex items-center gap-3">
            <label className="text-sm font-medium min-w-[80px]">Show as:</label>
            <select
              value={showAs}
              onChange={(e) => setShowAs(e.target.value as any)}
              className="flex-1 px-3 py-2 bg-background border border-border rounded text-sm"
            >
              <option value="ascii">ASCII</option>
              <option value="ebcdic">EBCDIC</option>
              <option value="hex">Hex Dump</option>
              <option value="c-array">C Array</option>
              <option value="raw">Raw</option>
              <option value="yaml">YAML</option>
            </select>
          </div>

          {/* Options */}
          <div className="flex items-center gap-6">
            <label className="flex items-center gap-2 text-sm cursor-pointer">
              <input
                type="checkbox"
                checked={showDeltaTimes}
                onChange={(e) => setShowDeltaTimes(e.target.checked)}
                className="w-4 h-4"
              />
              Show delta times
            </label>

            {/* Stream Navigation */}
            {allStreams.length > 1 && onNavigateStream && (
              <div className="flex items-center gap-2">
                <span className="text-sm text-muted-foreground">Navigate Streams:</span>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={!hasPrevStream}
                  onClick={() => hasPrevStream && onNavigateStream(allStreams[currentStreamIndex - 1])}
                  title="Previous stream (lower stream number)"
                >
                  <ChevronUp className="w-3 h-3 mr-1" />
                  Prev
                </Button>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={!hasNextStream}
                  onClick={() => hasNextStream && onNavigateStream(allStreams[currentStreamIndex + 1])}
                  title="Next stream (higher stream number)"
                >
                  Next
                  <ChevronDown className="w-3 h-3 ml-1" />
                </Button>
              </div>
            )}
          </div>

          {/* Find */}
          <div className="flex items-center gap-2">
            <Search className="w-4 h-4 text-muted-foreground" />
            <input
              type="text"
              placeholder="Find in stream..."
              value={findTerm}
              onChange={(e) => setFindTerm(e.target.value)}
              className="flex-1 px-3 py-2 bg-background border border-border rounded text-sm"
            />
          </div>
        </div>

        {/* Actions Bar */}
        <div className="px-6 py-2 border-b border-border flex items-center justify-between bg-muted/20">
          <div className="text-xs text-muted-foreground">
            Showing {displayData.length} bytes
            {findTerm && ` | Searching for: "${findTerm}"`}
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
        <div className="px-6 py-4 border-t border-border flex items-center justify-between bg-muted/20">
          <div className="text-sm text-muted-foreground">
            {streamFilter === 'timeline-all' ? 'Timeline View (All Streams)' : `TCP Stream ${stream.streamId} | ${stream.payloads?.length || 0} packets with payload | ${totalBytes} bytes total`}
          </div>
          <Button onClick={onClose}>Close</Button>
        </div>
      </div>
    </div>
  );
};

function hexToAscii(hex: string): string {
  if (!hex) return '';

  const cleaned = hex.replace(/:/g, '').replace(/\s/g, '');
  const bytes = cleaned.match(/.{1,2}/g) || [];

  return bytes
    .map(byte => {
      const code = parseInt(byte, 16);
      if (code === 10 || code === 13 || code === 9) return String.fromCharCode(code);
      if (code >= 32 && code <= 126) return String.fromCharCode(code);
      return '.';
    })
    .join('');
}
