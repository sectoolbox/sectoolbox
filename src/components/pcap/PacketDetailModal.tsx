import React, { useState } from 'react';
import { X, Copy, Download, ChevronRight, ChevronDown } from 'lucide-react';
import { Button } from '../ui/button';

interface PacketDetailModalProps {
  packet: any;
  onClose: () => void;
  onFollowStream?: () => void;
}

export const PacketDetailModal: React.FC<PacketDetailModalProps> = ({
  packet,
  onClose,
  onFollowStream
}) => {
  const [expandedLayers, setExpandedLayers] = useState<Set<string>>(new Set(['frame', 'eth', 'ip', 'tcp', 'http', 'dns']));
  const [activeView, setActiveView] = useState<'tree' | 'hex' | 'raw'>('tree');

  const toggleLayer = (layerName: string) => {
    const newExpanded = new Set(expandedLayers);
    if (newExpanded.has(layerName)) {
      newExpanded.delete(layerName);
    } else {
      newExpanded.add(layerName);
    }
    setExpandedLayers(newExpanded);
  };

  const renderLayerTree = (layerName: string, layerData: any, depth: number = 0) => {
    if (!layerData || typeof layerData !== 'object') return null;

    const isExpanded = expandedLayers.has(layerName);
    const hasChildren = Object.keys(layerData).length > 0;
    const indent = depth * 20;

    const layerDisplayNames: Record<string, string> = {
      'frame': 'Frame',
      'eth': 'Ethernet II',
      'ip': 'Internet Protocol Version 4',
      'ipv6': 'Internet Protocol Version 6',
      'tcp': 'Transmission Control Protocol',
      'udp': 'User Datagram Protocol',
      'http': 'Hypertext Transfer Protocol',
      'dns': 'Domain Name System',
      'tls': 'Transport Layer Security',
      'ssl': 'Secure Sockets Layer',
      'icmp': 'Internet Control Message Protocol',
      'arp': 'Address Resolution Protocol',
      'ssh': 'Secure Shell Protocol',
      'ftp': 'File Transfer Protocol',
      'smtp': 'Simple Mail Transfer Protocol'
    };

    return (
      <div key={layerName} className="font-mono text-xs">
        <div
          className="flex items-center gap-1 py-1 px-2 hover:bg-accent/10 cursor-pointer"
          style={{ paddingLeft: `${indent + 8}px` }}
          onClick={() => toggleLayer(layerName)}
        >
          {hasChildren ? (
            isExpanded ? (
              <ChevronDown className="w-3 h-3 text-accent flex-shrink-0" />
            ) : (
              <ChevronRight className="w-3 h-3 text-muted-foreground flex-shrink-0" />
            )
          ) : (
            <span className="w-3 h-3 inline-block" />
          )}
          <span className="font-semibold text-accent">
            {layerDisplayNames[layerName] || layerName.toUpperCase()}
          </span>
        </div>

        {isExpanded && hasChildren && (
          <div>
            {Object.entries(layerData).map(([field, value]) => {
              if (typeof value === 'object' && !Array.isArray(value) && value !== null) {
                return renderLayerTree(field, value, depth + 1);
              } else {
                const displayValue = Array.isArray(value) ? value[0] : value;
                if (!displayValue || displayValue === null) return null;

                return (
                  <div
                    key={field}
                    className="py-0.5 px-2 hover:bg-muted/20 flex items-start gap-2 group"
                    style={{ paddingLeft: `${indent + 32}px` }}
                  >
                    <span className="text-muted-foreground min-w-[250px] break-words">
                      {field.replace(/_/g, '.').replace(/\./g, ' ')}:
                    </span>
                    <span className="text-foreground break-all flex-1">
                      {String(displayValue)}
                    </span>
                    <button
                      onClick={(e) => {
                        e.stopPropagation();
                        navigator.clipboard.writeText(String(displayValue));
                      }}
                      className="opacity-0 group-hover:opacity-100 transition-opacity"
                    >
                      <Copy className="w-3 h-3 text-muted-foreground hover:text-accent" />
                    </button>
                  </div>
                );
              }
            })}
          </div>
        )}
      </div>
    );
  };

  // Extract hex data from packet
  const getPacketHexData = (): string | null => {
    // Try different locations where hex data might be
    if (packet.data) return packet.data;
    if (packet.rawLayers?.frame?.['frame.raw']) return packet.rawLayers.frame['frame.raw'][0] || packet.rawLayers.frame['frame.raw'];
    if (packet.layers?.frame?.['frame.raw']) return packet.layers.frame['frame.raw'][0] || packet.layers.frame['frame.raw'];
    if (packet.rawLayers?.frame_raw) return packet.rawLayers.frame_raw[0] || packet.rawLayers.frame_raw;

    // Try to extract from tcp.payload or other payload fields
    const tcpPayload = packet.rawLayers?.tcp?.['tcp.payload'] || packet.layers?.tcp?.['tcp.payload'];
    if (tcpPayload) return tcpPayload;

    return null;
  };

  const formatHexDump = (hexString: string) => {
    const hex = hexString.replace(/[:\s]/g, '');
    const lines: Array<{ offset: string; hex: string; ascii: string }> = [];

    for (let i = 0; i < hex.length; i += 32) {
      const chunk = hex.substr(i, 32);
      const offset = (i / 2).toString(16).padStart(4, '0').toUpperCase();
      const hexPart = chunk.match(/.{1,2}/g)?.join(' ') || '';
      const asciiPart = chunk
        .match(/.{1,2}/g)
        ?.map(byte => {
          const code = parseInt(byte, 16);
          return code >= 32 && code <= 126 ? String.fromCharCode(code) : '.';
        })
        .join('') || '';

      lines.push({ offset, hex: hexPart.padEnd(47, ' '), ascii: asciiPart });
    }

    return lines;
  };

  const copyAllData = () => {
    navigator.clipboard.writeText(JSON.stringify(packet, null, 2));
  };

  const copyHexData = () => {
    const hexData = getPacketHexData();
    navigator.clipboard.writeText(hexData || 'No hex data');
  };

  const packetHexData = getPacketHexData();

  return (
    <div className="fixed inset-0 bg-background/80 backdrop-blur-sm z-50 flex items-center justify-center p-4">
      <div className="bg-card border border-border rounded-lg w-full max-w-6xl max-h-[90vh] flex flex-col shadow-2xl">
        {/* Header */}
        <div className="px-6 py-4 border-b border-border flex items-center justify-between bg-muted/20">
          <div>
            <h2 className="text-lg font-semibold">Packet Details - Frame {packet.index}</h2>
            <div className="text-sm text-muted-foreground mt-1">
              {packet.source} → {packet.destination} | {packet.protocol} | {packet.size} bytes
            </div>
          </div>
          <div className="flex items-center gap-2">
            {packet.tcpStream !== undefined && onFollowStream && (
              <Button size="sm" variant="outline" onClick={onFollowStream}>
                Follow TCP Stream
              </Button>
            )}
            <Button variant="ghost" size="sm" onClick={onClose}>
              <X className="w-4 h-4" />
            </Button>
          </div>
        </div>

        {/* View Tabs */}
        <div className="flex gap-1 px-6 pt-3 border-b border-border">
          <button
            onClick={() => setActiveView('tree')}
            className={`px-4 py-2 text-sm font-medium border-b-2 ${
              activeView === 'tree' ? 'border-accent text-accent' : 'border-transparent text-muted-foreground'
            }`}
          >
            Protocol Tree
          </button>
          <button
            onClick={() => setActiveView('hex')}
            className={`px-4 py-2 text-sm font-medium border-b-2 ${
              activeView === 'hex' ? 'border-accent text-accent' : 'border-transparent text-muted-foreground'
            }`}
          >
            Hex Dump
          </button>
          <button
            onClick={() => setActiveView('raw')}
            className={`px-4 py-2 text-sm font-medium border-b-2 ${
              activeView === 'raw' ? 'border-accent text-accent' : 'border-transparent text-muted-foreground'
            }`}
          >
            Raw JSON
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-auto p-6 bg-background">
          {activeView === 'tree' && (
            <div className="space-y-2">
              {packet.rawLayers ? (
                Object.entries(packet.rawLayers).map(([layerName, layerData]) =>
                  renderLayerTree(layerName, layerData, 0)
                )
              ) : (
                <div className="text-center text-muted-foreground py-12">
                  <div className="text-sm">No layer data available for this packet</div>
                  <div className="text-xs mt-2">This may be a parsed packet without raw tshark layers</div>
                </div>
              )}
            </div>
          )}

          {activeView === 'hex' && (
            <div>
              {packetHexData ? (
                <div className="font-mono text-xs space-y-1">
                  {formatHexDump(packetHexData).map((line, i) => (
                    <div key={i} className="flex gap-4 hover:bg-muted/20 px-2 py-1 rounded">
                      <span className="text-accent font-bold w-16">{line.offset}</span>
                      <span className="text-green-400 w-96">{line.hex}</span>
                      <span className="text-blue-400">{line.ascii}</span>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="text-center text-muted-foreground py-12">
                  <div className="text-sm mb-2">No hex data available for this packet</div>
                  <div className="text-xs">Packet may not have frame.raw data in tshark output</div>
                </div>
              )}
            </div>
          )}

          {activeView === 'raw' && (
            <div className="font-mono text-xs">
              <pre className="whitespace-pre-wrap break-words bg-muted/20 p-4 rounded">
                {JSON.stringify(packet, null, 2)}
              </pre>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-4 border-t border-border flex items-center justify-between bg-muted/20">
          <div className="text-sm text-muted-foreground">
            Frame {packet.index} | {new Date(packet.timestamp).toLocaleString()} | {packet.size} bytes
          </div>
          <div className="flex gap-2">
            <Button size="sm" variant="outline" onClick={copyHexData}>
              <Copy className="w-3 h-3 mr-1" />
              Copy Hex
            </Button>
            <Button size="sm" variant="outline" onClick={copyAllData}>
              <Copy className="w-3 h-3 mr-1" />
              Copy All
            </Button>
            <Button size="sm" onClick={onClose}>
              Close
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
};
