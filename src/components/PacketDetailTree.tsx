import React, { useState } from 'react';
import { ChevronRight, ChevronDown, Copy } from 'lucide-react';
import { Button } from './ui/button';

interface PacketDetailTreeProps {
  packet: any;
}

export const PacketDetailTree: React.FC<PacketDetailTreeProps> = ({ packet }) => {
  const [expandedLayers, setExpandedLayers] = useState<Set<string>>(new Set(['frame', 'eth', 'ip', 'tcp']));

  const toggleLayer = (layerName: string) => {
    const newExpanded = new Set(expandedLayers);
    if (newExpanded.has(layerName)) {
      newExpanded.delete(layerName);
    } else {
      newExpanded.add(layerName);
    }
    setExpandedLayers(newExpanded);
  };

  const renderLayer = (layerName: string, layerData: any, depth: number = 0) => {
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
      'icmp': 'Internet Control Message Protocol',
      'arp': 'Address Resolution Protocol'
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
              if (typeof value === 'object' && !Array.isArray(value)) {
                // Nested object - render as sub-layer
                return renderLayer(field, value, depth + 1);
              } else {
                // Field value
                const displayValue = Array.isArray(value) ? value[0] : value;
                if (!displayValue) return null;

                return (
                  <div
                    key={field}
                    className="py-0.5 px-2 hover:bg-muted/20 flex items-start gap-2"
                    style={{ paddingLeft: `${indent + 32}px` }}
                  >
                    <span className="text-muted-foreground min-w-[200px]">
                      {field.replace(/_/g, '.').replace(/\./g, ' ')}:
                    </span>
                    <span className="text-foreground break-all">
                      {String(displayValue)}
                    </span>
                  </div>
                );
              }
            })}
          </div>
        )}
      </div>
    );
  };

  const copyHex = () => {
    if (packet.data) {
      navigator.clipboard.writeText(packet.data);
    }
  };

  return (
    <div className="space-y-2">
      {/* Packet Detail Tree */}
      <div className="bg-background border border-border rounded-lg overflow-hidden">
        <div className="bg-muted/50 px-3 py-2 border-b border-border flex items-center justify-between">
          <span className="text-sm font-semibold">Packet Details - Frame {packet.index}</span>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={copyHex}>
              <Copy className="w-3 h-3 mr-1" />
              Copy Hex
            </Button>
          </div>
        </div>

        <div className="max-h-96 overflow-auto">
          {packet.rawLayers ? (
            Object.entries(packet.rawLayers).map(([layerName, layerData]) =>
              renderLayer(layerName, layerData, 0)
            )
          ) : (
            <div className="p-4 text-center text-sm text-muted-foreground">
              No layer data available
            </div>
          )}
        </div>
      </div>

      {/* Hex Dump */}
      {packet.data && (
        <div className="bg-background border border-border rounded-lg overflow-hidden">
          <div className="bg-muted/50 px-3 py-2 border-b border-border">
            <span className="text-sm font-semibold">Packet Bytes ({packet.size} bytes)</span>
          </div>
          <div className="max-h-64 overflow-auto p-4">
            <div className="font-mono text-xs space-y-1">
              {formatHexDump(packet.data).map((line, i) => (
                <div key={i} className="flex gap-4">
                  <span className="text-accent font-bold">{line.offset}</span>
                  <span className="text-green-400">{line.hex}</span>
                  <span className="text-blue-400">{line.ascii}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

function formatHexDump(hexString: string): Array<{ offset: string; hex: string; ascii: string }> {
  // Remove spaces and colons
  const hex = hexString.replace(/[:\s]/g, '');
  const lines: Array<{ offset: string; hex: string; ascii: string }> = [];

  for (let i = 0; i < hex.length; i += 32) {
    const chunk = hex.substr(i, 32);
    const offset = (i / 2).toString(16).padStart(4, '0').toUpperCase();

    // Format hex part with spaces
    const hexPart = chunk.match(/.{1,2}/g)?.join(' ') || '';

    // Convert to ASCII
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
}
