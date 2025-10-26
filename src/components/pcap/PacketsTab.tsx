import React, { useState, useRef, useEffect } from 'react';
import { Search, Filter, ArrowUpDown } from 'lucide-react';
import { Button } from '../ui/button';
import toast from 'react-hot-toast';

interface PacketsTabProps {
  packets: any[];
  onFollowStream: (packet: any) => void;
  onApplyFilter: (filter: string) => void;
  selectedPacketIndex: number | null;
  onSelectPacket: (index: number) => void;
  onOpenPacketDetail: (packet: any) => void;
  externalFilter?: string;
}

export const PacketsTab: React.FC<PacketsTabProps> = ({
  packets,
  onFollowStream,
  onApplyFilter,
  selectedPacketIndex,
  onSelectPacket,
  onOpenPacketDetail,
  externalFilter
}) => {
  const [displayFilter, setDisplayFilter] = useState('');
  const [quickFilter, setQuickFilter] = useState('');
  const [sortColumn, setSortColumn] = useState<string | null>(null);
  const [sortDirection, setSortDirection] = useState<'asc' | 'desc'>('asc');
  const [contextMenu, setContextMenu] = useState<{ x: number; y: number; packet: any } | null>(null);
  const tableRef = useRef<HTMLDivElement>(null);

  // Sync external filter with display filter
  useEffect(() => {
    if (externalFilter !== undefined && externalFilter !== displayFilter) {
      setDisplayFilter(externalFilter);
    }
  }, [externalFilter]);

  // Filter packets based on search
  const filteredPackets = packets.filter(pkt => {
    if (!quickFilter) return true;
    const searchStr = `${pkt.protocol} ${pkt.source} ${pkt.destination} ${pkt.info} ${pkt.srcPort} ${pkt.destPort}`.toLowerCase();
    return searchStr.includes(quickFilter.toLowerCase());
  });

  // Apply display filter (basic implementation - can be enhanced)
  const displayFilteredPackets = filteredPackets.filter(pkt => {
    if (!displayFilter) return true;

    // Simple filter parsing
    try {
      if (displayFilter.includes('==')) {
        const [field, value] = displayFilter.split('==').map(s => s.trim());
        if (field === 'tcp.port' || field === 'port') {
          const port = parseInt(value);
          return pkt.srcPort === port || pkt.destPort === port;
        }
        if (field === 'ip.src' || field === 'src') {
          return pkt.source === value;
        }
        if (field === 'ip.dst' || field === 'dst') {
          return pkt.destination === value;
        }
        if (field === 'protocol' || field === 'proto') {
          return pkt.protocol?.toLowerCase() === value.toLowerCase();
        }
      } else if (displayFilter.includes('contains')) {
        const [, value] = displayFilter.split('contains').map(s => s.trim());
        const searchVal = value.replace(/["']/g, '');
        return JSON.stringify(pkt).toLowerCase().includes(searchVal.toLowerCase());
      } else {
        // Simple protocol filter
        return pkt.protocol?.toLowerCase().includes(displayFilter.toLowerCase());
      }
    } catch (e) {
      return true;
    }

    return true;
  });

  // Sort packets
  const sortedPackets = [...displayFilteredPackets];
  if (sortColumn) {
    sortedPackets.sort((a, b) => {
      let aVal = a[sortColumn];
      let bVal = b[sortColumn];

      if (sortColumn === 'timestamp') {
        aVal = new Date(aVal).getTime();
        bVal = new Date(bVal).getTime();
      } else if (typeof aVal === 'number') {
        // numeric sort
      } else {
        aVal = String(aVal || '');
        bVal = String(bVal || '');
      }

      if (sortDirection === 'asc') {
        return aVal > bVal ? 1 : -1;
      } else {
        return aVal < bVal ? 1 : -1;
      }
    });
  }

  const toggleSort = (column: string) => {
    if (sortColumn === column) {
      setSortDirection(sortDirection === 'asc' ? 'desc' : 'asc');
    } else {
      setSortColumn(column);
      setSortDirection('asc');
    }
  };


  const getRowColor = (pkt: any) => {
    if (pkt.colorRule === 'http-get') return 'bg-green-500/5 hover:bg-green-500/10';
    if (pkt.colorRule === 'http-post') return 'bg-blue-500/5 hover:bg-blue-500/10';
    if (pkt.colorRule === 'http') return 'bg-purple-500/5 hover:bg-purple-500/10';
    if (pkt.colorRule === 'dns') return 'bg-yellow-500/5 hover:bg-yellow-500/10';
    if (pkt.colorRule === 'tcp-syn') return 'bg-cyan-500/5 hover:bg-cyan-500/10';
    if (pkt.colorRule === 'tcp') return 'bg-blue-400/5 hover:bg-blue-400/10';
    if (pkt.colorRule === 'udp') return 'bg-green-400/5 hover:bg-green-400/10';
    if (pkt.colorRule === 'icmp') return 'bg-red-400/5 hover:bg-red-400/10';
    if (pkt.colorRule === 'arp') return 'bg-orange-400/5 hover:bg-orange-400/10';
    return 'hover:bg-muted/10';
  };

  const handleRightClick = (e: React.MouseEvent, packet: any) => {
    e.preventDefault();
    setContextMenu({ x: e.clientX, y: e.clientY, packet });
  };

  useEffect(() => {
    const handleClick = () => setContextMenu(null);
    document.addEventListener('click', handleClick);
    return () => document.removeEventListener('click', handleClick);
  }, []);

  return (
    <div className="space-y-4 p-4">
      {/* Filters */}
      <div className="flex gap-3 items-center flex-wrap">
        <div className="flex-1 flex items-center gap-2 bg-card border border-border rounded px-3 py-2">
          <Search className="w-4 h-4 text-muted-foreground" />
          <input
            type="text"
            placeholder="Quick search (source, dest, protocol, info)..."
            value={quickFilter}
            onChange={(e) => setQuickFilter(e.target.value)}
            className="flex-1 bg-transparent outline-none text-sm"
          />
        </div>
        <div className="flex items-center gap-2 bg-card border border-border rounded px-3 py-2">
          <Filter className="w-4 h-4 text-muted-foreground" />
          <input
            type="text"
            placeholder="Display filter (e.g., tcp.port == 80)"
            value={displayFilter}
            onChange={(e) => setDisplayFilter(e.target.value)}
            className="w-64 bg-transparent outline-none text-sm"
          />
        </div>
        <Button variant="outline" size="sm" onClick={() => { setQuickFilter(''); setDisplayFilter(''); }}>
          Clear
        </Button>
      </div>

      {/* Quick Filter Buttons */}
      <div className="flex gap-2 flex-wrap">
        <Button size="sm" variant="outline" onClick={() => setQuickFilter('HTTP')}>HTTP</Button>
        <Button size="sm" variant="outline" onClick={() => setQuickFilter('DNS')}>DNS</Button>
        <Button size="sm" variant="outline" onClick={() => setQuickFilter('TCP')}>TCP</Button>
        <Button size="sm" variant="outline" onClick={() => setQuickFilter('TLS')}>TLS</Button>
        <Button size="sm" variant="outline" onClick={() => setDisplayFilter('tcp.flags.syn == 1')}>SYN Packets</Button>
        <Button size="sm" variant="outline" onClick={() => setDisplayFilter('http.request')}>HTTP Requests</Button>
      </div>

      {/* Packet Count */}
      <div className="text-sm text-muted-foreground">
        Showing {sortedPackets.length} of {packets.length} packets
        {(quickFilter || displayFilter) && ` (filtered)`}
      </div>

      {/* Packet Table */}
      <div ref={tableRef} className="bg-card border border-border rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-muted/50 sticky top-0">
              <tr className="text-xs text-muted-foreground border-b">
                <th className="p-2 text-left w-12">#</th>
                <th className="p-2 text-left w-32 cursor-pointer" onClick={() => toggleSort('timestamp')}>
                  <div className="flex items-center gap-1">
                    Time <ArrowUpDown className="w-3 h-3" />
                  </div>
                </th>
                <th className="p-2 text-left w-32 cursor-pointer" onClick={() => toggleSort('source')}>
                  <div className="flex items-center gap-1">
                    Source <ArrowUpDown className="w-3 h-3" />
                  </div>
                </th>
                <th className="p-2 text-left w-32 cursor-pointer" onClick={() => toggleSort('destination')}>
                  <div className="flex items-center gap-1">
                    Destination <ArrowUpDown className="w-3 h-3" />
                  </div>
                </th>
                <th className="p-2 text-left w-20 cursor-pointer" onClick={() => toggleSort('protocol')}>
                  <div className="flex items-center gap-1">
                    Protocol <ArrowUpDown className="w-3 h-3" />
                  </div>
                </th>
                <th className="p-2 text-left w-20 cursor-pointer" onClick={() => toggleSort('size')}>
                  <div className="flex items-center gap-1">
                    Length <ArrowUpDown className="w-3 h-3" />
                  </div>
                </th>
                <th className="p-2 text-left">Info</th>
              </tr>
            </thead>
            <tbody>
              {sortedPackets.map((pkt) => (
                <tr
                  key={pkt.index}
                  className={`border-t cursor-pointer ${getRowColor(pkt)} ${selectedPacketIndex === pkt.index ? 'ring-2 ring-accent' : ''}`}
                  onClick={() => {
                    onSelectPacket(pkt.index);
                    onOpenPacketDetail(pkt);
                  }}
                  onContextMenu={(e) => handleRightClick(e, pkt)}
                  data-frame={pkt.index}
                >
                  <td className="p-2 text-accent font-mono text-xs">
                    {pkt.index}
                  </td>
                      <td className="p-2 font-mono text-xs text-muted-foreground">
                        {new Date(pkt.timestamp).toLocaleTimeString()}
                      </td>
                      <td className="p-2 font-mono text-xs">{pkt.source}</td>
                      <td className="p-2 font-mono text-xs">{pkt.destination}</td>
                      <td className="p-2">
                        <span className="px-2 py-1 bg-accent/20 text-accent rounded text-xs font-mono">
                          {pkt.protocol}
                        </span>
                      </td>
                      <td className="p-2 font-mono text-xs text-muted-foreground">
                        {pkt.size.toLocaleString()}
                      </td>
                  <td className="p-2 text-xs">
                    <div className="max-w-md truncate">{pkt.info}</div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Context Menu */}
      {contextMenu && (
        <div
          className="fixed bg-card border border-border rounded-lg shadow-lg py-1 z-50"
          style={{ top: contextMenu.y, left: contextMenu.x }}
        >
          <button
            className="w-full text-left px-4 py-2 text-sm hover:bg-muted"
            onClick={() => {
              if (contextMenu.packet.tcpStream !== undefined) {
                onFollowStream(contextMenu.packet);
              } else {
                toast.error('No TCP stream available for this packet');
              }
              setContextMenu(null);
            }}
          >
            Follow TCP Stream
          </button>
          <button
            className="w-full text-left px-4 py-2 text-sm hover:bg-muted"
            onClick={() => {
              navigator.clipboard.writeText(JSON.stringify(contextMenu.packet, null, 2));
              toast.success('Packet data copied to clipboard');
              setContextMenu(null);
            }}
          >
            Copy Packet Data
          </button>
          <button
            className="w-full text-left px-4 py-2 text-sm hover:bg-muted"
            onClick={() => {
              // Use exact same logic as the "Copy Hex" button in PacketDetailModal
              const getPacketHexData = (): string | null => {
                const pkt = contextMenu.packet;
                // Try different locations where hex data might be
                if (pkt.data) return pkt.data;
                if (pkt.rawLayers?.frame?.['frame.raw']) return pkt.rawLayers.frame['frame.raw'][0] || pkt.rawLayers.frame['frame.raw'];
                if (pkt.layers?.frame?.['frame.raw']) return pkt.layers.frame['frame.raw'][0] || pkt.layers.frame['frame.raw'];
                if (pkt.rawLayers?.frame_raw) return pkt.rawLayers.frame_raw[0] || pkt.rawLayers.frame_raw;

                // Try to extract from tcp.payload or other payload fields
                const tcpPayload = pkt.rawLayers?.tcp?.['tcp.payload'] || pkt.layers?.tcp?.['tcp.payload'];
                if (tcpPayload) return tcpPayload;

                return null;
              };
              
              const hexData = getPacketHexData();
              navigator.clipboard.writeText(hexData || 'No hex data');
              toast.success('Hex data copied to clipboard');
              setContextMenu(null);
            }}
          >
            Copy Hex Data
          </button>
          <button
            className="w-full text-left px-4 py-2 text-sm hover:bg-muted border-t"
            onClick={() => {
              onApplyFilter(`ip.src == ${contextMenu.packet.source}`);
              toast.success(`Filter applied: ip.src == ${contextMenu.packet.source}`);
              setContextMenu(null);
            }}
          >
            Filter by Source IP
          </button>
          <button
            className="w-full text-left px-4 py-2 text-sm hover:bg-muted"
            onClick={() => {
              onApplyFilter(`ip.dst == ${contextMenu.packet.destination}`);
              toast.success(`Filter applied: ip.dst == ${contextMenu.packet.destination}`);
              setContextMenu(null);
            }}
          >
            Filter by Destination IP
          </button>
        </div>
      )}
    </div>
  );
};
