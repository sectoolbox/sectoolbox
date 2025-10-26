// Extract TCP stream data from existing packets (no backend call needed)

import { hexToAscii } from './formatting';

export function extractTcpStream(packets: any[], streamId: number): any {
  // Filter packets for this stream
  const streamPackets = packets.filter(pkt => pkt.tcpStream === streamId);

  if (streamPackets.length === 0) {
    return {
      streamId,
      node0: 'Unknown',
      node1: 'Unknown',
      clientToServer: '',
      serverToClient: '',
      entireConversation: '',
      payloads: [],
      totalBytes: 0
    };
  }

  // Determine nodes
  const firstPacket = streamPackets[0];

  const srcPortDisplay = firstPacket.srcPort !== null && firstPacket.srcPort !== undefined ? firstPacket.srcPort : '?';
  const dstPortDisplay = (firstPacket.dstPort !== null && firstPacket.dstPort !== undefined)
    ? firstPacket.dstPort
    : (firstPacket.destPort !== null && firstPacket.destPort !== undefined ? firstPacket.destPort : '?');

  const node0 = `${firstPacket.source}:${srcPortDisplay}`;
  const node1 = `${firstPacket.destination}:${dstPortDisplay}`;

  // Extract payloads
  const payloads: any[] = [];
  let clientToServerData = '';
  let serverToClientData = '';

  streamPackets.forEach((pkt) => {
    // Try to extract TCP payload from raw layers
    const tcpPayloadHex = pkt.rawLayers?.tcp?.['tcp.payload'] || pkt.layers?.tcp?.['tcp.payload'];

    if (tcpPayloadHex) {
      // Convert hex to ASCII
      const asciiData = hexToAscii(tcpPayloadHex);

      if (asciiData.length > 0) {
        const isClientToServer = pkt.source === firstPacket.source && pkt.srcPort === firstPacket.srcPort;

        payloads.push({
          frame: pkt.frame,
          timestamp: pkt.timestamp,
          direction: isClientToServer ? 'client' : 'server',
          data: asciiData,
          length: asciiData.length,
          hexData: tcpPayloadHex
        });

        if (isClientToServer) {
          clientToServerData += asciiData;
        } else {
          serverToClientData += asciiData;
        }
      }
    }
  });

  const entireConversation = clientToServerData + serverToClientData;
  const totalBytes = entireConversation.length;

  return {
    streamId,
    node0,
    node1,
    clientToServer: clientToServerData,
    serverToClient: serverToClientData,
    entireConversation,
    payloads,
    totalBytes
  };
}

// Get all unique TCP stream IDs from packets
export function getAllStreamIds(packets: any[]): number[] {
  const ids = new Set<number>();

  packets.forEach(pkt => {
    if (pkt.tcpStream !== null && pkt.tcpStream !== undefined) {
      ids.add(pkt.tcpStream);
    }
  });

  return Array.from(ids).sort((a, b) => a - b);
}
