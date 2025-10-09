// USB PCAP Analysis Library
// Handles USB packet capture files with focus on HID keyboard reconstruction

export interface USBPacket {
  number: number
  timestamp: number
  source: string
  destination: string
  protocol: string
  info: string
  length: number
  endpoint: string
  direction: 'IN' | 'OUT' | 'SETUP'
  transferType: 'Control' | 'Bulk' | 'Interrupt' | 'Isochronous'
  capdata?: Uint8Array
  raw?: Uint8Array
}

export interface KeystrokeEvent {
  timestamp: number
  packetNumber: number
  key: string
  keyCode: number
  modifiers: {
    leftCtrl: boolean
    leftShift: boolean
    leftAlt: boolean
    leftGUI: boolean
    rightCtrl: boolean
    rightShift: boolean
    rightAlt: boolean
    rightGUI: boolean
  }
  rawData: Uint8Array
}

export interface USBDevice {
  deviceAddress: number
  vendorId?: string
  productId?: string
  deviceClass?: string
  deviceSubclass?: string
  manufacturer?: string
  product?: string
  serialNumber?: string
  endpoints: USBEndpoint[]
}

export interface USBEndpoint {
  address: number
  direction: 'IN' | 'OUT'
  transferType: 'Control' | 'Bulk' | 'Interrupt' | 'Isochronous'
  maxPacketSize: number
}

export interface USBAnalysisResult {
  packets: USBPacket[]
  devices: USBDevice[]
  keystrokes: KeystrokeEvent[]
  reconstructedText: string
  statistics: {
    totalPackets: number
    totalDevices: number
    totalKeystrokes: number
    captureStart: number
    captureEnd: number
    duration: number
  }
  leftoverData: Uint8Array[]
}

// HID Keyboard scan code to key mapping
const HID_KEYMAP: Record<number, string> = {
  0x00: '',
  0x04: 'a', 0x05: 'b', 0x06: 'c', 0x07: 'd', 0x08: 'e', 0x09: 'f',
  0x0a: 'g', 0x0b: 'h', 0x0c: 'i', 0x0d: 'j', 0x0e: 'k', 0x0f: 'l',
  0x10: 'm', 0x11: 'n', 0x12: 'o', 0x13: 'p', 0x14: 'q', 0x15: 'r',
  0x16: 's', 0x17: 't', 0x18: 'u', 0x19: 'v', 0x1a: 'w', 0x1b: 'x',
  0x1c: 'y', 0x1d: 'z',
  0x1e: '1', 0x1f: '2', 0x20: '3', 0x21: '4', 0x22: '5',
  0x23: '6', 0x24: '7', 0x25: '8', 0x26: '9', 0x27: '0',
  0x28: '\n', // Enter
  0x29: '[ESC]',
  0x2a: '[BACKSPACE]',
  0x2b: '\t', // Tab
  0x2c: ' ',  // Space
  0x2d: '-', 0x2e: '=', 0x2f: '[', 0x30: ']', 0x31: '\\',
  0x33: ';', 0x34: '\'', 0x35: '`', 0x36: ',', 0x37: '.', 0x38: '/',
  0x39: '[CAPSLOCK]',
  0x3a: '[F1]', 0x3b: '[F2]', 0x3c: '[F3]', 0x3d: '[F4]', 0x3e: '[F5]',
  0x3f: '[F6]', 0x40: '[F7]', 0x41: '[F8]', 0x42: '[F9]', 0x43: '[F10]',
  0x44: '[F11]', 0x45: '[F12]',
  0x4f: '[RIGHT]', 0x50: '[LEFT]', 0x51: '[DOWN]', 0x52: '[UP]',
  0x53: '[NUMLOCK]',
  0x54: '/', 0x55: '*', 0x56: '-', 0x57: '+',
  0x58: '\n', // Keypad Enter
  0x59: '1', 0x5a: '2', 0x5b: '3', 0x5c: '4', 0x5d: '5',
  0x5e: '6', 0x5f: '7', 0x60: '8', 0x61: '9', 0x62: '0',
  0x63: '.',
  0x65: '[MENU]',
}

// Shifted keys
const HID_SHIFT_KEYMAP: Record<number, string> = {
  0x04: 'A', 0x05: 'B', 0x06: 'C', 0x07: 'D', 0x08: 'E', 0x09: 'F',
  0x0a: 'G', 0x0b: 'H', 0x0c: 'I', 0x0d: 'J', 0x0e: 'K', 0x0f: 'L',
  0x10: 'M', 0x11: 'N', 0x12: 'O', 0x13: 'P', 0x14: 'Q', 0x15: 'R',
  0x16: 'S', 0x17: 'T', 0x18: 'U', 0x19: 'V', 0x1a: 'W', 0x1b: 'X',
  0x1c: 'Y', 0x1d: 'Z',
  0x1e: '!', 0x1f: '@', 0x20: '#', 0x21: '$', 0x22: '%',
  0x23: '^', 0x24: '&', 0x25: '*', 0x26: '(', 0x27: ')',
  0x2d: '_', 0x2e: '+', 0x2f: '{', 0x30: '}', 0x31: '|',
  0x33: ':', 0x34: '"', 0x35: '~', 0x36: '<', 0x37: '>', 0x38: '?',
}

// Parse PCAP file and extract USB packets
export function parseUSBPcap(buffer: ArrayBuffer): USBPacket[] {
  const view = new DataView(buffer)
  const packets: USBPacket[] = []

  // Check PCAP magic number
  const magic = view.getUint32(0, true)
  let littleEndian = true

  if (magic === 0xa1b2c3d4 || magic === 0xa1b23c4d) {
    littleEndian = true
  } else if (magic === 0xd4c3b2a1 || magic === 0x4d3cb2a1) {
    littleEndian = false
  } else {
    throw new Error('Invalid PCAP file format')
  }

  // Skip PCAP header (24 bytes)
  let offset = 24
  let packetNumber = 1

  while (offset < buffer.byteLength - 16) {
    try {
      // Read packet header
      const tsSec = view.getUint32(offset, littleEndian)
      const tsUsec = view.getUint32(offset + 4, littleEndian)
      const inclLen = view.getUint32(offset + 8, littleEndian)
      const origLen = view.getUint32(offset + 12, littleEndian)

      offset += 16

      if (offset + inclLen > buffer.byteLength) break

      // Extract packet data
      const packetData = new Uint8Array(buffer, offset, inclLen)

      // Parse USB packet (simplified - actual USB header varies)
      const packet = parseUSBPacketData(packetData, packetNumber, tsSec + tsUsec / 1000000)

      if (packet) {
        packets.push(packet)
      }

      packetNumber++
      offset += inclLen

    } catch (e) {
      console.error('Error parsing packet:', e)
      break
    }
  }

  return packets
}

function parseUSBPacketData(data: Uint8Array, packetNumber: number, timestamp: number): USBPacket | null {
  if (data.length < 27) return null

  // URB (USB Request Block) header parsing
  // This is a simplified version - actual USB pcap can have variations

  const endpoint = data[10]
  const transfer = data[9]
  const direction = (endpoint & 0x80) ? 'IN' : 'OUT'

  // Transfer types: 0=isochronous, 1=interrupt, 2=control, 3=bulk
  const transferTypes = ['Isochronous', 'Interrupt', 'Control', 'Bulk']
  const transferType = transferTypes[transfer % 4] as any

  // Extract leftover data (capdata) - usually starts after URB header
  const dataOffset = 64 // USB header size varies, typical is 64 bytes
  const capdata = data.length > dataOffset ? data.slice(dataOffset) : undefined

  return {
    number: packetNumber,
    timestamp,
    source: 'host',
    destination: `${data[11]}.${endpoint & 0x7f}`,
    protocol: 'USB',
    info: `URB_${direction}`,
    length: data.length,
    endpoint: `0x${(endpoint & 0x7f).toString(16).padStart(2, '0')}`,
    direction: direction as 'IN' | 'OUT',
    transferType,
    capdata,
    raw: data
  }
}

// Decode HID keyboard data from USB packets
export function decodeKeyboardData(packets: USBPacket[]): KeystrokeEvent[] {
  const keystrokes: KeystrokeEvent[] = []

  // Filter for HID keyboard packets (interrupt transfers, endpoint 0x81 typically)
  const keyboardPackets = packets.filter(p =>
    p.transferType === 'Interrupt' &&
    p.direction === 'IN' &&
    p.capdata && p.capdata.length >= 8
  )

  for (const packet of keyboardPackets) {
    if (!packet.capdata || packet.capdata.length < 8) continue

    // HID keyboard report format (8 bytes):
    // Byte 0: Modifier keys
    // Byte 1: Reserved
    // Byte 2-7: Key codes (up to 6 simultaneous keys)

    const modifierByte = packet.capdata[0]
    const keyCodes = Array.from(packet.capdata.slice(2, 8))

    // Parse modifier keys
    const modifiers = {
      leftCtrl: (modifierByte & 0x01) !== 0,
      leftShift: (modifierByte & 0x02) !== 0,
      leftAlt: (modifierByte & 0x04) !== 0,
      leftGUI: (modifierByte & 0x08) !== 0,
      rightCtrl: (modifierByte & 0x10) !== 0,
      rightShift: (modifierByte & 0x20) !== 0,
      rightAlt: (modifierByte & 0x40) !== 0,
      rightGUI: (modifierByte & 0x80) !== 0,
    }

    // Process each key code
    for (const keyCode of keyCodes) {
      if (keyCode === 0) continue // No key pressed

      const shiftPressed = modifiers.leftShift || modifiers.rightShift
      const keyMap = shiftPressed ? HID_SHIFT_KEYMAP : HID_KEYMAP
      const key = keyMap[keyCode] || HID_KEYMAP[keyCode] || `[0x${keyCode.toString(16)}]`

      keystrokes.push({
        timestamp: packet.timestamp,
        packetNumber: packet.number,
        key,
        keyCode,
        modifiers,
        rawData: packet.capdata
      })
    }
  }

  return keystrokes
}

// Reconstruct typed text from keystrokes
export function reconstructText(keystrokes: KeystrokeEvent[]): string {
  let text = ''
  let lastKeyCodes = new Set<number>()

  for (const keystroke of keystrokes) {
    // Avoid duplicate key events (key held down)
    if (lastKeyCodes.has(keystroke.keyCode)) continue

    lastKeyCodes = new Set([keystroke.keyCode])

    // Handle special keys
    if (keystroke.key === '[BACKSPACE]') {
      text = text.slice(0, -1)
      continue
    }

    // Add modifiers for special keys
    let prefix = ''
    if (keystroke.modifiers.leftCtrl || keystroke.modifiers.rightCtrl) {
      prefix += 'Ctrl+'
    }
    if (keystroke.modifiers.leftAlt || keystroke.modifiers.rightAlt) {
      prefix += 'Alt+'
    }
    if (keystroke.modifiers.leftGUI || keystroke.modifiers.rightGUI) {
      prefix += 'Win+'
    }

    if (prefix && keystroke.key.startsWith('[')) {
      text += `[${prefix}${keystroke.key.slice(1)}`
    } else if (prefix) {
      text += `[${prefix}${keystroke.key}]`
    } else {
      text += keystroke.key
    }
  }

  return text
}

// Main analysis function
export function analyzeUSBPcap(buffer: ArrayBuffer): USBAnalysisResult {
  const packets = parseUSBPcap(buffer)
  const keystrokes = decodeKeyboardData(packets)
  const reconstructedText = reconstructText(keystrokes)

  // Extract leftover data
  const leftoverData = packets
    .filter(p => p.capdata && p.capdata.length > 0)
    .map(p => p.capdata!)

  // Identify devices (simplified)
  const deviceAddresses = new Set(packets.map(p => p.destination.split('.')[0]))
  const devices: USBDevice[] = Array.from(deviceAddresses).map((addr, i) => ({
    deviceAddress: parseInt(addr) || i,
    endpoints: []
  }))

  // Calculate statistics
  const timestamps = packets.map(p => p.timestamp).filter(t => t > 0)
  const captureStart = timestamps.length > 0 ? Math.min(...timestamps) : 0
  const captureEnd = timestamps.length > 0 ? Math.max(...timestamps) : 0

  return {
    packets,
    devices,
    keystrokes,
    reconstructedText,
    statistics: {
      totalPackets: packets.length,
      totalDevices: devices.length,
      totalKeystrokes: keystrokes.length,
      captureStart,
      captureEnd,
      duration: captureEnd - captureStart
    },
    leftoverData
  }
}

// Format timestamp for display
export function formatTimestamp(timestamp: number): string {
  return timestamp.toFixed(6) + 's'
}

// Convert bytes to hex string
export function bytesToHex(bytes: Uint8Array): string {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, '0'))
    .join(' ')
}
