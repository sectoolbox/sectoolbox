// Real EVTX Binary Parser
// Extracts XML from EVTX binary format

import { EVTXEvent } from './evtxAnalysis'

/**
 * Parse EVTX file and extract events
 * Implements proper EVTX binary format parsing with XML extraction
 */
export function parseEVTXBinary(buffer: ArrayBuffer): EVTXEvent[] {
  const events: EVTXEvent[] = []
  const data = new Uint8Array(buffer)

  console.log(`Parsing EVTX file: ${buffer.byteLength} bytes`)

  // Validate EVTX signature
  const signature = String.fromCharCode(...data.slice(0, 7))
  if (signature !== 'ElfFile') {
    throw new Error('Invalid EVTX file: Missing ElfFile signature')
  }

  try {
    // Parse EVTX file header (4096 bytes)
    const header = parseEVTXHeader(data)
    console.log(`EVTX Header: ${header.chunkCount} chunks, next record ID: ${header.nextRecordId}`)

    // Parse all chunks (64KB each, starting at offset 4096)
    let eventNumber = 1
    for (let chunkIndex = 0; chunkIndex < header.chunkCount; chunkIndex++) {
      const chunkOffset = 4096 + (chunkIndex * 65536)

      if (chunkOffset >= data.length) break

      try {
        const chunkEvents = parseEVTXChunk(data, chunkOffset, eventNumber)
        events.push(...chunkEvents)
        eventNumber += chunkEvents.length
      } catch (err) {
        console.warn(`Failed to parse chunk ${chunkIndex}:`, err)
      }
    }

    console.log(`Successfully parsed ${events.length} events from EVTX file`)

    if (events.length === 0) {
      throw new Error('No events found in EVTX file')
    }

    return events.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
  } catch (error) {
    console.error('EVTX parsing error:', error)
    throw new Error(`Failed to parse EVTX file: ${error instanceof Error ? error.message : 'Unknown error'}`)
  }
}

/**
 * Parse EVTX file header
 */
function parseEVTXHeader(data: Uint8Array): { chunkCount: number; nextRecordId: number } {
  // Calculate chunk count based on file size
  const fileSize = data.length
  const headerSize = 4096
  const chunkSize = 65536 // 64KB

  // Number of chunks = (fileSize - headerSize) / chunkSize
  const dataSize = fileSize - headerSize
  const chunkCount = Math.floor(dataSize / chunkSize)

  // Get next record ID from header (offset 0x20, 8 bytes)
  const nextRecordId = readUInt64LE(data, 0x20)

  console.log(`File size: ${fileSize} bytes, Data size: ${dataSize} bytes, Chunk count: ${chunkCount}`)

  return { chunkCount, nextRecordId }
}

/**
 * Parse a single EVTX chunk (64KB)
 */
function parseEVTXChunk(data: Uint8Array, offset: number, startEventNumber: number): EVTXEvent[] {
  const events: EVTXEvent[] = []
  const chunkSize = 65536
  const chunkData = data.slice(offset, Math.min(offset + chunkSize, data.length))

  // Verify chunk signature
  const chunkSig = String.fromCharCode(...chunkData.slice(0, 7))
  if (chunkSig !== 'ElfChnk') {
    console.warn(`Invalid chunk signature at offset ${offset}: "${chunkSig}"`)
    return events
  }

  // Event records start at offset 128 (0x80) in the chunk
  let recordOffset = 128
  let eventNumber = startEventNumber
  let recordsFound = 0
  let recordsParsed = 0

  while (recordOffset + 24 < chunkData.length) {
    // Check for event record signature (0x2a2a0000 = "**\0\0")
    if (chunkData[recordOffset] === 0x2a &&
        chunkData[recordOffset + 1] === 0x2a &&
        chunkData[recordOffset + 2] === 0x00 &&
        chunkData[recordOffset + 3] === 0x00) {

      recordsFound++

      try {
        // Read record size
        const recordSize = readUInt32LE(chunkData, recordOffset + 4)

        if (recordSize > 24 && recordOffset + recordSize <= chunkData.length) {
          const recordData = chunkData.slice(recordOffset, recordOffset + recordSize)

          // Extract and parse event from record
          const event = parseEventFromRecord(recordData, eventNumber++)
          if (event) {
            events.push(event)
            recordsParsed++
          }

          recordOffset += recordSize
        } else {
          recordOffset += 4
        }
      } catch (err) {
        recordOffset += 4
      }
    } else {
      recordOffset += 4
    }
  }

  if (recordsFound > 0) {
    console.log(`Chunk at offset ${offset}: found ${recordsFound} records, successfully parsed ${recordsParsed} events`)
  }

  return events
}

/**
 * Extract XML from event record and parse into EVTXEvent
 */
function parseEventFromRecord(recordData: Uint8Array, eventNumber: number): EVTXEvent | null {
  try {
    // Try to extract XML from record (UTF-8)
    let xml = extractXMLFromRecord(recordData, 'utf-8')

    // Try UTF-16 if UTF-8 didn't work
    if (!xml) {
      xml = extractXMLFromRecord(recordData, 'utf-16le')
    }

    if (!xml) {
      // Log first time we see this to avoid spam
      if (eventNumber === 1) {
        console.warn('Failed to extract XML from first event record. Record size:', recordData.length)
        // Show first 100 bytes as hex to debug
        const preview = Array.from(recordData.slice(0, 100))
          .map(b => b.toString(16).padStart(2, '0'))
          .join(' ')
        console.log('Record preview (hex):', preview)
      }
      return null
    }

    // Parse XML to extract event data
    return parseXMLEvent(xml, eventNumber)
  } catch (err) {
    console.warn(`Error parsing event ${eventNumber}:`, err)
    return null
  }
}

/**
 * Extract XML string from record data with specific encoding
 */
function extractXMLFromRecord(data: Uint8Array, encoding: string): string | null {
  try {
    const text = new TextDecoder(encoding, { fatal: false }).decode(data)

    // Look for Event XML tags
    const patterns = [
      '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">',
      '<Event xmlns=',
      '<Event>'
    ]

    for (const pattern of patterns) {
      const startIdx = text.indexOf(pattern)
      if (startIdx !== -1) {
        const endIdx = text.indexOf('</Event>', startIdx)
        if (endIdx !== -1) {
          const xml = text.substring(startIdx, endIdx + 8)

          // Validate it looks like real XML
          if (xml.includes('EventID') || xml.includes('System')) {
            return xml.trim()
          }
        }
      }
    }
  } catch (err) {
    // Encoding error
  }

  return null
}

/**
 * Parse XML event string into EVTXEvent object
 */
function parseXMLEvent(xml: string, eventNumber: number): EVTXEvent | null {
  try {
    const parser = new DOMParser()
    const doc = parser.parseFromString(xml, 'text/xml')

    const parseError = doc.querySelector('parsererror')
    if (parseError) {
      return null
    }

    const eventElement = doc.querySelector('Event')
    if (!eventElement) return null

    const system = eventElement.querySelector('System')
    if (!system) return null

    // Extract fields
    const eventId = parseInt(system.querySelector('EventID')?.textContent || '0')
    const level = parseInt(system.querySelector('Level')?.textContent || '4')
    const computer = system.querySelector('Computer')?.textContent || 'Unknown'
    const channel = system.querySelector('Channel')?.textContent || 'Unknown'
    const provider = system.querySelector('Provider')?.getAttribute('Name') || 'Unknown'
    const recordId = parseInt(system.querySelector('EventRecordID')?.textContent || '0')

    const timeCreated = system.querySelector('TimeCreated')
    const timestamp = timeCreated?.getAttribute('SystemTime') || new Date().toISOString()

    const security = system.querySelector('Security')
    const userId = security?.getAttribute('UserID') || undefined

    const execution = system.querySelector('Execution')
    const processId = execution?.getAttribute('ProcessID') ? parseInt(execution.getAttribute('ProcessID')!) : undefined
    const threadId = execution?.getAttribute('ThreadID') ? parseInt(execution.getAttribute('ThreadID')!) : undefined

    // Extract EventData
    const eventDataElement = eventElement.querySelector('EventData')
    const eventData: Record<string, any> = {}
    let userName: string | undefined

    if (eventDataElement) {
      const dataElements = eventDataElement.querySelectorAll('Data')
      dataElements.forEach(dataEl => {
        const name = dataEl.getAttribute('Name')
        const value = dataEl.textContent
        if (name && value) {
          eventData[name] = value

          if (name === 'SubjectUserName' || name === 'TargetUserName' || name === 'AccountName') {
            userName = value
          }
        }
      })
    }

    // Build message
    const message = buildMessageFromEventData(eventId, eventData)

    return {
      number: eventNumber,
      eventId,
      level: mapLevelNumber(level),
      timestamp,
      source: channel,
      provider,
      channel,
      computer,
      message,
      recordId,
      userId,
      userName,
      processId,
      threadId,
      eventData: Object.keys(eventData).length > 0 ? eventData : undefined,
      raw: xml
    }
  } catch (err) {
    return null
  }
}

/**
 * Map level number to string
 */
function mapLevelNumber(level: number): EVTXEvent['level'] {
  switch (level) {
    case 1: return 'Critical'
    case 2: return 'Error'
    case 3: return 'Warning'
    case 4: return 'Information'
    case 5: return 'Verbose'
    default: return 'Unknown'
  }
}

/**
 * Build human-readable message from event data
 */
function buildMessageFromEventData(eventId: number, eventData: Record<string, any>): string {
  // Event descriptions
  const descriptions: Record<number, string> = {
    4624: 'Successful Logon',
    4625: 'Failed Logon',
    4634: 'Logoff',
    4688: 'Process Creation',
    4672: 'Special Privileges Assigned',
    1102: 'Security Log Cleared',
  }

  const baseDesc = descriptions[eventId] || `Event ID ${eventId}`
  const parts: string[] = [baseDesc]

  // Add key fields
  const keyFields = ['SubjectUserName', 'TargetUserName', 'WorkstationName', 'IpAddress', 'CommandLine', 'ProcessName']

  for (const field of keyFields) {
    if (eventData[field] && eventData[field] !== '-' && eventData[field] !== '') {
      parts.push(`${field}: ${eventData[field]}`)
    }
  }

  return parts.join(' | ')
}

/**
 * Read 32-bit little-endian unsigned integer
 */
function readUInt32LE(data: Uint8Array, offset: number): number {
  return data[offset] | (data[offset + 1] << 8) | (data[offset + 2] << 16) | (data[offset + 3] << 24)
}

/**
 * Read 64-bit little-endian unsigned integer (returns BigInt)
 */
function readUInt64LE(data: Uint8Array, offset: number): bigint {
  const low = BigInt(readUInt32LE(data, offset))
  const high = BigInt(readUInt32LE(data, offset + 4))
  return (high << 32n) | low
}
