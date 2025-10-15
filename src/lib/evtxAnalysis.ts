// EVTX Analysis Library
// Comprehensive Windows Event Log parsing and analysis for forensics and CTF

export interface EVTXEvent {
  number: number
  eventId: number
  level: 'Critical' | 'Error' | 'Warning' | 'Information' | 'Verbose' | 'Unknown'
  timestamp: string
  source: string
  provider: string
  channel: string
  computer: string
  message: string
  recordId: number
  userId?: string
  userName?: string
  keywords?: string[]
  task?: number
  taskCategory?: string
  opcode?: number
  processId?: number
  threadId?: number
  eventData?: Record<string, any>
  userData?: Record<string, any>
  raw?: any
}

export interface EVTXStatistics {
  totalEvents: number
  criticalCount: number
  errorCount: number
  warningCount: number
  infoCount: number
  timeRange: {
    start: string
    end: string
  }
  topEventIds: Array<{ eventId: number; count: number; description: string }>
  topSources: Array<{ source: string; count: number }>
  uniqueUsers: number
  uniqueComputers: number
}

export interface ThreatIndicator {
  type: string
  severity: 'Critical' | 'High' | 'Medium' | 'Low'
  description: string
  eventIds: number[]
  confidence: number
  timestamp: string
  details: string
}

export interface ExtractedArtifact {
  type: 'IP' | 'Username' | 'FilePath' | 'CommandLine' | 'RegistryKey' | 'TaskName' | 'ServiceName' | 'Hash'
  value: string
  context: string
  eventId: number
  timestamp: string
}

export interface TimelinePoint {
  timestamp: string
  count: number
  critical: number
  error: number
  warning: number
  info: number
}

export interface MITREAttack {
  technique: string
  id: string
  tactic: string
  description: string
  eventIds: number[]
  confidence: number
  severity: 'Critical' | 'High' | 'Medium' | 'Low'
}

export interface FlagCandidate {
  value: string
  type: 'CTF Flag' | 'Base64' | 'Hex' | 'Suspicious String'
  confidence: number
  context: string
  eventId: number
  timestamp: string
}

export interface UserSession {
  userName: string
  sessionId: string
  logonTime: string
  logoffTime?: string
  duration?: number
  computer: string
  logonType: string
  actions: EVTXEvent[]
  suspicious: boolean
}

export interface SuspiciousCommand {
  command: string
  reason: string
  severity: 'Critical' | 'High' | 'Medium' | 'Low'
  eventId: number
  timestamp: string
  user?: string
  indicators: string[]
}

export interface EVTXFile {
  name: string
  file: File
  result: EVTXAnalysisResult | null
}

export interface CorrelatedEvent {
  event: EVTXEvent
  relatedEvents: EVTXEvent[]
  correlationType: 'Logon Chain' | 'Privilege Escalation' | 'Process Execution' | 'Network Activity' | 'File Activity'
  confidence: number
}

export interface EVTXAnalysisResult {
  events: EVTXEvent[]
  statistics: EVTXStatistics
  threats: ThreatIndicator[]
  artifacts: ExtractedArtifact[]
  timeline: TimelinePoint[]
  mitreAttacks: MITREAttack[]
  flags: FlagCandidate[]
  userSessions: UserSession[]
  suspiciousCommands: SuspiciousCommand[]
  correlatedEvents?: CorrelatedEvent[]
  metadata: {
    fileName: string
    fileSize: number
    parseTime: number
    parserType: 'Native' | 'JavaScript'
    fileCount?: number
  }
}

// Event ID descriptions for common security and system events
const EVENT_DESCRIPTIONS: Record<number, string> = {
  // Security Events
  4624: 'Successful Logon',
  4625: 'Failed Logon',
  4634: 'Logoff',
  4648: 'Logon with Explicit Credentials',
  4672: 'Special Privileges Assigned',
  4673: 'Privileged Service Called',
  4674: 'Privileged Operation Attempted',
  4688: 'Process Creation',
  4689: 'Process Termination',
  4697: 'Service Installed',
  4698: 'Scheduled Task Created',
  4699: 'Scheduled Task Deleted',
  4700: 'Scheduled Task Enabled',
  4701: 'Scheduled Task Disabled',
  4702: 'Scheduled Task Updated',
  4720: 'User Account Created',
  4722: 'User Account Enabled',
  4723: 'Password Change Attempted',
  4724: 'Password Reset Attempted',
  4725: 'User Account Disabled',
  4726: 'User Account Deleted',
  4738: 'User Account Changed',
  4740: 'User Account Locked Out',
  4767: 'User Account Unlocked',
  4768: 'Kerberos TGT Requested',
  4769: 'Kerberos Service Ticket Requested',
  4776: 'NTLM Authentication',
  4778: 'Session Reconnected',
  4779: 'Session Disconnected',
  4798: 'Group Membership Enumerated',
  4799: 'Security-Enabled Local Group Membership Enumerated',
  1102: 'Security Log Cleared',

  // System Events
  7045: 'Service Installed (System)',

  // PowerShell Events
  4103: 'PowerShell Module Logging',
  4104: 'PowerShell Script Block Logging',

  // RDP Events
  1149: 'RDP Authentication Success',
  21: 'RDP Session Logon',
  22: 'RDP Shell Start',
  24: 'RDP Session Disconnected',
  25: 'RDP Session Reconnected',

  // Windows Defender
  1116: 'Malware Detected',
  1117: 'Malware Action Taken',
  1118: 'Malware Action Failed',
  1119: 'Critical Error',
}

/**
 * Parse EVTX file and extract events
 * This implementation extracts XML from EVTX binary format
 */
export function parseEVTX(buffer: ArrayBuffer): EVTXEvent[] {
  const events: EVTXEvent[] = []
  const data = new Uint8Array(buffer)

  console.log(`Parsing EVTX file: ${buffer.byteLength} bytes`)

  // Verify EVTX signature
  const signature = new TextDecoder().decode(data.slice(0, 7))
  if (signature !== 'ElfFile') {
    throw new Error('Invalid EVTX file: Missing ElfFile signature')
  }

  try {
    // Extract all XML strings from the EVTX binary
    const xmlStrings = extractAllXMLFromEVTX(data)

    console.log(`Found ${xmlStrings.length} XML event records in EVTX file`)

    if (xmlStrings.length === 0) {
      throw new Error('No event records found in EVTX file')
    }

    // Parse each XML string into an event object
    let eventNumber = 1
    for (const xml of xmlStrings) {
      try {
        const event = parseXMLEvent(xml, eventNumber++)
        if (event) {
          events.push(event)
        }
      } catch (err) {
        console.warn(`Failed to parse XML event:`, err)
      }
    }

    console.log(`Successfully parsed ${events.length} events`)

    return events.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
  } catch (error) {
    console.error('EVTX parsing error:', error)
    throw new Error(`Failed to parse EVTX file: ${error instanceof Error ? error.message : 'Unknown error'}`)
  }
}

/**
 * Extract all XML strings from EVTX binary data
 */
function extractAllXMLFromEVTX(data: Uint8Array): string[] {
  const xmlStrings: string[] = []
  const chunkSize = 65536 // 64KB chunks
  let offset = 4096 // Skip file header

  // Search through chunks for event records
  while (offset < data.length) {
    // Check for chunk signature
    const chunkSig = new TextDecoder().decode(data.slice(offset, offset + 7))

    if (chunkSig === 'ElfChnk') {
      // Parse events from this chunk
      const chunkEnd = Math.min(offset + chunkSize, data.length)
      const chunkData = data.slice(offset, chunkEnd)

      // Find event records in chunk (signature 0x2a2a0000)
      for (let i = 128; i < chunkData.length - 24; i++) {
        if (chunkData[i] === 0x2a && chunkData[i + 1] === 0x2a &&
            chunkData[i + 2] === 0x00 && chunkData[i + 3] === 0x00) {

          // Read record size
          const recordSize = readUInt32LE(chunkData, i + 4)

          if (recordSize > 24 && i + recordSize <= chunkData.length) {
            const recordData = chunkData.slice(i, i + recordSize)

            // Extract XML from record (try both UTF-8 and UTF-16)
            const xml = extractXMLFromRecord(recordData)
            if (xml) {
              xmlStrings.push(xml)
            }

            // Skip to next record
            i += recordSize - 1
          }
        }
      }
    }

    offset += chunkSize
  }

  return xmlStrings
}

/**
 * Extract XML from an event record
 */
function extractXMLFromRecord(recordData: Uint8Array): string | null {
  // Try to find XML in UTF-8
  let xml = extractXMLWithEncoding(recordData, 'utf-8')
  if (xml) return xml

  // Try UTF-16LE (common in Windows)
  xml = extractXMLWithEncoding(recordData, 'utf-16le')
  if (xml) return xml

  return null
}

/**
 * Extract XML with specific encoding
 */
function extractXMLWithEncoding(data: Uint8Array, encoding: string): string | null {
  try {
    const text = new TextDecoder(encoding, { fatal: false }).decode(data)

    // Look for Event XML tags
    const startPatterns = [
      '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">',
      '<Event xmlns=',
      '<Event>'
    ]

    for (const pattern of startPatterns) {
      const startIdx = text.indexOf(pattern)
      if (startIdx !== -1) {
        const endIdx = text.indexOf('</Event>', startIdx)
        if (endIdx !== -1) {
          const xml = text.substring(startIdx, endIdx + 8) // +8 for '</Event>'

          // Validate it looks like real XML
          if (xml.includes('EventID') || xml.includes('System') || xml.includes('EventData')) {
            return xml.trim()
          }
        }
      }
    }
  } catch (err) {
    // Encoding error, try next
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

    // Check for parse errors
    const parseError = doc.querySelector('parsererror')
    if (parseError) {
      return null
    }

    const eventElement = doc.querySelector('Event')
    if (!eventElement) return null

    // Extract System section
    const system = eventElement.querySelector('System')
    if (!system) return null

    const eventId = parseInt(system.querySelector('EventID')?.textContent || '0')
    const level = parseInt(system.querySelector('Level')?.textContent || '4')
    const computer = system.querySelector('Computer')?.textContent || 'Unknown'
    const channel = system.querySelector('Channel')?.textContent || 'Unknown'
    const provider = system.querySelector('Provider')?.getAttribute('Name') || 'Unknown'
    const recordId = parseInt(system.querySelector('EventRecordID')?.textContent || '0')

    // Extract timestamp
    const timeCreated = system.querySelector('TimeCreated')
    const timestamp = timeCreated?.getAttribute('SystemTime') || new Date().toISOString()

    // Extract security info
    const security = system.querySelector('Security')
    const userId = security?.getAttribute('UserID') || undefined

    // Extract execution info
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

          // Extract username from common fields
          if (name === 'SubjectUserName' || name === 'TargetUserName' || name === 'AccountName') {
            userName = value
          }
        }
      })
    }

    // Build message from event data
    const message = buildMessageFromEventData(eventId, eventData)

    const event: EVTXEvent = {
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

    return event
  } catch (err) {
    console.warn('Error parsing XML event:', err)
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
  // Get base description
  const baseDesc = EVENT_DESCRIPTIONS[eventId] || `Event ID ${eventId}`

  // Add relevant event data
  const parts: string[] = [baseDesc]

  // Add key fields based on event type
  const keyFields = ['SubjectUserName', 'TargetUserName', 'WorkstationName', 'IpAddress', 'CommandLine', 'ProcessName', 'ServiceName', 'TaskName']

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
 * Analyze EVTX events and generate statistics
 */
export function analyzeStatistics(events: EVTXEvent[]): EVTXStatistics {
  const eventIdCounts = new Map<number, number>()
  const sourceCounts = new Map<string, number>()
  const users = new Set<string>()
  const computers = new Set<string>()

  let critical = 0, error = 0, warning = 0, info = 0

  events.forEach(event => {
    // Count by level
    if (event.level === 'Critical') critical++
    else if (event.level === 'Error') error++
    else if (event.level === 'Warning') warning++
    else if (event.level === 'Information') info++

    // Count event IDs
    eventIdCounts.set(event.eventId, (eventIdCounts.get(event.eventId) || 0) + 1)

    // Count sources
    sourceCounts.set(event.source, (sourceCounts.get(event.source) || 0) + 1)

    // Track users and computers
    if (event.userName) users.add(event.userName)
    if (event.computer) computers.add(event.computer)
  })

  // Get top event IDs
  const topEventIds = Array.from(eventIdCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 10)
    .map(([eventId, count]) => ({
      eventId,
      count,
      description: EVENT_DESCRIPTIONS[eventId] || 'Unknown Event'
    }))

  // Get top sources
  const topSources = Array.from(sourceCounts.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([source, count]) => ({ source, count }))

  // Time range
  const timestamps = events.map(e => new Date(e.timestamp).getTime()).filter(t => !isNaN(t))
  const start = timestamps.length ? new Date(Math.min(...timestamps)).toISOString() : new Date().toISOString()
  const end = timestamps.length ? new Date(Math.max(...timestamps)).toISOString() : new Date().toISOString()

  return {
    totalEvents: events.length,
    criticalCount: critical,
    errorCount: error,
    warningCount: warning,
    infoCount: info,
    timeRange: { start, end },
    topEventIds,
    topSources,
    uniqueUsers: users.size,
    uniqueComputers: computers.size
  }
}

/**
 * Detect security threats and suspicious activity
 */
export function detectThreats(events: EVTXEvent[]): ThreatIndicator[] {
  const threats: ThreatIndicator[] = []

  // Count failed logons
  const failedLogons = events.filter(e => e.eventId === 4625)
  if (failedLogons.length > 5) {
    threats.push({
      type: 'Multiple Failed Logons',
      severity: failedLogons.length > 20 ? 'High' : 'Medium',
      description: `Detected ${failedLogons.length} failed logon attempts`,
      eventIds: [4625],
      confidence: Math.min(95, 60 + failedLogons.length),
      timestamp: failedLogons[0]?.timestamp || new Date().toISOString(),
      details: `Possible brute force attack or password guessing attempt`
    })
  }

  // Log clearing (major red flag)
  const logClears = events.filter(e => e.eventId === 1102)
  if (logClears.length > 0) {
    threats.push({
      type: 'Security Log Cleared',
      severity: 'Critical',
      description: `Security audit log was cleared ${logClears.length} time(s)`,
      eventIds: [1102],
      confidence: 100,
      timestamp: logClears[0]?.timestamp || new Date().toISOString(),
      details: 'Attacker may be attempting to hide tracks. Immediate investigation required.'
    })
  }

  // Scheduled task creation
  const scheduledTasks = events.filter(e => e.eventId === 4698)
  if (scheduledTasks.length > 0) {
    threats.push({
      type: 'Scheduled Task Created',
      severity: 'Medium',
      description: `${scheduledTasks.length} scheduled task(s) created`,
      eventIds: [4698],
      confidence: 70,
      timestamp: scheduledTasks[0]?.timestamp || new Date().toISOString(),
      details: 'Scheduled tasks are commonly used for persistence mechanisms'
    })
  }

  // Service installation
  const services = events.filter(e => e.eventId === 7045 || e.eventId === 4697)
  if (services.length > 0) {
    threats.push({
      type: 'Service Installed',
      severity: 'Medium',
      description: `${services.length} new service(s) installed`,
      eventIds: [7045, 4697],
      confidence: 65,
      timestamp: services[0]?.timestamp || new Date().toISOString(),
      details: 'New services may indicate malware or persistence mechanisms'
    })
  }

  // PowerShell activity
  const powershell = events.filter(e => e.eventId === 4103 || e.eventId === 4104)
  if (powershell.length > 10) {
    threats.push({
      type: 'High PowerShell Activity',
      severity: 'Medium',
      description: `${powershell.length} PowerShell execution events detected`,
      eventIds: [4103, 4104],
      confidence: 60,
      timestamp: powershell[0]?.timestamp || new Date().toISOString(),
      details: 'PowerShell is frequently used by attackers for post-exploitation'
    })
  }

  // Account lockouts
  const lockouts = events.filter(e => e.eventId === 4740)
  if (lockouts.length > 0) {
    threats.push({
      type: 'Account Lockouts',
      severity: 'Low',
      description: `${lockouts.length} account(s) locked out`,
      eventIds: [4740],
      confidence: 50,
      timestamp: lockouts[0]?.timestamp || new Date().toISOString(),
      details: 'Multiple failed authentication attempts or misconfigured applications'
    })
  }

  return threats.sort((a, b) => {
    const severityOrder = { Critical: 0, High: 1, Medium: 2, Low: 3 }
    return severityOrder[a.severity] - severityOrder[b.severity]
  })
}

/**
 * Extract artifacts (IPs, usernames, paths, etc.)
 */
export function extractArtifacts(events: EVTXEvent[]): ExtractedArtifact[] {
  const artifacts: ExtractedArtifact[] = []
  const seen = new Set<string>()

  events.forEach(event => {
    const message = event.message || ''

    // Extract IP addresses
    const ipRegex = /\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g
    const ips = message.match(ipRegex)
    if (ips) {
      ips.forEach(ip => {
        const key = `IP:${ip}`
        if (!seen.has(key)) {
          seen.add(key)
          artifacts.push({
            type: 'IP',
            value: ip,
            context: message.substring(0, 100),
            eventId: event.eventId,
            timestamp: event.timestamp
          })
        }
      })
    }

    // Extract usernames
    if (event.userName) {
      const key = `Username:${event.userName}`
      if (!seen.has(key)) {
        seen.add(key)
        artifacts.push({
          type: 'Username',
          value: event.userName,
          context: `User: ${event.userName}`,
          eventId: event.eventId,
          timestamp: event.timestamp
        })
      }
    }

    // Extract file paths
    const pathRegex = /[A-Z]:\\(?:[^\s\\]+\\)*[^\s\\]+/gi
    const paths = message.match(pathRegex)
    if (paths) {
      paths.forEach(path => {
        const key = `FilePath:${path}`
        if (!seen.has(key)) {
          seen.add(key)
          artifacts.push({
            type: 'FilePath',
            value: path,
            context: message.substring(0, 100),
            eventId: event.eventId,
            timestamp: event.timestamp
          })
        }
      })
    }
  })

  return artifacts
}

/**
 * Build timeline data for visualization
 */
export function buildTimeline(events: EVTXEvent[]): TimelinePoint[] {
  const timeGroups = new Map<string, TimelinePoint>()

  events.forEach(event => {
    // Group by hour
    const date = new Date(event.timestamp)
    const hourKey = new Date(date.getFullYear(), date.getMonth(), date.getDate(), date.getHours()).toISOString()

    const existing = timeGroups.get(hourKey) || {
      timestamp: hourKey,
      count: 0,
      critical: 0,
      error: 0,
      warning: 0,
      info: 0
    }

    existing.count++
    if (event.level === 'Critical') existing.critical++
    else if (event.level === 'Error') existing.error++
    else if (event.level === 'Warning') existing.warning++
    else if (event.level === 'Information') existing.info++

    timeGroups.set(hourKey, existing)
  })

  return Array.from(timeGroups.values()).sort((a, b) =>
    new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
  )
}

/**
 * Map events to MITRE ATT&CK techniques
 */
export function mapToMITRE(events: EVTXEvent[], threats: ThreatIndicator[]): MITREAttack[] {
  const attacks: MITREAttack[] = []

  // T1078 - Valid Accounts (Multiple failed logons)
  const failedLogons = events.filter(e => e.eventId === 4625)
  if (failedLogons.length > 5) {
    attacks.push({
      technique: 'Valid Accounts',
      id: 'T1078',
      tactic: 'Initial Access / Persistence',
      description: 'Adversary may attempt to use valid credentials obtained through brute force',
      eventIds: [4625],
      confidence: Math.min(95, 60 + failedLogons.length),
      severity: failedLogons.length > 20 ? 'High' : 'Medium'
    })
  }

  // T1070.001 - Indicator Removal: Clear Windows Event Logs
  const logClears = events.filter(e => e.eventId === 1102)
  if (logClears.length > 0) {
    attacks.push({
      technique: 'Clear Windows Event Logs',
      id: 'T1070.001',
      tactic: 'Defense Evasion',
      description: 'Adversary cleared event logs to cover tracks',
      eventIds: [1102],
      confidence: 100,
      severity: 'Critical'
    })
  }

  // T1053.005 - Scheduled Task/Job: Scheduled Task
  const scheduledTasks = events.filter(e => e.eventId === 4698)
  if (scheduledTasks.length > 0) {
    attacks.push({
      technique: 'Scheduled Task',
      id: 'T1053.005',
      tactic: 'Persistence / Execution',
      description: 'Adversary may use scheduled tasks for persistence or execution',
      eventIds: [4698],
      confidence: 75,
      severity: 'Medium'
    })
  }

  // T1543.003 - Create or Modify System Process: Windows Service
  const services = events.filter(e => e.eventId === 7045 || e.eventId === 4697)
  if (services.length > 0) {
    attacks.push({
      technique: 'Windows Service',
      id: 'T1543.003',
      tactic: 'Persistence / Privilege Escalation',
      description: 'Adversary may create or modify Windows services for persistence',
      eventIds: [7045, 4697],
      confidence: 70,
      severity: 'Medium'
    })
  }

  // T1059.001 - Command and Scripting Interpreter: PowerShell
  const powershell = events.filter(e => e.eventId === 4103 || e.eventId === 4104)
  if (powershell.length > 5) {
    attacks.push({
      technique: 'PowerShell',
      id: 'T1059.001',
      tactic: 'Execution',
      description: 'Adversary may use PowerShell for execution and post-exploitation',
      eventIds: [4103, 4104],
      confidence: 65,
      severity: powershell.length > 20 ? 'High' : 'Medium'
    })
  }

  // T1110 - Brute Force
  if (failedLogons.length > 10) {
    attacks.push({
      technique: 'Brute Force',
      id: 'T1110',
      tactic: 'Credential Access',
      description: 'Adversary attempting to gain access through password guessing',
      eventIds: [4625],
      confidence: Math.min(90, 50 + failedLogons.length * 2),
      severity: failedLogons.length > 30 ? 'Critical' : 'High'
    })
  }

  // T1134 - Access Token Manipulation
  const privilegeUse = events.filter(e => e.eventId === 4672)
  if (privilegeUse.length > 10) {
    attacks.push({
      technique: 'Access Token Manipulation',
      id: 'T1134',
      tactic: 'Privilege Escalation',
      description: 'Suspicious privilege assignments detected',
      eventIds: [4672],
      confidence: 60,
      severity: 'Medium'
    })
  }

  return attacks.sort((a, b) => {
    const severityOrder = { Critical: 0, High: 1, Medium: 2, Low: 3 }
    return severityOrder[a.severity] - severityOrder[b.severity]
  })
}

/**
 * Detect CTF flags and suspicious strings
 */
export function detectFlags(events: EVTXEvent[]): FlagCandidate[] {
  const flags: FlagCandidate[] = []
  const seen = new Set<string>()

  events.forEach(event => {
    const text = event.message || ''

    // CTF flag patterns
    const ctfPatterns = [
      /(?:flag|ctf|htb|thm|pwn)\{[^}]{10,}\}/gi,
      /[A-Z0-9]{20,}/g,
      /flag[_-]?[a-z0-9]{10,}/gi
    ]

    ctfPatterns.forEach((pattern, idx) => {
      const matches = text.match(pattern)
      if (matches) {
        matches.forEach(match => {
          if (!seen.has(match) && match.length >= 10) {
            seen.add(match)
            flags.push({
              value: match,
              type: idx === 0 ? 'CTF Flag' : 'Suspicious String',
              confidence: idx === 0 ? 95 : 70,
              context: text.substring(0, 150),
              eventId: event.eventId,
              timestamp: event.timestamp
            })
          }
        })
      }
    })

    // Base64 detection
    const base64Regex = /(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?/g
    const base64Matches = text.match(base64Regex)
    if (base64Matches) {
      base64Matches.forEach(match => {
        if (match.length >= 20 && !seen.has(match)) {
          seen.add(match)
          flags.push({
            value: match,
            type: 'Base64',
            confidence: 80,
            context: text.substring(0, 150),
            eventId: event.eventId,
            timestamp: event.timestamp
          })
        }
      })
    }

    // Hex strings
    const hexRegex = /0x[0-9A-Fa-f]{16,}/g
    const hexMatches = text.match(hexRegex)
    if (hexMatches) {
      hexMatches.forEach(match => {
        if (!seen.has(match)) {
          seen.add(match)
          flags.push({
            value: match,
            type: 'Hex',
            confidence: 75,
            context: text.substring(0, 150),
            eventId: event.eventId,
            timestamp: event.timestamp
          })
        }
      })
    }
  })

  return flags.sort((a, b) => b.confidence - a.confidence)
}

/**
 * Detect suspicious command lines
 */
export function detectSuspiciousCommands(events: EVTXEvent[]): SuspiciousCommand[] {
  const commands: SuspiciousCommand[] = []

  // Suspicious patterns
  const suspiciousPatterns = [
    { pattern: /powershell.*-enc.*[A-Za-z0-9+/=]{20,}/i, reason: 'Encoded PowerShell command', severity: 'High' as const, indicators: ['Base64 Encoding', 'PowerShell'] },
    { pattern: /powershell.*downloadstring/i, reason: 'PowerShell download cradle', severity: 'Critical' as const, indicators: ['Download', 'PowerShell'] },
    { pattern: /powershell.*invoke-expression/i, reason: 'PowerShell IEX execution', severity: 'High' as const, indicators: ['Code Execution', 'PowerShell'] },
    { pattern: /mimikatz/i, reason: 'Mimikatz credential dumping tool', severity: 'Critical' as const, indicators: ['Credential Theft', 'Post-Exploitation'] },
    { pattern: /psexec/i, reason: 'PsExec remote execution', severity: 'Medium' as const, indicators: ['Lateral Movement', 'Remote Execution'] },
    { pattern: /wmic.*process.*call.*create/i, reason: 'WMIC process creation', severity: 'Medium' as const, indicators: ['Process Creation', 'Execution'] },
    { pattern: /cmd.*\/c.*echo.*>>/i, reason: 'Command line file write', severity: 'Low' as const, indicators: ['File Write', 'Persistence'] },
    { pattern: /net.*user.*\/add/i, reason: 'User account creation', severity: 'High' as const, indicators: ['Account Creation', 'Persistence'] },
    { pattern: /reg.*add.*run/i, reason: 'Registry run key modification', severity: 'High' as const, indicators: ['Registry Modification', 'Persistence'] },
    { pattern: /schtasks.*\/create/i, reason: 'Scheduled task creation', severity: 'Medium' as const, indicators: ['Scheduled Task', 'Persistence'] },
    { pattern: /certutil.*-decode/i, reason: 'Certutil used for decoding', severity: 'Medium' as const, indicators: ['LOLBin', 'Deobfuscation'] },
    { pattern: /bitsadmin.*\/transfer/i, reason: 'BITS used for download', severity: 'Medium' as const, indicators: ['Download', 'LOLBin'] }
  ]

  events.forEach(event => {
    const message = event.message || ''

    suspiciousPatterns.forEach(({ pattern, reason, severity, indicators }) => {
      if (pattern.test(message)) {
        const match = message.match(pattern)
        commands.push({
          command: match ? match[0] : message.substring(0, 200),
          reason,
          severity,
          eventId: event.eventId,
          timestamp: event.timestamp,
          user: event.userName,
          indicators
        })
      }
    })
  })

  return commands.sort((a, b) => {
    const severityOrder = { Critical: 0, High: 1, Medium: 2, Low: 3 }
    return severityOrder[a.severity] - severityOrder[b.severity]
  })
}

/**
 * Reconstruct user sessions
 */
export function reconstructUserSessions(events: EVTXEvent[]): UserSession[] {
  const sessions = new Map<string, UserSession>()

  // Group logon and logoff events
  const logonEvents = events.filter(e => e.eventId === 4624)
  const logoffEvents = events.filter(e => e.eventId === 4634)

  logonEvents.forEach(logon => {
    const sessionKey = `${logon.userName || 'Unknown'}-${logon.computer}-${logon.timestamp}`

    const session: UserSession = {
      userName: logon.userName || 'Unknown',
      sessionId: logon.recordId.toString(),
      logonTime: logon.timestamp,
      computer: logon.computer,
      logonType: '2', // Interactive
      actions: [logon],
      suspicious: false
    }

    // Find corresponding logoff
    const logoff = logoffEvents.find(e =>
      e.userName === logon.userName &&
      e.computer === logon.computer &&
      new Date(e.timestamp) > new Date(logon.timestamp)
    )

    if (logoff) {
      session.logoffTime = logoff.timestamp
      session.duration = new Date(logoff.timestamp).getTime() - new Date(logon.timestamp).getTime()
      session.actions.push(logoff)
    }

    // Find all actions during session
    const sessionActions = events.filter(e =>
      e.userName === logon.userName &&
      e.computer === logon.computer &&
      new Date(e.timestamp) >= new Date(logon.timestamp) &&
      (!session.logoffTime || new Date(e.timestamp) <= new Date(session.logoffTime))
    )

    session.actions.push(...sessionActions)

    // Check if suspicious
    const hasPrivilegeUse = sessionActions.some(e => e.eventId === 4672)
    const hasProcessCreation = sessionActions.some(e => e.eventId === 4688)
    const shortSession = session.duration && session.duration < 60000 // Less than 1 minute

    session.suspicious = (hasPrivilegeUse && hasProcessCreation) || shortSession || false

    sessions.set(sessionKey, session)
  })

  return Array.from(sessions.values())
    .sort((a, b) => new Date(b.logonTime).getTime() - new Date(a.logonTime).getTime())
}

/**
 * Main analysis function
 */
export function analyzeEVTX(buffer: ArrayBuffer, fileName: string): EVTXAnalysisResult {
  const startTime = performance.now()

  // Parse events
  const events = parseEVTX(buffer)

  // Analyze statistics
  const statistics = analyzeStatistics(events)

  // Detect threats
  const threats = detectThreats(events)

  // Extract artifacts
  const artifacts = extractArtifacts(events)

  // Build timeline
  const timeline = buildTimeline(events)

  // Map to MITRE ATT&CK
  const mitreAttacks = mapToMITRE(events, threats)

  // Detect flags
  const flags = detectFlags(events)

  // Detect suspicious commands
  const suspiciousCommands = detectSuspiciousCommands(events)

  // Reconstruct user sessions
  const userSessions = reconstructUserSessions(events)

  // Correlate events (attack chains)
  const correlatedEvents = correlateEvents(events)

  const parseTime = performance.now() - startTime

  return {
    events,
    statistics,
    threats,
    artifacts,
    timeline,
    mitreAttacks,
    flags,
    userSessions,
    suspiciousCommands,
    correlatedEvents,
    metadata: {
      fileName,
      fileSize: buffer.byteLength,
      parseTime,
      parserType: 'Native'
    }
  }
}

/**
 * Get event ID description
 */
export function getEventDescription(eventId: number): string {
  return EVENT_DESCRIPTIONS[eventId] || 'Unknown Event'
}

/**
 * Filter events by criteria
 */
export function filterEvents(
  events: EVTXEvent[],
  filters: {
    eventId?: number
    level?: string
    source?: string
    searchTerm?: string
    startDate?: string
    endDate?: string
  }
): EVTXEvent[] {
  return events.filter(event => {
    if (filters.eventId && event.eventId !== filters.eventId) return false
    if (filters.level && event.level !== filters.level) return false
    if (filters.source && event.source !== filters.source) return false
    if (filters.searchTerm) {
      const term = filters.searchTerm.toLowerCase()
      const searchable = `${event.message} ${event.provider} ${event.userName || ''}`.toLowerCase()
      if (!searchable.includes(term)) return false
    }
    if (filters.startDate) {
      if (new Date(event.timestamp) < new Date(filters.startDate)) return false
    }
    if (filters.endDate) {
      if (new Date(event.timestamp) > new Date(filters.endDate)) return false
    }
    return true
  })
}

/**
 * Correlate events to build attack chains
 */
export function correlateEvents(events: EVTXEvent[]): CorrelatedEvent[] {
  const correlated: CorrelatedEvent[] = []
  const processedEventIds = new Set<number>()

  // Find logon chains (4624 -> 4672 -> 4688)
  const logons = events.filter(e => e.eventId === 4624)
  logons.forEach(logon => {
    if (processedEventIds.has(logon.number)) return

    const relatedEvents: EVTXEvent[] = []
    const logonTime = new Date(logon.timestamp).getTime()

    // Find privilege assignment within 5 seconds
    const privilegeUse = events.find(e =>
      e.eventId === 4672 &&
      e.userName === logon.userName &&
      Math.abs(new Date(e.timestamp).getTime() - logonTime) < 5000
    )

    if (privilegeUse) {
      relatedEvents.push(privilegeUse)

      // Find process creation within 30 seconds
      const processCreation = events.find(e =>
        e.eventId === 4688 &&
        e.userName === logon.userName &&
        new Date(e.timestamp).getTime() > logonTime &&
        Math.abs(new Date(e.timestamp).getTime() - logonTime) < 30000
      )

      if (processCreation) {
        relatedEvents.push(processCreation)

        correlated.push({
          event: logon,
          relatedEvents,
          correlationType: 'Logon Chain',
          confidence: 90
        })

        processedEventIds.add(logon.number)
        relatedEvents.forEach(e => processedEventIds.add(e.number))
      }
    }
  })

  // Find privilege escalation patterns (4672 -> 4673/4674)
  const privileges = events.filter(e => e.eventId === 4672)
  privileges.forEach(priv => {
    if (processedEventIds.has(priv.number)) return

    const privTime = new Date(priv.timestamp).getTime()
    const privilegedOps = events.filter(e =>
      (e.eventId === 4673 || e.eventId === 4674) &&
      e.userName === priv.userName &&
      Math.abs(new Date(e.timestamp).getTime() - privTime) < 10000
    )

    if (privilegedOps.length > 0) {
      correlated.push({
        event: priv,
        relatedEvents: privilegedOps,
        correlationType: 'Privilege Escalation',
        confidence: 85
      })

      processedEventIds.add(priv.number)
      privilegedOps.forEach(e => processedEventIds.add(e.number))
    }
  })

  // Find process execution chains (4688 -> 4689)
  const processStarts = events.filter(e => e.eventId === 4688)
  processStarts.forEach(start => {
    if (processedEventIds.has(start.number)) return

    const startTime = new Date(start.timestamp).getTime()
    const processEnd = events.find(e =>
      e.eventId === 4689 &&
      e.computer === start.computer &&
      new Date(e.timestamp).getTime() > startTime &&
      Math.abs(new Date(e.timestamp).getTime() - startTime) < 60000
    )

    if (processEnd) {
      correlated.push({
        event: start,
        relatedEvents: [processEnd],
        correlationType: 'Process Execution',
        confidence: 80
      })

      processedEventIds.add(start.number)
      processedEventIds.add(processEnd.number)
    }
  })

  return correlated.sort((a, b) => b.confidence - a.confidence)
}

/**
 * Merge multiple EVTX analysis results
 */
export function mergeEVTXResults(results: EVTXAnalysisResult[]): EVTXAnalysisResult {
  if (results.length === 0) {
    throw new Error('No results to merge')
  }

  if (results.length === 1) {
    return results[0]
  }

  // Merge events from all files
  const allEvents = results.flatMap(r => r.events)
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())

  // Recalculate statistics on merged data
  const statistics = analyzeStatistics(allEvents)

  // Merge and deduplicate threats
  const allThreats = results.flatMap(r => r.threats)
  const threatMap = new Map<string, ThreatIndicator>()
  allThreats.forEach(threat => {
    const key = `${threat.type}-${threat.eventIds.join(',')}`
    if (!threatMap.has(key)) {
      threatMap.set(key, threat)
    }
  })
  const threats = Array.from(threatMap.values())

  // Merge artifacts
  const allArtifacts = results.flatMap(r => r.artifacts)
  const artifactMap = new Map<string, ExtractedArtifact>()
  allArtifacts.forEach(artifact => {
    const key = `${artifact.type}-${artifact.value}`
    if (!artifactMap.has(key)) {
      artifactMap.set(key, artifact)
    }
  })
  const artifacts = Array.from(artifactMap.values())

  // Rebuild timeline
  const timeline = buildTimeline(allEvents)

  // Recalculate MITRE attacks
  const mitreAttacks = mapToMITRE(allEvents, threats)

  // Merge flags
  const allFlags = results.flatMap(r => r.flags)
  const flagMap = new Map<string, FlagCandidate>()
  allFlags.forEach(flag => {
    if (!flagMap.has(flag.value)) {
      flagMap.set(flag.value, flag)
    }
  })
  const flags = Array.from(flagMap.values())

  // Merge suspicious commands
  const allCommands = results.flatMap(r => r.suspiciousCommands)
  const commandMap = new Map<string, SuspiciousCommand>()
  allCommands.forEach(cmd => {
    const key = `${cmd.command}-${cmd.timestamp}`
    if (!commandMap.has(key)) {
      commandMap.set(key, cmd)
    }
  })
  const suspiciousCommands = Array.from(commandMap.values())

  // Reconstruct user sessions across all logs
  const userSessions = reconstructUserSessions(allEvents)

  // Perform cross-log correlation
  const correlatedEvents = correlateEvents(allEvents)

  const totalSize = results.reduce((sum, r) => sum + r.metadata.fileSize, 0)
  const totalTime = results.reduce((sum, r) => sum + r.metadata.parseTime, 0)

  return {
    events: allEvents,
    statistics,
    threats,
    artifacts,
    timeline,
    mitreAttacks,
    flags,
    userSessions,
    suspiciousCommands,
    correlatedEvents,
    metadata: {
      fileName: `${results.length} files merged`,
      fileSize: totalSize,
      parseTime: totalTime,
      parserType: 'Native',
      fileCount: results.length
    }
  }
}

/**
 * Analyze multiple EVTX files and merge results
 */
export async function analyzeMultipleEVTX(files: { name: string; buffer: ArrayBuffer }[]): Promise<EVTXAnalysisResult> {
  const results = files.map(({ name, buffer }) => analyzeEVTX(buffer, name))
  return mergeEVTXResults(results)
}
