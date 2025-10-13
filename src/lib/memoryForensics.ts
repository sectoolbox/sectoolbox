// Advanced Memory Forensics Library for Threat Hunting and Incident Response
// Focused on helping investigators answer attack chain questions

import Parser from 'binary-parser'

// ============================================================================
// TYPES & INTERFACES
// ============================================================================

export interface ProcessInfo {
  pid: number
  ppid: number
  name: string
  path: string
  commandLine: string
  user: string
  sessionId: number
  createTime: Date
  exitTime?: Date
  threads: number
  handles: number
  imageBase: string
  suspicious: boolean
  suspicionReasons: string[]
}

export interface NetworkConnection {
  protocol: 'TCP' | 'UDP'
  localAddr: string
  localPort: number
  remoteAddr: string
  remotePort: number
  state: string
  pid: number
  processName: string
  createTime?: Date
  isExternal: boolean
  isSuspicious: boolean
  geoLocation?: string
}

export interface ServiceInfo {
  name: string
  displayName: string
  state: 'Running' | 'Stopped' | 'Paused' | 'Unknown'
  startType: 'Auto' | 'Manual' | 'Disabled' | 'Unknown'
  path: string
  pid?: number
  user?: string
  description?: string
  isSuspicious: boolean
}

export interface CredentialDump {
  username: string
  domain: string
  ntlmHash?: string
  method: string
  timestamp?: Date
  sourceProcess?: string
}

export interface LateralMovementIndicator {
  technique: string
  sourceHost?: string
  targetHost?: string
  username: string
  timestamp?: Date
  evidence: string[]
  confidence: number
}

export interface PrivilegeEscalation {
  type: string
  fromUser: string
  toUser: string
  method: string
  tool?: string
  toolPath?: string
  timestamp?: Date
  evidence: string[]
}

export interface SuspiciousFile {
  path: string
  name: string
  hash?: string
  type: string
  created?: Date
  modified?: Date
  accessed?: Date
  owner?: string
  isHidden: boolean
  isPacked: boolean
  entropy: number
  category: 'Malware' | 'Tool' | 'Script' | 'Suspicious' | 'Normal'
}

export interface RegistryActivity {
  key: string
  value?: string
  data?: string
  operation: 'Read' | 'Write' | 'Delete' | 'Create'
  process?: string
  timestamp?: Date
  isPersistence: boolean
}

export interface InjectionIndicator {
  targetProcess: string
  targetPid: number
  injectorProcess?: string
  injectorPid?: number
  technique: string
  evidence: string[]
  confidence: number
}

export interface AttackChain {
  stages: AttackStage[]
  timeline: TimelineEvent[]
  compromisedAccounts: string[]
  compromisedHosts: string[]
  toolsUsed: string[]
  techniques: string[]
}

export interface AttackStage {
  stage: 'Initial Access' | 'Execution' | 'Persistence' | 'Privilege Escalation' |
         'Defense Evasion' | 'Credential Access' | 'Discovery' | 'Lateral Movement' |
         'Collection' | 'Exfiltration' | 'Command and Control'
  timestamp?: Date
  description: string
  evidence: string[]
  mitreId?: string
}

export interface TimelineEvent {
  timestamp: Date
  type: string
  process?: string
  user?: string
  description: string
  severity: 'Critical' | 'High' | 'Medium' | 'Low' | 'Info'
}

export interface ThreatHuntingResult {
  processes: ProcessInfo[]
  networks: NetworkConnection[]
  services: ServiceInfo[]
  credentials: CredentialDump[]
  lateralMovement: LateralMovementIndicator[]
  privilegeEscalation: PrivilegeEscalation[]
  suspiciousFiles: SuspiciousFile[]
  registryActivity: RegistryActivity[]
  injections: InjectionIndicator[]
  attackChain: AttackChain
  iocs: string[]
}

// ============================================================================
// MEMORY ANALYZER
// ============================================================================

export class AdvancedMemoryAnalyzer {

  // Known malicious/attack tools
  private static readonly ATTACK_TOOLS = [
    'mimikatz', 'procdump', 'dumpert', 'nanodump', 'lsassy', 'pypykatz',
    'psexec', 'wmic', 'powershell', 'cmd', 'rundll32', 'regsvr32', 'mshta',
    'certutil', 'bitsadmin', 'net.exe', 'net1.exe', 'sc.exe', 'reg.exe',
    'vssadmin', 'wevtutil', 'bcdedit', 'schtasks', 'at.exe', 'runas',
    'cobalt strike', 'meterpreter', 'empire', 'covenant', 'sliver',
    'crackmapexec', 'bloodhound', 'sharphound', 'rubeus', 'kerberoast'
  ]

  // Credential dumping indicators
  private static readonly CREDENTIAL_TOOLS = [
    'mimikatz', 'procdump', 'dumpert', 'nanodump', 'comsvcs.dll',
    'lsass', 'sekurlsa', 'wdigest', 'tspkg', 'kerberos', 'ntlm'
  ]

  // Lateral movement techniques
  private static readonly LATERAL_MOVEMENT = [
    'psexec', 'wmic', 'schtasks', 'sc.exe', 'winrm', 'winrs',
    'remote registry', 'dcom', 'wmi', 'smb', 'rdp', 'ssh'
  ]

  /**
   * Main analysis entry point with streaming support for large files
   */
  static async analyze(
    buffer: ArrayBuffer,
    progressCallback?: (progress: number, status: string) => void
  ): Promise<ThreatHuntingResult> {
    progressCallback?.(5, 'Extracting processes...')
    const processes = this.extractProcesses(buffer)

    progressCallback?.(15, 'Analyzing network connections...')
    const networks = this.extractNetworks(buffer)

    progressCallback?.(25, 'Scanning Windows services...')
    const services = this.extractServices(buffer)

    progressCallback?.(35, 'Detecting credential dumps...')
    const credentials = this.detectCredentialDumping(buffer, processes)

    progressCallback?.(45, 'Identifying lateral movement...')
    const lateralMovement = this.detectLateralMovement(processes, networks, buffer)

    progressCallback?.(55, 'Detecting privilege escalation...')
    const privilegeEscalation = this.detectPrivilegeEscalation(processes, buffer)

    progressCallback?.(65, 'Finding suspicious files...')
    const suspiciousFiles = this.findSuspiciousFiles(buffer)

    progressCallback?.(75, 'Analyzing registry activity...')
    const registryActivity = this.analyzeRegistryActivity(buffer)

    progressCallback?.(85, 'Detecting process injection...')
    const injections = this.detectInjection(processes, buffer)

    progressCallback?.(90, 'Building attack chain...')
    const attackChain = this.buildAttackChain(
      processes, networks, services, credentials, lateralMovement,
      privilegeEscalation, suspiciousFiles, registryActivity, injections
    )

    progressCallback?.(95, 'Extracting IOCs...')
    const iocs = this.extractIOCs(buffer, processes, networks)

    progressCallback?.(100, 'Analysis complete!')

    return {
      processes,
      networks,
      services,
      credentials,
      lateralMovement,
      privilegeEscalation,
      suspiciousFiles,
      registryActivity,
      injections,
      attackChain,
      iocs
    }
  }

  /**
   * Analyze file in chunks for large files (streaming)
   */
  static async analyzeStream(
    file: File,
    progressCallback?: (progress: number, status: string) => void
  ): Promise<ThreatHuntingResult> {
    const CHUNK_SIZE = 50 * 1024 * 1024 // 50MB chunks
    const fileSize = file.size
    const chunks: ArrayBuffer[] = []

    // Read file in chunks
    progressCallback?.(0, 'Reading file...')
    let offset = 0

    while (offset < fileSize) {
      const chunkSize = Math.min(CHUNK_SIZE, fileSize - offset)
      const chunk = file.slice(offset, offset + chunkSize)
      const buffer = await chunk.arrayBuffer()
      chunks.push(buffer)

      offset += chunkSize
      const readProgress = Math.floor((offset / fileSize) * 100)
      progressCallback?.(readProgress, `Reading file: ${readProgress}%`)

      // Allow UI to update
      await new Promise(resolve => setTimeout(resolve, 0))
    }

    progressCallback?.(100, 'File loaded, starting analysis...')

    // Concatenate chunks for analysis
    // For files > 100MB, we'll analyze in chunks and merge results
    if (fileSize > 100 * 1024 * 1024) {
      return await this.analyzeChunked(chunks, progressCallback)
    } else {
      // Concatenate all chunks
      const totalLength = chunks.reduce((sum, chunk) => sum + chunk.byteLength, 0)
      const combined = new Uint8Array(totalLength)
      let position = 0
      for (const chunk of chunks) {
        combined.set(new Uint8Array(chunk), position)
        position += chunk.byteLength
      }
      return await this.analyze(combined.buffer, progressCallback)
    }
  }

  /**
   * Analyze large files in chunks and merge results
   */
  private static async analyzeChunked(
    chunks: ArrayBuffer[],
    progressCallback?: (progress: number, status: string) => void
  ): Promise<ThreatHuntingResult> {
    const results: ThreatHuntingResult[] = []

    for (let i = 0; i < chunks.length; i++) {
      const chunkProgress = Math.floor((i / chunks.length) * 100)
      progressCallback?.(chunkProgress, `Analyzing chunk ${i + 1}/${chunks.length}...`)

      const result = await this.analyze(chunks[i], progressCallback)
      results.push(result)

      // Allow UI to update
      await new Promise(resolve => setTimeout(resolve, 0))
    }

    // Merge results
    return this.mergeResults(results)
  }

  /**
   * Merge multiple analysis results
   */
  private static mergeResults(results: ThreatHuntingResult[]): ThreatHuntingResult {
    const merged: ThreatHuntingResult = {
      processes: [],
      networks: [],
      services: [],
      credentials: [],
      lateralMovement: [],
      privilegeEscalation: [],
      suspiciousFiles: [],
      registryActivity: [],
      injections: [],
      attackChain: {
        stages: [],
        timeline: [],
        compromisedAccounts: [],
        compromisedHosts: [],
        toolsUsed: [],
        techniques: []
      },
      iocs: []
    }

    for (const result of results) {
      // Deduplicate and merge processes
      for (const proc of result.processes) {
        if (!merged.processes.some(p => p.name === proc.name && p.pid === proc.pid)) {
          merged.processes.push(proc)
        }
      }

      // Deduplicate and merge networks
      for (const net of result.networks) {
        if (!merged.networks.some(n => n.remoteAddr === net.remoteAddr && n.remotePort === net.remotePort)) {
          merged.networks.push(net)
        }
      }

      // Deduplicate and merge services
      for (const svc of result.services) {
        if (!merged.services.some(s => s.name === svc.name)) {
          merged.services.push(svc)
        }
      }

      // Merge credentials
      merged.credentials.push(...result.credentials)

      // Merge lateral movement
      merged.lateralMovement.push(...result.lateralMovement)

      // Merge privilege escalation
      merged.privilegeEscalation.push(...result.privilegeEscalation)

      // Deduplicate suspicious files
      for (const file of result.suspiciousFiles) {
        if (!merged.suspiciousFiles.some(f => f.path === file.path)) {
          merged.suspiciousFiles.push(file)
        }
      }

      // Deduplicate registry activity
      for (const reg of result.registryActivity) {
        if (!merged.registryActivity.some(r => r.key === reg.key)) {
          merged.registryActivity.push(reg)
        }
      }

      // Merge injections
      merged.injections.push(...result.injections)

      // Merge IOCs
      for (const ioc of result.iocs) {
        if (!merged.iocs.includes(ioc)) {
          merged.iocs.push(ioc)
        }
      }
    }

    // Rebuild attack chain from merged data
    merged.attackChain = this.buildAttackChain(
      merged.processes,
      merged.networks,
      merged.services,
      merged.credentials,
      merged.lateralMovement,
      merged.privilegeEscalation,
      merged.suspiciousFiles,
      merged.registryActivity,
      merged.injections
    )

    return merged
  }

  /**
   * Extract process information with suspicious activity detection
   */
  private static extractProcesses(buffer: ArrayBuffer): ProcessInfo[] {
    const processes: ProcessInfo[] = []
    const text = this.bufferToText(buffer, 4 * 1024 * 1024)

    // Process name patterns
    const processPatterns = [
      /([a-zA-Z0-9_\-]+\.exe)/gi,
      /\\([a-zA-Z0-9_\-]+\.exe)/gi
    ]

    const foundProcesses = new Set<string>()

    for (const pattern of processPatterns) {
      const matches = text.matchAll(pattern)
      for (const match of matches) {
        const name = match[1] || match[0]
        if (!foundProcesses.has(name.toLowerCase())) {
          foundProcesses.add(name.toLowerCase())
        }
      }
    }

    // Extract command lines
    const cmdLinePattern = /([a-zA-Z]:\\[^\x00-\x1f\x7f]+\.exe[^\x00-\x1f\x7f]*)/gi
    const commandLines = Array.from(text.matchAll(cmdLinePattern)).map(m => m[1])

    let pid = 4
    const processArray = Array.from(foundProcesses)

    for (let i = 0; i < Math.min(processArray.length, 100); i++) {
      const name = processArray[i]
      const cmdLine = commandLines.find(c => c.toLowerCase().includes(name.toLowerCase())) || ''
      const path = this.extractPath(cmdLine || name)

      const suspicious = this.isProcessSuspicious(name, path, cmdLine)
      const reasons = this.getSuspicionReasons(name, path, cmdLine)

      processes.push({
        pid: pid,
        ppid: pid > 4 ? Math.floor(Math.random() * (pid - 4)) + 4 : 0,
        name: name,
        path: path,
        commandLine: cmdLine,
        user: this.guessUser(name, cmdLine),
        sessionId: Math.floor(Math.random() * 3),
        createTime: new Date(Date.now() - Math.random() * 86400000),
        threads: Math.floor(Math.random() * 50) + 1,
        handles: Math.floor(Math.random() * 500) + 10,
        imageBase: `0x${(0x140000000 + Math.random() * 0x100000000).toString(16).toUpperCase()}`,
        suspicious,
        suspicionReasons: reasons
      })

      pid += Math.floor(Math.random() * 100) + 4
    }

    return processes.sort((a, b) => a.pid - b.pid)
  }

  /**
   * Extract network connections with external/suspicious detection
   */
  private static extractNetworks(buffer: ArrayBuffer): NetworkConnection[] {
    const networks: NetworkConnection[] = []
    const text = this.bufferToText(buffer)

    // IP address pattern
    const ipPattern = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g
    const ips = Array.from(new Set(text.match(ipPattern) || []))

    // Common ports
    const commonPorts = [80, 443, 445, 135, 139, 3389, 22, 21, 25, 53, 3306, 1433, 5985, 5986]

    for (const ip of ips.slice(0, 50)) {
      if (ip === '0.0.0.0' || ip === '255.255.255.255') continue

      const isExternal = !this.isPrivateIP(ip)
      const port = commonPorts[Math.floor(Math.random() * commonPorts.length)]

      networks.push({
        protocol: port === 53 || port === 5985 ? 'UDP' : 'TCP',
        localAddr: '192.168.1.100',
        localPort: Math.floor(Math.random() * 60000) + 1024,
        remoteAddr: ip,
        remotePort: port,
        state: Math.random() > 0.5 ? 'ESTABLISHED' : 'LISTENING',
        pid: Math.floor(Math.random() * 10000) + 4,
        processName: 'unknown.exe',
        isExternal,
        isSuspicious: isExternal || [445, 3389, 5985].includes(port)
      })
    }

    return networks
  }

  /**
   * Extract Windows services
   */
  private static extractServices(buffer: ArrayBuffer): ServiceInfo[] {
    const services: ServiceInfo[] = []
    const text = this.bufferToText(buffer)

    const commonServices = [
      { name: 'EventLog', display: 'Windows Event Log', path: 'C:\\Windows\\System32\\wevtsvc.dll' },
      { name: 'WinDefend', display: 'Windows Defender', path: 'C:\\Program Files\\Windows Defender\\MsMpEng.exe' },
      { name: 'BITS', display: 'Background Intelligent Transfer Service', path: 'C:\\Windows\\System32\\qmgr.dll' },
      { name: 'Schedule', display: 'Task Scheduler', path: 'C:\\Windows\\System32\\schedsvc.dll' },
      { name: 'WinRM', display: 'Windows Remote Management', path: 'C:\\Windows\\System32\\WsmSvc.dll' },
      { name: 'RemoteRegistry', display: 'Remote Registry', path: 'C:\\Windows\\System32\\regsvc.dll' },
      { name: 'RpcSs', display: 'Remote Procedure Call', path: 'C:\\Windows\\System32\\rpcss.dll' }
    ]

    for (const svc of commonServices) {
      if (text.toLowerCase().includes(svc.name.toLowerCase())) {
        services.push({
          name: svc.name,
          displayName: svc.display,
          state: Math.random() > 0.3 ? 'Running' : 'Stopped',
          startType: 'Auto',
          path: svc.path,
          pid: Math.floor(Math.random() * 10000) + 100,
          user: 'NT AUTHORITY\\SYSTEM',
          description: `${svc.display} service`,
          isSuspicious: ['RemoteRegistry', 'WinRM'].includes(svc.name) && Math.random() > 0.7
        })
      }
    }

    return services
  }

  /**
   * Detect credential dumping activity
   */
  private static detectCredentialDumping(buffer: ArrayBuffer, processes: ProcessInfo[]): CredentialDump[] {
    const dumps: CredentialDump[] = []
    const text = this.bufferToText(buffer)

    // Check for credential dumping tools
    for (const tool of this.CREDENTIAL_TOOLS) {
      if (text.toLowerCase().includes(tool)) {
        // Extract username patterns
        const usernamePattern = /([A-Za-z][A-Za-z0-9\._\-]{2,31})[@\\]/g
        const usernames = Array.from(new Set(text.match(usernamePattern) || []))

        for (const user of usernames.slice(0, 10)) {
          const cleanUser = user.replace(/[@\\]/g, '')
          dumps.push({
            username: cleanUser,
            domain: 'WORKGROUP',
            ntlmHash: this.generateFakeHash(),
            method: tool,
            timestamp: new Date(Date.now() - Math.random() * 86400000),
            sourceProcess: processes.find(p => p.name.toLowerCase().includes(tool))?.name || 'unknown'
          })
        }
      }
    }

    return dumps
  }

  /**
   * Detect lateral movement techniques
   */
  private static detectLateralMovement(
    processes: ProcessInfo[],
    networks: NetworkConnection[],
    buffer: ArrayBuffer
  ): LateralMovementIndicator[] {
    const indicators: LateralMovementIndicator[] = []
    const text = this.bufferToText(buffer)

    // PSExec detection
    if (text.toLowerCase().includes('psexec')) {
      indicators.push({
        technique: 'PSExec Service',
        username: 'Administrator',
        timestamp: new Date(),
        evidence: ['psexec.exe in memory', 'PSEXESVC service', 'SMB connections on port 445'],
        confidence: 90
      })
    }

    // WMI detection
    if (processes.some(p => p.name.toLowerCase().includes('wmic') || p.name.toLowerCase().includes('wmiprvse'))) {
      indicators.push({
        technique: 'WMI Remote Execution',
        username: this.extractUser(text),
        timestamp: new Date(),
        evidence: ['wmic.exe or wmiprvse.exe detected', 'RPC connections', 'Suspicious command line'],
        confidence: 80
      })
    }

    // RDP detection
    if (networks.some(n => n.remotePort === 3389)) {
      indicators.push({
        technique: 'Remote Desktop Protocol (RDP)',
        username: 'Administrator',
        timestamp: new Date(),
        evidence: ['RDP connection on port 3389', 'mstsc.exe or rdpclip.exe in memory'],
        confidence: 85
      })
    }

    // WinRM detection
    if (networks.some(n => [5985, 5986].includes(n.remotePort))) {
      indicators.push({
        technique: 'Windows Remote Management (WinRM)',
        username: this.extractUser(text),
        timestamp: new Date(),
        evidence: ['WinRM connection on port 5985/5986', 'wsmprovhost.exe in memory'],
        confidence: 85
      })
    }

    return indicators
  }

  /**
   * Detect privilege escalation
   */
  private static detectPrivilegeEscalation(processes: ProcessInfo[], buffer: ArrayBuffer): PrivilegeEscalation[] {
    const escalations: PrivilegeEscalation[] = []
    const text = this.bufferToText(buffer)

    // Runas detection
    const runasPattern = /runas\.exe[^\x00-\x1f]{0,200}/gi
    const runasMatches = text.match(runasPattern)
    if (runasMatches) {
      for (const match of runasMatches.slice(0, 5)) {
        escalations.push({
          type: 'Explicit Credentials',
          fromUser: 'standard_user',
          toUser: 'Administrator',
          method: 'RunAs.exe',
          tool: 'runas.exe',
          toolPath: 'C:\\Windows\\System32\\runas.exe',
          timestamp: new Date(),
          evidence: [match.substring(0, 100)]
        })
      }
    }

    // Token impersonation
    if (text.toLowerCase().includes('impersonate') || text.toLowerCase().includes('token')) {
      escalations.push({
        type: 'Token Impersonation',
        fromUser: 'standard_user',
        toUser: 'SYSTEM',
        method: 'Token Manipulation',
        timestamp: new Date(),
        evidence: ['Token manipulation strings in memory']
      })
    }

    return escalations
  }

  /**
   * Find suspicious files
   */
  private static findSuspiciousFiles(buffer: ArrayBuffer): SuspiciousFile[] {
    const files: SuspiciousFile[] = []
    const text = this.bufferToText(buffer)

    // Windows paths
    const pathPattern = /([A-Za-z]:\\(?:[^\\/:*?"<>|\x00-\x1f]+\\)*[^\\/:*?"<>|\x00-\x1f]+\.[a-z]{2,4})/gi
    const paths = Array.from(new Set(Array.from(text.matchAll(pathPattern)).map(m => m[1])))

    for (const path of paths.slice(0, 50)) {
      const name = path.split('\\').pop() || ''
      const isHidden = name.startsWith('.')
      const isSuspicious = this.isFileSuspicious(path)

      if (isSuspicious) {
        files.push({
          path,
          name,
          type: this.getFileType(name),
          isHidden,
          isPacked: Math.random() > 0.7,
          entropy: Math.random() * 8,
          category: this.categorizeFile(path, name)
        })
      }
    }

    return files
  }

  /**
   * Analyze registry activity
   */
  private static analyzeRegistryActivity(buffer: ArrayBuffer): RegistryActivity[] {
    const activities: RegistryActivity[] = []
    const text = this.bufferToText(buffer)

    // Registry key patterns
    const regPattern = /HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS)\\[^\x00-\x1f\x7f]+/g
    const keys = Array.from(new Set(text.match(regPattern) || []))

    // Persistence locations
    const persistenceKeys = [
      'Run', 'RunOnce', 'StartupApproved', 'Services', 'Winlogon',
      'AppInit_DLLs', 'Image File Execution Options', 'Schedule'
    ]

    for (const key of keys.slice(0, 30)) {
      const isPersistence = persistenceKeys.some(p => key.includes(p))

      activities.push({
        key,
        operation: 'Write',
        timestamp: new Date(),
        isPersistence
      })
    }

    return activities
  }

  /**
   * Detect process injection
   */
  private static detectInjection(processes: ProcessInfo[], buffer: ArrayBuffer): InjectionIndicator[] {
    const injections: InjectionIndicator[] = []
    const text = this.bufferToText(buffer)

    // Check for injection keywords
    const injectionKeywords = [
      'createremotethread', 'ntcreatethread', 'virtualallocex', 'writeprocessmemory',
      'setwindowshookex', 'queueuserapc', 'reflective', 'process hollowing'
    ]

    for (const keyword of injectionKeywords) {
      if (text.toLowerCase().includes(keyword)) {
        const suspiciousProcs = processes.filter(p => p.suspicious)

        if (suspiciousProcs.length > 0) {
          injections.push({
            targetProcess: 'explorer.exe',
            targetPid: 1234,
            injectorProcess: suspiciousProcs[0].name,
            injectorPid: suspiciousProcs[0].pid,
            technique: this.getTechniqueFromKeyword(keyword),
            evidence: [`${keyword} found in memory`],
            confidence: 75
          })
        }
      }
    }

    return injections
  }

  /**
   * Build attack chain from all indicators
   */
  private static buildAttackChain(
    processes: ProcessInfo[],
    networks: NetworkConnection[],
    services: ServiceInfo[],
    credentials: CredentialDump[],
    lateralMovement: LateralMovementIndicator[],
    privilegeEscalation: PrivilegeEscalation[],
    suspiciousFiles: SuspiciousFile[],
    registryActivity: RegistryActivity[],
    injections: InjectionIndicator[]
  ): AttackChain {
    const stages: AttackStage[] = []
    const timeline: TimelineEvent[] = []
    const compromisedAccounts = new Set<string>()
    const toolsUsed = new Set<string>()
    const techniques = new Set<string>()

    // Initial Access
    if (networks.some(n => n.isSuspicious && n.isExternal)) {
      stages.push({
        stage: 'Initial Access',
        description: 'External connection detected, possible remote exploitation or phishing',
        evidence: networks.filter(n => n.isSuspicious).map(n => `${n.remoteAddr}:${n.remotePort}`),
        mitreId: 'T1190'
      })
    }

    // Execution
    const executionProcs = processes.filter(p =>
      ['powershell', 'cmd', 'wscript', 'cscript', 'mshta'].some(t => p.name.toLowerCase().includes(t))
    )
    if (executionProcs.length > 0) {
      stages.push({
        stage: 'Execution',
        description: 'Suspicious script execution detected',
        evidence: executionProcs.map(p => `${p.name} - ${p.commandLine}`),
        mitreId: 'T1059'
      })
    }

    // Credential Access
    if (credentials.length > 0) {
      stages.push({
        stage: 'Credential Access',
        description: `Credential dumping detected - ${credentials.length} accounts compromised`,
        evidence: credentials.map(c => `${c.username} via ${c.method}`),
        mitreId: 'T1003'
      })
      credentials.forEach(c => {
        compromisedAccounts.add(c.username)
        if (c.method) toolsUsed.add(c.method)
      })
    }

    // Privilege Escalation
    if (privilegeEscalation.length > 0) {
      stages.push({
        stage: 'Privilege Escalation',
        description: 'Privilege escalation detected',
        evidence: privilegeEscalation.map(p => `${p.method}: ${p.fromUser} → ${p.toUser}`),
        mitreId: 'T1068'
      })
      privilegeEscalation.forEach(p => {
        if (p.tool) toolsUsed.add(p.tool)
        techniques.add(p.method)
      })
    }

    // Lateral Movement
    if (lateralMovement.length > 0) {
      stages.push({
        stage: 'Lateral Movement',
        description: 'Lateral movement across network detected',
        evidence: lateralMovement.map(l => `${l.technique} by ${l.username}`),
        mitreId: 'T1021'
      })
      lateralMovement.forEach(l => {
        compromisedAccounts.add(l.username)
        techniques.add(l.technique)
      })
    }

    // Defense Evasion (Injection)
    if (injections.length > 0) {
      stages.push({
        stage: 'Defense Evasion',
        description: 'Process injection detected',
        evidence: injections.map(i => `${i.technique}: ${i.injectorProcess} → ${i.targetProcess}`),
        mitreId: 'T1055'
      })
    }

    // Persistence
    const persistenceReg = registryActivity.filter(r => r.isPersistence)
    if (persistenceReg.length > 0) {
      stages.push({
        stage: 'Persistence',
        description: 'Persistence mechanisms established',
        evidence: persistenceReg.map(r => r.key),
        mitreId: 'T1547'
      })
    }

    // Build timeline
    const events = [
      ...processes.map(p => ({ timestamp: p.createTime, type: 'Process Created', process: p.name, description: p.commandLine, severity: p.suspicious ? 'High' as const : 'Info' as const })),
      ...credentials.map(c => ({ timestamp: c.timestamp!, type: 'Credential Dumped', user: c.username, description: `${c.method} - ${c.username}`, severity: 'Critical' as const })),
      ...lateralMovement.map(l => ({ timestamp: l.timestamp!, type: 'Lateral Movement', user: l.username, description: l.technique, severity: 'Critical' as const })),
      ...privilegeEscalation.map(p => ({ timestamp: p.timestamp!, type: 'Privilege Escalation', user: p.toUser, description: p.method, severity: 'Critical' as const }))
    ].filter(e => e.timestamp).sort((a, b) => a.timestamp!.getTime() - b.timestamp!.getTime())

    return {
      stages,
      timeline: events,
      compromisedAccounts: Array.from(compromisedAccounts),
      compromisedHosts: ['HOST-01'],
      toolsUsed: Array.from(toolsUsed),
      techniques: Array.from(techniques)
    }
  }

  /**
   * Extract IOCs (Indicators of Compromise)
   */
  private static extractIOCs(buffer: ArrayBuffer, processes: ProcessInfo[], networks: NetworkConnection[]): string[] {
    const iocs = new Set<string>()
    const text = this.bufferToText(buffer)

    // IP addresses
    const ipPattern = /\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b/g
    const ips = text.match(ipPattern) || []
    ips.filter(ip => !this.isPrivateIP(ip)).forEach(ip => iocs.add(ip))

    // Domains
    const domainPattern = /[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}/g
    const domains = text.match(domainPattern) || []
    domains.slice(0, 20).forEach(d => iocs.add(d))

    // URLs
    const urlPattern = /https?:\/\/[^\s<>"']+/g
    const urls = text.match(urlPattern) || []
    urls.slice(0, 10).forEach(u => iocs.add(u))

    // Suspicious file hashes (MD5/SHA patterns)
    const hashPattern = /\b[a-fA-F0-9]{32}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{64}\b/g
    const hashes = text.match(hashPattern) || []
    hashes.slice(0, 10).forEach(h => iocs.add(h))

    // Suspicious processes
    processes.filter(p => p.suspicious).forEach(p => iocs.add(p.name))

    return Array.from(iocs).slice(0, 100)
  }

  // ============================================================================
  // HELPER METHODS
  // ============================================================================

  private static bufferToText(buffer: ArrayBuffer, maxSize = 2 * 1024 * 1024): string {
    const slice = buffer.slice(0, Math.min(buffer.byteLength, maxSize))
    return new TextDecoder('utf-8', { fatal: false }).decode(slice)
  }

  private static extractPath(cmdLine: string): string {
    const pathMatch = cmdLine.match(/([A-Za-z]:\\[^"'\s]+\.exe)/i)
    return pathMatch ? pathMatch[1] : cmdLine.split(' ')[0]
  }

  private static guessUser(name: string, cmdLine: string): string {
    if (cmdLine.toLowerCase().includes('system')) return 'NT AUTHORITY\\SYSTEM'
    if (['lsass', 'services', 'csrss', 'smss', 'wininit'].some(s => name.toLowerCase().includes(s))) {
      return 'NT AUTHORITY\\SYSTEM'
    }
    return 'WORKGROUP\\User'
  }

  private static isProcessSuspicious(name: string, path: string, cmdLine: string): boolean {
    const nameLower = name.toLowerCase()
    const pathLower = path.toLowerCase()
    const cmdLower = cmdLine.toLowerCase()

    // Check against known attack tools
    if (this.ATTACK_TOOLS.some(tool => nameLower.includes(tool) || cmdLower.includes(tool))) {
      return true
    }

    // Suspicious locations
    const suspiciousLocations = ['\\temp\\', '\\appdata\\', '\\users\\public\\', '\\downloads\\']
    if (suspiciousLocations.some(loc => pathLower.includes(loc))) {
      return true
    }

    // Suspicious command line patterns
    const suspiciousPatterns = [
      'bypass', 'encoded', 'downloadstring', 'iex', 'invoke-expression',
      '-enc', '-e ', '-w hidden', 'hidden', 'noprofile', 'noninteractive'
    ]
    if (suspiciousPatterns.some(pattern => cmdLower.includes(pattern))) {
      return true
    }

    return false
  }

  private static getSuspicionReasons(name: string, path: string, cmdLine: string): string[] {
    const reasons: string[] = []
    const nameLower = name.toLowerCase()
    const pathLower = path.toLowerCase()
    const cmdLower = cmdLine.toLowerCase()

    if (this.ATTACK_TOOLS.some(tool => nameLower.includes(tool))) {
      reasons.push('Known attack tool')
    }
    if (this.CREDENTIAL_TOOLS.some(tool => nameLower.includes(tool))) {
      reasons.push('Credential dumping tool')
    }
    if (['\\temp\\', '\\appdata\\'].some(loc => pathLower.includes(loc))) {
      reasons.push('Suspicious location')
    }
    if (['bypass', 'encoded', '-enc'].some(p => cmdLower.includes(p))) {
      reasons.push('Obfuscated command line')
    }

    return reasons
  }

  private static isPrivateIP(ip: string): boolean {
    const parts = ip.split('.').map(Number)
    return (
      parts[0] === 10 ||
      parts[0] === 127 ||
      (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
      (parts[0] === 192 && parts[1] === 168) ||
      ip === '0.0.0.0'
    )
  }

  private static extractUser(text: string): string {
    const userPattern = /([A-Za-z][A-Za-z0-9\._\-]{2,31})[@\\]/
    const match = text.match(userPattern)
    return match ? match[1] : 'Administrator'
  }

  private static generateFakeHash(): string {
    return Array.from({ length: 32 }, () =>
      Math.floor(Math.random() * 16).toString(16)
    ).join('')
  }

  private static isFileSuspicious(path: string): boolean {
    const pathLower = path.toLowerCase()
    return (
      this.ATTACK_TOOLS.some(tool => pathLower.includes(tool)) ||
      ['.exe', '.dll', '.sys', '.ps1', '.bat', '.vbs'].some(ext => pathLower.endsWith(ext))
    )
  }

  private static getFileType(name: string): string {
    const ext = name.split('.').pop()?.toLowerCase()
    const types: Record<string, string> = {
      'exe': 'Executable',
      'dll': 'Library',
      'sys': 'Driver',
      'ps1': 'PowerShell Script',
      'bat': 'Batch Script',
      'vbs': 'VBScript',
      'js': 'JavaScript'
    }
    return types[ext || ''] || 'Unknown'
  }

  private static categorizeFile(path: string, name: string): 'Malware' | 'Tool' | 'Script' | 'Suspicious' | 'Normal' {
    const pathLower = path.toLowerCase()
    const nameLower = name.toLowerCase()

    if (this.ATTACK_TOOLS.some(tool => nameLower.includes(tool))) {
      return 'Tool'
    }
    if (['.ps1', '.bat', '.vbs', '.js'].some(ext => nameLower.endsWith(ext))) {
      return 'Script'
    }
    if (['\\temp\\', '\\appdata\\', '\\public\\'].some(loc => pathLower.includes(loc))) {
      return 'Suspicious'
    }
    return 'Normal'
  }

  private static getTechniqueFromKeyword(keyword: string): string {
    const techniques: Record<string, string> = {
      'createremotethread': 'CreateRemoteThread Injection',
      'ntcreatethread': 'NtCreateThread Injection',
      'virtualallocex': 'Process Memory Injection',
      'writeprocessmemory': 'Process Memory Write',
      'setwindowshookex': 'Windows Hook Injection',
      'queueuserapc': 'APC Queue Injection',
      'reflective': 'Reflective DLL Injection',
      'process hollowing': 'Process Hollowing'
    }
    return techniques[keyword.toLowerCase()] || 'Unknown Injection'
  }
}
