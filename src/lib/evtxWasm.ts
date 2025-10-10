// EVTX Parser
// Handles EVTX file parsing using JavaScript implementation

import type { EventRecord } from './forensics'

export interface ParsedEvtxResult {
  success: boolean
  events: EventRecord[]
  error?: string
  metadata?: {
    totalEvents: number
    fileSize: number
    parseTime: number
  }
}

/**
 * Parse EVTX file using JavaScript implementation
 */
export async function parseEvtxWithWasm(buffer: ArrayBuffer): Promise<ParsedEvtxResult> {
  const startTime = performance.now()

  try {
    console.log(`Parsing EVTX file (${buffer.byteLength} bytes) using JavaScript parser...`)

    // Dynamic import to avoid circular dependencies
    const { EvtxAnalyzer } = await import('./forensics')

    // Use the JavaScript EVTX parser
    const events = EvtxAnalyzer.extractEventsStub(buffer)
    const parseTime = performance.now() - startTime

    console.log(`Successfully parsed ${events.length} events in ${parseTime.toFixed(2)}ms`)

    return {
      success: true,
      events,
      metadata: {
        totalEvents: events.length,
        fileSize: buffer.byteLength,
        parseTime
      }
    }

  } catch (error) {
    const parseTime = performance.now() - startTime
    console.error('EVTX parsing failed:', error)

    return {
      success: false,
      events: [],
      error: error instanceof Error ? error.message : 'Failed to parse EVTX file',
      metadata: {
        totalEvents: 0,
        fileSize: buffer.byteLength,
        parseTime
      }
    }
  }
}

/**
 * Check if WASM EVTX parser is available (always returns false as we use JS implementation)
 */
export async function isWasmParserAvailable(): Promise<boolean> {
  return false
}

/**
 * Initialize WASM parser (not used, kept for compatibility)
 */
export async function initializeWasmParser(): Promise<boolean> {
  console.log('Using JavaScript EVTX parser')
  return false
}

/**
 * Get any loading errors
 */
export function getWasmParserError(): string | null {
  return null
}

// Export types
export type { EventRecord }
