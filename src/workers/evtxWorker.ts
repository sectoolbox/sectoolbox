// EVTX Parser Web Worker
// Parses EVTX files in background thread to prevent UI blocking

import { analyzeEVTX, analyzeMultipleEVTX } from '../lib/evtxAnalysis'

export interface WorkerMessage {
  type: 'parse-single' | 'parse-multiple'
  payload: {
    fileBuffers: Array<{ name: string; buffer: ArrayBuffer }>
  }
}

export interface WorkerResponse {
  type: 'progress' | 'complete' | 'error'
  payload: any
}

// Handle messages from main thread
self.onmessage = async (event: MessageEvent<WorkerMessage>) => {
  const { type, payload } = event.data

  try {
    if (type === 'parse-single') {
      const { name, buffer } = payload.fileBuffers[0]

      // Send progress updates
      postMessage({
        type: 'progress',
        payload: { progress: 10, status: 'Loading file...' }
      })

      postMessage({
        type: 'progress',
        payload: { progress: 30, status: 'Parsing EVTX events...' }
      })

      const result = analyzeEVTX(buffer, name)

      postMessage({
        type: 'progress',
        payload: { progress: 70, status: 'Analyzing threats...' }
      })

      postMessage({
        type: 'progress',
        payload: { progress: 100, status: 'Analysis complete' }
      })

      // Send final result
      postMessage({
        type: 'complete',
        payload: result
      })
    } else if (type === 'parse-multiple') {
      postMessage({
        type: 'progress',
        payload: { progress: 10, status: `Loading ${payload.fileBuffers.length} files...` }
      })

      postMessage({
        type: 'progress',
        payload: { progress: 40, status: 'Parsing events from all files...' }
      })

      const result = await analyzeMultipleEVTX(payload.fileBuffers)

      postMessage({
        type: 'progress',
        payload: { progress: 85, status: 'Correlating events...' }
      })

      postMessage({
        type: 'progress',
        payload: { progress: 100, status: 'Analysis complete' }
      })

      postMessage({
        type: 'complete',
        payload: result
      })
    }
  } catch (error) {
    postMessage({
      type: 'error',
      payload: {
        message: error instanceof Error ? error.message : 'Unknown error occurred'
      }
    })
  }
}
