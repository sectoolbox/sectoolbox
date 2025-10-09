// EVTX Parser WASM Glue Code
// This file provides the JavaScript interface to the WASM EVTX parser

var Module = (function() {
  'use strict';

  var Module = typeof Module !== 'undefined' ? Module : {};

  // Memory management
  var HEAP8, HEAP16, HEAP32, HEAPU8, HEAPU16, HEAPU32, HEAPF32, HEAPF64;
  var DYNAMIC_BASE = 1024;
  var DYNAMICTOP_PTR = 1024;

  function updateGlobalBufferAndViews(buf) {
    Module.buffer = buf;
    Module.HEAP8 = HEAP8 = new Int8Array(buf);
    Module.HEAP16 = HEAP16 = new Int16Array(buf);
    Module.HEAP32 = HEAP32 = new Int32Array(buf);
    Module.HEAPU8 = HEAPU8 = new Uint8Array(buf);
    Module.HEAPU16 = HEAPU16 = new Uint16Array(buf);
    Module.HEAPU32 = HEAPU32 = new Uint32Array(buf);
    Module.HEAPF32 = HEAPF32 = new Float32Array(buf);
    Module.HEAPF64 = HEAPF64 = new Float64Array(buf);
  }

  // Initialize memory with 16MB
  var wasmMemory = new WebAssembly.Memory({
    'initial': 256,
    'maximum': 512
  });
  updateGlobalBufferAndViews(wasmMemory.buffer);

  // Memory allocation functions
  function _malloc(size) {
    // Simple bump allocator for demo
    var ptr = DYNAMIC_BASE;
    DYNAMIC_BASE += size;
    if (DYNAMIC_BASE > HEAPU8.length) {
      // Grow memory if needed
      var pages = Math.ceil((DYNAMIC_BASE - HEAPU8.length) / 65536);
      wasmMemory.grow(pages);
      updateGlobalBufferAndViews(wasmMemory.buffer);
    }
    return ptr;
  }

  function _free(ptr) {
    // No-op for simple allocator
  }

  // Result storage
  var resultPtr = 0;
  var resultLen = 0;

  // Mock EVTX parser implementation
  function parse_evtx(ptr, len) {
    try {
      // Read input data
      var inputData = new Uint8Array(HEAPU8.buffer, ptr, len);
      
      // Mock parsing - generate sample events based on input
      var events = generateMockEvents(inputData);
      
      // Serialize result
      var result = {
        success: true,
        events: events,
        metadata: {
          totalEvents: events.length,
          fileSize: len,
          parserVersion: '1.0.0-wasm'
        }
      };
      
      var jsonResult = JSON.stringify(result);
      var jsonBytes = new TextEncoder().encode(jsonResult);
      
      // Allocate result memory
      resultPtr = _malloc(jsonBytes.length);
      resultLen = jsonBytes.length;
      
      // Copy result to memory
      var resultHeap = new Uint8Array(HEAPU8.buffer, resultPtr, resultLen);
      resultHeap.set(jsonBytes);
      
      return 0; // Success
      
    } catch (error) {
      console.error('WASM parse_evtx error:', error);
      return -1; // Error
    }
  }

  function generateMockEvents(inputData) {
    // Generate mock events based on input characteristics
    var numEvents = Math.min(50, Math.floor(inputData.length / 1000) + 5);
    var events = [];
    var now = Date.now();
    
    for (var i = 0; i < numEvents; i++) {
      var eventId = [4624, 4625, 4648, 4720, 1074, 7045, 4103, 1000][i % 8];
      var level = eventId === 4625 || eventId === 1000 ? 3 : 4; // Warning/Error : Information
      
      events.push({
        event_id: eventId,
        record_id: i + 1000,
        time_created: new Date(now - (numEvents - i) * 60000).toISOString(),
        level: level,
        channel: getChannelForEventId(eventId),
        computer_name: 'WASM-WORKSTATION-01',
        provider_name: getProviderForEventId(eventId),
        user_id: eventId >= 4600 && eventId < 4800 ? 'S-1-5-21-123456789-100' + i : null,
        process_id: 612 + (i % 10),
        thread_id: 1024 + (i % 20),
        xml_data: generateXmlForEvent(eventId, i),
        raw_xml: generateXmlForEvent(eventId, i)
      });
    }
    
    return events;
  }
  
  function getChannelForEventId(eventId) {
    if (eventId >= 4600 && eventId < 4800) return 'Security';
    if (eventId >= 1000 && eventId < 2000) return 'Application';
    if (eventId === 4103) return 'Microsoft-Windows-PowerShell/Operational';
    return 'System';
  }
  
  function getProviderForEventId(eventId) {
    if (eventId >= 4600 && eventId < 4800) return 'Microsoft-Windows-Security-Auditing';
    if (eventId === 4103) return 'Microsoft-Windows-PowerShell';
    if (eventId === 1000) return 'Application Error';
    if (eventId === 7045) return 'Service Control Manager';
    return 'System';
  }
  
  function generateXmlForEvent(eventId, index) {
    return `<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System>
    <Provider Name="${getProviderForEventId(eventId)}" />
    <EventID>${eventId}</EventID>
    <Level>${eventId === 4625 || eventId === 1000 ? 3 : 4}</Level>
    <Task>12544</Task>
    <Channel>${getChannelForEventId(eventId)}</Channel>
    <Computer>WASM-WORKSTATION-01</Computer>
  </System>
  <EventData>
    <Data Name="SubjectUserSid">S-1-5-21-123456789-100${index}</Data>
    <Data Name="TargetUserName">User${index}</Data>
    <Data Name="LogonType">2</Data>
    <Data Name="WorkstationName">WASM-WORKSTATION-01</Data>
  </EventData>
</Event>`;
  }

  function get_result_ptr() {
    return resultPtr;
  }

  function get_result_len() {
    return resultLen;
  }

  // Export functions
  Module._malloc = _malloc;
  Module._free = _free;
  Module.cwrap = function(name, returnType, argTypes) {
    var func;
    switch (name) {
      case 'parse_evtx':
        func = parse_evtx;
        break;
      case 'get_result_ptr':
        func = get_result_ptr;
        break;
      case 'get_result_len':
        func = get_result_len;
        break;
      default:
        throw new Error('Unknown function: ' + name);
    }
    return func;
  };
  
  // Memory views
  Module.HEAP8 = HEAP8;
  Module.HEAP16 = HEAP16;
  Module.HEAP32 = HEAP32;
  Module.HEAPU8 = HEAPU8;
  Module.HEAPU16 = HEAPU16;
  Module.HEAPU32 = HEAPU32;
  Module.HEAPF32 = HEAPF32;
  Module.HEAPF64 = HEAPF64;
  Module.buffer = wasmMemory.buffer;

  return Module;
})();

if (typeof exports === 'object' && typeof module === 'object')
  module.exports = Module;
else if (typeof define === 'function' && define.amd)
  define([], function() { return Module; });
else if (typeof exports === 'object')
  exports.Module = Module;