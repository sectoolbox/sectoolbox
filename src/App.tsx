import React, { Suspense, lazy } from 'react'
import { BrowserRouter as Router, Routes, Route } from 'react-router-dom'
import Layout from './components/Layout'

const Dashboard = lazy(() => import('./pages/Dashboard'))
const PcapAnalysis = lazy(() => import('./pages/PcapAnalysis'))
const USBPcapAnalysis = lazy(() => import('./pages/USBPcapAnalysis'))
const ImageAnalysis = lazy(() => import('./pages/ImageAnalysis'))
const CryptoTools = lazy(() => import('./pages/CryptoTools'))
const WebTools = lazy(() => import('./pages/WebTools'))
const DigitalForensics = lazy(() => import('./pages/DigitalForensics'))
const EVTXAnalysis = lazy(() => import('./pages/EVTXAnalysis'))
const MemoryForensics = lazy(() => import('./pages/MemoryForensics'))
const FolderScanner = lazy(() => import('./pages/FolderScanner'))
const AudioAnalysis = lazy(() => import('./pages/AudioAnalysis'))
const Network = lazy(() => import('./pages/Network'))
const ThreatIntel = lazy(() => import('./pages/ThreatIntel'))

function App() {
  return (
    <Router>
      <div className="min-h-screen bg-background matrix-bg">
        <Layout>
          <Suspense fallback={<div className="min-h-screen flex items-center justify-center">Loading...</div>}>
            <Routes>
              <Route path="/" element={<Dashboard />} />
              <Route path="/pcap" element={<PcapAnalysis />} />
              <Route path="/pcap-usb" element={<USBPcapAnalysis />} />
              <Route path="/image" element={<ImageAnalysis />} />
              <Route path="/crypto" element={<CryptoTools />} />
              <Route path="/web" element={<WebTools />} />
              <Route path="/forensics" element={<DigitalForensics />} />
              <Route path="/forensics-evtx" element={<EVTXAnalysis />} />
              <Route path="/memory" element={<MemoryForensics />} />
              <Route path="/folder-scanner" element={<FolderScanner />} />
              <Route path="/audio" element={<AudioAnalysis />} />
              <Route path="/network" element={<Network />} />
              <Route path="/threat-intel" element={<ThreatIntel />} />
            </Routes>
          </Suspense>
        </Layout>
      </div>
    </Router>
  )
}

export default App
