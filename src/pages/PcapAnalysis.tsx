import React, { useState, useEffect, useRef } from 'react';
import { useLocation } from 'react-router-dom';
import { Upload, Cloud, Activity, Download, AlertTriangle } from 'lucide-react';
import { Button } from '../components/ui/button';
import { apiClient } from '../services/api';
import { useBackendJob } from '../hooks/useBackendJob';
import { parseTsharkPackets, detectSuspiciousActivity } from '../lib/tsharkParser';
import { analyzeIntelligence } from '../lib/pcapIntelligence';
import { IntelligenceTab } from '../components/pcap/IntelligenceTab';
import { PacketsTab } from '../components/pcap/PacketsTab';
import { StreamsTab } from '../components/pcap/StreamsTab';
import { ExplorerTab } from '../components/pcap/ExplorerTab';
import { AnalysisTab } from '../components/pcap/AnalysisTab';
import { FollowStreamModal } from '../components/pcap/FollowStreamModal';
import { PacketDetailModal } from '../components/pcap/PacketDetailModal';
import toast from 'react-hot-toast';

type TabType = 'intelligence' | 'packets' | 'streams' | 'explorer' | 'analysis';

const PcapAnalysis: React.FC = () => {
  const location = useLocation();
  const fileInputRef = useRef<HTMLInputElement>(null);

  // File state
  const [file, setFile] = useState<File | null>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);

  // Backend integration
  const { jobStatus, isLoading: isBackendLoading, startJob } = useBackendJob();

  // Analysis results
  const [packets, setPackets] = useState<any[]>([]);
  const [allPackets, setAllPackets] = useState<any[]>([]); // Unfiltered original data
  const [protocols, setProtocols] = useState<any[]>([]);
  const [httpSessions, setHttpSessions] = useState<any[]>([]);
  const [dnsQueries, setDnsQueries] = useState<any[]>([]);
  const [conversations, setConversations] = useState<any[]>([]);
  const [endpoints, setEndpoints] = useState<string[]>([]);
  const [findings, setFindings] = useState<any[]>([]);
  const [stats, setStats] = useState({
    totalPackets: 0,
    timespan: '0:00',
    protocols: [],
    hosts: 0,
    dataTransfer: 0
  });

  // UI state
  const [activeTab, setActiveTab] = useState<TabType>('intelligence');
  const [selectedPacketIndex, setSelectedPacketIndex] = useState<number | null>(null);
  const [selectedPacket, setSelectedPacket] = useState<any>(null);
  const [followStreamData, setFollowStreamData] = useState<any>(null);
  const [currentFilter, setCurrentFilter] = useState('');
  const [notice, setNotice] = useState<string | null>(null);
  const [currentJobId, setCurrentJobId] = useState<string | null>(null);

  // Handle file upload from dashboard
  useEffect(() => {
    const state = location.state as any;
    if (state?.quickUploadFile && state?.quickUploadAutoAnalyze) {
      const uploadedFile = state.quickUploadFile as File;
      setFile(uploadedFile);
      setTimeout(() => startAnalysis(uploadedFile), 500);
    }
  }, [location]);

  // Watch for backend job updates
  useEffect(() => {
    if (jobStatus) {
      if (jobStatus.status === 'processing') {
        setNotice(`Processing: ${jobStatus.progress}% - ${jobStatus.message || ''}`);
      } else if (jobStatus.status === 'completed') {
        console.log('📦 Backend results received:', jobStatus.results);
        setCurrentJobId(jobStatus.jobId); // Store jobId for Follow Stream
        processBackendResults(jobStatus.results);
        setNotice('Analysis completed successfully!');
        setIsAnalyzing(false);
        toast.success('PCAP analysis completed!');
      } else if (jobStatus.status === 'failed') {
        setNotice(`Analysis failed: ${jobStatus.error}`);
        setIsAnalyzing(false);
        toast.error('Analysis failed');
      }
    }
  }, [jobStatus]);

  const startAnalysis = async (fileToAnalyze?: File) => {
    const targetFile = fileToAnalyze || file;
    if (!targetFile) {
      toast.error('Please upload a file first');
      return;
    }

    setIsAnalyzing(true);
    setNotice('Starting deep analysis...');
    resetResults();

    try {
      const response = await apiClient.analyzePcap(targetFile, 'full');

      if (response.jobId) {
        setNotice(`Analysis started: ${response.jobId}`);
        startJob(response.jobId);
      } else {
        // Immediate response (shouldn't happen with async worker)
        processBackendResults(response);
        setIsAnalyzing(false);
      }
    } catch (error: any) {
      console.error('Analysis error:', error);
      setNotice(`Failed to start analysis: ${error.message}`);
      setIsAnalyzing(false);
      toast.error('Failed to start analysis');
    }
  };

  const processBackendResults = (results: any) => {
    console.log('📊 Processing backend results...');

    const rawPackets = results.packets || [];
    console.log(`📦 Received ${rawPackets.length} packets`);

    // Check if this is raw tshark JSON
    if (rawPackets.length > 0 && rawPackets[0]._source) {
      console.log('✅ Parsing raw tshark dump...');
      const parsed = parseTsharkPackets(rawPackets);

      setAllPackets(parsed.packets);
      setPackets(parsed.packets);
      setProtocols(parsed.protocols.details);
      setHttpSessions(parsed.httpSessions);
      setDnsQueries(parsed.dnsQueries);
      setConversations(parsed.conversations);
      setEndpoints(parsed.endpoints);

      // Run intelligence analysis
      const intelligence = analyzeIntelligence(
        parsed.packets,
        parsed.httpSessions,
        parsed.dnsQueries,
        parsed.conversations
      );
      setFindings(intelligence);

      // Calculate stats
      const timespan = calculateTimespan(parsed.packets);
      const totalBytes = parsed.conversations.reduce((sum, conv) => sum + conv.bytes, 0);

      setStats({
        totalPackets: parsed.packets.length,
        timespan,
        protocols: parsed.protocols.details,
        hosts: parsed.endpoints.length,
        dataTransfer: totalBytes
      });

      console.log('✅ Analysis complete:', {
        packets: parsed.packets.length,
        protocols: parsed.protocols.details.length,
        http: parsed.httpSessions.length,
        dns: parsed.dnsQueries.length,
        findings: intelligence.length
      });

      // Auto-switch to Intelligence tab if findings exist
      if (intelligence.some(f => f.severity === 'critical')) {
        setActiveTab('intelligence');
      }
    } else {
      console.warn('⚠️ Unexpected data format');
      setPackets(rawPackets);
      setAllPackets(rawPackets);
    }
  };

  const resetResults = () => {
    setPackets([]);
    setAllPackets([]);
    setProtocols([]);
    setHttpSessions([]);
    setDnsQueries([]);
    setConversations([]);
    setEndpoints([]);
    setFindings([]);
    setStats({
      totalPackets: 0,
      timespan: '0:00',
      protocols: [],
      hosts: 0,
      dataTransfer: 0
    });
  };

  const handleJumpToPacket = (frameNumber: number) => {
    setActiveTab('packets');
    setSelectedPacketIndex(frameNumber);
    // Scroll to packet
    setTimeout(() => {
      const element = document.querySelector(`[data-frame="${frameNumber}"]`);
      element?.scrollIntoView({ behavior: 'smooth', block: 'center' });
    }, 100);
  };

  const handleApplyFilter = (filter: string) => {
    setCurrentFilter(filter);
    setActiveTab('packets');
    // Filter will be applied in PacketsTab
  };

  const handleFollowStream = async (stream: any) => {
    if (!currentJobId || !file) {
      toast.error('Cannot follow stream - missing job data');
      return;
    }

    // Call backend to get actual stream data using tshark
    try {
      const streamId = stream.tcpStream;
      if (streamId === undefined) {
        toast.error('No TCP stream ID available');
        return;
      }

      toast.info('Extracting TCP stream...');
      const streamData = await apiClient.followTcpStream(currentJobId, streamId, file.name);

      setFollowStreamData(streamData);
      toast.success('Stream extracted!');
    } catch (error: any) {
      console.error('Follow stream error:', error);
      toast.error(`Failed to follow stream: ${error.message}`);
    }
  };

  const handleFileSelect = (selectedFile: File) => {
    setFile(selectedFile);
    resetResults();
    setNotice(null);
  };

  const handleDrop = (event: React.DragEvent) => {
    event.preventDefault();
    const droppedFile = event.dataTransfer.files[0];
    if (droppedFile) handleFileSelect(droppedFile);
  };

  const calculateTimespan = (packets: any[]): string => {
    if (packets.length < 2) return '0:00';

    const first = new Date(packets[0].timestamp).getTime();
    const last = new Date(packets[packets.length - 1].timestamp).getTime();
    const diff = (last - first) / 1000; // seconds

    const minutes = Math.floor(diff / 60);
    const seconds = Math.floor(diff % 60);
    return `${minutes}:${String(seconds).padStart(2, '0')}`;
  };

  const exportResults = () => {
    const exportData = {
      filename: file?.name,
      analyzed: new Date().toISOString(),
      stats,
      findings,
      packets: allPackets,
      httpSessions,
      dnsQueries,
      conversations
    };

    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${file?.name || 'pcap'}-analysis.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex flex-col h-screen">
      {/* Header */}
      <div className="flex-none px-6 py-4 border-b border-border bg-card">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold">PCAP Deep Analysis</h1>
            <p className="text-sm text-muted-foreground">
              Wireshark-level packet analysis with intelligent threat detection
            </p>
          </div>
          {allPackets.length > 0 && (
            <Button variant="outline" onClick={exportResults}>
              <Download className="w-4 h-4 mr-2" />
              Export All Data
            </Button>
          )}
        </div>
      </div>

      {/* File Upload or Info */}
      <div className="flex-none px-6 py-4 bg-background">
        {!file ? (
          <div
            className="border-2 border-dashed border-border rounded-lg p-8 text-center hover:border-accent transition-colors cursor-pointer"
            onDragOver={(e) => e.preventDefault()}
            onDrop={handleDrop}
            onClick={() => fileInputRef.current?.click()}
          >
            <Upload className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
            <p className="text-lg font-medium mb-2">Drop PCAP file here or click to browse</p>
            <p className="text-sm text-muted-foreground">
              Supports .pcap and .pcapng files | Deep analysis powered by tshark
            </p>
            <input
              ref={fileInputRef}
              type="file"
              accept=".pcap,.pcapng,.cap"
              onChange={(e) => {
                const selected = e.target.files?.[0];
                if (selected) handleFileSelect(selected);
              }}
              className="hidden"
            />
          </div>
        ) : (
          <div className="flex items-center justify-between bg-card border border-border rounded-lg p-4">
            <div className="flex items-center gap-3">
              <div className="w-10 h-10 rounded bg-accent/20 flex items-center justify-center">
                <Cloud className="w-5 h-5 text-accent" />
              </div>
              <div>
                <p className="font-medium">{file.name}</p>
                <p className="text-sm text-muted-foreground">
                  {(file.size / 1024 / 1024).toFixed(2)} MB
                  {stats.totalPackets > 0 && ` • ${stats.totalPackets.toLocaleString()} packets`}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Button
                onClick={() => startAnalysis()}
                disabled={isAnalyzing}
                className="bg-accent hover:bg-accent/90"
              >
                {isAnalyzing ? (
                  <>
                    <Activity className="w-4 h-4 animate-spin mr-2" />
                    Analyzing...
                  </>
                ) : (
                  <>
                    <Cloud className="w-4 h-4 mr-2" />
                    Deep Analysis
                  </>
                )}
              </Button>
              <Button
                variant="outline"
                onClick={() => {
                  setFile(null);
                  resetResults();
                  setNotice(null);
                }}
              >
                Remove
              </Button>
            </div>
          </div>
        )}
      </div>

      {/* Notice/Progress Bar */}
      {notice && (
        <div className="flex-none px-6 py-2 bg-muted/20 border-b border-border">
          <div className="flex items-center gap-2 text-sm">
            <Activity className="w-4 h-4 text-accent" />
            <span>{notice}</span>
          </div>
        </div>
      )}

      {/* Main Content - Tabs */}
      {allPackets.length > 0 && (
        <div className="flex-1 flex flex-col overflow-hidden">
          {/* Tab Navigation */}
          <div className="flex-none border-b border-border bg-card">
            <div className="px-6 flex gap-1">
              <TabButton
                active={activeTab === 'intelligence'}
                onClick={() => setActiveTab('intelligence')}
                badge={findings.filter(f => f.severity === 'critical').length}
                badgeColor="red"
              >
                Intelligence
              </TabButton>
              <TabButton
                active={activeTab === 'packets'}
                onClick={() => setActiveTab('packets')}
                badge={packets.length}
              >
                Packets
              </TabButton>
              <TabButton
                active={activeTab === 'streams'}
                onClick={() => setActiveTab('streams')}
                badge={httpSessions.length + dnsQueries.length}
              >
                Streams
              </TabButton>
              <TabButton
                active={activeTab === 'explorer'}
                onClick={() => setActiveTab('explorer')}
              >
                Explorer
              </TabButton>
              <TabButton
                active={activeTab === 'analysis'}
                onClick={() => setActiveTab('analysis')}
              >
                Analysis
              </TabButton>
            </div>
          </div>

          {/* Tab Content */}
          <div className="flex-1 overflow-auto bg-background">
            {activeTab === 'intelligence' && (
              <IntelligenceTab
                findings={findings}
                packets={allPackets}
                httpSessions={httpSessions}
                dnsQueries={dnsQueries}
                conversations={conversations}
                stats={stats}
                onJumpToPacket={handleJumpToPacket}
                onApplyFilter={handleApplyFilter}
              />
            )}

            {activeTab === 'packets' && (
              <PacketsTab
                packets={packets}
                onFollowStream={handleFollowStream}
                onApplyFilter={handleApplyFilter}
                selectedPacketIndex={selectedPacketIndex}
                onSelectPacket={setSelectedPacketIndex}
                onOpenPacketDetail={setSelectedPacket}
              />
            )}

            {activeTab === 'streams' && (
              <StreamsTab
                httpSessions={httpSessions}
                dnsQueries={dnsQueries}
                conversations={conversations}
                onFollowStream={handleFollowStream}
                onJumpToPacket={handleJumpToPacket}
              />
            )}

            {activeTab === 'explorer' && (
              <ExplorerTab
                packets={allPackets}
                onJumpToPacket={handleJumpToPacket}
                onApplyFilter={handleApplyFilter}
              />
            )}

            {activeTab === 'analysis' && (
              <AnalysisTab
                packets={allPackets}
                protocols={protocols}
                conversations={conversations}
                endpoints={endpoints}
                httpSessions={httpSessions}
                dnsQueries={dnsQueries}
              />
            )}
          </div>
        </div>
      )}

      {/* Empty State */}
      {!file && !allPackets.length && (
        <div className="flex-1 flex items-center justify-center">
          <div className="text-center text-muted-foreground">
            <Upload className="w-16 h-16 mx-auto mb-4 opacity-50" />
            <p className="text-lg">Upload a PCAP file to begin analysis</p>
          </div>
        </div>
      )}

      {/* Follow Stream Modal */}
      {followStreamData && (
        <FollowStreamModal
          packets={allPackets}
          stream={followStreamData}
          onClose={() => setFollowStreamData(null)}
        />
      )}

      {/* Packet Detail Modal */}
      {selectedPacket && (
        <PacketDetailModal
          packet={selectedPacket}
          onClose={() => setSelectedPacket(null)}
          onFollowStream={
            selectedPacket.tcpStream !== undefined
              ? () => {
                  setFollowStreamData({ tcpStream: selectedPacket.tcpStream });
                  setSelectedPacket(null);
                }
              : undefined
          }
        />
      )}
    </div>
  );
};

interface TabButtonProps {
  active: boolean;
  onClick: () => void;
  children: React.ReactNode;
  badge?: number;
  badgeColor?: string;
}

const TabButton: React.FC<TabButtonProps> = ({ active, onClick, children, badge, badgeColor = 'accent' }) => {
  return (
    <button
      onClick={onClick}
      className={`px-4 py-3 text-sm font-medium border-b-2 transition-colors relative ${
        active
          ? 'border-accent text-accent'
          : 'border-transparent text-muted-foreground hover:text-foreground'
      }`}
    >
      {children}
      {badge !== undefined && badge > 0 && (
        <span className={`ml-2 px-2 py-0.5 rounded-full text-xs font-bold ${
          badgeColor === 'red' ? 'bg-red-400/20 text-red-400' : 'bg-accent/20 text-accent'
        }`}>
          {badge}
        </span>
      )}
    </button>
  );
};

export default PcapAnalysis;
