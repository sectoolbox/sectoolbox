import React, { useState, useEffect } from 'react';
import { Upload, Activity, AlertTriangle, X } from 'lucide-react';
import { Button } from '../components/ui/button';
import { Card } from '../components/ui/card';
import { useBackendJob } from '../hooks/useBackendJob';
import { toast } from '../hooks/use-toast';
import { apiClient } from '../services/api';
import { EventsTab } from '../components/eventlogs/EventsTab';
import { OverviewTab } from '../components/eventlogs/OverviewTab';
import { ExportTab } from '../components/eventlogs/ExportTab';
import { SearchTab } from '../components/eventlogs/SearchTab';
import { TimelineTab } from '../components/eventlogs/TimelineTab';
import { MitreTab } from '../components/eventlogs/MitreTab';
import { ThreatIntelTab } from '../components/eventlogs/ThreatIntelTab';
import { OrganizedTab } from '../components/eventlogs/OrganizedTab';

type TabType = 'overview' | 'events' | 'timeline' | 'search' | 'export' | 'mitre' | 'threatintel' | 'organized';

export const EventLogs: React.FC = () => {
  const [file, setFile] = useState<File | null>(null);
  const [activeTab, setActiveTab] = useState<TabType>('overview');
  const [parsedData, setParsedData] = useState<any>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  
  const { jobStatus, startJob } = useBackendJob();

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selectedFile = e.target.files?.[0];
    if (selectedFile) {
      if (!selectedFile.name.endsWith('.evtx')) {
        toast({ title: 'Invalid file type', description: 'Please select a .evtx file', variant: 'destructive' });
        return;
      }
      
      // Check file size (1.5GB max)
      if (selectedFile.size > 1.5 * 1024 * 1024 * 1024) {
        toast({ title: 'File too large', description: 'Maximum file size is 1.5GB', variant: 'destructive' });
        return;
      }
      
      setFile(selectedFile);
      setParsedData(null);
    }
  };

  const handleAnalyze = async () => {
    if (!file) return;

    setIsAnalyzing(true);

    try {
      const response = await apiClient.analyzeEventLog(file);

      if (response.jobId) {
        startJob(response.jobId);
      } else {
        toast({ title: 'Error', description: response.error || 'Failed to start analysis', variant: 'destructive' });
        setIsAnalyzing(false);
      }
    } catch (error: any) {
      toast({ title: 'Error', description: error.message, variant: 'destructive' });
      setIsAnalyzing(false);
    }
  };

  const handleReset = () => {
    setFile(null);
    setParsedData(null);
    setIsAnalyzing(false);
    setActiveTab('overview');
  };

  // Watch for job status updates
  useEffect(() => {
    if (jobStatus) {
      if (jobStatus.status === 'completed') {
        setParsedData(jobStatus.results);
        setIsAnalyzing(false);
        toast({ title: 'Analysis complete', description: `Parsed ${jobStatus.results?.metadata?.totalEvents || 0} events` });
      } else if (jobStatus.status === 'failed') {
        toast({ title: 'Analysis failed', description: jobStatus.error, variant: 'destructive' });
        setIsAnalyzing(false);
      }
    }
  }, [jobStatus]);

  return (
    <div className="flex flex-col h-screen">
      {/* Header */}
      <div className="flex-none px-6 py-4 border-b border-border bg-card">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold">Windows Event Log Analyzer</h1>
            <p className="text-sm text-muted-foreground">
              Parse and analyze Windows .evtx files - Security, System, Application logs
            </p>
          </div>
        </div>
      </div>

      {/* File Upload or Info */}
      <div className="flex-none px-6 py-4 bg-background">
        {!parsedData && !file && (
          <div
            className="border-2 border-dashed border-border rounded-lg p-8 text-center hover:border-accent transition-colors cursor-pointer"
          >
            <Upload className="w-12 h-12 text-muted-foreground mx-auto mb-4" />
            <p className="text-lg font-medium mb-2">Drop Event Log file here or click to browse</p>
            <p className="text-sm text-muted-foreground">
              Supports .evtx files | Maximum file size: 1.5GB
            </p>
            <input
              id="evtx-upload"
              type="file"
              accept=".evtx"
              onChange={handleFileSelect}
              className="hidden"
            />
            <label htmlFor="evtx-upload">
              <Button variant="outline" className="mt-4 cursor-pointer" asChild>
                <span>Choose File</span>
              </Button>
            </label>
          </div>
        )}

        {!parsedData && file && (
          <div>
            <div className="flex items-center justify-between bg-card border border-border rounded-lg p-4">
              <div className="flex items-center gap-3">
                <div className="w-10 h-10 rounded bg-accent/20 flex items-center justify-center">
                  <Upload className="w-5 h-5 text-accent" />
                </div>
                <div>
                  <p className="font-medium">{file.name}</p>
                  <p className="text-sm text-muted-foreground">
                    {(file.size / (1024 * 1024)).toFixed(2)} MB
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Button
                  onClick={handleAnalyze}
                  disabled={isAnalyzing}
                  variant="outline"
                  className="hover:bg-accent hover:text-white hover:border-accent hover:scale-105 transition-all duration-200 tracking-wide"
                >
                  {isAnalyzing ? (
                    <>
                      <Activity className="w-4 h-4 animate-spin mr-2" />
                      Analyzing...
                    </>
                  ) : (
                    <>
                      <Activity className="w-4 h-4 mr-2" />
                      Analyze
                    </>
                  )}
                </Button>
                <Button
                  variant="outline"
                  onClick={handleReset}
                  disabled={isAnalyzing}
                  className="hover:bg-red-500 hover:text-white hover:border-red-500 hover:scale-105 transition-all duration-200 tracking-wide"
                >
                  Remove
                </Button>
              </div>
            </div>

            {/* Job Progress */}
            {isAnalyzing && jobStatus && (
              <div className="mt-4 bg-muted/20 rounded-lg p-4">
                <div className="flex items-center gap-3 mb-3">
                  <Activity className="w-5 h-5 animate-spin text-accent" />
                  <span className="font-medium">Processing event log file...</span>
                </div>
                <p className="text-sm text-muted-foreground">
                  {jobStatus.message || 'Parsing events and analyzing for threats...'}
                </p>
              </div>
            )}
          </div>
        )}
      </div>

      {/* Analysis Results */}
      {parsedData && (
        <div className="flex-1 overflow-auto p-6">
          <div className="space-y-4">
            {/* Header with stats */}
            <Card className="p-4">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-6">
                  <div>
                    <div className="text-sm text-muted-foreground">File</div>
                    <div className="font-mono font-semibold">{parsedData.filename}</div>
                  </div>
                  <div>
                    <div className="text-sm text-muted-foreground">Total Events</div>
                    <div className="font-mono font-semibold text-accent">
                      {parsedData.metadata?.totalEvents?.toLocaleString() || 0}
                    </div>
                  </div>
                  {parsedData.threats && parsedData.threats.length > 0 && (
                    <div>
                      <div className="text-sm text-muted-foreground">Threats Detected</div>
                      <div className="font-mono font-semibold text-destructive flex items-center gap-1">
                        <AlertTriangle className="w-4 h-4" />
                        {parsedData.threats.length}
                      </div>
                    </div>
                  )}
                </div>
                <Button variant="outline" onClick={handleReset}>
                  <X className="w-4 h-4 mr-2" />
                  Close
                </Button>
              </div>
            </Card>

            {/* Tabs */}
            <div className="flex gap-2 bg-muted/20 p-1 rounded-lg w-fit flex-wrap">
              <TabButton active={activeTab === 'overview'} onClick={() => setActiveTab('overview')}>
                Overview
              </TabButton>
              <TabButton active={activeTab === 'events'} onClick={() => setActiveTab('events')}>
                Events
              </TabButton>
              <TabButton active={activeTab === 'mitre'} onClick={() => setActiveTab('mitre')}>
                MITRE ATT&CK
              </TabButton>
              <TabButton active={activeTab === 'threatintel'} onClick={() => setActiveTab('threatintel')}>
                Threat Intel
              </TabButton>
              <TabButton active={activeTab === 'organized'} onClick={() => setActiveTab('organized')}>
                Organized
              </TabButton>
              <TabButton active={activeTab === 'timeline'} onClick={() => setActiveTab('timeline')}>
                Timeline
              </TabButton>
              <TabButton active={activeTab === 'search'} onClick={() => setActiveTab('search')}>
                Search
              </TabButton>
              <TabButton active={activeTab === 'export'} onClick={() => setActiveTab('export')}>
                Export
              </TabButton>
            </div>

            {/* Tab Content */}
            <div>
              {activeTab === 'overview' && (
                <OverviewTab 
                  analysis={parsedData.analysis}
                  iocs={parsedData.iocs}
                  threats={parsedData.threats}
                  flags={parsedData.flags}
                  events={parsedData.events}
                  metadata={parsedData.metadata}
                />
              )}
              {activeTab === 'events' && parsedData.events && (
                <EventsTab events={parsedData.events} />
              )}
              {activeTab === 'mitre' && parsedData.events && (
                <MitreTab events={parsedData.events} />
              )}
              {activeTab === 'threatintel' && parsedData.iocs && (
                <ThreatIntelTab iocs={parsedData.iocs} />
              )}
              {activeTab === 'organized' && parsedData.events && (
                <OrganizedTab events={parsedData.events} />
              )}
              {activeTab === 'timeline' && parsedData.events && (
                <TimelineTab events={parsedData.events} analysis={parsedData.analysis} />
              )}
              {activeTab === 'search' && parsedData.events && (
                <SearchTab events={parsedData.events} />
              )}
              {activeTab === 'export' && (
                <ExportTab 
                  events={parsedData.events}
                  analysis={parsedData.analysis}
                  iocs={parsedData.iocs}
                  threats={parsedData.threats}
                  metadata={parsedData.metadata}
                />
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

// Tab Button Component
const TabButton: React.FC<{ active: boolean; onClick: () => void; children: React.ReactNode }> = ({ 
  active, 
  onClick, 
  children 
}) => (
  <button
    onClick={onClick}
    className={`px-4 py-2 rounded text-sm font-medium transition-colors ${
      active ? 'bg-accent text-background' : 'hover:bg-muted'
    }`}
  >
    {children}
  </button>
);

export default EventLogs;
