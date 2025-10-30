import React, { useState, useEffect } from 'react';
import { useLocation } from 'react-router-dom';
import { Upload, Activity, X, CheckCircle } from 'lucide-react';
import { Button } from '../components/ui/button';
import { Card } from '../components/ui/card';
import { useBackendJob } from '../hooks/useBackendJob';
import { toast } from '../hooks/use-toast';
import { apiClient } from '../services/api';
import { EventsTab } from '../components/eventlogs/EventsTab';
import { OverviewTab } from '../components/eventlogs/OverviewTab';
import { ExportTab } from '../components/eventlogs/ExportTab';
import { SearchTab } from '../components/eventlogs/SearchTab';
import { OrganizedTab } from '../components/eventlogs/OrganizedTab';
import { CriticalAlertsBar } from '../components/eventlogs/CriticalAlertsBar';
import { QuickStatsCards } from '../components/eventlogs/QuickStatsCards';
import { QuickJumpButtons } from '../components/eventlogs/QuickJumpButtons';

type TabType = 'overview' | 'events' | 'search' | 'export' | 'organized';

// Analysis stages for EventLogs
const EVENTLOG_STAGES = [
  'Uploading file to server',
  'Parsing EVTX structure',
  'Extracting event records',
  'Analyzing security events',
  'Detecting anomalies',
  'Organizing by categories',
  'Generating statistics'
];

export const EventLogs: React.FC = () => {
  const location = useLocation();
  const [file, setFile] = useState<File | null>(null);
  const [activeTab, setActiveTab] = useState<TabType>('overview');
  const [parsedData, setParsedData] = useState<any>(null);
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  
  const { jobStatus, startJob } = useBackendJob();

  // Handle quick upload from Dashboard
  useEffect(() => {
    const state = location.state as any;
    if (state?.quickUploadFile && state?.quickUploadAutoAnalyze) {
      const uploadedFile = state.quickUploadFile;
      setFile(uploadedFile);
      // Auto-analyze after a short delay to let UI update
      setTimeout(() => {
        handleAnalyzeFile(uploadedFile);
      }, 100);
      // Clear location state
      window.history.replaceState({}, document.title);
    }
  }, [location]);

  const handleAnalyzeFile = async (fileToAnalyze: File) => {
    setIsAnalyzing(true);

    try {
      const response = await apiClient.analyzeEventLog(fileToAnalyze);

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
    await handleAnalyzeFile(file);
  };

  const handleReset = () => {
    setFile(null);
    setParsedData(null);
    setIsAnalyzing(false);
    setActiveTab('overview');
  };

  const handleQuickJump = (_targetType: 'threat' | 'critical' | 'suspicious') => {
    setActiveTab('events');
    // Scroll to top of events tab to see filtered results
    setTimeout(() => {
      window.scrollTo({ top: 0, behavior: 'smooth' });
    }, 100);
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
      {/* Multi-Stage EventLog Analysis Pipeline Loading Overlay */}
      {isAnalyzing && jobStatus && (
        <div className="fixed inset-0 bg-black/60 backdrop-blur-md z-50 flex items-center justify-center">
          <div className="bg-background border-2 border-accent rounded-lg p-8 shadow-2xl max-w-xl w-full mx-4">
            <div className="flex flex-col gap-6">
              {/* Title */}
              <div className="text-center">
                <h3 className="text-xl font-bold text-accent mb-2 flex items-center justify-center gap-2">
                  <Activity className="w-6 h-6 animate-pulse" />
                  Analyzing Event Log
                </h3>
                <p className="text-sm text-muted-foreground">
                  {jobStatus.message || 'Processing...'}
                </p>
              </div>

              {/* Task List with Status */}
              <div className="space-y-2">
                {EVENTLOG_STAGES.map((task, index) => {
                  const taskNumber = index + 1
                  const progressPercentage = jobStatus.progress || 0
                  const stagesCompleted = Math.floor((progressPercentage / 100) * EVENTLOG_STAGES.length)
                  const isComplete = index < stagesCompleted
                  const isCurrent = index === stagesCompleted && progressPercentage < 100
                  
                  return (
                    <div
                      key={task}
                      className={`flex items-start gap-3 p-3 rounded-lg transition-all duration-300 ${
                        isComplete 
                          ? 'bg-accent/10 border border-accent/30' 
                          : isCurrent
                          ? 'bg-accent/20 border-2 border-accent shadow-md'
                          : 'bg-background/50 border border-border opacity-50'
                      }`}
                    >
                      {/* Status Icon */}
                      <div className="flex-shrink-0 mt-0.5">
                        {isComplete ? (
                          <CheckCircle className="w-5 h-5 text-accent" />
                        ) : isCurrent ? (
                          <Activity className="w-5 h-5 text-accent animate-spin" />
                        ) : (
                          <div className="w-5 h-5 rounded-full border-2 border-border" />
                        )}
                      </div>
                      
                      {/* Task Info */}
                      <div className="flex-1 min-w-0">
                        <div className={`text-sm font-medium ${
                          isComplete || isCurrent ? 'text-foreground' : 'text-muted-foreground'
                        }`}>
                          {task}
                        </div>
                      </div>
                      
                      {/* Task Number Badge */}
                      <div className={`flex-shrink-0 text-xs font-mono px-2 py-0.5 rounded ${
                        isComplete 
                          ? 'bg-accent text-background' 
                          : isCurrent
                          ? 'bg-accent/30 text-accent font-bold'
                          : 'bg-muted text-muted-foreground'
                      }`}>
                        {taskNumber}
                      </div>
                    </div>
                  )
                })}
              </div>

              {/* Progress Bar */}
              <div className="space-y-2">
                <div className="flex items-center justify-between text-xs text-muted-foreground">
                  <span>Overall Progress</span>
                  <span className="font-mono font-bold text-accent">
                    {Math.round(jobStatus.progress || 0)}%
                  </span>
                </div>
                <div className="w-full h-2 bg-background/50 rounded-full overflow-hidden border border-border">
                  <div 
                    className="h-full bg-gradient-to-r from-accent to-accent/80 transition-all duration-500 ease-out"
                    style={{ width: `${jobStatus.progress || 0}%` }}
                  />
                </div>
              </div>

              {/* Animation Dots */}
              <div className="flex items-center justify-center gap-1">
                <div className="w-2 h-2 bg-accent rounded-full animate-bounce" style={{animationDelay: '0ms'}}></div>
                <div className="w-2 h-2 bg-accent rounded-full animate-bounce" style={{animationDelay: '150ms'}}></div>
                <div className="w-2 h-2 bg-accent rounded-full animate-bounce" style={{animationDelay: '300ms'}}></div>
              </div>
            </div>
          </div>
        </div>
      )}

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

            {/* Estimated analysis time warning */}
            {file && !parsedData && (
              <div className="mt-4 p-3 bg-yellow-500/10 border border-yellow-500/30 rounded-lg flex items-start gap-3">
                <Activity className="w-5 h-5 text-yellow-500 flex-shrink-0 mt-0.5" />
                <p className="text-sm text-yellow-500">
                  This {(file.size / 1024 / 1024).toFixed(1)} MB event log will take approximately{' '}
                  {Math.ceil((file.size / 1024 / 1024) * 2.2 + 6)} seconds to analyze.
                </p>
              </div>
            )}

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
                <div className="flex items-center gap-4">
                  <div>
                    <div className="text-sm text-muted-foreground">File</div>
                    <div className="font-mono font-semibold">{parsedData.filename}</div>
                  </div>
                </div>
                <Button variant="outline" onClick={handleReset}>
                  <X className="w-4 h-4 mr-2" />
                  Close
                </Button>
              </div>
            </Card>

            {/* Critical Alerts Banner */}
            {parsedData.events && parsedData.events.length > 0 && (
              <CriticalAlertsBar 
                events={parsedData.events}
                onJumpToEvent={(_eventId) => {
                  setActiveTab('events');
                  // Scroll to event with matching ID - implement in EventsTab
                }}
              />
            )}

            {/* Quick Stats Cards */}
            {parsedData.events && parsedData.events.length > 0 && (
              <QuickStatsCards events={parsedData.events} />
            )}

            {/* Tabs */}
            <div className="grid grid-cols-2 sm:grid-cols-4 md:grid-cols-5 gap-2 bg-card border border-border p-2 rounded-lg">
              <TabButton active={activeTab === 'overview'} onClick={() => setActiveTab('overview')}>
                Overview
              </TabButton>
              <TabButton active={activeTab === 'events'} onClick={() => setActiveTab('events')}>
                Events
              </TabButton>
              <TabButton active={activeTab === 'organized'} onClick={() => setActiveTab('organized')}>
                Organized
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
              {activeTab === 'organized' && parsedData.events && (
                <OrganizedTab events={parsedData.events} />
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

          {/* Quick Jump Buttons */}
          {parsedData.events && parsedData.events.length > 0 && (
            <QuickJumpButtons 
              events={parsedData.events}
              onJumpTo={handleQuickJump}
            />
          )}
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
