import React, { useState, useEffect } from 'react';
import { Upload, Activity, AlertTriangle, X } from 'lucide-react';
import { Button } from '../components/ui/button';
import { Card } from '../components/ui/card';
import { useBackendJob } from '../hooks/useBackendJob';
import { toast } from '../hooks/use-toast';

type TabType = 'events' | 'timeline' | 'analysis' | 'search' | 'export';

export const EventLogs: React.FC = () => {
  const [file, setFile] = useState<File | null>(null);
  const [activeTab, setActiveTab] = useState<TabType>('events');
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
      const formData = new FormData();
      formData.append('file', file);

      const response = await fetch('/api/v1/eventlogs/analyze', {
        method: 'POST',
        body: formData
      });

      const result = await response.json();

      if (result.jobId) {
        startJob(result.jobId);
      } else {
        toast({ title: 'Error', description: result.error || 'Failed to start analysis', variant: 'destructive' });
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
    setActiveTab('events');
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
    <div className="min-h-screen bg-background p-6">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-3xl font-bold flex items-center gap-2">
              <Activity className="w-8 h-8 text-accent" />
              Windows Event Log Analyzer
            </h1>
            <p className="text-muted-foreground mt-1">
              Parse and analyze Windows .evtx files - Security, System, Application logs
            </p>
          </div>
        </div>

        {/* File Upload Section */}
        {!parsedData && (
          <Card className="p-8">
            <div className="space-y-6">
              <div className="flex items-center justify-center">
                <div className="text-center space-y-4">
                  <div className="flex justify-center">
                    <div className="p-4 bg-accent/10 rounded-full">
                      <Upload className="w-12 h-12 text-accent" />
                    </div>
                  </div>
                  
                  <div>
                    <h3 className="text-xl font-semibold mb-2">Upload Event Log File</h3>
                    <p className="text-muted-foreground">
                      Select a Windows Event Log (.evtx) file to analyze
                      <br />
                      Maximum file size: 1.5GB
                    </p>
                  </div>

                  <div className="flex flex-col items-center gap-3">
                    <input
                      id="evtx-upload"
                      type="file"
                      accept=".evtx"
                      onChange={handleFileSelect}
                      className="hidden"
                    />
                    <label htmlFor="evtx-upload">
                      <Button size="lg" className="w-full cursor-pointer" asChild>
                        <span>Choose File</span>
                      </Button>
                    </label>

                    {file && (
                      <div className="flex items-center gap-2 text-sm">
                        <span className="font-mono">{file.name}</span>
                        <span className="text-muted-foreground">
                          ({(file.size / (1024 * 1024)).toFixed(2)} MB)
                        </span>
                      </div>
                    )}
                  </div>

                  {file && (
                    <Button 
                      onClick={handleAnalyze}
                      size="lg"
                      disabled={isAnalyzing}
                      className="w-64"
                    >
                      {isAnalyzing ? 'Analyzing...' : 'Analyze Event Log'}
                    </Button>
                  )}
                </div>
              </div>

              {/* Job Progress */}
              {isAnalyzing && jobStatus && (
                <div className="bg-muted/20 rounded-lg p-4">
                  <div className="flex items-center gap-3 mb-2">
                    <Activity className="w-5 h-5 animate-spin text-accent" />
                    <span className="font-medium">Processing...</span>
                  </div>
                  <div className="w-full bg-muted rounded-full h-2 mb-2">
                    <div 
                      className="bg-accent h-2 rounded-full transition-all duration-300"
                      style={{ width: `${jobStatus.progress || 0}%` }}
                    />
                  </div>
                  <p className="text-sm text-muted-foreground">
                    {jobStatus.progress || 0}% - {jobStatus.message || 'Processing...'}
                  </p>
                </div>
              )}
            </div>
          </Card>
        )}

        {/* Analysis Results */}
        {parsedData && (
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
            <div className="flex gap-2 bg-muted/20 p-1 rounded-lg w-fit">
              <TabButton active={activeTab === 'events'} onClick={() => setActiveTab('events')}>
                Events
              </TabButton>
              <TabButton active={activeTab === 'timeline'} onClick={() => setActiveTab('timeline')}>
                Timeline
              </TabButton>
              <TabButton active={activeTab === 'analysis'} onClick={() => setActiveTab('analysis')}>
                Analysis
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
              {activeTab === 'events' && <div className="text-muted-foreground">Events tab - Coming soon</div>}
              {activeTab === 'timeline' && <div className="text-muted-foreground">Timeline tab - Coming soon</div>}
              {activeTab === 'analysis' && <div className="text-muted-foreground">Analysis tab - Coming soon</div>}
              {activeTab === 'search' && <div className="text-muted-foreground">Search tab - Coming soon</div>}
              {activeTab === 'export' && <div className="text-muted-foreground">Export tab - Coming soon</div>}
            </div>
          </div>
        )}
      </div>
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
