import React from 'react';
import { Construction, HardDrive, Cpu, Database, Activity } from 'lucide-react';
import { Card } from '../components/ui/card';

const MemoryForensics: React.FC = () => {
  return (
    <div className="flex flex-col h-screen">
      {/* Header */}
      <div className="flex-none px-6 py-4 border-b border-border bg-card">
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold">Memory Forensics</h1>
            <p className="text-sm text-muted-foreground">
              Analyze memory dumps for malware, rootkits, and forensic artifacts
            </p>
          </div>
        </div>
      </div>

      {/* Main Content */}
      <div className="flex-1 overflow-auto p-6">
        <div className="max-w-4xl mx-auto space-y-6">
          {/* Under Construction Card */}
          <Card className="p-8 text-center border-2 border-dashed border-border">
            <Construction className="w-16 h-16 mx-auto mb-4 text-yellow-500" />
            <h2 className="text-2xl font-bold mb-2">Currently Under Construction</h2>
            <p className="text-muted-foreground mb-6">
              This feature is being developed and will be available soon
            </p>
          </Card>

          {/* Planned Features */}
          <Card className="p-6">
            <h3 className="text-lg font-semibold mb-4">Planned Features</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <div className="flex items-start gap-3 p-3 rounded bg-muted/20">
                <HardDrive className="w-5 h-5 text-blue-500 flex-shrink-0 mt-0.5" />
                <div>
                  <div className="font-medium text-sm mb-1">Memory Dump Analysis</div>
                  <div className="text-xs text-muted-foreground">
                    Parse and analyze raw memory dumps (.raw, .mem, .dmp)
                  </div>
                </div>
              </div>

              <div className="flex items-start gap-3 p-3 rounded bg-muted/20">
                <Cpu className="w-5 h-5 text-green-500 flex-shrink-0 mt-0.5" />
                <div>
                  <div className="font-medium text-sm mb-1">Process Analysis</div>
                  <div className="text-xs text-muted-foreground">
                    Extract running processes, DLLs, and handles
                  </div>
                </div>
              </div>

              <div className="flex items-start gap-3 p-3 rounded bg-muted/20">
                <Database className="w-5 h-5 text-purple-500 flex-shrink-0 mt-0.5" />
                <div>
                  <div className="font-medium text-sm mb-1">Artifact Extraction</div>
                  <div className="text-xs text-muted-foreground">
                    Network connections, registry keys, and credentials
                  </div>
                </div>
              </div>

              <div className="flex items-start gap-3 p-3 rounded bg-muted/20">
                <Activity className="w-5 h-5 text-red-500 flex-shrink-0 mt-0.5" />
                <div>
                  <div className="font-medium text-sm mb-1">Malware Detection</div>
                  <div className="text-xs text-muted-foreground">
                    Identify suspicious processes and injected code
                  </div>
                </div>
              </div>
            </div>
          </Card>

          {/* Info Card */}
          <Card className="p-6 bg-blue-500/5 border-blue-500/20">
            <div className="text-sm">
              <div className="font-semibold text-blue-400 mb-2">Integration with Volatility Framework</div>
              <p className="text-muted-foreground">
                This feature will integrate with the Volatility 3 framework to provide comprehensive 
                memory forensics capabilities including process listing, network connections, malware detection, 
                and artifact extraction.
              </p>
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
};

export default MemoryForensics;
