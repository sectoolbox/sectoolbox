import React, { useState } from 'react';
import { BarChart3, PieChart as PieChartIcon, TrendingUp, Users, Globe, Activity } from 'lucide-react';
import { ResponsiveContainer, PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, Legend, LineChart, Line } from 'recharts';
import { Button } from '../ui/button';

interface AnalysisTabProps {
  packets: any[];
  protocols: any[];
  conversations: any[];
  endpoints: string[];
  httpSessions: any[];
  dnsQueries: any[];
}

export const AnalysisTab: React.FC<AnalysisTabProps> = ({
  packets,
  protocols,
  conversations,
  endpoints,
  httpSessions,
  dnsQueries
}) => {
  const [activeChart, setActiveChart] = useState<'protocols' | 'endpoints' | 'timeline' | 'conversations'>('protocols');

  // Calculate timeline data (packets over time)
  const timelineData = useMemo(() => {
    const buckets = new Map<string, { packets: number; bytes: number }>();

    packets.forEach(pkt => {
      const time = new Date(pkt.timestamp);
      const bucket = `${time.getHours()}:${String(time.getMinutes()).padStart(2, '0')}`;

      const existing = buckets.get(bucket) || { packets: 0, bytes: 0 };
      existing.packets++;
      existing.bytes += pkt.size || 0;
      buckets.set(bucket, existing);
    });

    return Array.from(buckets.entries())
      .map(([time, data]) => ({ time, ...data }))
      .sort((a, b) => a.time.localeCompare(b.time));
  }, [packets]);

  // Top endpoints by packet count
  const endpointStats = useMemo(() => {
    const stats = new Map<string, { packets: number; bytes: number }>();

    packets.forEach(pkt => {
      [pkt.source, pkt.destination].forEach(ip => {
        if (ip && ip !== 'N/A') {
          const existing = stats.get(ip) || { packets: 0, bytes: 0 };
          existing.packets++;
          existing.bytes += pkt.size || 0;
          stats.set(ip, existing);
        }
      });
    });

    return Array.from(stats.entries())
      .map(([ip, data]) => ({ ip, ...data }))
      .sort((a, b) => b.packets - a.packets)
      .slice(0, 10);
  }, [packets]);

  const colors = ['#10b981', '#3b82f6', '#f59e0b', '#ef4444', '#8b5cf6', '#06b6d4', '#f97316', '#84cc16'];

  return (
    <div className="space-y-6 p-4">
      {/* Chart Selector */}
      <div className="flex gap-2 flex-wrap">
        <Button
          size="sm"
          variant={activeChart === 'protocols' ? 'default' : 'outline'}
          onClick={() => setActiveChart('protocols')}
        >
          <PieChartIcon className="w-4 h-4 mr-2" />
          Protocol Distribution
        </Button>
        <Button
          size="sm"
          variant={activeChart === 'endpoints' ? 'default' : 'outline'}
          onClick={() => setActiveChart('endpoints')}
        >
          <Users className="w-4 h-4 mr-2" />
          Top Endpoints
        </Button>
        <Button
          size="sm"
          variant={activeChart === 'timeline' ? 'default' : 'outline'}
          onClick={() => setActiveChart('timeline')}
        >
          <Activity className="w-4 h-4 mr-2" />
          Timeline
        </Button>
        <Button
          size="sm"
          variant={activeChart === 'conversations' ? 'default' : 'outline'}
          onClick={() => setActiveChart('conversations')}
        >
          <TrendingUp className="w-4 h-4 mr-2" />
          Conversations
        </Button>
      </div>

      {/* Protocol Distribution */}
      {activeChart === 'protocols' && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          <div className="bg-card border border-border rounded-lg p-4">
            <h3 className="font-semibold mb-4">Protocol Distribution</h3>
            <ResponsiveContainer width="100%" height={300}>
              <PieChart>
                <Pie
                  data={protocols.slice(0, 8)}
                  dataKey="count"
                  nameKey="name"
                  cx="50%"
                  cy="50%"
                  outerRadius={100}
                  label={({ name, percentage }) => `${name} ${percentage}%`}
                >
                  {protocols.slice(0, 8).map((entry, index) => (
                    <Cell key={`cell-${index}`} fill={colors[index % colors.length]} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>

          <div className="bg-card border border-border rounded-lg p-4">
            <h3 className="font-semibold mb-4">Protocol Breakdown</h3>
            <div className="space-y-2 max-h-80 overflow-auto">
              {protocols.map((proto, idx) => (
                <div key={idx} className="flex items-center justify-between p-2 bg-muted/20 rounded">
                  <div className="flex items-center gap-3">
                    <div
                      className="w-4 h-4 rounded"
                      style={{ backgroundColor: colors[idx % colors.length] }}
                    />
                    <span className="font-mono text-sm">{proto.name}</span>
                  </div>
                  <div className="text-right">
                    <div className="text-sm font-semibold">{proto.count} packets</div>
                    <div className="text-xs text-muted-foreground">{proto.percentage}%</div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Endpoints */}
      {activeChart === 'endpoints' && (
        <div className="bg-card border border-border rounded-lg p-4">
          <h3 className="font-semibold mb-4">Top 10 Endpoints by Traffic</h3>
          <ResponsiveContainer width="100%" height={400}>
            <BarChart data={endpointStats}>
              <XAxis dataKey="ip" angle={-45} textAnchor="end" height={100} />
              <YAxis />
              <Tooltip />
              <Legend />
              <Bar dataKey="packets" fill="#10b981" name="Packets" />
            </BarChart>
          </ResponsiveContainer>

          <div className="mt-4 space-y-2">
            {endpointStats.map((endpoint, idx) => (
              <div key={idx} className="flex items-center justify-between p-2 bg-muted/20 rounded">
                <span className="font-mono text-sm">{endpoint.ip}</span>
                <div className="text-right text-xs">
                  <div>{endpoint.packets} packets</div>
                  <div className="text-muted-foreground">{(endpoint.bytes / 1024).toFixed(1)} KB</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Timeline */}
      {activeChart === 'timeline' && (
        <div className="bg-card border border-border rounded-lg p-4">
          <h3 className="font-semibold mb-4">Traffic Over Time</h3>
          <ResponsiveContainer width="100%" height={400}>
            <LineChart data={timelineData}>
              <XAxis dataKey="time" />
              <YAxis yAxisId="left" />
              <YAxis yAxisId="right" orientation="right" />
              <Tooltip />
              <Legend />
              <Line yAxisId="left" type="monotone" dataKey="packets" stroke="#10b981" name="Packets" />
              <Line yAxisId="right" type="monotone" dataKey="bytes" stroke="#3b82f6" name="Bytes" />
            </LineChart>
          </ResponsiveContainer>
        </div>
      )}

      {/* Conversations */}
      {activeChart === 'conversations' && (
        <div className="bg-card border border-border rounded-lg p-4">
          <h3 className="font-semibold mb-4">Top Conversations</h3>
          <div className="space-y-2 max-h-96 overflow-auto">
            {conversations
              .sort((a, b) => b.packets - a.packets)
              .slice(0, 20)
              .map((conv, idx) => (
                <div key={idx} className="border border-border rounded p-3">
                  <div className="flex items-center justify-between mb-2">
                    <div className="font-mono text-sm">
                      {conv.source}:{conv.srcPort || 0} ↔ {conv.destination}:{conv.destPort || 0}
                    </div>
                    <div className="text-xs text-muted-foreground">
                      {conv.protocols.join(', ')}
                    </div>
                  </div>
                  <div className="grid grid-cols-3 gap-2 text-xs">
                    <div>
                      <span className="text-muted-foreground">Packets:</span>
                      <span className="ml-2 font-mono">{conv.packets}</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Bytes:</span>
                      <span className="ml-2 font-mono">{(conv.bytes / 1024).toFixed(1)} KB</span>
                    </div>
                    <div>
                      <span className="text-muted-foreground">Duration:</span>
                      <span className="ml-2 font-mono">
                        {conv.duration ? `${(conv.duration / 1000).toFixed(2)}s` : 'N/A'}
                      </span>
                    </div>
                  </div>
                </div>
              ))}
          </div>
        </div>
      )}
    </div>
  );
};

function useMemo<T>(factory: () => T, deps: any[]): T {
  return factory();
}
