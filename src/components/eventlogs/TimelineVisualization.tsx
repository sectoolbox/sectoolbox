import React, { useMemo } from 'react';
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  PieChart,
  Pie,
  Cell,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts';
import { Card } from '../ui/card';
import { Badge } from '../ui/badge';
import { TrendingUp, TrendingDown, AlertTriangle, Activity } from 'lucide-react';
import { detectAnomalies, calculateStatistics } from '@/lib/eventLogUtils';

interface TimelineVisualizationProps {
  events: any[];
}

export const TimelineVisualization: React.FC<TimelineVisualizationProps> = ({ events }) => {
  const stats = useMemo(() => calculateStatistics(events), [events]);
  const anomalies = useMemo(() => detectAnomalies(events), [events]);

  // Prepare hourly data
  const hourlyData = useMemo(() => {
    const data = Object.entries(stats.byHour).map(([hour, count]) => ({
      hour: new Date(hour).toLocaleString('en-US', { 
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
      }),
      count,
      timestamp: hour,
    }));
    return data.sort((a, b) => a.timestamp.localeCompare(b.timestamp));
  }, [stats.byHour]);

  // Level distribution for pie chart
  const levelData = useMemo(() => {
    return Object.entries(stats.byLevel).map(([name, value]) => ({
      name,
      value,
    }));
  }, [stats.byLevel]);

  const LEVEL_COLORS: Record<string, string> = {
    'Critical': '#ef4444',
    'Error': '#f97316',
    'Warning': '#eab308',
    'Information': '#3b82f6',
    'Verbose': '#6b7280',
  };

  // Top Event IDs
  const topEventIds = useMemo(() => {
    return Object.entries(stats.topEventIds)
      .sort(([, a], [, b]) => (b as number) - (a as number))
      .slice(0, 10)
      .map(([eventId, count]) => ({
        eventId: `Event ${eventId}`,
        count,
      }));
  }, [stats.topEventIds]);

  return (
    <div className="space-y-6">
      {/* Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">Total Events</p>
              <p className="text-2xl font-bold">{stats.total.toLocaleString()}</p>
            </div>
            <Activity className="w-8 h-8 text-blue-500 opacity-50" />
          </div>
          <div className="mt-2 text-xs text-muted-foreground">
            Avg: {Math.round(stats.averageEventsPerHour)}/hour
          </div>
        </Card>

        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">Critical Events</p>
              <p className="text-2xl font-bold text-red-500">{stats.criticalCount}</p>
            </div>
            <AlertTriangle className="w-8 h-8 text-red-500 opacity-50" />
          </div>
          <div className="mt-2 text-xs text-muted-foreground">
            {stats.total > 0 ? ((stats.criticalCount / stats.total) * 100).toFixed(1) : 0}% of total
          </div>
        </Card>

        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">Error Events</p>
              <p className="text-2xl font-bold text-orange-500">{stats.errorCount}</p>
            </div>
            <TrendingUp className="w-8 h-8 text-orange-500 opacity-50" />
          </div>
          <div className="mt-2 text-xs text-muted-foreground">
            {stats.total > 0 ? ((stats.errorCount / stats.total) * 100).toFixed(1) : 0}% of total
          </div>
        </Card>

        <Card className="p-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">Warning Events</p>
              <p className="text-2xl font-bold text-yellow-500">{stats.warningCount}</p>
            </div>
            <TrendingDown className="w-8 h-8 text-yellow-500 opacity-50" />
          </div>
          <div className="mt-2 text-xs text-muted-foreground">
            {stats.total > 0 ? ((stats.warningCount / stats.total) * 100).toFixed(1) : 0}% of total
          </div>
        </Card>
      </div>

      {/* Anomalies Alert */}
      {anomalies.length > 0 && (
        <Card className="p-4 border-yellow-500/50 bg-yellow-500/5">
          <div className="flex items-start gap-3">
            <AlertTriangle className="w-5 h-5 text-yellow-500 flex-shrink-0 mt-0.5" />
            <div className="flex-1">
              <h3 className="font-semibold text-yellow-500 mb-2">Anomalies Detected</h3>
              <p className="text-sm text-muted-foreground mb-3">
                {anomalies.length} time periods with unusual activity levels detected
              </p>
              <div className="space-y-2">
                {anomalies.slice(0, 5).map((anomaly, idx) => (
                  <div key={idx} className="flex items-center justify-between text-sm">
                    <span className="font-mono text-xs">
                      {new Date(anomaly.hour).toLocaleString()}
                    </span>
                    <Badge variant="outline" className="font-mono">
                      {anomaly.count} events (+{anomaly.deviation}%)
                    </Badge>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </Card>
      )}

      {/* Timeline Area Chart */}
      <Card className="p-4">
        <h3 className="text-lg font-semibold mb-4">Event Timeline</h3>
        <ResponsiveContainer width="100%" height={300}>
          <AreaChart data={hourlyData}>
            <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
            <XAxis 
              dataKey="hour" 
              className="text-xs"
              tick={{ fill: 'currentColor', fontSize: 11 }}
            />
            <YAxis 
              className="text-xs"
              tick={{ fill: 'currentColor', fontSize: 11 }}
            />
            <Tooltip 
              contentStyle={{ 
                backgroundColor: 'hsl(var(--background))',
                border: '1px solid hsl(var(--border))',
                borderRadius: '0.5rem',
              }}
            />
            <Area 
              type="monotone" 
              dataKey="count" 
              stroke="#3b82f6" 
              fill="#3b82f6" 
              fillOpacity={0.3}
              name="Events"
            />
          </AreaChart>
        </ResponsiveContainer>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity Distribution Pie Chart */}
        <Card className="p-4">
          <h3 className="text-lg font-semibold mb-4">Severity Distribution</h3>
          <ResponsiveContainer width="100%" height={300}>
            <PieChart>
              <Pie
                data={levelData}
                cx="50%"
                cy="50%"
                labelLine={false}
                label={({ name, percent }) => `${name} ${(percent * 100).toFixed(0)}%`}
                outerRadius={100}
                fill="#8884d8"
                dataKey="value"
              >
                {levelData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={LEVEL_COLORS[entry.name] || '#6b7280'} />
                ))}
              </Pie>
              <Tooltip 
                contentStyle={{ 
                  backgroundColor: 'hsl(var(--background))',
                  border: '1px solid hsl(var(--border))',
                  borderRadius: '0.5rem',
                }}
              />
            </PieChart>
          </ResponsiveContainer>
        </Card>

        {/* Top Event IDs */}
        <Card className="p-4">
          <h3 className="text-lg font-semibold mb-4">Top Event IDs</h3>
          <ResponsiveContainer width="100%" height={300}>
            <BarChart data={topEventIds} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" className="stroke-muted" />
              <XAxis 
                type="number"
                className="text-xs"
                tick={{ fill: 'currentColor', fontSize: 11 }}
              />
              <YAxis 
                type="category"
                dataKey="eventId" 
                className="text-xs"
                tick={{ fill: 'currentColor', fontSize: 11 }}
                width={100}
              />
              <Tooltip 
                contentStyle={{ 
                  backgroundColor: 'hsl(var(--background))',
                  border: '1px solid hsl(var(--border))',
                  borderRadius: '0.5rem',
                }}
              />
              <Bar dataKey="count" fill="#10b981" radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </Card>
      </div>

      {/* Time Range Info */}
      {stats.timeRange.start && (
        <Card className="p-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 text-sm">
            <div>
              <p className="text-muted-foreground mb-1">First Event</p>
              <p className="font-mono text-xs">
                {new Date(stats.timeRange.start).toLocaleString()}
              </p>
            </div>
            <div>
              <p className="text-muted-foreground mb-1">Last Event</p>
              <p className="font-mono text-xs">
                {new Date(stats.timeRange.end).toLocaleString()}
              </p>
            </div>
            <div>
              <p className="text-muted-foreground mb-1">Time Span</p>
              <p className="font-mono text-xs">
                {(() => {
                  const diff = new Date(stats.timeRange.end).getTime() - new Date(stats.timeRange.start).getTime();
                  const hours = Math.floor(diff / (1000 * 60 * 60));
                  const days = Math.floor(hours / 24);
                  return days > 0 ? `${days}d ${hours % 24}h` : `${hours}h`;
                })()}
              </p>
            </div>
          </div>
        </Card>
      )}
    </div>
  );
};
