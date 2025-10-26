import React, { useMemo } from 'react';
import { Calendar, TrendingUp, AlertTriangle } from 'lucide-react';
import { Card } from '../ui/card';

interface TimelineTabProps {
  events: any[];
  analysis?: {
    timeline?: Array<{ date: string; count: number }>;
  };
}

export const TimelineTab: React.FC<TimelineTabProps> = ({ events }) => {
  // Group events by hour
  const hourlyData = useMemo(() => {
    const groups: Record<string, { count: number; levels: Record<string, number> }> = {};
    
    events.forEach(event => {
      const date = new Date(event.timestamp);
      const hourKey = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')} ${String(date.getHours()).padStart(2, '0')}:00`;
      
      if (!groups[hourKey]) {
        groups[hourKey] = { count: 0, levels: {} };
      }
      
      groups[hourKey].count++;
      groups[hourKey].levels[event.levelName] = (groups[hourKey].levels[event.levelName] || 0) + 1;
    });
    
    return Object.entries(groups)
      .map(([time, data]) => ({ time, ...data }))
      .sort((a, b) => a.time.localeCompare(b.time));
  }, [events]);

  // Group events by day
  const dailyData = useMemo(() => {
    const groups: Record<string, { count: number; levels: Record<string, number> }> = {};
    
    events.forEach(event => {
      const date = new Date(event.timestamp);
      const dayKey = `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}-${String(date.getDate()).padStart(2, '0')}`;
      
      if (!groups[dayKey]) {
        groups[dayKey] = { count: 0, levels: {} };
      }
      
      groups[dayKey].count++;
      groups[dayKey].levels[event.levelName] = (groups[dayKey].levels[event.levelName] || 0) + 1;
    });
    
    return Object.entries(groups)
      .map(([date, data]) => ({ date, ...data }))
      .sort((a, b) => a.date.localeCompare(b.date));
  }, [events]);

  const maxCount = Math.max(...hourlyData.map(d => d.count), 1);

  const getLevelColor = (level: string) => {
    switch (level) {
      case 'Critical': return 'bg-red-500';
      case 'Error': return 'bg-red-400';
      case 'Warning': return 'bg-yellow-500';
      case 'Information': return 'bg-blue-500';
      default: return 'bg-muted';
    }
  };

  return (
    <div className="space-y-6">
      {/* Daily Summary */}
      <Card className="p-4">
        <div className="flex items-center gap-2 mb-4">
          <Calendar className="w-5 h-5 text-accent" />
          <h3 className="text-lg font-semibold">Daily Event Distribution</h3>
        </div>
        
        <div className="space-y-3">
          {dailyData.map((day) => {
            const percentage = (day.count / events.length) * 100;
            
            return (
              <div key={day.date}>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-sm font-medium">{day.date}</span>
                  <span className="text-sm text-muted-foreground">
                    {day.count.toLocaleString()} events ({percentage.toFixed(1)}%)
                  </span>
                </div>
                <div className="w-full bg-muted/20 rounded-full h-6 overflow-hidden">
                  <div className="h-full flex">
                    {Object.entries(day.levels).map(([level, count]) => {
                      const levelPercent = (count / day.count) * 100;
                      return (
                        <div
                          key={level}
                          className={`${getLevelColor(level)} transition-all`}
                          style={{ width: `${levelPercent}%` }}
                          title={`${level}: ${count}`}
                        />
                      );
                    })}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </Card>

      {/* Hourly Timeline */}
      <Card className="p-4">
        <div className="flex items-center gap-2 mb-4">
          <TrendingUp className="w-5 h-5 text-accent" />
          <h3 className="text-lg font-semibold">Hourly Activity Timeline</h3>
        </div>

        <div className="space-y-1">
          {hourlyData.map((hour) => {
            const barWidth = (hour.count / maxCount) * 100;
            
            return (
              <div key={hour.time} className="flex items-center gap-3">
                <div className="text-xs text-muted-foreground w-32 font-mono flex-shrink-0">
                  {hour.time}
                </div>
                <div className="flex-1 relative">
                  <div className="w-full bg-muted/20 rounded h-8 overflow-hidden">
                    <div
                      className="h-full bg-accent/50 transition-all hover:bg-accent/70 relative group"
                      style={{ width: `${barWidth}%` }}
                    >
                      <div className="absolute inset-0 flex items-center justify-end pr-2">
                        <span className="text-xs font-medium text-foreground">
                          {hour.count}
                        </span>
                      </div>
                      
                      {/* Tooltip on hover */}
                      <div className="absolute left-0 top-full mt-1 hidden group-hover:block bg-popover border border-border rounded p-2 z-10 text-xs whitespace-nowrap">
                        {Object.entries(hour.levels).map(([level, count]) => (
                          <div key={level} className="flex items-center gap-2">
                            <span className={`w-2 h-2 rounded-full ${getLevelColor(level)}`} />
                            <span>{level}: {count}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      </Card>

      {/* Event Burst Detection */}
      <Card className="p-4">
        <div className="flex items-center gap-2 mb-4">
          <AlertTriangle className="w-5 h-5 text-yellow-500" />
          <h3 className="text-lg font-semibold">Activity Anomalies</h3>
        </div>

        <div className="space-y-3">
          {hourlyData
            .filter(hour => hour.count > maxCount * 0.5) // High activity periods
            .slice(0, 5)
            .map((hour) => (
              <div key={hour.time} className="p-3 bg-yellow-500/10 border border-yellow-500/30 rounded">
                <div className="flex items-start justify-between">
                  <div>
                    <div className="font-medium text-sm">{hour.time}</div>
                    <div className="text-xs text-muted-foreground mt-1">
                      High activity detected: {hour.count} events
                    </div>
                    <div className="flex items-center gap-2 mt-2">
                      {Object.entries(hour.levels).map(([level, count]) => (
                        <span key={level} className="text-xs px-2 py-1 rounded bg-muted/50">
                          {level}: {count}
                        </span>
                      ))}
                    </div>
                  </div>
                  <span className="text-xs text-yellow-500 font-medium">
                    {((hour.count / maxCount) * 100).toFixed(0)}% of peak
                  </span>
                </div>
              </div>
            ))}
          
          {hourlyData.filter(hour => hour.count > maxCount * 0.5).length === 0 && (
            <div className="text-sm text-muted-foreground text-center py-4">
              No significant activity anomalies detected
            </div>
          )}
        </div>
      </Card>
    </div>
  );
};
