import React, { useState, useMemo } from 'react';
import { Layers, ChevronDown, ChevronRight, Eye } from 'lucide-react';
import { Card } from '../ui/card';
import { Badge } from '../ui/badge';

interface OrganizedTabProps {
  events: any[];
}

export const OrganizedTab: React.FC<OrganizedTabProps> = ({ events }) => {
  const [expandedFields, setExpandedFields] = useState<Set<string>>(new Set());
  const [expandedValues, setExpandedValues] = useState<Set<string>>(new Set());

  // Organize all event data by field names and values
  const organizedData = useMemo(() => {
    const fieldMap = new Map<string, Map<string, number[]>>();

    events.forEach((event, eventIndex) => {
      if (!event.data || typeof event.data !== 'object') return;

      Object.entries(event.data).forEach(([fieldName, fieldValue]) => {
        if (!fieldMap.has(fieldName)) {
          fieldMap.set(fieldName, new Map());
        }

        const valueMap = fieldMap.get(fieldName)!;
        const valueStr = String(fieldValue || '(empty)');

        if (!valueMap.has(valueStr)) {
          valueMap.set(valueStr, []);
        }

        valueMap.get(valueStr)!.push(eventIndex);
      });
    });

    // Convert to sorted array
    return Array.from(fieldMap.entries())
      .map(([fieldName, valueMap]) => ({
        fieldName,
        values: Array.from(valueMap.entries())
          .map(([value, eventIndices]) => ({
            value,
            count: eventIndices.length,
            eventIndices,
          }))
          .sort((a, b) => b.count - a.count), // Sort by count descending
        totalValues: valueMap.size,
      }))
      .sort((a, b) => a.fieldName.localeCompare(b.fieldName)); // Sort fields alphabetically
  }, [events]);

  const toggleField = (fieldName: string) => {
    const newExpanded = new Set(expandedFields);
    if (newExpanded.has(fieldName)) {
      newExpanded.delete(fieldName);
    } else {
      newExpanded.add(fieldName);
    }
    setExpandedFields(newExpanded);
  };

  const toggleValue = (key: string) => {
    const newExpanded = new Set(expandedValues);
    if (newExpanded.has(key)) {
      newExpanded.delete(key);
    } else {
      newExpanded.add(key);
    }
    setExpandedValues(newExpanded);
  };

  if (organizedData.length === 0) {
    return (
      <Card className="p-8 text-center">
        <Layers className="w-16 h-16 mx-auto mb-4 text-muted-foreground opacity-50" />
        <h3 className="text-lg font-semibold mb-2">No Event Data Found</h3>
        <p className="text-sm text-muted-foreground">
          No structured event data available to organize.
        </p>
      </Card>
    );
  }

  return (
    <div className="space-y-6">
      {/* Summary */}
      <Card className="p-4">
        <div className="flex items-center gap-3">
          <Layers className="w-6 h-6 text-blue-500" />
          <div>
            <h3 className="text-lg font-semibold">Event Data Fields</h3>
            <p className="text-sm text-muted-foreground">
              {organizedData.length} unique fields found across {events.length} events
            </p>
          </div>
        </div>
      </Card>

      {/* Organized Fields */}
      <Card className="p-6">
        <div className="space-y-2">
          {organizedData.map((field) => {
            const isFieldExpanded = expandedFields.has(field.fieldName);

            return (
              <div key={field.fieldName} className="border border-border rounded-lg overflow-hidden">
                {/* Field Header */}
                <div
                  className="p-3 bg-muted/5 cursor-pointer hover:bg-muted/10 transition-colors"
                  onClick={() => toggleField(field.fieldName)}
                >
                  <div className="flex items-center gap-3">
                    {isFieldExpanded ? (
                      <ChevronDown className="w-5 h-5 text-muted-foreground flex-shrink-0" />
                    ) : (
                      <ChevronRight className="w-5 h-5 text-muted-foreground flex-shrink-0" />
                    )}
                    <div className="flex-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="font-semibold text-foreground">{field.fieldName}</span>
                        <Badge variant="outline" className="text-xs">
                          {field.totalValues} unique values
                        </Badge>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Field Values */}
                {isFieldExpanded && (
                  <div className="border-t border-border bg-muted/5 p-4">
                    <div className="space-y-2 max-h-96 overflow-y-auto">
                      {field.values.map((valueData) => {
                        const valueKey = `${field.fieldName}:${valueData.value}`;
                        const isValueExpanded = expandedValues.has(valueKey);

                        return (
                          <div key={valueKey} className="border border-border rounded overflow-hidden">
                            {/* Value Header */}
                            <div
                              className="p-2 bg-card cursor-pointer hover:bg-muted/50 transition-colors"
                              onClick={() => toggleValue(valueKey)}
                            >
                              <div className="flex items-center gap-2">
                                {isValueExpanded ? (
                                  <ChevronDown className="w-4 h-4 text-muted-foreground flex-shrink-0" />
                                ) : (
                                  <ChevronRight className="w-4 h-4 text-muted-foreground flex-shrink-0" />
                                )}
                                <div className="flex-1 flex items-center justify-between gap-2 min-w-0">
                                  <span className="text-sm font-mono break-all">{valueData.value}</span>
                                  <Badge className="flex-shrink-0 text-xs">
                                    {valueData.count} events
                                  </Badge>
                                </div>
                              </div>
                            </div>

                            {/* Related Events */}
                            {isValueExpanded && (
                              <div className="border-t border-border bg-muted/30 p-3">
                                <div className="flex items-center gap-2 mb-2 text-xs text-muted-foreground">
                                  <Eye className="w-3 h-3" />
                                  <span>Events containing this value ({valueData.eventIndices.length})</span>
                                </div>
                                <div className="space-y-2 max-h-64 overflow-y-auto">
                                  {valueData.eventIndices.slice(0, 50).map((eventIdx) => {
                                    const event = events[eventIdx];
                                    return (
                                      <div key={eventIdx} className="p-2 bg-card border border-border rounded text-xs">
                                        <div className="grid grid-cols-2 gap-2 mb-1">
                                          <div>
                                            <span className="text-muted-foreground">Event ID:</span>{' '}
                                            <span className="font-mono font-semibold">{event.eventId}</span>
                                          </div>
                                          <div>
                                            <span className="text-muted-foreground">Record:</span>{' '}
                                            <span className="font-mono">#{event.recordId}</span>
                                          </div>
                                          <div>
                                            <span className="text-muted-foreground">Provider:</span>{' '}
                                            <span className="font-mono text-xs truncate">{event.provider}</span>
                                          </div>
                                          <div>
                                            <span className="text-muted-foreground">Computer:</span>{' '}
                                            <span className="font-mono text-xs truncate">{event.computer}</span>
                                          </div>
                                        </div>
                                        <div className="text-xs text-muted-foreground">
                                          {new Date(event.timestamp).toLocaleString()}
                                        </div>
                                      </div>
                                    );
                                  })}
                                  {valueData.eventIndices.length > 50 && (
                                    <p className="text-xs text-muted-foreground text-center py-2">
                                      Showing first 50 of {valueData.eventIndices.length} events
                                    </p>
                                  )}
                                </div>
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </Card>
    </div>
  );
};
