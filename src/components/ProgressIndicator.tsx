import React from 'react';
import { Loader2 } from 'lucide-react';

interface ProgressIndicatorProps {
  message?: string;
  progress?: number; // 0-100
  variant?: 'spinner' | 'bar' | 'dots';
  size?: 'sm' | 'md' | 'lg';
  className?: string;
}

export const ProgressIndicator: React.FC<ProgressIndicatorProps> = ({
  message = 'Processing...',
  progress,
  variant = 'spinner',
  size = 'md',
  className = ''
}) => {
  const sizeClasses = {
    sm: 'w-4 h-4',
    md: 'w-6 h-6',
    lg: 'w-8 h-8'
  };

  const renderSpinner = () => (
    <div className={`flex flex-col items-center justify-center space-y-3 ${className}`}>
      <Loader2 className={`${sizeClasses[size]} text-accent animate-spin`} />
      <p className="text-sm text-muted-foreground">{message}</p>
      {typeof progress === 'number' && (
        <p className="text-xs text-muted-foreground font-mono">{progress}%</p>
      )}
    </div>
  );

  const renderBar = () => (
    <div className={`space-y-2 ${className}`}>
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">{message}</p>
        {typeof progress === 'number' && (
          <p className="text-sm font-mono text-accent">{progress}%</p>
        )}
      </div>
      <div className="w-full h-2 bg-muted rounded-full overflow-hidden">
        <div
          className="h-full bg-accent transition-all duration-300 ease-out"
          style={{ width: `${typeof progress === 'number' ? progress : 0}%` }}
        />
      </div>
    </div>
  );

  const renderDots = () => (
    <div className={`flex items-center space-x-2 ${className}`}>
      <div className="flex space-x-1">
        <div className="w-2 h-2 bg-accent rounded-full animate-bounce" style={{ animationDelay: '0ms' }} />
        <div className="w-2 h-2 bg-accent rounded-full animate-bounce" style={{ animationDelay: '150ms' }} />
        <div className="w-2 h-2 bg-accent rounded-full animate-bounce" style={{ animationDelay: '300ms' }} />
      </div>
      <p className="text-sm text-muted-foreground">{message}</p>
    </div>
  );

  switch (variant) {
    case 'bar':
      return renderBar();
    case 'dots':
      return renderDots();
    case 'spinner':
    default:
      return renderSpinner();
  }
};

// Overlay version for full-page loading
export const ProgressOverlay: React.FC<ProgressIndicatorProps> = (props) => {
  return (
    <div className="fixed inset-0 bg-background/80 backdrop-blur-sm z-50 flex items-center justify-center">
      <div className="bg-card border border-border rounded-lg p-8 shadow-2xl">
        <ProgressIndicator {...props} />
      </div>
    </div>
  );
};
