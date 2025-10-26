import React from 'react';

interface ProgressTrackerProps {
  progress: number; // 0-100
  message?: string;
  className?: string;
}

export const ProgressTracker: React.FC<ProgressTrackerProps> = ({ 
  progress, 
  message,
  className = '' 
}) => {
  return (
    <div className={`w-full max-w-3xl mx-auto p-4 bg-gray-900/50 border border-gray-800 rounded-lg backdrop-blur-sm ${className}`}>
      {/* Progress percentage and message in one line */}
      <div className="flex justify-between items-center mb-3">
        <span className="text-sm text-gray-400">
          {message || 'Processing...'}
        </span>
        <span className="text-sm font-mono font-bold text-blue-400">
          {Math.round(progress)}%
        </span>
      </div>

      {/* Progress bar */}
      <div className="w-full bg-gray-800 rounded-full h-2 overflow-hidden">
        <div
          className="bg-gradient-to-r from-blue-500 via-blue-400 to-cyan-400 h-2 rounded-full transition-all duration-300 ease-out relative"
          style={{ width: `${Math.min(100, Math.max(0, progress))}%` }}
        >
          {/* Animated shine effect */}
          <div className="absolute inset-0 bg-gradient-to-r from-transparent via-white/30 to-transparent animate-shimmer" />
        </div>
      </div>
    </div>
  );
};
