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
    <div className={`w-full max-w-2xl mx-auto p-6 bg-white dark:bg-gray-800 rounded-lg shadow-lg ${className}`}>
      {/* Progress percentage */}
      <div className="flex justify-between items-center mb-2">
        <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
          Processing...
        </span>
        <span className="text-sm font-bold text-blue-600 dark:text-blue-400">
          {Math.round(progress)}%
        </span>
      </div>

      {/* Progress bar */}
      <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-3 mb-4 overflow-hidden">
        <div
          className="bg-gradient-to-r from-blue-500 to-blue-600 h-3 rounded-full transition-all duration-500 ease-out"
          style={{ width: `${Math.min(100, Math.max(0, progress))}%` }}
        >
          {/* Animated shine effect */}
          <div className="h-full w-full bg-gradient-to-r from-transparent via-white to-transparent opacity-20 animate-shimmer" />
        </div>
      </div>

      {/* Status message */}
      {message && (
        <div className="text-center">
          <p className="text-sm text-gray-600 dark:text-gray-400 animate-pulse">
            {message}
          </p>
        </div>
      )}
    </div>
  );
};
