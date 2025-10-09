import React, { useCallback, useState } from 'react';
import { Upload, File } from 'lucide-react';

interface FileDropZoneProps {
  onFileSelect: (file: File) => void;
  accept?: string;
  maxSize?: number; // in bytes
  className?: string;
  children?: React.ReactNode;
}

export const FileDropZone: React.FC<FileDropZoneProps> = ({
  onFileSelect,
  accept = '*',
  maxSize = 100 * 1024 * 1024, // 100MB default
  className = '',
  children
}) => {
  const [isDragging, setIsDragging] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const handleDrag = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
  }, []);

  const handleDragIn = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    if (e.dataTransfer.items && e.dataTransfer.items.length > 0) {
      setIsDragging(true);
    }
  }, []);

  const handleDragOut = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
  }, []);

  const validateFile = (file: File): string | null => {
    if (file.size > maxSize) {
      return `File size exceeds ${(maxSize / 1024 / 1024).toFixed(0)}MB limit`;
    }

    if (accept !== '*') {
      const acceptedTypes = accept.split(',').map(t => t.trim());
      const fileExtension = '.' + file.name.split('.').pop()?.toLowerCase();
      const fileMimeType = file.type;

      const isAccepted = acceptedTypes.some(type => {
        if (type.startsWith('.')) {
          return fileExtension === type.toLowerCase();
        }
        if (type.includes('*')) {
          const baseType = type.split('/')[0];
          return fileMimeType.startsWith(baseType);
        }
        return fileMimeType === type;
      });

      if (!isAccepted) {
        return `File type not accepted. Expected: ${accept}`;
      }
    }

    return null;
  };

  const handleDrop = useCallback((e: React.DragEvent) => {
    e.preventDefault();
    e.stopPropagation();
    setIsDragging(false);
    setError(null);

    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      const validationError = validateFile(file);

      if (validationError) {
        setError(validationError);
        return;
      }

      onFileSelect(file);
    }
  }, [onFileSelect, accept, maxSize]);

  const handleFileInput = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    setError(null);
    if (e.target.files && e.target.files.length > 0) {
      const file = e.target.files[0];
      const validationError = validateFile(file);

      if (validationError) {
        setError(validationError);
        return;
      }

      onFileSelect(file);
    }
  }, [onFileSelect, accept, maxSize]);

  return (
    <div className={className}>
      <div
        onDragEnter={handleDragIn}
        onDragLeave={handleDragOut}
        onDragOver={handleDrag}
        onDrop={handleDrop}
        className={`
          relative border-2 border-dashed rounded-lg p-8 text-center
          transition-all duration-200 cursor-pointer
          ${isDragging
            ? 'border-accent bg-accent/10 scale-[1.02]'
            : 'border-border hover:border-accent/50 hover:bg-accent/5'
          }
        `}
      >
        <input
          type="file"
          accept={accept}
          onChange={handleFileInput}
          className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
          aria-label="File upload input"
        />

        {children || (
          <div className="flex flex-col items-center space-y-3">
            <div className={`p-4 rounded-full ${isDragging ? 'bg-accent/20' : 'bg-muted'} transition-colors`}>
              {isDragging ? (
                <File className="w-8 h-8 text-accent animate-bounce" />
              ) : (
                <Upload className="w-8 h-8 text-muted-foreground" />
              )}
            </div>
            <div>
              <p className="text-sm font-medium text-foreground">
                {isDragging ? 'Drop file here' : 'Drag & drop file here'}
              </p>
              <p className="text-xs text-muted-foreground mt-1">
                or click to browse
              </p>
            </div>
            {accept !== '*' && (
              <p className="text-xs text-muted-foreground">
                Accepted: {accept}
              </p>
            )}
          </div>
        )}
      </div>

      {error && (
        <div className="mt-2 p-2 bg-destructive/10 border border-destructive/20 rounded text-sm text-destructive">
          {error}
        </div>
      )}
    </div>
  );
};
