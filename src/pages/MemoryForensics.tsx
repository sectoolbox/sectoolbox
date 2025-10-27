import React from 'react';
import { Construction } from 'lucide-react';

const MemoryForensics: React.FC = () => {
  return (
    <div className="min-h-screen bg-gradient-to-br from-gray-900 via-gray-800 to-gray-900 text-white p-8 flex items-center justify-center">
      <div className="text-center">
        <Construction className="w-24 h-24 mx-auto mb-6 text-yellow-500" />
        <h1 className="text-4xl font-bold mb-4">Memory Forensics</h1>
        <p className="text-xl text-gray-400">Currently Under Construction</p>
      </div>
    </div>
  );
};

export default MemoryForensics;
