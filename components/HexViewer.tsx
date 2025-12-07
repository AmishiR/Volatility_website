import React, { useEffect, useState } from 'react';

const HexViewer: React.FC = () => {
  const [hexData, setHexData] = useState<string[]>([]);

  useEffect(() => {
    // Generate a random hex line: Address + 8 bytes
    const generateLine = () => {
      const addr = '0x' + Math.floor(Math.random() * 0xFFFFFF).toString(16).padStart(8, '0').toUpperCase();
      const bytes = Array.from({ length: 8 }, () => Math.floor(Math.random() * 255).toString(16).padStart(2, '0').toUpperCase()).join(' ');
      const ascii = Array.from({ length: 8 }, () => {
        const charCode = Math.floor(Math.random() * (126 - 33) + 33);
        return String.fromCharCode(charCode);
      }).join('');
      return `${addr}  ${bytes}  |${ascii}|`;
    };

    // Initial fill
    const initial = Array.from({ length: 8 }, generateLine);
    setHexData(initial);

    // Update effect
    const interval = setInterval(() => {
        setHexData(prev => [...prev.slice(1), generateLine()]);
    }, 150);

    return () => clearInterval(interval);
  }, []);

  return (
    <div className="font-mono text-xs text-[#33ff33] opacity-60 overflow-hidden h-full select-none">
        {hexData.map((line, i) => (
            <div key={i} className="whitespace-pre">{line}</div>
        ))}
    </div>
  );
};

export default HexViewer;