import React, { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import ScanlineOverlay from './ScanlineOverlay'; 

interface VolatilityLoaderProps {
  onComplete: () => void;
}

const VolatilityLoader: React.FC<VolatilityLoaderProps> = ({ onComplete }) => {
  const [textLines, setTextLines] = useState<string[]>([]);
  const [progress, setProgress] = useState(0);

  const sequence = [
    "INITIALIZING KERNEL...",
    "LOADING VOLATILITY 3 PLUGINS...",
    "MOUNTING SUSPICIOUS.MEM...",
    "DECRYPTING ARTIFACTS...",
    "ACCESS GRANTED."
  ];

  useEffect(() => {
    // 1. Text Typing Logic
    let currentLine = 0;
    const lineInterval = setInterval(() => {
      if (currentLine < sequence.length) {
        setTextLines((prev) => [...prev, sequence[currentLine]]);
        currentLine++;
      }
    }, 500);

    // 2. Progress Bar Logic
    const progressInterval = setInterval(() => {
      setProgress((prev) => {
        if (prev >= 100) {
          clearInterval(progressInterval);
          clearInterval(lineInterval);
          setTimeout(onComplete, 800); 
          return 100;
        }
        return prev + Math.floor(Math.random() * 10) + 1;
      });
    }, 150);

    return () => {
      clearInterval(lineInterval);
      clearInterval(progressInterval);
    };
  }, [onComplete]);

  return (
    <motion.div
      className="fixed inset-0 z-50 bg-black flex flex-col items-center justify-center font-mono text-[#33ff33] p-8 overflow-hidden"
      exit={{ 
        opacity: 0, 
        scale: 1.1, 
        filter: "blur(10px)",
        transition: { duration: 0.8, ease: "easeInOut" } 
      }}
    >
      <ScanlineOverlay />
      
      <div className="w-full max-w-2xl relative z-10 flex flex-col items-center">
        
        {/* REPLACED ASCII WITH NORMAL TEXT */}
        <h1 className="text-5xl md:text-7xl font-black tracking-tighter mb-12 animate-pulse drop-shadow-[0_0_10px_rgba(51,255,51,0.5)]">
          VOLATILITY 3
        </h1>

        {/* Boot Logs */}
        <div className="w-full h-48 border-l-2 border-[#33ff33] pl-4 mb-6 bg-[#001100]/50 p-4 font-mono text-sm md:text-base">
          {textLines.map((line, i) => (
            <motion.div 
              key={i}
              initial={{ opacity: 0, x: -10 }}
              animate={{ opacity: 1, x: 0 }}
              className="mb-2"
            >
              <span className="opacity-50 mr-3">{`>`}</span>
              {line}
            </motion.div>
          ))}
          <div className="w-3 h-5 bg-[#33ff33] animate-pulse mt-2"></div>
        </div>

        {/* Progress Bar */}
        <div className="w-full border-2 border-[#33ff33] p-1 h-10 relative">
          <motion.div 
            className="h-full bg-[#33ff33]"
            initial={{ width: "0%" }}
            animate={{ width: `${progress}%` }}
          />
          <div className="absolute inset-0 flex items-center justify-center text-black font-bold mix-blend-screen text-sm tracking-[0.2em]">
            LOADING... {progress}%
          </div>
        </div>
      </div>
    </motion.div>
  );
};

export default VolatilityLoader;