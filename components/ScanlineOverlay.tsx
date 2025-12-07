import React from 'react';

const ScanlineOverlay: React.FC = () => {
  return (
    <div className="crt-overlay fixed inset-0 z-50 pointer-events-none opacity-40 mix-blend-overlay h-full w-full"></div>
  );
};

export default ScanlineOverlay;