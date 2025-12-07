import React from 'react';

interface RetroButtonProps {
  label: string;
  subLabel: string;
  onClick?: () => void;
  className?: string;
  variant?: 'danger' | 'success';
}

const RetroButton: React.FC<RetroButtonProps> = ({ label, subLabel, onClick, className = '', variant = 'danger' }) => {
  const borderColor = variant === 'danger' ? 'border-[#ff9999] hover:border-[#ffcccc]' : 'border-[#33ff33] hover:border-[#ccffcc]';
  const gradientFrom = variant === 'danger' ? 'from-[#ff8888]' : 'from-[#33aa33]';
  const gradientTo = variant === 'danger' ? 'to-[#cc4444]' : 'to-[#116611]';
  const textColor = variant === 'danger' ? 'text-white' : 'text-[#eeffee]';

  return (
    <button 
      onClick={onClick}
      className={`group relative overflow-hidden border-2 ${borderColor} transition-all duration-100 ${className}`}
    >
      {/* Gradient Background */}
      <div className={`absolute inset-0 bg-gradient-to-b ${gradientFrom} ${gradientTo} opacity-80 group-hover:opacity-100 transition-opacity`}></div>
      
      {/* Content */}
      <div className="relative z-10 p-2 text-center">
        <div className={`${textColor} text-sm uppercase tracking-widest drop-shadow-md`}>{label}</div>
        <div className={`${textColor} text-lg font-bold drop-shadow-md leading-tight`}>{subLabel}</div>
      </div>

      {/* Scanline effect specifically for button */}
      <div className="absolute inset-0 bg-[url('data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAACCAYAAACZgbYnAAAABlBMVEX///8AAABVwtN+AAAAAnRSTlMbn8h4eAAAAA1JREFUCJlj+v///38ACx8D/s8KRYEAAAAASUVORK5CYII=')] opacity-20 pointer-events-none"></div>
    </button>
  );
};

export default RetroButton;