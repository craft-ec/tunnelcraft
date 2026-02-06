import React from 'react';
import './TitleBar.css';

export const TitleBar: React.FC = () => {
  const handleMinimize = () => {
    window.electronAPI.minimize();
  };

  const handleClose = () => {
    window.electronAPI.close();
  };

  return (
    <div className="title-bar">
      <div className="title-bar-drag">
        <span className="title">TunnelCraft</span>
      </div>
      <div className="window-controls">
        <button className="control-button minimize" onClick={handleMinimize} aria-label="Minimize">
          <svg viewBox="0 0 12 12">
            <rect x="2" y="5.5" width="8" height="1" />
          </svg>
        </button>
        <button className="control-button close" onClick={handleClose} aria-label="Close">
          <svg viewBox="0 0 12 12">
            <path d="M2 2 L10 10 M10 2 L2 10" strokeWidth="1.5" stroke="currentColor" />
          </svg>
        </button>
      </div>
    </div>
  );
};
