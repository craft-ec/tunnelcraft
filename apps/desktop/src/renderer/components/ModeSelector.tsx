import React from 'react';
import { useVPN } from '../context/VPNContext';
import './ModeSelector.css';

type NodeMode = 'client' | 'node' | 'both';

interface ModeOption {
  value: NodeMode;
  label: string;
  description: string;
}

const modes: ModeOption[] = [
  { value: 'client', label: 'Client', description: 'Use VPN (spend credits)' },
  { value: 'node', label: 'Node', description: 'Help network (earn credits)' },
  { value: 'both', label: 'Both', description: 'Earn & spend' },
];

export const ModeSelector: React.FC = () => {
  const { mode, setMode, status } = useVPN();
  return (
    <div className="mode-selector">
      <h3 className="selector-title">Mode</h3>
      <div className="mode-options">
        {modes.map((opt) => (
          <button
            key={opt.value}
            className={`mode-option ${mode === opt.value ? 'selected' : ''}`}
            onClick={() => setMode(opt.value)}
          >
            <span className="mode-name">{opt.label}</span>
            <span className="mode-description">{opt.description}</span>
          </button>
        ))}
      </div>
    </div>
  );
};
