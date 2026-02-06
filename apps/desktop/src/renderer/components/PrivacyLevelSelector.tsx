import React from 'react';
import { useVPN, type PrivacyLevel } from '../context/VPNContext';
import './PrivacyLevelSelector.css';

interface LevelOption {
  value: PrivacyLevel;
  label: string;
  hops: number;
  description: string;
}

const levels: LevelOption[] = [
  { value: 'direct', label: 'Direct', hops: 0, description: 'No relay hops' },
  { value: 'light', label: 'Light', hops: 1, description: '1 relay hop' },
  { value: 'standard', label: 'Standard', hops: 2, description: '2 relay hops' },
  { value: 'paranoid', label: 'Paranoid', hops: 3, description: '3 relay hops' },
];

export const PrivacyLevelSelector: React.FC = () => {
  const { privacyLevel, setPrivacyLevel, status } = useVPN();
  const isDisabled = status.state === 'connected' || status.state === 'connecting';

  return (
    <div className="privacy-selector">
      <h3 className="selector-title">Privacy Level</h3>
      <div className="levels">
        {levels.map((level) => (
          <button
            key={level.value}
            className={`level-option ${privacyLevel === level.value ? 'selected' : ''}`}
            onClick={() => setPrivacyLevel(level.value)}
            disabled={isDisabled}
          >
            <div className="level-header">
              <span className="level-name">{level.label}</span>
              <span className="level-hops">{level.hops} hops</span>
            </div>
            <span className="level-description">{level.description}</span>
          </button>
        ))}
      </div>
      {isDisabled && (
        <p className="disabled-note">Disconnect to change privacy level</p>
      )}
    </div>
  );
};
