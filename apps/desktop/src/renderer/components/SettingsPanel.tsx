import React, { useState } from 'react';
import { useVPN } from '../context/VPNContext';
import './SettingsPanel.css';

export const SettingsPanel: React.FC = () => {
  const { mode, setMode, status, nodeStats, credits } = useVPN();
  const [localDiscovery, setLocalDiscoveryState] = useState(true);

  const setLocalDiscovery = (enabled: boolean) => {
    setLocalDiscoveryState(enabled);
    window.electronAPI.setLocalDiscovery(enabled).catch(() => {
      // Revert on failure
      setLocalDiscoveryState(!enabled);
    });
  };
  const isConnected = status.state === 'connected' || status.state === 'connecting';

  const isRelay = mode === 'node' || mode === 'both';
  const isExit = mode === 'both';

  const handleRelayToggle = () => {
    if (isConnected) return;
    if (isRelay) {
      setMode('client');
    } else {
      setMode(isExit ? 'both' : 'node');
    }
  };

  const handleExitToggle = () => {
    if (isConnected || !isRelay) return;
    if (isExit) {
      setMode('node');
    } else {
      setMode('both');
    }
  };

  return (
    <div className="settings-panel">
      <h3 className="panel-title">Settings</h3>

      {/* Node Configuration */}
      <div className="settings-section">
        <span className="section-label">Node Configuration</span>

        <div className="setting-row">
          <div className="setting-left">
            <span className="setting-label">Allow Relay</span>
          </div>
          <label className={`toggle ${isRelay ? 'on' : ''} ${isConnected ? 'disabled' : ''}`}>
            <input
              type="checkbox"
              checked={isRelay}
              onChange={handleRelayToggle}
              disabled={isConnected}
            />
            <span className="toggle-slider" />
          </label>
        </div>

        <div className="setting-row">
          <div className="setting-left">
            <span className="setting-label">Allow Exit</span>
          </div>
          <label className={`toggle ${isExit ? 'on' : ''} ${isConnected || !isRelay ? 'disabled' : ''}`}>
            <input
              type="checkbox"
              checked={isExit}
              onChange={handleExitToggle}
              disabled={isConnected || !isRelay}
            />
            <span className="toggle-slider" />
          </label>
        </div>
      </div>

      {/* Network */}
      <div className="settings-section">
        <span className="section-label">Network</span>

        <div className="setting-row">
          <span className="setting-label">Connected Peers</span>
          <span className="setting-value">{status.connectedPeers}</span>
        </div>

        <div className="setting-row">
          <span className="setting-label">Bootstrap Nodes</span>
          <span className="setting-value">Default</span>
        </div>

        <div className="setting-row">
          <div className="setting-left">
            <span className="setting-label">Local Discovery</span>
          </div>
          <label className={`toggle ${localDiscovery ? 'on' : ''}`}>
            <input
              type="checkbox"
              checked={localDiscovery}
              onChange={(e) => setLocalDiscovery(e.target.checked)}
            />
            <span className="toggle-slider" />
          </label>
        </div>
      </div>

      {/* Account */}
      <div className="settings-section">
        <span className="section-label">Account</span>

        <div className="setting-row">
          <span className="setting-label">Credit Balance</span>
          <span className="setting-value">{credits.toLocaleString()}</span>
        </div>

        {nodeStats && (
          <div className="setting-row">
            <span className="setting-label">Earnings</span>
            <span className="setting-value setting-value-earned">
              +{nodeStats.credits_earned}
            </span>
          </div>
        )}

        <div className="setting-row">
          <span className="setting-label">Peer ID</span>
          <span className="setting-value setting-value-mono">
            {status.peerId ? `${status.peerId.slice(0, 8)}...` : 'N/A'}
          </span>
        </div>
      </div>

      {/* About */}
      <div className="settings-section">
        <span className="section-label">About</span>

        <a className="setting-link" href="https://tunnelcraft.app/docs" target="_blank" rel="noreferrer">
          Documentation
          <span className="link-arrow">&rsaquo;</span>
        </a>

        <a className="setting-link" href="https://github.com/craft-ec/tunnelcraft/discussions" target="_blank" rel="noreferrer">
          Community
          <span className="link-arrow">&rsaquo;</span>
        </a>

        <a className="setting-link" href="https://github.com/craft-ec/tunnelcraft/issues" target="_blank" rel="noreferrer">
          Report Issue
          <span className="link-arrow">&rsaquo;</span>
        </a>

        <div className="setting-row">
          <span className="setting-label">Version</span>
          <span className="setting-value">1.0.0</span>
        </div>
      </div>
    </div>
  );
};
