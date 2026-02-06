import React from 'react';
import { useVPN } from '../context/VPNContext';
import './StatusCard.css';

export const StatusCard: React.FC = () => {
  const { status, credits } = useVPN();

  const getStatusColor = () => {
    switch (status.state) {
      case 'connected':
        return '#22c55e';
      case 'connecting':
      case 'disconnecting':
        return '#eab308';
      case 'error':
        return '#ef4444';
      default:
        return '#64748b';
    }
  };

  const getStatusText = () => {
    switch (status.state) {
      case 'connected':
        return 'Connected';
      case 'connecting':
        return 'Connecting...';
      case 'disconnecting':
        return 'Disconnecting...';
      case 'error':
        return 'Error';
      default:
        return 'Disconnected';
    }
  };

  return (
    <div className="status-card">
      <div className={`status-indicator ${status.state}`} style={{ backgroundColor: getStatusColor() }} />
      <div className="status-info">
        <h2 className="status-text">{getStatusText()}</h2>
        {status.state === 'connected' && status.exitNode && (
          <p className="exit-node">Exit: {status.exitNode}</p>
        )}
        {status.state === 'error' && status.errorMessage && (
          <p className="error-message">{status.errorMessage}</p>
        )}
      </div>
      <div className="status-details">
        <div className="detail">
          <span className="label">Peers</span>
          <span className="value">{status.connectedPeers}</span>
        </div>
        <div className="detail">
          <span className="label">Credits</span>
          <span className="value">{credits}</span>
        </div>
      </div>
    </div>
  );
};
