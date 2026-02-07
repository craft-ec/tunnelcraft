import React, { useState } from 'react';
import './KeyManagementModal.css';

interface KeyManagementModalProps {
  mode: 'export' | 'import';
  onClose: () => void;
  onSuccess: (publicKey: string) => void;
}

export const KeyManagementModal: React.FC<KeyManagementModalProps> = ({ mode, onClose, onSuccess }) => {
  const [password, setPassword] = useState('');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [filePath, setFilePath] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const [success, setSuccessState] = useState<string | null>(null);

  const isExport = mode === 'export';

  const handleSelectFile = async () => {
    try {
      if (isExport) {
        const result = await window.electronAPI.showSaveDialog({
          title: 'Export TunnelCraft Key',
          defaultPath: 'tunnelcraft-key.enc',
          filters: [
            { name: 'Encrypted Key', extensions: ['enc'] },
            { name: 'All Files', extensions: ['*'] },
          ],
        });
        if (!result.canceled && result.filePath) {
          setFilePath(result.filePath);
        }
      } else {
        const result = await window.electronAPI.showOpenDialog({
          title: 'Import TunnelCraft Key',
          filters: [
            { name: 'Encrypted Key', extensions: ['enc'] },
            { name: 'All Files', extensions: ['*'] },
          ],
          properties: ['openFile'],
        });
        if (!result.canceled && result.filePaths.length > 0) {
          setFilePath(result.filePaths[0]);
        }
      }
    } catch {
      setError('Failed to open file dialog');
    }
  };

  const handleSubmit = async () => {
    setError(null);

    if (!password) {
      setError('Password is required');
      return;
    }

    if (isExport && password !== confirmPassword) {
      setError('Passwords do not match');
      return;
    }

    if (password.length < 8) {
      setError('Password must be at least 8 characters');
      return;
    }

    if (!filePath) {
      setError('Please select a file');
      return;
    }

    setLoading(true);
    try {
      if (isExport) {
        const result = await window.electronAPI.exportKey(filePath, password);
        if (result.success && result.public_key) {
          setSuccessState(`Key exported. Public key: ${result.public_key.slice(0, 16)}...`);
          onSuccess(result.public_key);
        } else {
          setError(result.error || 'Export failed');
        }
      } else {
        const result = await window.electronAPI.importKey(filePath, password);
        if (result.success && result.public_key) {
          setSuccessState(`Key imported. New public key: ${result.public_key.slice(0, 16)}...`);
          onSuccess(result.public_key);
        } else {
          setError(result.error || 'Import failed');
        }
      }
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="km-overlay" onClick={onClose}>
      <div className="km-modal" onClick={(e) => e.stopPropagation()}>
        <div className="km-header">
          <h3>{isExport ? 'Export Key' : 'Import Key'}</h3>
          <button className="km-close" onClick={onClose}>&times;</button>
        </div>

        {!isExport && (
          <div className="km-warning">
            This will replace your current identity. Existing credits will be lost.
          </div>
        )}

        <div className="km-body">
          {/* File selection */}
          <div className="km-field">
            <label className="km-label">File</label>
            <div className="km-file-row">
              <span className="km-file-path">
                {filePath || 'No file selected'}
              </span>
              <button className="km-browse-btn" onClick={handleSelectFile}>
                Browse
              </button>
            </div>
          </div>

          {/* Password */}
          <div className="km-field">
            <label className="km-label">Password</label>
            <div className="km-input-row">
              <input
                type={showPassword ? 'text' : 'password'}
                className="km-input"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter password"
                autoFocus
              />
              <button
                className="km-toggle-pw"
                onClick={() => setShowPassword(!showPassword)}
                tabIndex={-1}
              >
                {showPassword ? 'Hide' : 'Show'}
              </button>
            </div>
          </div>

          {/* Confirm password (export only) */}
          {isExport && (
            <div className="km-field">
              <label className="km-label">Confirm Password</label>
              <input
                type={showPassword ? 'text' : 'password'}
                className="km-input"
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="Confirm password"
              />
            </div>
          )}

          {error && <div className="km-error">{error}</div>}
          {success && <div className="km-success">{success}</div>}
        </div>

        <div className="km-footer">
          <button className="km-cancel-btn" onClick={onClose}>Cancel</button>
          <button
            className="km-submit-btn"
            onClick={handleSubmit}
            disabled={loading || !!success}
          >
            {loading ? (isExport ? 'Exporting...' : 'Importing...') : (success ? 'Done' : (isExport ? 'Export' : 'Import'))}
          </button>
        </div>
      </div>
    </div>
  );
};
