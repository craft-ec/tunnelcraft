import React, { useState } from 'react';
import { useVPN } from '../context/VPNContext';
import './RequestPanel.css';

type HttpMethod = 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'HEAD';

interface HeaderEntry {
  key: string;
  value: string;
}

interface RequestHistoryItem {
  id: number;
  method: HttpMethod;
  url: string;
  status: number;
  body: string;
  timestamp: number;
}

const HOP_COSTS: Record<string, number> = {
  direct: 0,
  light: 1,
  standard: 2,
  paranoid: 3,
};

export const RequestPanel: React.FC = () => {
  const { status, privacyLevel, credits } = useVPN();
  const [method, setMethod] = useState<HttpMethod>('GET');
  const [url, setUrl] = useState('');
  const [requestBody, setRequestBody] = useState('');
  const [headers, setHeaders] = useState<HeaderEntry[]>([]);
  const [showHeaders, setShowHeaders] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [response, setResponse] = useState<{ status: number; body: string } | null>(null);
  const [history, setHistory] = useState<RequestHistoryItem[]>([]);
  const [nextId, setNextId] = useState(1);

  if (status.state !== 'connected') {
    return null;
  }

  const estimatedCost = 1 + (HOP_COSTS[privacyLevel] || 2);
  const canAfford = credits >= estimatedCost;

  const addHeader = () => {
    setHeaders((prev) => [...prev, { key: '', value: '' }]);
  };

  const updateHeader = (index: number, field: 'key' | 'value', val: string) => {
    setHeaders((prev) => prev.map((h, i) => (i === index ? { ...h, [field]: val } : h)));
  };

  const removeHeader = (index: number) => {
    setHeaders((prev) => prev.filter((_, i) => i !== index));
  };

  const handleSend = async () => {
    if (!url.trim()) return;
    setIsLoading(true);
    setResponse(null);

    try {
      const hasBody = method === 'POST' || method === 'PUT' || method === 'PATCH';
      const headerObj: Record<string, string> = {};
      for (const h of headers) {
        if (h.key.trim()) {
          headerObj[h.key.trim()] = h.value;
        }
      }

      const result = await window.electronAPI.request(
        method,
        url.trim(),
        hasBody ? requestBody : undefined,
        Object.keys(headerObj).length > 0 ? headerObj : undefined,
      );

      if (!result.success) {
        const errRes = { status: 0, body: result.error ?? 'Request failed' };
        setResponse(errRes);
        return;
      }

      const res = {
        status: result.status ?? 0,
        body: result.body ?? 'No response',
      };
      setResponse(res);

      setHistory((prev) => {
        const item: RequestHistoryItem = {
          id: nextId,
          method,
          url: url.trim(),
          status: res.status,
          body: res.body,
          timestamp: Date.now(),
        };
        setNextId((n) => n + 1);
        return [item, ...prev].slice(0, 5);
      });
    } catch (err) {
      setResponse({
        status: 0,
        body: (err as Error).message || 'Request failed',
      });
    } finally {
      setIsLoading(false);
    }
  };

  const handleHistoryClick = (item: RequestHistoryItem) => {
    setMethod(item.method);
    setUrl(item.url);
    setResponse({ status: item.status, body: item.body });
  };

  const statusClass = response
    ? response.status >= 200 && response.status < 300
      ? 'status-success'
      : 'status-error'
    : '';

  return (
    <div className="request-panel">
      <h3 className="panel-title">HTTP Request</h3>

      <div className="method-selector">
        {(['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD'] as HttpMethod[]).map((m) => (
          <button
            key={m}
            className={`method-button ${method === m ? 'selected' : ''}`}
            onClick={() => setMethod(m)}
          >
            {m}
          </button>
        ))}
      </div>

      <input
        type="text"
        className="url-input"
        value={url}
        onChange={(e) => setUrl(e.target.value)}
        placeholder="https://example.com"
        onKeyDown={(e) => e.key === 'Enter' && handleSend()}
        aria-label="Request URL"
      />

      {/* Headers */}
      <button
        className="headers-toggle"
        onClick={() => setShowHeaders(!showHeaders)}
      >
        Headers {headers.length > 0 && `(${headers.length})`} {showHeaders ? '▾' : '▸'}
      </button>

      {showHeaders && (
        <div className="headers-section">
          {headers.map((h, i) => (
            <div key={i} className="header-row">
              <input
                className="header-input header-key"
                value={h.key}
                onChange={(e) => updateHeader(i, 'key', e.target.value)}
                placeholder="Key"
                aria-label="Header name"
              />
              <input
                className="header-input header-value"
                value={h.value}
                onChange={(e) => updateHeader(i, 'value', e.target.value)}
                placeholder="Value"
                aria-label="Header value"
              />
              <button className="header-remove" onClick={() => removeHeader(i)}>
                &times;
              </button>
            </div>
          ))}
          <button className="add-header-button" onClick={addHeader}>
            + Add Header
          </button>
        </div>
      )}

      {(method === 'POST' || method === 'PUT' || method === 'PATCH') && (
        <textarea
          className="body-input"
          value={requestBody}
          onChange={(e) => setRequestBody(e.target.value)}
          placeholder="Request body (JSON, text, etc.)"
          rows={3}
          aria-label="Request body"
        />
      )}

      {/* Cost estimation */}
      <div className="cost-estimate">
        <span className="cost-label">Est. cost:</span>
        <span className={`cost-value ${!canAfford ? 'cost-insufficient' : ''}`}>
          {estimatedCost} credit{estimatedCost !== 1 ? 's' : ''}
        </span>
        {!canAfford && <span className="cost-warning">Insufficient credits</span>}
      </div>

      <button
        className="send-button"
        onClick={handleSend}
        disabled={isLoading || !url.trim()}
      >
        {isLoading ? 'Sending...' : 'Send'}
      </button>

      {response && (
        <div className="response-area">
          <div className="response-header">
            <span className={`status-badge ${statusClass}`}>
              {response.status || 'ERR'}
            </span>
            <span className="response-label">Response</span>
          </div>
          <pre className="response-body">{response.body}</pre>
        </div>
      )}

      {history.length > 0 && (
        <div className="history-section">
          <span className="history-label">Recent</span>
          {history.map((item) => (
            <button
              key={item.id}
              className="history-item"
              onClick={() => handleHistoryClick(item)}
            >
              <span className={`history-method ${item.method.toLowerCase()}`}>
                {item.method}
              </span>
              <span className="history-url">{item.url}</span>
              <span className={`history-status ${item.status >= 200 && item.status < 300 ? 'status-success' : 'status-error'}`}>
                {item.status || 'ERR'}
              </span>
            </button>
          ))}
        </div>
      )}
    </div>
  );
};
