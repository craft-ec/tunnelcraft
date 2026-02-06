import React, { useState, useCallback } from 'react';
import { useVPN } from '../context/VPNContext';
import './RequestPanel.css';

type HttpMethod = 'GET' | 'POST';

interface RequestHistoryItem {
  id: number;
  method: HttpMethod;
  url: string;
  status: number;
  body: string;
  timestamp: number;
}

export const RequestPanel: React.FC = () => {
  const { status } = useVPN();
  const [method, setMethod] = useState<HttpMethod>('GET');
  const [url, setUrl] = useState('');
  const [requestBody, setRequestBody] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [response, setResponse] = useState<{ status: number; body: string } | null>(null);
  const [history, setHistory] = useState<RequestHistoryItem[]>([]);
  const [nextId, setNextId] = useState(1);

  if (status.state !== 'connected') {
    return null;
  }

  const handleSend = async () => {
    if (!url.trim()) return;
    setIsLoading(true);
    setResponse(null);

    try {
      const result = await window.electronAPI.request(
        method,
        url.trim(),
        method === 'POST' ? requestBody : undefined,
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
        {(['GET', 'POST'] as HttpMethod[]).map((m) => (
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
      />

      {method === 'POST' && (
        <textarea
          className="body-input"
          value={requestBody}
          onChange={(e) => setRequestBody(e.target.value)}
          placeholder="Request body (JSON, text, etc.)"
          rows={3}
        />
      )}

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
