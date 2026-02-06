import React, { useState } from 'react';
import { useVPN } from '../context/VPNContext';
import type { ExitNode } from '../context/VPNContext';
import './ExitNodePanel.css';

const getCountryFlag = (countryCode: string): string => {
  const codePoints = countryCode
    .toUpperCase()
    .split('')
    .map((char) => 127397 + char.charCodeAt(0));
  return String.fromCodePoint(...codePoints);
};

const scoreClass = (score: number): string => {
  if (score <= 40) return 'score-good';
  if (score <= 70) return 'score-medium';
  return 'score-poor';
};

type RegionFilter = 'all' | 'eu' | 'na' | 'ap' | 'sa' | 'af' | 'me' | 'oc';

const REGION_LABELS: Record<RegionFilter, string> = {
  all: 'All',
  eu: 'Europe',
  na: 'N. America',
  sa: 'S. America',
  ap: 'Asia-Pacific',
  oc: 'Oceania',
  me: 'Middle East',
  af: 'Africa',
};

const ScoreBar: React.FC<{ label: string; value: number; max: number; color: string }> = ({ label, value, max, color }) => (
  <div className="score-bar-row">
    <span className="score-bar-label">{label}</span>
    <div className="score-bar-track">
      <div
        className="score-bar-fill"
        style={{ width: `${Math.min(100, (value / max) * 100)}%`, backgroundColor: color }}
      />
    </div>
    <span className="score-bar-value">{value}</span>
  </div>
);

export const ExitNodePanel: React.FC = () => {
  const { mode, exitNode, availableExits, setExitNode } = useVPN();
  const [showList, setShowList] = useState(false);
  const [regionFilter, setRegionFilter] = useState<RegionFilter>('all');

  if (mode !== 'client' && mode !== 'both') {
    return null;
  }

  const handleSelect = (node: ExitNode) => {
    setExitNode(node);
    setShowList(false);
  };

  const filtered = availableExits
    .filter((n) => regionFilter === 'all' || n.region === regionFilter)
    .sort((a, b) => a.score - b.score);

  return (
    <div className="exit-node-panel">
      <h3 className="panel-title">Exit Node</h3>

      {exitNode ? (
        <>
          <div className="current-exit">
            <span className="exit-flag">{getCountryFlag(exitNode.countryCode)}</span>
            <div className="exit-details">
              <span className="exit-city">{exitNode.city}</span>
              <span className="exit-country">
                {exitNode.countryName} &middot; {exitNode.region.toUpperCase()}
              </span>
            </div>
            <span className={`exit-score-badge ${scoreClass(exitNode.score)}`}>
              {exitNode.score}
            </span>
          </div>

          {/* Score breakdown */}
          <div className="score-breakdown">
            <ScoreBar label="Latency" value={exitNode.latencyMs} max={300} color="#3b82f6" />
            <ScoreBar label="Load" value={exitNode.loadPercent} max={100} color="#f59e0b" />
            <ScoreBar label="Score" value={exitNode.score} max={100} color={exitNode.score <= 40 ? '#22c55e' : exitNode.score <= 70 ? '#f59e0b' : '#ef4444'} />
          </div>
        </>
      ) : (
        <div className="no-exit">No exit selected</div>
      )}

      <button
        className="change-exit-button"
        onClick={() => setShowList(!showList)}
        aria-expanded={showList}
      >
        {showList ? 'Close' : exitNode ? 'Change' : 'Select Exit'}
      </button>

      {showList && (
        <>
          {/* Region filter */}
          <div className="region-filter">
            {(Object.keys(REGION_LABELS) as RegionFilter[]).map((r) => (
              <button
                key={r}
                className={`region-button ${regionFilter === r ? 'active' : ''}`}
                onClick={() => setRegionFilter(r)}
              >
                {REGION_LABELS[r]}
              </button>
            ))}
          </div>

          <div className="exit-list">
            {filtered.length === 0 && (
              <div className="no-exit">No exits in this region</div>
            )}
            {filtered.map((node) => (
              <button
                key={node.id}
                className={`exit-list-item ${exitNode?.id === node.id ? 'selected' : ''}`}
                onClick={() => handleSelect(node)}
              >
                <span className="exit-item-flag">{getCountryFlag(node.countryCode)}</span>
                <div className="exit-item-details">
                  <span className="exit-item-city">{node.city}</span>
                  <span className="exit-item-meta">
                    {node.countryCode} &middot; {node.latencyMs}ms &middot; {node.loadPercent}% load
                  </span>
                </div>
                <span className={`exit-item-score ${scoreClass(node.score)}`}>
                  {node.score}
                </span>
              </button>
            ))}
          </div>
        </>
      )}
    </div>
  );
};
