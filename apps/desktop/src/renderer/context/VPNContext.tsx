import React, { createContext, useContext, useEffect, useState, useCallback, useRef, ReactNode } from 'react';

type ConnectionState = 'disconnected' | 'connecting' | 'connected' | 'disconnecting' | 'error';
type PrivacyLevel = 'direct' | 'light' | 'standard' | 'paranoid';
type NodeMode = 'client' | 'node' | 'both';

export interface ExitNode {
  id: string;
  countryCode: string;
  countryName: string;
  city: string;
  region: string;
  score: number;
  latencyMs: number;
  loadPercent: number;
}

interface VPNStatus {
  state: ConnectionState;
  peerId: string;
  connectedPeers: number;
  credits: number;
  exitNode: string | null;
  errorMessage: string | null;
}

interface NetworkStats {
  bytesSent: number;
  bytesReceived: number;
  requestsMade: number;
  requestsCompleted: number;
  uptimeSecs: number;
}

interface NodeStats {
  shards_relayed: number;
  requests_exited: number;
  peers_connected: number;
  credits_earned: number;
  credits_spent: number;
  bytes_sent: number;
  bytes_received: number;
  bytes_relayed: number;
}

interface VPNContextType {
  status: VPNStatus;
  stats: NetworkStats;
  nodeStats: NodeStats | null;
  privacyLevel: PrivacyLevel;
  mode: NodeMode;
  credits: number;
  isLoading: boolean;
  error: string | null;
  exitNode: ExitNode | null;
  availableExits: ExitNode[];
  setExitNode: (node: ExitNode) => void;
  connect: () => Promise<void>;
  disconnect: () => Promise<void>;
  toggle: () => Promise<void>;
  setPrivacyLevel: (level: PrivacyLevel) => Promise<void>;
  setMode: (mode: NodeMode) => Promise<void>;
  purchaseCredits: (amount: number) => Promise<void>;
}

const defaultStatus: VPNStatus = {
  state: 'disconnected',
  peerId: '',
  connectedPeers: 0,
  credits: 0,
  exitNode: null,
  errorMessage: null,
};

const defaultStats: NetworkStats = {
  bytesSent: 0,
  bytesReceived: 0,
  requestsMade: 0,
  requestsCompleted: 0,
  uptimeSecs: 0,
};

const mockAvailableExits: ExitNode[] = [
  { id: '1', countryCode: 'DE', countryName: 'Germany', city: 'Frankfurt', region: 'eu', score: 28, latencyMs: 45, loadPercent: 35 },
  { id: '2', countryCode: 'NL', countryName: 'Netherlands', city: 'Amsterdam', region: 'eu', score: 32, latencyMs: 52, loadPercent: 42 },
  { id: '3', countryCode: 'US', countryName: 'United States', city: 'New York', region: 'na', score: 45, latencyMs: 85, loadPercent: 65 },
  { id: '4', countryCode: 'JP', countryName: 'Japan', city: 'Tokyo', region: 'ap', score: 58, latencyMs: 180, loadPercent: 55 },
  { id: '5', countryCode: 'SG', countryName: 'Singapore', city: 'Singapore', region: 'ap', score: 42, latencyMs: 165, loadPercent: 28 },
  { id: '6', countryCode: 'GB', countryName: 'United Kingdom', city: 'London', region: 'eu', score: 35, latencyMs: 60, loadPercent: 48 },
  { id: '7', countryCode: 'CH', countryName: 'Switzerland', city: 'Zurich', region: 'eu', score: 22, latencyMs: 40, loadPercent: 20 },
  { id: '8', countryCode: 'CA', countryName: 'Canada', city: 'Toronto', region: 'na', score: 50, latencyMs: 95, loadPercent: 58 },
];

const VPNContext = createContext<VPNContextType | null>(null);

export const useVPN = (): VPNContextType => {
  const context = useContext(VPNContext);
  if (!context) {
    throw new Error('useVPN must be used within a VPNProvider');
  }
  return context;
};

interface VPNProviderProps {
  children: ReactNode;
}

export const VPNProvider: React.FC<VPNProviderProps> = ({ children }) => {
  const [status, setStatus] = useState<VPNStatus>(defaultStatus);
  const [stats, setStats] = useState<NetworkStats>(defaultStats);
  const [nodeStats, setNodeStats] = useState<NodeStats | null>(null);
  const [privacyLevel, setPrivacyLevelState] = useState<PrivacyLevel>('standard');
  const [mode, setModeState] = useState<NodeMode>('both');
  const [credits, setCreditsState] = useState(0);
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [exitNode, setExitNodeState] = useState<ExitNode | null>(mockAvailableExits[0]);
  const [availableExits] = useState<ExitNode[]>(mockAvailableExits);
  const nodeStatsIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  // Subscribe to VPN events
  useEffect(() => {
    const unsubscribeState = window.electronAPI.onStateChange((state) => {
      setStatus((prev) => ({ ...prev, state: state as ConnectionState }));
    });

    const unsubscribeStats = window.electronAPI.onStatsUpdate((newStats) => {
      setStats(newStats as NetworkStats);
    });

    const unsubscribeError = window.electronAPI.onError((errorMessage) => {
      setError(errorMessage);
      setStatus((prev) => ({ ...prev, state: 'error', errorMessage }));
    });

    // Get initial status
    window.electronAPI.getStatus().then((result) => {
      if (result.success && result.status) {
        setStatus(result.status as VPNStatus);
      }
    });

    return () => {
      unsubscribeState();
      unsubscribeStats();
      unsubscribeError();
    };
  }, []);

  const connect = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      const result = await window.electronAPI.connect({ privacyLevel });
      if (!result.success) {
        throw new Error(result.error || 'Connection failed');
      }
    } catch (err) {
      setError((err as Error).message);
      setStatus((prev) => ({ ...prev, state: 'error' }));
    } finally {
      setIsLoading(false);
    }
  }, [privacyLevel]);

  const disconnect = useCallback(async () => {
    setIsLoading(true);
    setError(null);

    try {
      const result = await window.electronAPI.disconnect();
      if (!result.success) {
        throw new Error(result.error || 'Disconnect failed');
      }
    } catch (err) {
      setError((err as Error).message);
    } finally {
      setIsLoading(false);
    }
  }, []);

  const toggle = useCallback(async () => {
    if (status.state === 'connected' || status.state === 'connecting') {
      await disconnect();
    } else {
      await connect();
    }
  }, [status.state, connect, disconnect]);

  const setPrivacyLevel = useCallback(async (level: PrivacyLevel) => {
    try {
      const result = await window.electronAPI.setPrivacyLevel(level);
      if (result.success) {
        setPrivacyLevelState(level);
      }
    } catch (err) {
      setError((err as Error).message);
    }
  }, []);

  const setMode = useCallback(async (newMode: NodeMode) => {
    try {
      const result = await window.electronAPI.setMode(newMode);
      if (result.success) {
        setModeState(newMode);
      }
    } catch (err) {
      setError((err as Error).message);
    }
  }, []);

  const purchaseCredits = useCallback(async (amount: number) => {
    try {
      const result = await window.electronAPI.purchaseCredits(amount);
      if (result.success && result.balance !== undefined) {
        setCreditsState(result.balance);
      }
    } catch (err) {
      setError((err as Error).message);
    }
  }, []);

  const setExitNode = useCallback((node: ExitNode) => {
    setExitNodeState(node);
    // Wire through to daemon
    window.electronAPI.setExitNode(node.region, node.countryCode, node.city).catch((err) => {
      setError((err as Error).message);
    });
  }, []);

  // Fetch node stats and credits periodically when connected
  useEffect(() => {
    const fetchNodeData = async () => {
      try {
        const [statsResult, creditsResult] = await Promise.all([
          window.electronAPI.getNodeStats(),
          window.electronAPI.getCredits(),
        ]);
        if (statsResult.success && statsResult.stats) {
          setNodeStats(statsResult.stats as NodeStats);
        }
        if (creditsResult.success && creditsResult.credits !== undefined) {
          setCreditsState(creditsResult.credits);
        }
      } catch {
        // Ignore fetch errors during polling
      }
    };

    if (status.state === 'connected') {
      fetchNodeData();
      nodeStatsIntervalRef.current = setInterval(fetchNodeData, 5000);
    } else {
      if (nodeStatsIntervalRef.current) {
        clearInterval(nodeStatsIntervalRef.current);
        nodeStatsIntervalRef.current = null;
      }
      setNodeStats(null);
    }

    return () => {
      if (nodeStatsIntervalRef.current) {
        clearInterval(nodeStatsIntervalRef.current);
      }
    };
  }, [status.state]);

  const value: VPNContextType = {
    status,
    stats,
    nodeStats,
    privacyLevel,
    mode,
    credits,
    isLoading,
    error,
    exitNode,
    availableExits,
    setExitNode,
    connect,
    disconnect,
    toggle,
    setPrivacyLevel,
    setMode,
    purchaseCredits,
  };

  return <VPNContext.Provider value={value}>{children}</VPNContext.Provider>;
};
