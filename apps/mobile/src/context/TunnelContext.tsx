/**
 * TunnelCraft Context
 *
 * Global state management for the VPN/Node functionality.
 * Wired through to native bridge (TunnelCraftVPN) for real operations.
 */

import React, { createContext, useContext, useState, useEffect, useCallback, useRef, ReactNode } from 'react';
import { NodeMode } from '../theme/colors';
import { TunnelCraftVPN } from '../native/TunnelCraftVPN';
import { LogService } from '../services/LogService';

// Types matching the Rust UniFFI bindings
export type PrivacyLevel = 'direct' | 'light' | 'standard' | 'paranoid';

export type ExitRegion = 'auto' | 'na' | 'eu' | 'ap' | 'sa' | 'af' | 'me' | 'oc';

// Exit selection can be region (flexible) or country (strict)
export type ExitSelectionType = 'region' | 'country';

export interface ExitSelection {
  type: ExitSelectionType;
  region: ExitRegion;
  countryCode?: string; // Only set when type === 'country'
}

// Available exit node info
export interface AvailableExit {
  id: string;
  countryCode: string;
  countryName: string;
  city?: string;
  region: ExitRegion;
  latencyMs: number;
  reputation: number;
}

export type ConnectionState = 'disconnected' | 'connecting' | 'connected' | 'disconnecting' | 'error';

export interface NodeStats {
  bytesSent: number;
  bytesReceived: number;
  shardsRelayed: number;
  requestsExited: number;
  creditsEarned: number;
  creditsSpent: number;
  connectedPeers: number;
  uptimeSecs: number;
}

// Detected node location (for Node/Both mode announcement)
export interface DetectedLocation {
  region: ExitRegion;
  countryCode: string;
  countryName: string;
  city?: string;
  isp?: string;
  org?: string;
}

export interface TunnelContextType {
  // Connection state
  connectionState: ConnectionState;
  isConnected: boolean;

  // Mode
  mode: NodeMode;
  setMode: (mode: NodeMode) => void;

  // Privacy
  privacyLevel: PrivacyLevel;
  setPrivacyLevel: (level: PrivacyLevel) => void;

  // Exit Selection (Client mode - region or country)
  exitSelection: ExitSelection;
  setExitSelection: (selection: ExitSelection) => void;

  // Available exit nodes
  availableExits: AvailableExit[];

  // Detected Location (Node mode - auto-detected)
  detectedLocation: DetectedLocation | null;
  isDetectingLocation: boolean;

  // Stats
  stats: NodeStats;

  // Actions
  connect: () => Promise<void>;
  disconnect: () => Promise<void>;
  toggleConnection: () => Promise<void>;

  // Credits
  credits: number;
  purchaseCredits: (amount: number) => Promise<void>;

  // HTTP Request
  request: (method: string, url: string, body?: string, headers?: Record<string, string>) => Promise<{ status: number; body: string }>;
}

const defaultStats: NodeStats = {
  bytesSent: 0,
  bytesReceived: 0,
  shardsRelayed: 0,
  requestsExited: 0,
  creditsEarned: 0,
  creditsSpent: 0,
  connectedPeers: 0,
  uptimeSecs: 0,
};

export const TunnelContext = createContext<TunnelContextType | undefined>(undefined);

interface TunnelProviderProps {
  children: ReactNode;
}

// Fallback exit nodes (shown until real discovery populates)
const fallbackExits: AvailableExit[] = [
  { id: '1', countryCode: 'US', countryName: 'United States', city: 'New York', region: 'na', latencyMs: 45, reputation: 98 },
  { id: '2', countryCode: 'DE', countryName: 'Germany', city: 'Frankfurt', region: 'eu', latencyMs: 120, reputation: 99 },
  { id: '3', countryCode: 'NL', countryName: 'Netherlands', city: 'Amsterdam', region: 'eu', latencyMs: 115, reputation: 97 },
  { id: '4', countryCode: 'JP', countryName: 'Japan', city: 'Tokyo', region: 'ap', latencyMs: 180, reputation: 97 },
  { id: '5', countryCode: 'SG', countryName: 'Singapore', city: 'Singapore', region: 'ap', latencyMs: 165, reputation: 98 },
  { id: '6', countryCode: 'GB', countryName: 'United Kingdom', city: 'London', region: 'eu', latencyMs: 110, reputation: 98 },
  { id: '7', countryCode: 'CH', countryName: 'Switzerland', city: 'Zurich', region: 'eu', latencyMs: 122, reputation: 99 },
  { id: '8', countryCode: 'AU', countryName: 'Australia', city: 'Sydney', region: 'oc', latencyMs: 210, reputation: 96 },
];

export function TunnelProvider({ children }: TunnelProviderProps) {
  const [connectionState, setConnectionState] = useState<ConnectionState>('disconnected');
  const [mode, setModeState] = useState<NodeMode>('both');
  const [privacyLevel, setPrivacyLevelState] = useState<PrivacyLevel>('standard');
  const [exitSelection, setExitSelectionState] = useState<ExitSelection>({ type: 'region', region: 'auto' });
  const [availableExits] = useState<AvailableExit[]>(fallbackExits);
  const [detectedLocation, setDetectedLocation] = useState<DetectedLocation | null>(null);
  const [isDetectingLocation, setIsDetectingLocation] = useState(false);
  const [stats, setStats] = useState<NodeStats>(defaultStats);
  const [credits, setCredits] = useState(0);
  const uptimeRef = useRef(0);
  const uptimeIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const isConnected = connectionState === 'connected';

  // Subscribe to native event listeners
  useEffect(() => {
    const unsubState = TunnelCraftVPN.onStateChange((state) => {
      setConnectionState(state as ConnectionState);
    });

    const unsubError = TunnelCraftVPN.onError((error) => {
      LogService.error('TunnelContext', 'VPN error: ' + error);
      setConnectionState('error');
    });

    const unsubStats = TunnelCraftVPN.onStatsUpdate((nativeStats) => {
      setStats((prev) => ({
        ...prev,
        bytesSent: nativeStats.bytesSent ?? prev.bytesSent,
        bytesReceived: nativeStats.bytesReceived ?? prev.bytesReceived,
      }));
    });

    // Fetch initial status
    TunnelCraftVPN.getStatus().then((status) => {
      setConnectionState(status.state as ConnectionState);
      if (status.credits) setCredits(status.credits);
    }).catch(() => {
      // Native module may not be available in dev/simulator
    });

    return () => {
      unsubState();
      unsubError();
      unsubStats();
    };
  }, []);

  // Poll node stats when connected
  useEffect(() => {
    if (!isConnected) {
      if (uptimeIntervalRef.current) {
        clearInterval(uptimeIntervalRef.current);
        uptimeIntervalRef.current = null;
      }
      return;
    }

    uptimeRef.current = 0;

    const pollStats = async () => {
      try {
        const nodeStats = await TunnelCraftVPN.getStats();
        uptimeRef.current += 5;
        setStats({
          bytesSent: nodeStats.bytesSent ?? 0,
          bytesReceived: nodeStats.bytesReceived ?? 0,
          shardsRelayed: nodeStats.shardsRelayed ?? 0,
          requestsExited: nodeStats.requestsExited ?? 0,
          creditsEarned: nodeStats.creditsEarned ?? 0,
          creditsSpent: nodeStats.creditsSpent ?? 0,
          connectedPeers: nodeStats.peersConnected ?? 0,
          uptimeSecs: uptimeRef.current,
        });
      } catch {
        // Stats polling can fail if native module not ready
        uptimeRef.current += 5;
        setStats((prev) => ({ ...prev, uptimeSecs: uptimeRef.current }));
      }
    };

    pollStats();
    uptimeIntervalRef.current = setInterval(pollStats, 5000);

    return () => {
      if (uptimeIntervalRef.current) {
        clearInterval(uptimeIntervalRef.current);
      }
    };
  }, [isConnected]);

  // Auto-detect location when in Node/Both mode
  useEffect(() => {
    if ((mode === 'node' || mode === 'both') && !detectedLocation && !isDetectingLocation) {
      detectLocation();
    }
  }, [mode]);

  const detectLocation = useCallback(async () => {
    setIsDetectingLocation(true);
    try {
      const response = await fetch('http://ip-api.com/json/?fields=status,country,countryCode,regionName,city,isp,org,as,lat,lon');
      const data = await response.json();

      if (data.status === 'success') {
        const region = mapCountryToRegion(data.countryCode);
        setDetectedLocation({
          region,
          countryCode: data.countryCode,
          countryName: data.country,
          city: data.city,
          isp: data.isp,
          org: data.org,
        });
      }
    } catch (error) {
      LogService.warn('TunnelContext', 'Failed to detect location: ' + error);
      setDetectedLocation({
        region: 'auto',
        countryCode: 'XX',
        countryName: 'Unknown',
      });
    } finally {
      setIsDetectingLocation(false);
    }
  }, []);

  const mapCountryToRegion = (countryCode: string): ExitRegion => {
    const regionMap: Record<string, ExitRegion> = {
      US: 'na', CA: 'na', MX: 'na',
      GB: 'eu', DE: 'eu', FR: 'eu', IT: 'eu', ES: 'eu', NL: 'eu', BE: 'eu',
      AT: 'eu', CH: 'eu', SE: 'eu', NO: 'eu', DK: 'eu', FI: 'eu', PL: 'eu',
      JP: 'ap', KR: 'ap', CN: 'ap', HK: 'ap', TW: 'ap', SG: 'ap', MY: 'ap',
      TH: 'ap', VN: 'ap', PH: 'ap', ID: 'ap', IN: 'ap',
      AU: 'oc', NZ: 'oc',
      BR: 'sa', AR: 'sa', CL: 'sa', CO: 'sa', PE: 'sa',
      AE: 'me', SA: 'me', IL: 'me', TR: 'me', QA: 'me',
      ZA: 'af', EG: 'af', NG: 'af', KE: 'af', MA: 'af',
    };
    return regionMap[countryCode] || 'auto';
  };

  const connect = useCallback(async () => {
    setConnectionState('connecting');
    try {
      await TunnelCraftVPN.connect({ privacyLevel });
      setConnectionState('connected');
    } catch (error) {
      LogService.error('TunnelContext', 'Connect failed: ' + error);
      setConnectionState('error');
    }
  }, [privacyLevel]);

  const disconnect = useCallback(async () => {
    setConnectionState('disconnecting');
    try {
      await TunnelCraftVPN.disconnect();
      setConnectionState('disconnected');
      setStats(defaultStats);
    } catch (error) {
      LogService.error('TunnelContext', 'Disconnect failed: ' + error);
      setConnectionState('error');
    }
  }, []);

  const toggleConnection = useCallback(async () => {
    if (isConnected) {
      await disconnect();
    } else {
      await connect();
    }
  }, [isConnected, connect, disconnect]);

  const setMode = useCallback((newMode: NodeMode) => {
    setModeState(newMode);
    TunnelCraftVPN.setMode(newMode).catch((err) => {
      LogService.error('TunnelContext', 'setMode failed: ' + err);
    });
  }, []);

  const setPrivacyLevel = useCallback((level: PrivacyLevel) => {
    setPrivacyLevelState(level);
    TunnelCraftVPN.setPrivacyLevel(level).catch((err) => {
      LogService.error('TunnelContext', 'setPrivacyLevel failed: ' + err);
    });
  }, []);

  const setExitSelection = useCallback((selection: ExitSelection) => {
    setExitSelectionState(selection);
    const region = selection.region === 'auto' ? 'auto' : selection.region;
    TunnelCraftVPN.selectExit(
      region,
      selection.countryCode,
      undefined,
    ).catch((err) => {
      LogService.error('TunnelContext', 'selectExit failed: ' + err);
    });
  }, []);

  const purchaseCredits = useCallback(async (amount: number) => {
    try {
      const result = await TunnelCraftVPN.purchaseCredits(amount);
      setCredits(result.balance);
    } catch (error) {
      LogService.error('TunnelContext', 'purchaseCredits failed: ' + error);
    }
  }, []);

  const request = useCallback(async (method: string, url: string, body?: string, headers?: Record<string, string>): Promise<{ status: number; body: string }> => {
    return TunnelCraftVPN.request(method, url, body, headers);
  }, []);

  const value: TunnelContextType = {
    connectionState,
    isConnected,
    mode,
    setMode,
    privacyLevel,
    setPrivacyLevel,
    exitSelection,
    setExitSelection,
    availableExits,
    detectedLocation,
    isDetectingLocation,
    stats,
    connect,
    disconnect,
    toggleConnection,
    credits,
    purchaseCredits,
    request,
  };

  return <TunnelContext.Provider value={value}>{children}</TunnelContext.Provider>;
}

export function useTunnel() {
  const context = useContext(TunnelContext);
  if (!context) {
    throw new Error('useTunnel must be used within a TunnelProvider');
  }
  return context;
}
