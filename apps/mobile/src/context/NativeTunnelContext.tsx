/**
 * Native-Bridged TunnelCraft Context
 *
 * This context connects the React Native UI to the native VPN modules.
 * It replaces the mock implementation with real native calls.
 */

import React, {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  useRef,
  ReactNode,
} from 'react';
import { Platform, AppState, AppStateStatus } from 'react-native';
import TunnelCraftVPN, {
  ConnectionState,
  PrivacyLevel,
  VPNStatus,
  NetworkStats,
  VPNConfig,
} from '../native/TunnelCraftVPN';
import { NodeMode } from '../theme/colors';
import { TunnelContext, TunnelContextType, AvailableExit } from './TunnelContext';
import { LogService } from '../services/LogService';

// Re-export types
export type { ConnectionState, PrivacyLevel };
export type ExitRegion = 'auto' | 'na' | 'eu' | 'ap' | 'sa' | 'af' | 'me' | 'oc';
export type ExitSelectionType = 'region' | 'country';

export interface ExitSelection {
  type: ExitSelectionType;
  region: ExitRegion;
  countryCode?: string;
}

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

export interface DetectedLocation {
  region: ExitRegion;
  countryCode: string;
  countryName: string;
  city?: string;
  isp?: string;
  org?: string;
}

interface NativeTunnelContextType {
  // Connection state
  connectionState: ConnectionState;
  isConnected: boolean;
  isConnecting: boolean;
  errorMessage: string | null;

  // Mode
  mode: NodeMode;
  setMode: (mode: NodeMode) => void;

  // Privacy
  privacyLevel: PrivacyLevel;
  setPrivacyLevel: (level: PrivacyLevel) => Promise<void>;

  // Exit Selection
  exitSelection: ExitSelection;
  setExitSelection: (selection: ExitSelection) => void;

  // Detected Location (Node mode)
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
  setCredits: (credits: number) => Promise<void>;
  purchaseCredits: (amount: number) => Promise<void>;

  // HTTP Request
  request: (method: string, url: string, body?: string, headers?: Record<string, string>) => Promise<{ status: number; body: string }>;

  // Status
  refreshStatus: () => Promise<void>;
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

const NativeTunnelContext = createContext<NativeTunnelContextType | undefined>(undefined);

interface NativeTunnelProviderProps {
  children: ReactNode;
}

export function NativeTunnelProvider({ children }: NativeTunnelProviderProps) {
  const [connectionState, setConnectionState] = useState<ConnectionState>('disconnected');
  const [errorMessage, setErrorMessage] = useState<string | null>(null);
  const [mode, setModeState] = useState<NodeMode>('both');
  const [privacyLevel, setPrivacyLevelState] = useState<PrivacyLevel>('standard');
  const [exitSelection, setExitSelectionState] = useState<ExitSelection>({ type: 'region', region: 'auto' });
  const [detectedLocation, setDetectedLocation] = useState<DetectedLocation | null>(null);
  const [isDetectingLocation, setIsDetectingLocation] = useState(false);
  const [stats, setStats] = useState<NodeStats>(defaultStats);
  const [credits, setCreditsState] = useState(1000);
  const [availableExits, setAvailableExits] = useState<AvailableExit[]>([
    { id: '1', countryCode: 'US', countryName: 'United States', city: 'New York', region: 'na', latencyMs: 45, reputation: 98 },
    { id: '2', countryCode: 'DE', countryName: 'Germany', city: 'Frankfurt', region: 'eu', latencyMs: 120, reputation: 99 },
    { id: '3', countryCode: 'NL', countryName: 'Netherlands', city: 'Amsterdam', region: 'eu', latencyMs: 115, reputation: 97 },
    { id: '4', countryCode: 'JP', countryName: 'Japan', city: 'Tokyo', region: 'ap', latencyMs: 180, reputation: 97 },
    { id: '5', countryCode: 'SG', countryName: 'Singapore', city: 'Singapore', region: 'ap', latencyMs: 165, reputation: 98 },
    { id: '6', countryCode: 'GB', countryName: 'United Kingdom', city: 'London', region: 'eu', latencyMs: 110, reputation: 98 },
    { id: '7', countryCode: 'CH', countryName: 'Switzerland', city: 'Zurich', region: 'eu', latencyMs: 122, reputation: 99 },
    { id: '8', countryCode: 'AU', countryName: 'Australia', city: 'Sydney', region: 'oc', latencyMs: 210, reputation: 96 },
  ]);

  const appState = useRef(AppState.currentState);
  const statsIntervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const isConnected = connectionState === 'connected';
  const isConnecting = connectionState === 'connecting';

  // Subscribe to native events
  useEffect(() => {
    const unsubscribeState = TunnelCraftVPN.onStateChange((state) => {
      LogService.info('NativeTunnelContext', 'State changed: ' + state);
      setConnectionState(state);

      if (state === 'error') {
        setErrorMessage('Connection error occurred');
      } else {
        setErrorMessage(null);
      }
    });

    const unsubscribeError = TunnelCraftVPN.onError((error) => {
      LogService.error('NativeTunnelContext', 'Error: ' + error);
      setErrorMessage(error);
    });

    const unsubscribeStats = TunnelCraftVPN.onStatsUpdate((nativeStats: Record<string, number>) => {
      setStats(prev => ({
        ...prev,
        bytesSent: nativeStats.bytesSent ?? prev.bytesSent,
        bytesReceived: nativeStats.bytesReceived ?? prev.bytesReceived,
        uptimeSecs: nativeStats.uptimeSecs ?? prev.uptimeSecs,
        shardsRelayed: nativeStats.shardsRelayed ?? prev.shardsRelayed,
        requestsExited: nativeStats.requestsExited ?? prev.requestsExited,
        creditsEarned: nativeStats.creditsEarned ?? prev.creditsEarned,
        creditsSpent: nativeStats.creditsSpent ?? prev.creditsSpent,
        connectedPeers: nativeStats.connectedPeers ?? prev.connectedPeers,
      }));
    });

    return () => {
      unsubscribeState();
      unsubscribeError();
      unsubscribeStats();
    };
  }, []);

  // Handle app state changes (background/foreground)
  useEffect(() => {
    const subscription = AppState.addEventListener('change', (nextAppState: AppStateStatus) => {
      if (appState.current.match(/inactive|background/) && nextAppState === 'active') {
        // App came to foreground - refresh status
        refreshStatus();
      }
      appState.current = nextAppState;
    });

    return () => {
      subscription.remove();
    };
  }, []);

  // Periodic status refresh when connected
  useEffect(() => {
    if (isConnected) {
      statsIntervalRef.current = setInterval(() => {
        refreshStatus();
      }, 5000);
    } else {
      if (statsIntervalRef.current) {
        clearInterval(statsIntervalRef.current);
        statsIntervalRef.current = null;
      }
    }

    return () => {
      if (statsIntervalRef.current) {
        clearInterval(statsIntervalRef.current);
      }
    };
  }, [isConnected]);

  // Detect location for node mode
  useEffect(() => {
    if ((mode === 'node' || mode === 'both') && !detectedLocation && !isDetectingLocation) {
      detectLocation();
    }
  }, [mode, detectedLocation, isDetectingLocation]);

  const detectLocation = useCallback(async () => {
    setIsDetectingLocation(true);
    try {
      const response = await fetch('http://ip-api.com/json/?fields=status,country,countryCode,city,isp,org');
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
      LogService.warn('NativeTunnelContext', 'Failed to detect location: ' + error);
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
      GB: 'eu', DE: 'eu', FR: 'eu', IT: 'eu', ES: 'eu', NL: 'eu',
      JP: 'ap', KR: 'ap', CN: 'ap', SG: 'ap', MY: 'ap',
      AU: 'oc', NZ: 'oc',
      BR: 'sa', AR: 'sa', CL: 'sa',
      AE: 'me', SA: 'me', IL: 'me',
      ZA: 'af', EG: 'af', NG: 'af',
    };
    return regionMap[countryCode] || 'auto';
  };

  const refreshStatus = useCallback(async () => {
    try {
      const status = await TunnelCraftVPN.getStatus();
      setConnectionState(status.state);
      setCreditsState(status.credits);
      
      if (status.errorMessage) {
        setErrorMessage(status.errorMessage);
      }
    } catch (error) {
      LogService.warn('NativeTunnelContext', 'Failed to refresh status: ' + error);
    }
  }, []);

  const connect = useCallback(async () => {
    try {
      setConnectionState('connecting');
      setErrorMessage(null);

      const config: Partial<VPNConfig> = {
        privacyLevel,
      };

      await TunnelCraftVPN.connect(config);

      // Status will be updated via event listener
    } catch (error) {
      LogService.error('NativeTunnelContext', 'Connect failed: ' + error);
      setConnectionState('error');
      setErrorMessage(error instanceof Error ? error.message : 'Connection failed');
    }
  }, [privacyLevel]);

  const disconnect = useCallback(async () => {
    try {
      setConnectionState('disconnecting');
      await TunnelCraftVPN.disconnect();
      setStats(defaultStats);
    } catch (error) {
      LogService.error('NativeTunnelContext', 'Disconnect failed: ' + error);
      setErrorMessage(error instanceof Error ? error.message : 'Disconnect failed');
    }
  }, []);

  const toggleConnection = useCallback(async () => {
    if (isConnected || isConnecting) {
      await disconnect();
    } else {
      await connect();
    }
  }, [isConnected, isConnecting, connect, disconnect]);

  const setMode = useCallback(async (newMode: NodeMode) => {
    setModeState(newMode);
    try {
      await TunnelCraftVPN.setMode(newMode);
    } catch (error) {
      LogService.error('NativeTunnelContext', 'Failed to set mode: ' + error);
    }
  }, []);

  const setPrivacyLevel = useCallback(async (level: PrivacyLevel) => {
    setPrivacyLevelState(level);

    if (isConnected) {
      try {
        await TunnelCraftVPN.setPrivacyLevel(level);
      } catch (error) {
        LogService.error('NativeTunnelContext', 'Failed to set privacy level: ' + error);
      }
    }
  }, [isConnected]);

  const setExitSelection = useCallback((selection: ExitSelection) => {
    setExitSelectionState(selection);
    const region = selection.region === 'auto' ? 'auto' : selection.region;
    TunnelCraftVPN.selectExit(
      region,
      selection.countryCode,
      undefined,
    ).catch((error) => {
      LogService.error('NativeTunnelContext', 'Failed to set exit selection: ' + error);
    });
  }, []);

  const setCredits = useCallback(async (newCredits: number) => {
    setCreditsState(newCredits);
    try {
      await TunnelCraftVPN.setCredits(newCredits);
    } catch (error) {
      LogService.error('NativeTunnelContext', 'Failed to set credits: ' + error);
    }
  }, []);

  const purchaseCredits = useCallback(async (amount: number) => {
    try {
      const result = await TunnelCraftVPN.purchaseCredits(amount);
      setCreditsState(result.balance);
    } catch (error) {
      LogService.error('NativeTunnelContext', 'Failed to purchase credits: ' + error);
      setErrorMessage(error instanceof Error ? error.message : 'Purchase failed');
    }
  }, []);

  const request = useCallback(async (method: string, url: string, body?: string, headers?: Record<string, string>): Promise<{ status: number; body: string }> => {
    try {
      return await TunnelCraftVPN.request(method, url, body, headers);
    } catch (error) {
      LogService.error('NativeTunnelContext', 'Request failed: ' + error);
      return { status: 0, body: error instanceof Error ? error.message : 'Request failed' };
    }
  }, []);

  const value: NativeTunnelContextType = {
    connectionState,
    isConnected,
    isConnecting,
    errorMessage,
    mode,
    setMode,
    privacyLevel,
    setPrivacyLevel,
    exitSelection,
    setExitSelection,
    detectedLocation,
    isDetectingLocation,
    stats,
    connect,
    disconnect,
    toggleConnection,
    credits,
    setCredits,
    purchaseCredits,
    request,
    refreshStatus,
  };

  // Map native context to TunnelContextType for useTunnel() compatibility
  const tunnelContextValue: TunnelContextType = {
    connectionState,
    isConnected,
    mode,
    setMode,
    privacyLevel,
    setPrivacyLevel,
    exitSelection,
    setExitSelection,
    availableExits: availableExits,
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

  return (
    <NativeTunnelContext.Provider value={value}>
      <TunnelContext.Provider value={tunnelContextValue}>
        {children}
      </TunnelContext.Provider>
    </NativeTunnelContext.Provider>
  );
}

export function useNativeTunnel() {
  const context = useContext(NativeTunnelContext);
  if (!context) {
    throw new Error('useNativeTunnel must be used within a NativeTunnelProvider');
  }
  return context;
}

export default NativeTunnelContext;
