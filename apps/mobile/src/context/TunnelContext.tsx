/**
 * TunnelCraft Context
 *
 * Global state management for the VPN/Node functionality
 */

import React, { createContext, useContext, useState, useEffect, useCallback, ReactNode } from 'react';
import { NodeMode } from '../theme/colors';

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
  request: (method: string, url: string, body?: string) => Promise<{ status: number; body: string }>;
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

// Mock available exit nodes (in real app, fetched from network)
const mockAvailableExits: AvailableExit[] = [
  { id: '1', countryCode: 'US', countryName: 'United States', city: 'New York', region: 'na', latencyMs: 45, reputation: 98 },
  { id: '2', countryCode: 'US', countryName: 'United States', city: 'Los Angeles', region: 'na', latencyMs: 62, reputation: 95 },
  { id: '3', countryCode: 'US', countryName: 'United States', city: 'Miami', region: 'na', latencyMs: 55, reputation: 92 },
  { id: '4', countryCode: 'CA', countryName: 'Canada', city: 'Toronto', region: 'na', latencyMs: 58, reputation: 94 },
  { id: '5', countryCode: 'CA', countryName: 'Canada', city: 'Vancouver', region: 'na', latencyMs: 72, reputation: 91 },
  { id: '6', countryCode: 'DE', countryName: 'Germany', city: 'Frankfurt', region: 'eu', latencyMs: 120, reputation: 99 },
  { id: '7', countryCode: 'DE', countryName: 'Germany', city: 'Berlin', region: 'eu', latencyMs: 125, reputation: 96 },
  { id: '8', countryCode: 'NL', countryName: 'Netherlands', city: 'Amsterdam', region: 'eu', latencyMs: 115, reputation: 97 },
  { id: '9', countryCode: 'GB', countryName: 'United Kingdom', city: 'London', region: 'eu', latencyMs: 110, reputation: 98 },
  { id: '10', countryCode: 'FR', countryName: 'France', city: 'Paris', region: 'eu', latencyMs: 118, reputation: 95 },
  { id: '11', countryCode: 'CH', countryName: 'Switzerland', city: 'Zurich', region: 'eu', latencyMs: 122, reputation: 99 },
  { id: '12', countryCode: 'JP', countryName: 'Japan', city: 'Tokyo', region: 'ap', latencyMs: 180, reputation: 97 },
  { id: '13', countryCode: 'SG', countryName: 'Singapore', city: 'Singapore', region: 'ap', latencyMs: 165, reputation: 98 },
  { id: '14', countryCode: 'KR', countryName: 'South Korea', city: 'Seoul', region: 'ap', latencyMs: 175, reputation: 94 },
  { id: '15', countryCode: 'AU', countryName: 'Australia', city: 'Sydney', region: 'oc', latencyMs: 210, reputation: 96 },
  { id: '16', countryCode: 'AU', countryName: 'Australia', city: 'Melbourne', region: 'oc', latencyMs: 215, reputation: 93 },
  { id: '17', countryCode: 'BR', countryName: 'Brazil', city: 'Sao Paulo', region: 'sa', latencyMs: 145, reputation: 91 },
  { id: '18', countryCode: 'AE', countryName: 'UAE', city: 'Dubai', region: 'me', latencyMs: 155, reputation: 95 },
  { id: '19', countryCode: 'IL', countryName: 'Israel', city: 'Tel Aviv', region: 'me', latencyMs: 140, reputation: 94 },
  { id: '20', countryCode: 'ZA', countryName: 'South Africa', city: 'Johannesburg', region: 'af', latencyMs: 195, reputation: 89 },
];

export function TunnelProvider({ children }: TunnelProviderProps) {
  const [connectionState, setConnectionState] = useState<ConnectionState>('disconnected');
  const [mode, setModeState] = useState<NodeMode>('both');
  const [privacyLevel, setPrivacyLevelState] = useState<PrivacyLevel>('standard');
  const [exitSelection, setExitSelectionState] = useState<ExitSelection>({ type: 'region', region: 'auto' });
  const [availableExits] = useState<AvailableExit[]>(mockAvailableExits);
  const [detectedLocation, setDetectedLocation] = useState<DetectedLocation | null>(null);
  const [isDetectingLocation, setIsDetectingLocation] = useState(false);
  const [stats, setStats] = useState<NodeStats>(defaultStats);
  const [credits, setCredits] = useState(1000); // Demo credits

  const isConnected = connectionState === 'connected';

  // Auto-detect location when in Node/Both mode
  useEffect(() => {
    if ((mode === 'node' || mode === 'both') && !detectedLocation && !isDetectingLocation) {
      detectLocation();
    }
  }, [mode]);

  const detectLocation = useCallback(async () => {
    setIsDetectingLocation(true);
    try {
      // Use ip-api.com for geo-detection (free tier, no API key needed)
      // Include ISP and org fields for service provider detection
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
      console.warn('Failed to detect location:', error);
      // Use fallback
      setDetectedLocation({
        region: 'auto',
        countryCode: 'XX',
        countryName: 'Unknown',
      });
    } finally {
      setIsDetectingLocation(false);
    }
  }, []);

  // Map country code to region
  const mapCountryToRegion = (countryCode: string): ExitRegion => {
    const regionMap: Record<string, ExitRegion> = {
      // North America
      US: 'na', CA: 'na', MX: 'na',
      // Europe
      GB: 'eu', DE: 'eu', FR: 'eu', IT: 'eu', ES: 'eu', NL: 'eu', BE: 'eu',
      AT: 'eu', CH: 'eu', SE: 'eu', NO: 'eu', DK: 'eu', FI: 'eu', PL: 'eu',
      // Asia Pacific
      JP: 'ap', KR: 'ap', CN: 'ap', HK: 'ap', TW: 'ap', SG: 'ap', MY: 'ap',
      TH: 'ap', VN: 'ap', PH: 'ap', ID: 'ap', IN: 'ap',
      // Oceania
      AU: 'oc', NZ: 'oc',
      // South America
      BR: 'sa', AR: 'sa', CL: 'sa', CO: 'sa', PE: 'sa',
      // Middle East
      AE: 'me', SA: 'me', IL: 'me', TR: 'me', QA: 'me',
      // Africa
      ZA: 'af', EG: 'af', NG: 'af', KE: 'af', MA: 'af',
    };
    return regionMap[countryCode] || 'auto';
  };

  // Simulate stats updates when connected
  useEffect(() => {
    if (!isConnected) return;

    const interval = setInterval(() => {
      setStats((prev) => {
        const isClient = mode === 'client' || mode === 'both';
        const isNode = mode === 'node' || mode === 'both';

        return {
          ...prev,
          uptimeSecs: prev.uptimeSecs + 1,
          bytesSent: isClient ? prev.bytesSent + Math.floor(Math.random() * 5000) : prev.bytesSent,
          bytesReceived: isClient ? prev.bytesReceived + Math.floor(Math.random() * 15000) : prev.bytesReceived,
          shardsRelayed: isNode ? prev.shardsRelayed + Math.floor(Math.random() * 3) : prev.shardsRelayed,
          requestsExited: isNode && Math.random() > 0.7 ? prev.requestsExited + 1 : prev.requestsExited,
          creditsEarned: isNode ? prev.creditsEarned + Math.floor(Math.random() * 2) : prev.creditsEarned,
          creditsSpent: isClient ? prev.creditsSpent + Math.floor(Math.random() * 1) : prev.creditsSpent,
          connectedPeers: Math.max(3, Math.min(25, prev.connectedPeers + Math.floor(Math.random() * 3) - 1)),
        };
      });
    }, 1000);

    return () => clearInterval(interval);
  }, [isConnected, mode]);

  const connect = useCallback(async () => {
    setConnectionState('connecting');
    // Simulate connection delay
    await new Promise<void>((resolve) => setTimeout(resolve, 1500));
    setConnectionState('connected');
    setStats((prev) => ({ ...prev, connectedPeers: 8 }));
  }, []);

  const disconnect = useCallback(async () => {
    setConnectionState('disconnecting');
    await new Promise<void>((resolve) => setTimeout(resolve, 500));
    setConnectionState('disconnected');
    setStats(defaultStats);
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
    // In real app, would call: TunnelCraftUnifiedNode.setMode(newMode)
  }, []);

  const setPrivacyLevel = useCallback((level: PrivacyLevel) => {
    setPrivacyLevelState(level);
    // In real app, would call: TunnelCraftUnifiedNode.setPrivacyLevel(level)
  }, []);

  const setExitSelection = useCallback((selection: ExitSelection) => {
    setExitSelectionState(selection);
    // In real app, would call: TunnelCraftUnifiedNode.setExitSelection(selection)
  }, []);

  const purchaseCredits = useCallback(async (amount: number) => {
    setCredits((prev) => prev + amount);
  }, []);

  const request = useCallback(async (method: string, url: string, body?: string): Promise<{ status: number; body: string }> => {
    // Mock: simulate a network delay and return a fake response
    await new Promise<void>((resolve) => setTimeout(resolve, 800));
    return {
      status: 200,
      body: JSON.stringify({ mock: true, method, url, message: 'Mock response from TunnelCraft' }),
    };
  }, []);

  // Calculate net credits
  useEffect(() => {
    setCredits((prev) => prev + stats.creditsEarned - stats.creditsSpent);
  }, [stats.creditsEarned, stats.creditsSpent]);

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
