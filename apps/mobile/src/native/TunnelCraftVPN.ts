import {NativeModules, NativeEventEmitter, Platform} from 'react-native';

type NodeMode = 'client' | 'node' | 'both';

// Native module interface
interface TunnelCraftVPNModule {
  // Connection
  connect(config: VPNConfig): Promise<void>;
  disconnect(): Promise<void>;

  // Status
  getStatus(): Promise<VPNStatus>;
  isConnected(): Promise<boolean>;

  // Configuration
  setPrivacyLevel(level: PrivacyLevel): Promise<void>;
  setCredits(credits: number): Promise<void>;
  setMode(mode: string): Promise<void>;
  purchaseCredits(amount: number): Promise<{ balance: number }>;

  // HTTP Request
  request(params: { method: string; url: string; body?: string; headers?: Record<string, string> }): Promise<{ status: number; body: string }>;

  // Exit Node Selection
  selectExit(params: { region: string; countryCode?: string; city?: string }): Promise<void>;

  // Stats
  getStats(): Promise<NodeStats>;

  // Constants
  getConstants(): {
    STATE_DISCONNECTED: string;
    STATE_CONNECTING: string;
    STATE_CONNECTED: string;
    STATE_DISCONNECTING: string;
    STATE_ERROR: string;
  };
}

// Types
export type ConnectionState =
  | 'disconnected'
  | 'connecting'
  | 'connected'
  | 'disconnecting'
  | 'error';

export type PrivacyLevel = 'direct' | 'light' | 'standard' | 'paranoid';

export interface VPNConfig {
  privacyLevel: PrivacyLevel;
  bootstrapPeer?: string;
  requestTimeoutSecs?: number;
}

export interface VPNStatus {
  state: ConnectionState;
  peerId: string;
  connectedPeers: number;
  credits: number;
  exitNode?: string;
  errorMessage?: string;
}

export interface NetworkStats {
  bytesSent: number;
  bytesReceived: number;
  requestsMade: number;
  requestsCompleted: number;
  uptimeSecs: number;
}

export interface NodeStats {
  shardsRelayed: number;
  requestsExited: number;
  peersConnected: number;
  creditsEarned: number;
  creditsSpent: number;
  bytesSent: number;
  bytesReceived: number;
  bytesRelayed: number;
}

// Get the native module
const {TunnelCraftVPN: NativeVPN} = NativeModules as {
  TunnelCraftVPN: TunnelCraftVPNModule;
};

if (!NativeVPN) {
  console.error(
    'TunnelCraftVPN native module not found. Make sure you have linked the native code.',
  );
}

// Event emitter for status updates
const vpnEventEmitter = NativeVPN
  ? new NativeEventEmitter(NativeModules.TunnelCraftVPN)
  : null;

// VPN API
export const TunnelCraftVPN = {
  /**
   * Connect to the VPN network
   */
  async connect(config: Partial<VPNConfig> = {}): Promise<void> {
    const fullConfig: VPNConfig = {
      privacyLevel: config.privacyLevel ?? 'standard',
      bootstrapPeer: config.bootstrapPeer,
      requestTimeoutSecs: config.requestTimeoutSecs ?? 30,
    };
    return NativeVPN.connect(fullConfig);
  },

  /**
   * Disconnect from the VPN network
   */
  async disconnect(): Promise<void> {
    return NativeVPN.disconnect();
  },

  /**
   * Get current VPN status
   */
  async getStatus(): Promise<VPNStatus> {
    return NativeVPN.getStatus();
  },

  /**
   * Check if connected
   */
  async isConnected(): Promise<boolean> {
    return NativeVPN.isConnected();
  },

  /**
   * Set privacy level (number of relay hops)
   */
  async setPrivacyLevel(level: PrivacyLevel): Promise<void> {
    return NativeVPN.setPrivacyLevel(level);
  },

  /**
   * Set available credits (for testing without payment)
   */
  async setCredits(credits: number): Promise<void> {
    return NativeVPN.setCredits(credits);
  },

  /**
   * Set node mode (client, node, or both)
   */
  async setMode(mode: NodeMode): Promise<void> {
    return NativeVPN.setMode(mode);
  },

  /**
   * Purchase credits using mock settlement
   */
  async purchaseCredits(amount: number): Promise<{ balance: number }> {
    return NativeVPN.purchaseCredits(amount);
  },

  /**
   * Send an HTTP request through the VPN tunnel
   */
  async request(method: string, url: string, body?: string, headers?: Record<string, string>): Promise<{ status: number; body: string }> {
    return NativeVPN.request({ method, url, body, headers });
  },

  /**
   * Select preferred exit node by geography
   */
  async selectExit(region: string, countryCode?: string, city?: string): Promise<void> {
    return NativeVPN.selectExit({ region, countryCode, city });
  },

  /**
   * Get node statistics (relay/exit metrics)
   */
  async getStats(): Promise<NodeStats> {
    return NativeVPN.getStats();
  },

  /**
   * Subscribe to VPN state changes
   */
  onStateChange(callback: (state: ConnectionState) => void): () => void {
    if (!vpnEventEmitter) {
      return () => {};
    }
    const subscription = vpnEventEmitter.addListener('onStateChange', callback);
    return () => subscription.remove();
  },

  /**
   * Subscribe to VPN errors
   */
  onError(callback: (error: string) => void): () => void {
    if (!vpnEventEmitter) {
      return () => {};
    }
    const subscription = vpnEventEmitter.addListener('onError', callback);
    return () => subscription.remove();
  },

  /**
   * Subscribe to stats updates
   */
  onStatsUpdate(callback: (stats: NetworkStats) => void): () => void {
    if (!vpnEventEmitter) {
      return () => {};
    }
    const subscription = vpnEventEmitter.addListener('onStatsUpdate', callback);
    return () => subscription.remove();
  },
};

export default TunnelCraftVPN;
