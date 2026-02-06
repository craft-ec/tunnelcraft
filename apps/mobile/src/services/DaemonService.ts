/**
 * DaemonService
 *
 * Handles IPC communication with the Rust daemon via React Native bridge.
 * On iOS: Uses Network Extension + FFI bindings (uniffi)
 * On Android: Uses VpnService + JNI bindings (uniffi)
 */

import { NativeModules, NativeEventEmitter } from 'react-native';
import type {
  PrivacyLevel,
  ExitRegion,
  NodeMode,
  AvailableExit,
  NodeStats,
  ConnectionHistoryEntry,
  EarningsEntry,
  SpeedTestResult,
} from '../context/TunnelContext';
import { getSettlementConfig, type SettlementConfig } from '../config/settlement';
import { LogService } from './LogService';

const TAG = 'DaemonService';

// Native module interface
interface TunnelCraftDaemon {
  // Connection
  connect(config: ConnectionConfig): Promise<void>;
  disconnect(): Promise<void>;
  getConnectionState(): Promise<ConnectionState>;

  // Exit nodes
  getAvailableExits(): Promise<AvailableExit[]>;
  selectExit(exitId: string): Promise<void>;
  getSelectedExit(): Promise<AvailableExit | null>;

  // Node mode
  setNodeMode(mode: NodeMode, allowExit: boolean): Promise<void>;
  getNodeMode(): Promise<{ mode: NodeMode; allowExit: boolean }>;

  // Stats
  getStats(): Promise<NodeStats>;
  getConnectionHistory(): Promise<ConnectionHistoryEntry[]>;
  getEarningsHistory(): Promise<EarningsEntry[]>;

  // Credits
  getCredits(): Promise<number>;
  purchaseCredits(amount: number, paymentMethod: string): Promise<boolean>;

  // Speed test
  runSpeedTest(): Promise<SpeedTestResult>;
  getSpeedTestHistory(): Promise<SpeedTestResult[]>;

  // Keys
  getPublicKey(): Promise<string>;
  getNodeId(): Promise<string>;
  getCreditHash(): Promise<string>;
  exportPrivateKey(password: string): Promise<string>;
  importPrivateKey(encryptedKey: string, password: string): Promise<boolean>;

  // Settings
  setPrivacyLevel(level: PrivacyLevel): Promise<void>;
  setBandwidthLimit(mbps: number): Promise<void>;
  setExitEnabled(enabled: boolean): Promise<void>;

  // Split Tunneling
  setSplitTunnelRules(rules: SplitTunnelRule[], mode: SplitTunnelMode): Promise<void>;
  getSplitTunnelRules(): Promise<SplitTunnelConfig>;

  // Settlement (simple accumulate + manual claim)
  getNodePoints(): Promise<NodePoints>;
  getClaimHistory(limit?: number): Promise<ClaimHistory[]>;
  claimRewards(): Promise<ClaimResult>;
  withdrawRewards(amount: number): Promise<ClaimResult>;
}

interface ConnectionConfig {
  privacyLevel: PrivacyLevel;
  exitRegion?: ExitRegion;
  exitCountryCode?: string;
  nodeMode: NodeMode;
  allowExit: boolean;
  bandwidthLimitMbps: number;
}

type ConnectionState = 'disconnected' | 'connecting' | 'connected' | 'disconnecting' | 'error';

// Settlement types (simplified - no epochs)
interface NodePoints {
  pendingShards: number;
  pendingPoints: number;
  lifetimePoints: number;
  availableRewards: number;
}

interface ClaimHistory {
  id: string;
  timestamp: number;
  shardsSettled: number;
  pointsEarned: number;
  txSignature?: string;
}

interface ClaimResult {
  success: boolean;
  txSignature?: string;
  shardsSettled: number;
  pointsEarned: number;
  error?: string;
}

// Split tunneling types
type SplitTunnelMode = 'include' | 'exclude';

interface SplitTunnelRule {
  id: string;
  type: 'ip' | 'domain' | 'app';
  target: string; // IP address, CIDR, domain, or bundle ID
  enabled: boolean;
}

interface SplitTunnelConfig {
  mode: SplitTunnelMode;
  rules: SplitTunnelRule[];
}

// Event types from daemon (keys match what's emitted internally)
interface DaemonEvents {
  connectionStateChange: (state: ConnectionState) => void;
  statsUpdate: (stats: NodeStats) => void;
  exitsUpdate: (exits: AvailableExit[]) => void;
  creditsUpdate: (credits: number) => void;
  pointsUpdate: (nodePoints: NodePoints) => void;
  error: (error: { code: string; message: string }) => void;
}

class DaemonServiceClass {
  private daemon: TunnelCraftDaemon | null = null;
  private eventEmitter: NativeEventEmitter | null = null;
  private listeners: Map<string, Set<Function>> = new Map();
  private isInitialized = false;
  private settlementConfig: SettlementConfig;

  constructor() {
    // Load settlement configuration (devnet by default in development)
    this.settlementConfig = getSettlementConfig();
    LogService.info(TAG, `Settlement mode: ${this.settlementConfig.mode}`);
    LogService.info(TAG, `Program ID: ${this.settlementConfig.programId}`);
  }

  async initialize(): Promise<boolean> {
    if (this.isInitialized) {
      LogService.debug(TAG, 'Already initialized, skipping');
      return true;
    }

    LogService.info(TAG, 'Initializing DaemonService...');

    try {
      // Get native module
      const { TunnelCraftDaemon: NativeDaemon } = NativeModules;

      if (!NativeDaemon) {
        LogService.error(TAG, 'Native module TunnelCraftDaemon not found!');
        throw new Error('TunnelCraftDaemon native module not available. Ensure the app is built with native modules.');
      }

      LogService.info(TAG, 'Native module found, using real daemon');
      this.daemon = NativeDaemon;
      this.eventEmitter = new NativeEventEmitter(NativeDaemon);
      this.setupEventListeners();

      // Configure settlement on native side
      await this.configureSettlement(this.settlementConfig);

      this.isInitialized = true;
      LogService.info(TAG, 'Initialization complete');
      return true;
    } catch (error) {
      LogService.error(TAG, 'Failed to initialize', error);
      return false;
    }
  }

  // Configure settlement layer (passed to Rust daemon via FFI)
  private async configureSettlement(config: SettlementConfig): Promise<void> {
    if (!this.daemon) return;

    // Native module will pass this to the Rust settlement client
    // The Rust side uses SettlementConfig::devnet(program_id) or ::mock()
    try {
      // @ts-ignore - This method will be implemented in native modules
      if (typeof this.daemon.configureSettlement === 'function') {
        await this.daemon.configureSettlement({
          mode: config.mode,
          rpcUrl: config.rpcUrl,
          programId: config.programId,
          commitment: config.commitment,
        });
        LogService.info(TAG, `Settlement configured: ${config.mode} mode`);
      }
    } catch (error) {
      LogService.warn(TAG, 'configureSettlement not available in native module');
    }
  }

  getSettlementConfig(): SettlementConfig {
    return this.settlementConfig;
  }

  private setupEventListeners(): void {
    if (!this.eventEmitter) return;

    LogService.debug(TAG, 'Setting up event listeners');

    this.eventEmitter.addListener('onConnectionStateChange', (state: ConnectionState) => {
      LogService.info(TAG, 'Event: connectionStateChange', state);
      this.emit('connectionStateChange', state);
    });

    this.eventEmitter.addListener('onStatsUpdate', (stats: NodeStats) => {
      LogService.debug(TAG, 'Event: statsUpdate', { peers: stats.connectedPeers, uptime: stats.uptimeSecs });
      this.emit('statsUpdate', stats);
    });

    this.eventEmitter.addListener('onExitsUpdate', (exits: AvailableExit[]) => {
      LogService.info(TAG, 'Event: exitsUpdate', { count: exits.length });
      this.emit('exitsUpdate', exits);
    });

    this.eventEmitter.addListener('onCreditsUpdate', (credits: number) => {
      LogService.info(TAG, 'Event: creditsUpdate', credits);
      this.emit('creditsUpdate', credits);
    });

    this.eventEmitter.addListener('onError', (error: { code: string; message: string }) => {
      LogService.error(TAG, 'Event: error', error);
      this.emit('error', error);
    });
  }

  // Event subscription
  on<K extends keyof DaemonEvents>(event: K, callback: DaemonEvents[K]): () => void {
    if (!this.listeners.has(event)) {
      this.listeners.set(event, new Set());
    }
    this.listeners.get(event)!.add(callback);

    return () => {
      this.listeners.get(event)?.delete(callback);
    };
  }

  private emit(event: string, data: unknown): void {
    this.listeners.get(event)?.forEach((callback) => callback(data));
  }

  // Connection methods
  async connect(config: ConnectionConfig): Promise<void> {
    LogService.info(TAG, 'connect() called', config);
    await this.ensureInitialized();
    try {
      await this.daemon!.connect(config);
      LogService.info(TAG, 'connect() succeeded');
      // Explicitly emit connected state in case native event doesn't fire
      this.emit('connectionStateChange', 'connected');
    } catch (error) {
      LogService.error(TAG, 'connect() failed', error);
      this.emit('connectionStateChange', 'error');
      throw error;
    }
  }

  async disconnect(): Promise<void> {
    LogService.info(TAG, 'disconnect() called');
    await this.ensureInitialized();
    try {
      await this.daemon!.disconnect();
      LogService.info(TAG, 'disconnect() succeeded');
      // Explicitly emit disconnected state in case native event doesn't fire
      this.emit('connectionStateChange', 'disconnected');
    } catch (error) {
      LogService.error(TAG, 'disconnect() failed', error);
      this.emit('connectionStateChange', 'error');
      throw error;
    }
  }

  async getConnectionState(): Promise<ConnectionState> {
    await this.ensureInitialized();
    const state = await this.daemon!.getConnectionState();
    LogService.debug(TAG, 'getConnectionState()', state);
    return state;
  }

  // Exit nodes
  async getAvailableExits(): Promise<AvailableExit[]> {
    LogService.debug(TAG, 'getAvailableExits() called');
    await this.ensureInitialized();
    try {
      const exits = await this.daemon!.getAvailableExits();
      LogService.info(TAG, 'getAvailableExits() result', { count: exits.length, exits: exits.map(e => `${e.countryCode}:${e.city}`) });
      return exits;
    } catch (error) {
      LogService.error(TAG, 'getAvailableExits() failed', error);
      throw error;
    }
  }

  async selectExit(exitId: string): Promise<void> {
    LogService.info(TAG, 'selectExit() called', { exitId });
    await this.ensureInitialized();
    try {
      await this.daemon!.selectExit(exitId);
      LogService.info(TAG, 'selectExit() succeeded');
    } catch (error) {
      LogService.error(TAG, 'selectExit() failed', error);
      throw error;
    }
  }

  async getSelectedExit(): Promise<AvailableExit | null> {
    await this.ensureInitialized();
    const exit = await this.daemon!.getSelectedExit();
    LogService.debug(TAG, 'getSelectedExit()', exit);
    return exit;
  }

  // Node mode
  async setNodeMode(mode: NodeMode, allowExit: boolean): Promise<void> {
    LogService.info(TAG, 'setNodeMode() called', { mode, allowExit });
    await this.ensureInitialized();
    return this.daemon!.setNodeMode(mode, allowExit);
  }

  async getNodeMode(): Promise<{ mode: NodeMode; allowExit: boolean }> {
    await this.ensureInitialized();
    const result = await this.daemon!.getNodeMode();
    LogService.debug(TAG, 'getNodeMode()', result);
    return result;
  }

  // Stats
  async getStats(): Promise<NodeStats> {
    await this.ensureInitialized();
    return this.daemon!.getStats();
  }

  async getConnectionHistory(): Promise<ConnectionHistoryEntry[]> {
    await this.ensureInitialized();
    const history = await this.daemon!.getConnectionHistory();
    LogService.debug(TAG, 'getConnectionHistory()', { count: history.length });
    return history;
  }

  async getEarningsHistory(): Promise<EarningsEntry[]> {
    await this.ensureInitialized();
    const history = await this.daemon!.getEarningsHistory();
    LogService.debug(TAG, 'getEarningsHistory()', { count: history.length });
    return history;
  }

  // Credits
  async getCredits(): Promise<number> {
    await this.ensureInitialized();
    const credits = await this.daemon!.getCredits();
    LogService.debug(TAG, 'getCredits()', credits);
    return credits;
  }

  async purchaseCredits(amount: number, paymentMethod: string): Promise<boolean> {
    await this.ensureInitialized();
    return this.daemon!.purchaseCredits(amount, paymentMethod);
  }

  // Speed test
  async runSpeedTest(): Promise<SpeedTestResult> {
    await this.ensureInitialized();
    return this.daemon!.runSpeedTest();
  }

  async getSpeedTestHistory(): Promise<SpeedTestResult[]> {
    await this.ensureInitialized();
    return this.daemon!.getSpeedTestHistory();
  }

  // Keys
  async getPublicKey(): Promise<string> {
    await this.ensureInitialized();
    return this.daemon!.getPublicKey();
  }

  async getNodeId(): Promise<string> {
    await this.ensureInitialized();
    return this.daemon!.getNodeId();
  }

  async getCreditHash(): Promise<string> {
    await this.ensureInitialized();
    return this.daemon!.getCreditHash();
  }

  async exportPrivateKey(password: string): Promise<string> {
    await this.ensureInitialized();
    return this.daemon!.exportPrivateKey(password);
  }

  async importPrivateKey(encryptedKey: string, password: string): Promise<boolean> {
    await this.ensureInitialized();
    return this.daemon!.importPrivateKey(encryptedKey, password);
  }

  // Settings
  async setPrivacyLevel(level: PrivacyLevel): Promise<void> {
    await this.ensureInitialized();
    return this.daemon!.setPrivacyLevel(level);
  }

  async setBandwidthLimit(mbps: number): Promise<void> {
    await this.ensureInitialized();
    return this.daemon!.setBandwidthLimit(mbps);
  }

  async setExitEnabled(enabled: boolean): Promise<void> {
    await this.ensureInitialized();
    return this.daemon!.setExitEnabled(enabled);
  }

  // Split Tunneling
  async setSplitTunnelRules(rules: SplitTunnelRule[], mode: SplitTunnelMode): Promise<void> {
    LogService.info(TAG, 'setSplitTunnelRules() called', { mode, rulesCount: rules.length });
    await this.ensureInitialized();
    try {
      await this.daemon!.setSplitTunnelRules(rules, mode);
      LogService.info(TAG, 'setSplitTunnelRules() succeeded');
    } catch (error) {
      LogService.error(TAG, 'setSplitTunnelRules() failed', error);
      throw error;
    }
  }

  async getSplitTunnelRules(): Promise<SplitTunnelConfig> {
    await this.ensureInitialized();
    try {
      const config = await this.daemon!.getSplitTunnelRules();
      LogService.debug(TAG, 'getSplitTunnelRules()', config);
      return config;
    } catch (error) {
      LogService.error(TAG, 'getSplitTunnelRules() failed', error);
      throw error;
    }
  }

  // Settlement (simple accumulate + manual claim)
  async getNodePoints(): Promise<NodePoints> {
    await this.ensureInitialized();
    const points = await this.daemon!.getNodePoints();
    LogService.debug(TAG, 'getNodePoints()', points);
    return points;
  }

  async getClaimHistory(limit?: number): Promise<ClaimHistory[]> {
    await this.ensureInitialized();
    const history = await this.daemon!.getClaimHistory(limit ?? 10);
    LogService.debug(TAG, 'getClaimHistory()', { count: history.length });
    return history;
  }

  async claimRewards(): Promise<ClaimResult> {
    LogService.info(TAG, 'claimRewards() called');
    await this.ensureInitialized();
    try {
      const result = await this.daemon!.claimRewards();
      LogService.info(TAG, 'claimRewards() result', result);
      return result;
    } catch (error) {
      LogService.error(TAG, 'claimRewards() failed', error);
      throw error;
    }
  }

  async withdrawRewards(amount: number): Promise<ClaimResult> {
    LogService.info(TAG, 'withdrawRewards() called', { amount });
    await this.ensureInitialized();
    try {
      const result = await this.daemon!.withdrawRewards(amount);
      LogService.info(TAG, 'withdrawRewards() result', result);
      return result;
    } catch (error) {
      LogService.error(TAG, 'withdrawRewards() failed', error);
      throw error;
    }
  }

  private async ensureInitialized(): Promise<void> {
    if (!this.isInitialized) {
      await this.initialize();
    }
    if (!this.daemon) {
      throw new Error('DaemonService not initialized');
    }
  }

}

export const DaemonService = new DaemonServiceClass();
export type { ConnectionConfig, ConnectionState, DaemonEvents, NodePoints, ClaimHistory, ClaimResult, SplitTunnelMode, SplitTunnelRule, SplitTunnelConfig };
export type { SettlementConfig } from '../config/settlement';
export {
  TUNNELCRAFT_PROGRAM_ID,
  SETTLEMENT_PROGRAM_ID,
  USDC_MINT_DEVNET,
  USDC_MINT_MAINNET,
  GB_PRICE_USDC,
  CREDITS_PER_GB,
  NODE_SHARE_PERCENT,
  TREASURY_SHARE_PERCENT,
  DEVNET_CONFIG,
  MAINNET_CONFIG,
} from '../config/settlement';
