import { contextBridge, ipcRenderer } from 'electron';

// Expose protected methods that allow the renderer process to use
// the ipcRenderer without exposing the entire object
contextBridge.exposeInMainWorld('electronAPI', {
  // VPN operations
  connect: (config?: { privacyLevel?: string }) =>
    ipcRenderer.invoke('vpn:connect', config),

  disconnect: () =>
    ipcRenderer.invoke('vpn:disconnect'),

  getStatus: () =>
    ipcRenderer.invoke('vpn:status'),

  setPrivacyLevel: (level: string) =>
    ipcRenderer.invoke('vpn:setPrivacyLevel', level),

  purchaseCredits: (amount: number) =>
    ipcRenderer.invoke('vpn:purchaseCredits', amount),

  getCredits: () =>
    ipcRenderer.invoke('vpn:getCredits'),

  getNodeStats: () =>
    ipcRenderer.invoke('vpn:getNodeStats'),

  setMode: (mode: string) =>
    ipcRenderer.invoke('vpn:setMode', mode),

  request: (method: string, url: string, body?: string, headers?: Record<string, string>) =>
    ipcRenderer.invoke('vpn:request', { method, url, body, headers }),

  setExitNode: (region: string, countryCode?: string, city?: string) =>
    ipcRenderer.invoke('vpn:setExitNode', { region, countryCode, city }),

  setLocalDiscovery: (enabled: boolean) =>
    ipcRenderer.invoke('vpn:setLocalDiscovery', enabled),

  getAvailableExits: () =>
    ipcRenderer.invoke('vpn:getAvailableExits'),

  getConnectionHistory: () =>
    ipcRenderer.invoke('vpn:getConnectionHistory'),

  getEarningsHistory: () =>
    ipcRenderer.invoke('vpn:getEarningsHistory'),

  runSpeedTest: () =>
    ipcRenderer.invoke('vpn:runSpeedTest'),

  setBandwidthLimit: (limitKbps: number | null) =>
    ipcRenderer.invoke('vpn:setBandwidthLimit', limitKbps),

  exportKey: (path: string, password: string) =>
    ipcRenderer.invoke('vpn:exportKey', { path, password }),

  importKey: (path: string, password: string) =>
    ipcRenderer.invoke('vpn:importKey', { path, password }),

  // File dialogs
  showSaveDialog: (options: Electron.SaveDialogOptions) =>
    ipcRenderer.invoke('dialog:showSaveDialog', options) as Promise<Electron.SaveDialogReturnValue>,

  showOpenDialog: (options: Electron.OpenDialogOptions) =>
    ipcRenderer.invoke('dialog:showOpenDialog', options) as Promise<Electron.OpenDialogReturnValue>,

  // Window operations
  minimize: () =>
    ipcRenderer.invoke('window:minimize'),

  close: () =>
    ipcRenderer.invoke('window:close'),

  // Event listeners
  onStateChange: (callback: (state: string) => void) => {
    const handler = (_event: Electron.IpcRendererEvent, state: string) => callback(state);
    ipcRenderer.on('vpn:stateChange', handler);
    return () => ipcRenderer.removeListener('vpn:stateChange', handler);
  },

  onStatsUpdate: (callback: (stats: unknown) => void) => {
    const handler = (_event: Electron.IpcRendererEvent, stats: unknown) => callback(stats);
    ipcRenderer.on('vpn:statsUpdate', handler);
    return () => ipcRenderer.removeListener('vpn:statsUpdate', handler);
  },

  onError: (callback: (error: string) => void) => {
    const handler = (_event: Electron.IpcRendererEvent, error: string) => callback(error);
    ipcRenderer.on('vpn:error', handler);
    return () => ipcRenderer.removeListener('vpn:error', handler);
  },
});

// Type definitions for the exposed API
export interface ElectronAPI {
  connect: (config?: { privacyLevel?: string }) => Promise<{ success: boolean; error?: string }>;
  disconnect: () => Promise<{ success: boolean; error?: string }>;
  getStatus: () => Promise<{ success: boolean; status?: unknown; error?: string }>;
  setPrivacyLevel: (level: string) => Promise<{ success: boolean; error?: string }>;
  purchaseCredits: (amount: number) => Promise<{ success: boolean; balance?: number; error?: string }>;
  getCredits: () => Promise<{ success: boolean; credits?: number; error?: string }>;
  getNodeStats: () => Promise<{ success: boolean; stats?: unknown; error?: string }>;
  setMode: (mode: string) => Promise<{ success: boolean; error?: string }>;
  request: (method: string, url: string, body?: string, headers?: Record<string, string>) => Promise<{ success: boolean; status?: number; body?: string; error?: string }>;
  setExitNode: (region: string, countryCode?: string, city?: string) => Promise<{ success: boolean; error?: string }>;
  setLocalDiscovery: (enabled: boolean) => Promise<{ success: boolean; error?: string }>;
  getAvailableExits: () => Promise<{ success: boolean; exits?: Array<{ pubkey: string; country_code?: string; city?: string; region: string; score: number; load: number; latency_ms?: number }>; error?: string }>;
  getConnectionHistory: () => Promise<{ success: boolean; entries?: Array<{ id: number; connected_at: number; disconnected_at?: number; duration_secs?: number; exit_region?: string; bytes_sent: number; bytes_received: number }>; error?: string }>;
  getEarningsHistory: () => Promise<{ success: boolean; entries?: Array<{ id: number; timestamp: number; entry_type: string; credits_earned: number; shards_count: number }>; error?: string }>;
  runSpeedTest: () => Promise<{ success: boolean; result?: { download_mbps: number; upload_mbps: number; latency_ms: number; jitter_ms: number; timestamp: number }; error?: string }>;
  setBandwidthLimit: (limitKbps: number | null) => Promise<{ success: boolean; error?: string }>;
  exportKey: (path: string, password: string) => Promise<{ success: boolean; path?: string; public_key?: string; error?: string }>;
  importKey: (path: string, password: string) => Promise<{ success: boolean; public_key?: string; error?: string }>;
  showSaveDialog: (options: Electron.SaveDialogOptions) => Promise<Electron.SaveDialogReturnValue>;
  showOpenDialog: (options: Electron.OpenDialogOptions) => Promise<Electron.OpenDialogReturnValue>;
  minimize: () => Promise<void>;
  close: () => Promise<void>;
  onStateChange: (callback: (state: string) => void) => () => void;
  onStatsUpdate: (callback: (stats: unknown) => void) => () => void;
  onError: (callback: (error: string) => void) => () => void;
}

declare global {
  interface Window {
    electronAPI: ElectronAPI;
  }
}
