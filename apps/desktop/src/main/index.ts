import { app, BrowserWindow, ipcMain, dialog, Tray, Menu, nativeImage } from 'electron';
import * as path from 'path';
import { DaemonManager } from './daemon';
import { IPCClient } from './ipc';

let mainWindow: BrowserWindow | null = null;
let tray: Tray | null = null;
let daemonManager: DaemonManager | null = null;
let ipcClient: IPCClient | null = null;
let isQuitting = false;

const isDev = process.env.NODE_ENV === 'development';

async function createWindow(): Promise<void> {
  mainWindow = new BrowserWindow({
    width: 400,
    height: 600,
    minWidth: 350,
    minHeight: 500,
    frame: false,
    titleBarStyle: 'hiddenInset',
    transparent: true,
    vibrancy: 'under-window',
    webPreferences: {
      preload: path.join(__dirname, '../preload/index.js'),
      nodeIntegration: false,
      contextIsolation: true,
    },
  });

  if (isDev) {
    mainWindow.loadURL('http://localhost:5173');
    mainWindow.webContents.openDevTools({ mode: 'detach' });
  } else {
    mainWindow.loadFile(path.join(__dirname, '../renderer/index.html'));
  }

  mainWindow.on('close', (e) => {
    if (!isQuitting) {
      e.preventDefault();
      mainWindow?.hide();
    }
  });

  mainWindow.on('closed', () => {
    mainWindow = null;
  });
}

function createTray(): void {
  const iconPath = path.join(__dirname, '../../assets/tray-icon.png');
  const icon = nativeImage.createFromPath(iconPath);

  tray = new Tray(icon.isEmpty() ? nativeImage.createEmpty() : icon);

  const contextMenu = Menu.buildFromTemplate([
    { label: 'Show TunnelCraft', click: () => mainWindow?.show() },
    { type: 'separator' },
    { label: 'Connect', click: () => ipcClient?.connect() },
    { label: 'Disconnect', click: () => ipcClient?.disconnect() },
    { type: 'separator' },
    { label: 'Quit', click: () => {
      isQuitting = true;
      app.quit();
    }},
  ]);

  tray.setToolTip('TunnelCraft');
  tray.setContextMenu(contextMenu);

  tray.on('click', () => {
    mainWindow?.show();
  });
}

async function startDaemon(): Promise<void> {
  daemonManager = new DaemonManager();
  await daemonManager.start();

  ipcClient = new IPCClient();
  await ipcClient.connect();
}

// IPC handlers from renderer
function setupIpcHandlers(): void {
  ipcMain.handle('vpn:connect', async (_event, config) => {
    try {
      // Set privacy level before connecting if provided
      if (config?.privacyLevel) {
        await ipcClient?.setPrivacyLevel(config.privacyLevel);
      }
      await ipcClient?.vpnConnect(config);
      return { success: true };
    } catch (error) {
      return { success: false, error: (error as Error).message };
    }
  });

  ipcMain.handle('vpn:disconnect', async () => {
    try {
      await ipcClient?.vpnDisconnect();
      return { success: true };
    } catch (error) {
      return { success: false, error: (error as Error).message };
    }
  });

  ipcMain.handle('vpn:status', async () => {
    try {
      const status = await ipcClient?.getStatus();
      return { success: true, status };
    } catch (error) {
      return { success: false, error: (error as Error).message };
    }
  });

  ipcMain.handle('vpn:setPrivacyLevel', async (_event, level) => {
    try {
      await ipcClient?.setPrivacyLevel(level);
      return { success: true };
    } catch (error) {
      return { success: false, error: (error as Error).message };
    }
  });

  ipcMain.handle('vpn:purchaseCredits', async (_event, amount) => {
    try {
      const result = await ipcClient?.purchaseCredits(amount);
      return { success: true, ...((result ?? {}) as Record<string, unknown>) };
    } catch (error) {
      return { success: false, error: (error as Error).message };
    }
  });

  ipcMain.handle('vpn:getCredits', async () => {
    try {
      const result = await ipcClient?.getCredits();
      return { success: true, ...((result ?? {}) as Record<string, unknown>) };
    } catch (error) {
      return { success: false, error: (error as Error).message };
    }
  });

  ipcMain.handle('vpn:getNodeStats', async () => {
    try {
      const result = await ipcClient?.getNodeStats();
      return { success: true, stats: result };
    } catch (error) {
      return { success: false, error: (error as Error).message };
    }
  });

  ipcMain.handle('vpn:setMode', async (_event, mode) => {
    try {
      await ipcClient?.setMode(mode);
      return { success: true };
    } catch (error) {
      return { success: false, error: (error as Error).message };
    }
  });

  ipcMain.handle('vpn:request', async (_event, { method, url, body, headers }) => {
    try {
      const result = await ipcClient?.request(method, url, body, headers);
      return { success: true, ...((result ?? {}) as Record<string, unknown>) };
    } catch (error) {
      return { success: false, error: (error as Error).message };
    }
  });

  ipcMain.handle('vpn:setExitNode', async (_event, { region, countryCode, city }) => {
    try {
      await ipcClient?.setExitNode(region, countryCode, city);
      return { success: true };
    } catch (error) {
      return { success: false, error: (error as Error).message };
    }
  });

  ipcMain.handle('vpn:setLocalDiscovery', async (_event, enabled) => {
    try {
      await ipcClient?.setLocalDiscovery(enabled);
      return { success: true };
    } catch (error) {
      return { success: false, error: (error as Error).message };
    }
  });

  ipcMain.handle('vpn:getAvailableExits', async () => {
    try {
      const result = await ipcClient?.getAvailableExits();
      return { success: true, ...((result ?? {}) as Record<string, unknown>) };
    } catch (error) {
      return { success: false, error: (error as Error).message };
    }
  });

  ipcMain.handle('vpn:getConnectionHistory', async () => {
    try {
      const result = await ipcClient?.sendRaw('get_connection_history');
      return { success: true, ...((result ?? {}) as Record<string, unknown>) };
    } catch (error) {
      return { success: false, error: (error as Error).message };
    }
  });

  ipcMain.handle('vpn:getEarningsHistory', async () => {
    try {
      const result = await ipcClient?.sendRaw('get_earnings_history');
      return { success: true, ...((result ?? {}) as Record<string, unknown>) };
    } catch (error) {
      return { success: false, error: (error as Error).message };
    }
  });

  ipcMain.handle('vpn:runSpeedTest', async () => {
    try {
      const result = await ipcClient?.sendRaw('run_speed_test');
      return { success: true, ...((result ?? {}) as Record<string, unknown>) };
    } catch (error) {
      return { success: false, error: (error as Error).message };
    }
  });

  ipcMain.handle('vpn:setBandwidthLimit', async (_event, limitKbps: number | null) => {
    try {
      await ipcClient?.sendRaw('set_bandwidth_limit', { limit_kbps: limitKbps });
      return { success: true };
    } catch (error) {
      return { success: false, error: (error as Error).message };
    }
  });

  ipcMain.handle('vpn:exportKey', async (_event, { path, password }: { path: string; password: string }) => {
    try {
      const result = await ipcClient?.sendRaw('export_key', { path, password });
      return { success: true, ...((result ?? {}) as Record<string, unknown>) };
    } catch (error) {
      return { success: false, error: (error as Error).message };
    }
  });

  ipcMain.handle('vpn:importKey', async (_event, { path, password }: { path: string; password: string }) => {
    try {
      const result = await ipcClient?.sendRaw('import_key', { path, password });
      return { success: true, ...((result ?? {}) as Record<string, unknown>) };
    } catch (error) {
      return { success: false, error: (error as Error).message };
    }
  });

  ipcMain.handle('dialog:showSaveDialog', async (_event, options) => {
    if (!mainWindow) return { canceled: true, filePath: undefined };
    return dialog.showSaveDialog(mainWindow, options);
  });

  ipcMain.handle('dialog:showOpenDialog', async (_event, options) => {
    if (!mainWindow) return { canceled: true, filePaths: [] };
    return dialog.showOpenDialog(mainWindow, options);
  });

  ipcMain.handle('window:minimize', () => {
    mainWindow?.minimize();
  });

  ipcMain.handle('window:close', () => {
    mainWindow?.hide();
  });
}

// Forward daemon events to renderer
function setupEventForwarding(): void {
  ipcClient?.on('stateChange', (state) => {
    mainWindow?.webContents.send('vpn:stateChange', state);
  });

  ipcClient?.on('statsUpdate', (stats) => {
    mainWindow?.webContents.send('vpn:statsUpdate', stats);
  });

  ipcClient?.on('error', (error) => {
    mainWindow?.webContents.send('vpn:error', error);
  });
}

app.whenReady().then(async () => {
  setupIpcHandlers();
  try {
    await startDaemon();
    setupEventForwarding();
  } catch (err) {
    console.error('Failed to start daemon:', err);
  }
  await createWindow();
  createTray();
}).catch((err) => {
  console.error('Fatal startup error:', err);
  app.quit();
});

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    app.quit();
  }
});

app.on('activate', () => {
  if (mainWindow === null) {
    createWindow();
  } else {
    mainWindow.show();
  }
});

app.on('before-quit', async () => {
  await ipcClient?.disconnect();
  await daemonManager?.stop();
});
