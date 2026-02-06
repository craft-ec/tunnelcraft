import * as net from 'net';
import { EventEmitter } from 'events';

interface JsonRpcRequest {
  jsonrpc: '2.0';
  method: string;
  params?: unknown;
  id: number;
}

interface JsonRpcResponse {
  jsonrpc: '2.0';
  result?: unknown;
  error?: { code: number; message: string };
  id: number;
}

export class IPCClient extends EventEmitter {
  private socket: net.Socket | null = null;
  private requestId = 0;
  private pendingRequests = new Map<number, {
    resolve: (value: unknown) => void;
    reject: (reason: Error) => void;
  }>();
  private buffer = '';
  private isConnected = false;

  private getSocketPath(): string {
    if (process.platform === 'win32') {
      return '\\\\.\\pipe\\tunnelcraft';
    }
    if (process.platform === 'darwin') {
      return '/tmp/tunnelcraft.sock';
    }
    return (process.env.XDG_RUNTIME_DIR || '/tmp') + '/tunnelcraft.sock';
  }

  async connect(): Promise<void> {
    if (this.isConnected) {
      return;
    }

    const socketPath = this.getSocketPath();

    return new Promise((resolve, reject) => {
      this.socket = net.createConnection(socketPath);

      this.socket.on('connect', () => {
        this.isConnected = true;
        this.emit('connected');
        resolve();
      });

      this.socket.on('data', (data) => {
        this.handleData(data.toString());
      });

      this.socket.on('error', (err) => {
        if (!this.isConnected) {
          // Connection failed
          reject(err);
        } else {
          this.emit('error', err.message);
        }
      });

      this.socket.on('close', () => {
        this.isConnected = false;
        this.emit('disconnected');
      });

      // Timeout for initial connection
      setTimeout(() => {
        if (!this.isConnected) {
          this.socket?.destroy();
          reject(new Error('Connection timeout'));
        }
      }, 5000);
    });
  }

  async disconnect(): Promise<void> {
    if (this.socket) {
      await this.call('disconnect');
      this.socket.destroy();
      this.socket = null;
      this.isConnected = false;
    }
  }

  async getStatus(): Promise<unknown> {
    return this.call('status');
  }

  async vpnConnect(config?: { hops?: number }): Promise<void> {
    await this.call('connect', config);
    this.emit('stateChange', 'connecting');
  }

  async vpnDisconnect(): Promise<void> {
    await this.call('disconnect');
    this.emit('stateChange', 'disconnected');
  }

  async setPrivacyLevel(level: string): Promise<void> {
    await this.call('set_privacy_level', { level });
  }

  async purchaseCredits(amount: number): Promise<unknown> {
    return this.call('purchase_credits', { amount });
  }

  async getCredits(): Promise<unknown> {
    return this.call('get_credits');
  }

  async getNodeStats(): Promise<unknown> {
    return this.call('get_node_stats');
  }

  async setMode(mode: string): Promise<void> {
    await this.call('set_mode', { mode });
  }

  async request(method: string, url: string, body?: string, headers?: Record<string, string>): Promise<unknown> {
    return this.call('request', { method, url, body, headers });
  }

  async setExitNode(region: string, countryCode?: string, city?: string): Promise<void> {
    await this.call('set_exit_node', { region, country_code: countryCode, city });
  }

  async setLocalDiscovery(enabled: boolean): Promise<void> {
    await this.call('set_local_discovery', { enabled });
  }

  async getAvailableExits(): Promise<unknown> {
    return this.call('get_available_exits');
  }

  private async call(method: string, params?: unknown): Promise<unknown> {
    if (!this.socket || !this.isConnected) {
      throw new Error('Not connected to daemon');
    }

    const id = ++this.requestId;
    const request: JsonRpcRequest = {
      jsonrpc: '2.0',
      method,
      params,
      id,
    };

    return new Promise((resolve, reject) => {
      this.pendingRequests.set(id, { resolve, reject });

      const message = JSON.stringify(request) + '\n';
      this.socket?.write(message);

      // Request timeout
      setTimeout(() => {
        if (this.pendingRequests.has(id)) {
          this.pendingRequests.delete(id);
          reject(new Error('Request timeout'));
        }
      }, 30000);
    });
  }

  private handleData(data: string): void {
    this.buffer += data;

    // Process complete lines
    let newlineIndex;
    while ((newlineIndex = this.buffer.indexOf('\n')) !== -1) {
      const line = this.buffer.slice(0, newlineIndex);
      this.buffer = this.buffer.slice(newlineIndex + 1);

      if (line.trim()) {
        try {
          const response = JSON.parse(line) as JsonRpcResponse | { event: string; data: unknown };

          // Check if it's an event notification
          if ('event' in response) {
            this.handleEvent(response.event, response.data);
          } else {
            this.handleResponse(response);
          }
        } catch (err) {
          console.error('Failed to parse response:', line, err);
        }
      }
    }
  }

  private handleResponse(response: JsonRpcResponse): void {
    const pending = this.pendingRequests.get(response.id);
    if (pending) {
      this.pendingRequests.delete(response.id);

      if (response.error) {
        pending.reject(new Error(response.error.message));
      } else {
        pending.resolve(response.result);
      }
    }
  }

  private handleEvent(event: string, data: unknown): void {
    switch (event) {
      case 'state_change':
        this.emit('stateChange', data);
        break;
      case 'stats_update':
        this.emit('statsUpdate', data);
        break;
      case 'error':
        this.emit('error', data);
        break;
      default:
        console.warn('Unknown event:', event, data);
    }
  }
}
