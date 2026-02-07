// TunnelCraftCore - Swift wrapper for UniFFI bindings
// This provides a clean Swift API over the generated UniFFI code

import Foundation

/// Re-export UniFFI types with convenience extensions
public typealias TCConnectionState = ConnectionState
public typealias TCPrivacyLevel = PrivacyLevel
public typealias TCUnifiedNodeConfig = UnifiedNodeConfig
public typealias TCUnifiedNodeStats = UnifiedNodeStats
public typealias TCTunnelCraftNode = TunnelCraftUnifiedNode
public typealias TCError = TunnelCraftError

/// TunnelCraft namespace for initialization and utilities
public enum TunnelCraft {

    /// Initialize the TunnelCraft library
    /// Call this once at app startup before using any other API
    public static func initialize() {
        initLibrary()
        #if DEBUG
        print("[TunnelCraft] Library initialized via UniFFI")
        #endif
    }

    /// Create a default unified node configuration
    public static func defaultConfig() -> UnifiedNodeConfig {
        return createDefaultUnifiedConfig()
    }

    /// Create a custom unified node configuration for VPN client mode
    public static func config(
        privacyLevel: PrivacyLevel,
        bootstrapPeer: String? = nil,
        requestTimeoutSecs: UInt64 = 30
    ) -> UnifiedNodeConfig {
        return createUnifiedConfig(
            mode: .client,
            privacyLevel: privacyLevel,
            nodeType: .relay,
            bootstrapPeer: bootstrapPeer
        )
    }

    /// Create a unified node configuration with full control
    public static func unifiedConfig(
        mode: NodeMode,
        privacyLevel: PrivacyLevel,
        nodeType: NodeType,
        bootstrapPeer: String? = nil
    ) -> UnifiedNodeConfig {
        return createUnifiedConfig(
            mode: mode,
            privacyLevel: privacyLevel,
            nodeType: nodeType,
            bootstrapPeer: bootstrapPeer
        )
    }
}

// MARK: - PrivacyLevel Extensions

extension PrivacyLevel {
    public var hopCount: Int {
        switch self {
        case .direct: return 0
        case .light: return 1
        case .standard: return 2
        case .paranoid: return 3
        }
    }

    public var displayName: String {
        switch self {
        case .direct: return "Direct"
        case .light: return "Light"
        case .standard: return "Standard"
        case .paranoid: return "Paranoid"
        }
    }

    public var description: String {
        switch self {
        case .direct: return "Direct connection (0 hops)"
        case .light: return "1 relay hop"
        case .standard: return "2 relay hops"
        case .paranoid: return "3 relay hops (maximum privacy)"
        }
    }
}

// MARK: - ConnectionState Extensions

extension ConnectionState {
    public var isConnected: Bool {
        return self == .connected
    }

    public var isConnecting: Bool {
        return self == .connecting
    }

    public var isDisconnected: Bool {
        return self == .disconnected
    }

    public var displayName: String {
        switch self {
        case .disconnected: return "Disconnected"
        case .connecting: return "Connecting"
        case .connected: return "Connected"
        case .disconnecting: return "Disconnecting"
        case .error: return "Error"
        }
    }
}

// MARK: - UnifiedNodeStats Extensions

extension UnifiedNodeStats {
    public var formattedBytesSent: String {
        return formatBytes(bytesSent)
    }

    public var formattedBytesReceived: String {
        return formatBytes(bytesReceived)
    }

    public var formattedUptime: String {
        let hours = uptimeSecs / 3600
        let minutes = (uptimeSecs % 3600) / 60
        let seconds = uptimeSecs % 60

        if hours > 0 {
            return String(format: "%dh %dm %ds", hours, minutes, seconds)
        } else if minutes > 0 {
            return String(format: "%dm %ds", minutes, seconds)
        } else {
            return String(format: "%ds", seconds)
        }
    }

    private func formatBytes(_ bytes: UInt64) -> String {
        let kb = Double(bytes) / 1024.0
        let mb = kb / 1024.0
        let gb = mb / 1024.0

        if gb >= 1.0 {
            return String(format: "%.2f GB", gb)
        } else if mb >= 1.0 {
            return String(format: "%.2f MB", mb)
        } else if kb >= 1.0 {
            return String(format: "%.2f KB", kb)
        } else {
            return "\(bytes) B"
        }
    }
}
