import Foundation
import React
import NetworkExtension
import TunnelCraftCore

/// React Native Native Module for TunnelCraft VPN
/// Supports two modes:
/// - Development Mode (simulator): Mock VPN behavior for UI testing
/// - Production Mode (device): Real VPN via UniFFI Rust bindings
@objc(TunnelCraftVPN)
class TunnelCraftVPNModule: RCTEventEmitter {

    private var vpnManager: NETunnelProviderManager?
    private var hasListeners = false

    // UniFFI VPN client (production mode)
    private var vpnClient: TunnelCraftVpn?

    // Development mode state (for simulator testing)
    private var isDevelopmentMode: Bool = false
    private var mockState: String = "disconnected"
    private var mockCredits: UInt64 = 0
    private var mockConnectedPeers: Int = 0

    // MARK: - React Native Setup

    override init() {
        super.init()

        #if targetEnvironment(simulator)
        // Simulator: use development/mock mode
        isDevelopmentMode = true
        print("[TunnelCraftVPN] Running in DEVELOPMENT MODE (simulator)")
        #else
        // Real device: initialize real VPN
        isDevelopmentMode = false
        initializeLibrary()
        loadVPNConfiguration()
        observeVPNStatus()
        #endif
    }

    @objc override static func requiresMainQueueSetup() -> Bool {
        return true
    }

    override func supportedEvents() -> [String]! {
        return ["onStateChange", "onError", "onStatsUpdate"]
    }

    override func startObserving() {
        hasListeners = true
    }

    override func stopObserving() {
        hasListeners = false
    }

    // MARK: - Initialization

    private func initializeLibrary() {
        // Initialize the TunnelCraft Rust library
        TunnelCraft.initialize()
        print("[TunnelCraftVPN] Rust library initialized via UniFFI")
    }

    private func loadVPNConfiguration() {
        NETunnelProviderManager.loadAllFromPreferences { [weak self] managers, error in
            if let error = error {
                self?.sendError("Failed to load VPN config: \(error.localizedDescription)")
                return
            }

            self?.vpnManager = managers?.first { manager in
                guard let proto = manager.protocolConfiguration as? NETunnelProviderProtocol else {
                    return false
                }
                return proto.providerBundleIdentifier == "com.tunnelcraft.app.TunnelCraftVPN"
            }
        }
    }

    private func observeVPNStatus() {
        NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange,
            object: nil,
            queue: .main
        ) { [weak self] notification in
            guard let connection = notification.object as? NEVPNConnection else { return }
            self?.sendStateChange(connection.status)
        }
    }

    // MARK: - Exported Methods

    @objc(connect:withResolver:withRejecter:)
    func connect(
        _ config: NSDictionary,
        resolver resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        // Development mode: simulate connection
        if isDevelopmentMode {
            simulateConnect(config, resolver: resolve)
            return
        }

        Task {
            do {
                // Create UniFFI VPN client
                let privacyLevel = mapPrivacyLevel(config["privacyLevel"] as? String ?? "standard")
                let bootstrapPeer = config["bootstrapPeer"] as? String

                let vpnConfig = TunnelCraft.config(
                    privacyLevel: privacyLevel,
                    bootstrapPeer: bootstrapPeer,
                    requestTimeoutSecs: 30
                )

                vpnClient = try TunnelCraftVpn(config: vpnConfig)
                try vpnClient?.connect()

                // Also configure Network Extension if needed
                if vpnManager == nil {
                    try await createVPNConfiguration(config)
                }

                sendStateChangeString("connected")
                resolve(nil)
            } catch let error as TunnelCraftError {
                reject("E_CONNECT_FAILED", error.localizedDescription, nil)
            } catch {
                reject("E_CONNECT_FAILED", error.localizedDescription, error)
            }
        }
    }

    // MARK: - Development Mode Simulation

    private func simulateConnect(_ config: NSDictionary, resolver resolve: @escaping RCTPromiseResolveBlock) {
        // Simulate connection process
        mockState = "connecting"
        sendStateChangeString(mockState)

        // Simulate connection delay
        DispatchQueue.main.asyncAfter(deadline: .now() + 1.5) { [weak self] in
            guard let self = self else { return }
            self.mockState = "connected"
            self.mockConnectedPeers = Int.random(in: 3...8)
            self.sendStateChangeString(self.mockState)

            // Send periodic stats updates
            self.startMockStatsUpdates()
        }

        resolve(nil)
    }

    private var mockStatsTimer: Timer?

    private func startMockStatsUpdates() {
        mockStatsTimer?.invalidate()
        mockStatsTimer = Timer.scheduledTimer(withTimeInterval: 2.0, repeats: true) { [weak self] _ in
            guard let self = self, self.mockState == "connected" else { return }
            self.sendStatsUpdate([
                "bytesIn": Int.random(in: 1000...100000),
                "bytesOut": Int.random(in: 500...50000),
                "connectedPeers": self.mockConnectedPeers,
                "latencyMs": Int.random(in: 20...150)
            ])
        }
    }

    private func stopMockStatsUpdates() {
        mockStatsTimer?.invalidate()
        mockStatsTimer = nil
    }

    @objc(disconnect:withRejecter:)
    func disconnect(
        resolver resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        // Development mode: simulate disconnect
        if isDevelopmentMode {
            stopMockStatsUpdates()
            mockState = "disconnecting"
            sendStateChangeString(mockState)

            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) { [weak self] in
                self?.mockState = "disconnected"
                self?.mockConnectedPeers = 0
                self?.sendStateChangeString(self?.mockState ?? "disconnected")
            }

            resolve(nil)
            return
        }

        do {
            try vpnClient?.disconnect()
            vpnManager?.connection.stopVPNTunnel()
            sendStateChangeString("disconnected")
            resolve(nil)
        } catch {
            reject("E_DISCONNECT_FAILED", error.localizedDescription, error)
        }
    }

    @objc(getStatus:withRejecter:)
    func getStatus(
        resolver resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        // Development mode: return mock status
        if isDevelopmentMode {
            let status: [String: Any] = [
                "state": mockState,
                "peerId": "mock-peer-\(UUID().uuidString.prefix(8))",
                "connectedPeers": mockConnectedPeers,
                "credits": mockCredits,
                "exitNode": mockState == "connected" ? "exit-node-\(UUID().uuidString.prefix(6))" : NSNull(),
                "errorMessage": NSNull(),
                "isDevelopmentMode": true
            ]
            resolve(status)
            return
        }

        if let client = vpnClient {
            let status = client.getStatus()
            let result: [String: Any] = [
                "state": mapConnectionState(status.state),
                "peerId": status.peerId,
                "connectedPeers": status.connectedPeers,
                "credits": status.credits,
                "exitNode": status.exitNode ?? NSNull(),
                "errorMessage": status.errorMessage ?? NSNull(),
                "isDevelopmentMode": false
            ]
            resolve(result)
        } else {
            let state = vpnManager?.connection.status ?? .disconnected
            let status: [String: Any] = [
                "state": stateToString(state),
                "peerId": "",
                "connectedPeers": 0,
                "credits": 0,
                "exitNode": NSNull(),
                "errorMessage": NSNull()
            ]
            resolve(status)
        }
    }

    @objc(isConnected:withRejecter:)
    func isConnected(
        resolver resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        // Development mode: check mock state
        if isDevelopmentMode {
            resolve(mockState == "connected")
            return
        }

        resolve(vpnClient?.isConnected() ?? false)
    }

    @objc(setPrivacyLevel:withResolver:withRejecter:)
    func setPrivacyLevel(
        _ level: String,
        resolver resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        let privacyLevel = mapPrivacyLevel(level)
        vpnClient?.setPrivacyLevel(level: privacyLevel)

        // Store in user defaults for the extension to read
        UserDefaults(suiteName: "group.com.tunnelcraft.vpn")?.set(level, forKey: "privacyLevel")
        resolve(nil)
    }

    @objc(setCredits:withResolver:withRejecter:)
    func setCredits(
        _ credits: NSNumber,
        resolver resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        let creditValue = credits.uint64Value

        // Development mode: set mock credits
        if isDevelopmentMode {
            mockCredits = creditValue
            resolve(nil)
            return
        }

        vpnClient?.setCredits(credits: creditValue)

        // Store in user defaults for the extension to read
        UserDefaults(suiteName: "group.com.tunnelcraft.vpn")?.set(creditValue, forKey: "credits")
        resolve(nil)
    }

    @objc(setMode:withResolver:withRejecter:)
    func setMode(
        _ mode: String,
        resolver resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        // Development mode: just accept the mode
        if isDevelopmentMode {
            resolve(nil)
            return
        }

        // In production, delegate to UniFFI node's set_mode
        // The TunnelCraftVpn client wraps the unified node
        vpnClient?.setMode(mode: mode)
        resolve(nil)
    }

    @objc(purchaseCredits:withResolver:withRejecter:)
    func purchaseCredits(
        _ amount: NSNumber,
        resolver resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        let creditAmount = amount.uint64Value

        // Development mode: simulate purchase
        if isDevelopmentMode {
            mockCredits += creditAmount
            resolve(["balance": mockCredits])
            return
        }

        // In production, use mock settlement through UniFFI bindings
        do {
            let newBalance = try vpnClient?.purchaseCredits(amount: creditAmount) ?? creditAmount
            resolve(["balance": newBalance])
        } catch {
            reject("E_PURCHASE_FAILED", error.localizedDescription, error)
        }
    }

    @objc(request:withResolver:withRejecter:)
    func request(
        _ params: NSDictionary,
        resolver resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        let method = params["method"] as? String ?? "GET"
        let urlString = params["url"] as? String ?? ""
        let body = params["body"] as? String
        let headers = params["headers"] as? [String: String]
        let headerCount = headers?.count ?? 0

        // Development mode: return mock response
        if isDevelopmentMode {
            DispatchQueue.main.asyncAfter(deadline: .now() + 0.5) {
                resolve([
                    "status": 200,
                    "body": "{\"mock\":true,\"method\":\"\(method)\",\"url\":\"\(urlString)\",\"headers\":\(headerCount),\"message\":\"Mock response from TunnelCraft\"}"
                ])
            }
            return
        }

        // Production mode: call through UniFFI client
        Task {
            do {
                if let client = vpnClient {
                    let result = try client.request(method: method, url: urlString, body: body)
                    resolve([
                        "status": result.status,
                        "body": result.body
                    ])
                } else {
                    reject("E_REQUEST_FAILED", "VPN client not initialized", nil)
                }
            } catch {
                reject("E_REQUEST_FAILED", error.localizedDescription, error)
            }
        }
    }

    @objc(getStats:withRejecter:)
    func getStats(
        resolver resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        if isDevelopmentMode {
            resolve([
                "shardsRelayed": Int.random(in: 0...500),
                "requestsExited": Int.random(in: 0...50),
                "peersConnected": Int.random(in: 3...15),
                "creditsEarned": Int.random(in: 0...100),
                "creditsSpent": Int.random(in: 0...50),
                "bytesSent": Int.random(in: 1000...1000000),
                "bytesReceived": Int.random(in: 1000...5000000),
                "bytesRelayed": Int.random(in: 0...2000000)
            ])
            return
        }

        if let stats = vpnClient?.getStats() {
            resolve([
                "shardsRelayed": stats.shardsRelayed,
                "requestsExited": stats.requestsExited,
                "peersConnected": stats.peersConnected,
                "creditsEarned": stats.creditsEarned,
                "creditsSpent": stats.creditsSpent,
                "bytesSent": stats.bytesSent,
                "bytesReceived": stats.bytesReceived,
                "bytesRelayed": stats.bytesRelayed
            ])
        } else {
            resolve([
                "shardsRelayed": 0,
                "requestsExited": 0,
                "peersConnected": 0,
                "creditsEarned": 0,
                "creditsSpent": 0,
                "bytesSent": 0,
                "bytesReceived": 0,
                "bytesRelayed": 0
            ])
        }
    }

    @objc(selectExit:withResolver:withRejecter:)
    func selectExit(
        params: NSDictionary,
        resolver resolve: @escaping RCTPromiseResolveBlock,
        rejecter reject: @escaping RCTPromiseRejectBlock
    ) {
        let region = params["region"] as? String ?? "auto"
        let countryCode = params["countryCode"] as? String
        let city = params["city"] as? String

        if isDevelopmentMode {
            print("[TunnelCraftVPN] selectExit: region=\(region) country=\(countryCode ?? "nil") city=\(city ?? "nil")")
            resolve(nil)
            return
        }

        vpnClient?.selectExit(region: region, countryCode: countryCode, city: city)
        resolve(nil)
    }

    // MARK: - VPN Configuration

    private func createVPNConfiguration(_ config: NSDictionary) async throws {
        let manager = NETunnelProviderManager()

        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = "com.tunnelcraft.app.TunnelCraftVPN"
        proto.serverAddress = "TunnelCraft P2P Network"

        var providerConfig: [String: Any] = [:]
        if let privacyLevel = config["privacyLevel"] as? String {
            providerConfig["privacyLevel"] = privacyLevel
        }
        proto.providerConfiguration = providerConfig

        manager.protocolConfiguration = proto
        manager.localizedDescription = "TunnelCraft VPN"
        manager.isEnabled = true

        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()

        self.vpnManager = manager
    }

    // MARK: - Event Sending

    private func sendStateChange(_ status: NEVPNStatus) {
        guard hasListeners else { return }
        sendEvent(withName: "onStateChange", body: stateToString(status))
    }

    private func sendStateChangeString(_ state: String) {
        guard hasListeners else { return }
        sendEvent(withName: "onStateChange", body: state)
    }

    private func sendError(_ message: String) {
        guard hasListeners else { return }
        sendEvent(withName: "onError", body: message)
    }

    private func sendStatsUpdate(_ stats: [String: Any]) {
        guard hasListeners else { return }
        sendEvent(withName: "onStatsUpdate", body: stats)
    }

    // MARK: - Helpers

    private func stateToString(_ status: NEVPNStatus) -> String {
        switch status {
        case .invalid: return "error"
        case .disconnected: return "disconnected"
        case .connecting: return "connecting"
        case .connected: return "connected"
        case .reasserting: return "connecting"
        case .disconnecting: return "disconnecting"
        @unknown default: return "disconnected"
        }
    }

    private func mapPrivacyLevel(_ level: String) -> PrivacyLevel {
        switch level.lowercased() {
        case "direct": return .direct
        case "light": return .light
        case "standard": return .standard
        case "paranoid": return .paranoid
        default: return .standard
        }
    }

    private func mapConnectionState(_ state: ConnectionState) -> String {
        switch state {
        case .disconnected: return "disconnected"
        case .connecting: return "connecting"
        case .connected: return "connected"
        case .disconnecting: return "disconnecting"
        case .error: return "error"
        }
    }
}
