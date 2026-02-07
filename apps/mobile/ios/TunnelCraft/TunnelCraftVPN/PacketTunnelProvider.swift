import NetworkExtension
import os.log
import TunnelCraftCore

/// TunnelCraft Packet Tunnel Provider
///
/// This Network Extension handles VPN tunnel packets by routing them
/// through the TunnelCraft P2P network via UniFFI Rust bindings.
class PacketTunnelProvider: NEPacketTunnelProvider {

    private let log = OSLog(subsystem: "com.tunnelcraft.vpn", category: "PacketTunnel")
    private var vpnClient: TunnelCraftUnifiedNode?
    private var isConnected = false
    private let packetQueue = DispatchQueue(label: "com.tunnelcraft.packetQueue", qos: .userInteractive)

    // Bandwidth limiting
    private var bandwidthLimiter: BandwidthLimiter?

    // Split tunneling
    private var splitTunnelMode: String = "exclude" // "include" or "exclude"
    private var splitTunnelRules: [[String: Any]] = []
    private var dnsCache: [String: [String]] = [:]  // domain -> resolved IPs

    // App Group for sharing data with main app
    private let appGroup = "group.com.tunnelcraft.vpn"

    // MARK: - Tunnel Lifecycle

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        os_log("Starting TunnelCraft tunnel", log: log, type: .info)

        // Initialize the Rust library
        initLibrary()

        // Read configuration from shared UserDefaults
        let sharedDefaults = UserDefaults(suiteName: appGroup)
        let privacyLevelStr = sharedDefaults?.string(forKey: "privacyLevel") ?? "standard"
        let credits = sharedDefaults?.object(forKey: "credits") as? UInt64 ?? 1000
        let bandwidthLimitMbps = sharedDefaults?.integer(forKey: "bandwidthLimitMbps") ?? 0

        // Load split tunnel configuration
        loadSplitTunnelRules()

        // Initialize bandwidth limiter if limit is set
        if bandwidthLimitMbps > 0 {
            bandwidthLimiter = BandwidthLimiter(mbps: bandwidthLimitMbps)
            os_log("Bandwidth limit set to %d Mbps", log: log, type: .info, bandwidthLimitMbps)
        }

        // Map privacy level
        let privacyLevel: PrivacyLevel
        switch privacyLevelStr.lowercased() {
        case "direct": privacyLevel = .direct
        case "light": privacyLevel = .light
        case "paranoid": privacyLevel = .paranoid
        default: privacyLevel = .standard
        }

        // Create unified node configuration in client mode
        let config = createUnifiedConfig(
            mode: .client,
            privacyLevel: privacyLevel,
            nodeType: .relay,
            bootstrapPeer: options?["bootstrapPeer"] as? String
        )

        do {
            // Create unified node
            vpnClient = try TunnelCraftUnifiedNode(config: config)

            // Set credits from shared storage
            vpnClient?.setCredits(credits: credits)

            // Start and connect to network
            try vpnClient?.start()

            // Configure tunnel network settings
            let tunnelSettings = createTunnelSettings()

            setTunnelNetworkSettings(tunnelSettings) { [weak self] error in
                if let error = error {
                    os_log("Failed to set tunnel settings: %{public}@",
                           log: self?.log ?? .default, type: .error, error.localizedDescription)
                    completionHandler(error)
                    return
                }

                os_log("Tunnel settings configured", log: self?.log ?? .default, type: .info)
                self?.isConnected = true
                self?.startPacketHandling()
                completionHandler(nil)
            }

        } catch {
            os_log("Failed to start tunnel: %{public}@", log: log, type: .error, error.localizedDescription)
            completionHandler(error)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        os_log("Stopping TunnelCraft tunnel: %{public}@", log: log, type: .info, String(describing: reason))

        isConnected = false

        do {
            try vpnClient?.stop()
        } catch {
            os_log("Error during stop: %{public}@", log: log, type: .error, error.localizedDescription)
        }

        vpnClient = nil
        bandwidthLimiter = nil
        completionHandler()
    }

    // MARK: - Network Settings

    private func createTunnelSettings() -> NEPacketTunnelNetworkSettings {
        // Use a virtual IP for the tunnel
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: "10.8.0.1")

        // IPv4 settings
        let ipv4Settings = NEIPv4Settings(
            addresses: ["10.8.0.2"],
            subnetMasks: ["255.255.255.0"]
        )

        // Build routes based on split tunnel mode and rules
        var includedRoutes: [NEIPv4Route] = []
        var excludedRoutes: [NEIPv4Route] = []

        // Always exclude local/private networks
        let localNetworkRoutes = [
            NEIPv4Route(destinationAddress: "10.0.0.0", subnetMask: "255.0.0.0"),
            NEIPv4Route(destinationAddress: "172.16.0.0", subnetMask: "255.240.0.0"),
            NEIPv4Route(destinationAddress: "192.168.0.0", subnetMask: "255.255.0.0"),
            NEIPv4Route(destinationAddress: "127.0.0.0", subnetMask: "255.0.0.0"),
        ]

        if splitTunnelMode == "include" {
            // Include mode: Only tunnel specific IPs/domains
            // By default, don't route anything through tunnel
            // Add specific routes from rules
            for rule in splitTunnelRules {
                if let enabled = rule["enabled"] as? Bool, enabled,
                   let ruleType = rule["type"] as? String {
                    if ruleType == "ip", let target = rule["target"] as? String {
                        // Parse IP/CIDR
                        if let route = parseIPRoute(target) {
                            includedRoutes.append(route)
                        }
                    } else if ruleType == "domain", let target = rule["target"] as? String {
                        // Resolve domain to IP addresses and add as routes
                        let resolvedIPs = resolveDomain(target)
                        for ip in resolvedIPs {
                            includedRoutes.append(
                                NEIPv4Route(destinationAddress: ip, subnetMask: "255.255.255.255")
                            )
                        }
                    }
                }
            }

            // If no specific routes, default to routing all traffic
            if includedRoutes.isEmpty {
                includedRoutes = [NEIPv4Route.default()]
            }

            excludedRoutes = localNetworkRoutes

        } else {
            // Exclude mode (default): Tunnel everything except specific IPs/domains
            includedRoutes = [NEIPv4Route.default()]

            // Start with local networks
            excludedRoutes = localNetworkRoutes

            // Add excluded routes from rules
            for rule in splitTunnelRules {
                if let enabled = rule["enabled"] as? Bool, enabled,
                   let ruleType = rule["type"] as? String {
                    if ruleType == "ip", let target = rule["target"] as? String {
                        if let route = parseIPRoute(target) {
                            excludedRoutes.append(route)
                        }
                    } else if ruleType == "domain", let target = rule["target"] as? String {
                        // Resolve domain to IP addresses and add as excluded routes
                        let resolvedIPs = resolveDomain(target)
                        for ip in resolvedIPs {
                            excludedRoutes.append(
                                NEIPv4Route(destinationAddress: ip, subnetMask: "255.255.255.255")
                            )
                        }
                    }
                }
            }
        }

        ipv4Settings.includedRoutes = includedRoutes
        ipv4Settings.excludedRoutes = excludedRoutes

        os_log("Split tunnel mode: %{public}@, included routes: %d, excluded routes: %d",
               log: log, type: .info, splitTunnelMode, includedRoutes.count, excludedRoutes.count)

        settings.ipv4Settings = ipv4Settings

        // DNS settings - use secure DNS
        let dnsSettings = NEDNSSettings(servers: ["1.1.1.1", "8.8.8.8"])
        settings.dnsSettings = dnsSettings

        // MTU - matches SHARD_OVERHEAD calculation (1400 - 300 = 1100 payload)
        settings.mtu = 1400

        return settings
    }

    /// Parse an IP address or CIDR notation into an NEIPv4Route
    private func parseIPRoute(_ target: String) -> NEIPv4Route? {
        // Handle CIDR notation (e.g., "192.168.1.0/24")
        if target.contains("/") {
            let parts = target.split(separator: "/")
            guard parts.count == 2,
                  let prefix = Int(parts[1]),
                  prefix >= 0 && prefix <= 32 else {
                return nil
            }

            let ip = String(parts[0])
            let subnetMask = cidrToSubnetMask(prefix)
            return NEIPv4Route(destinationAddress: ip, subnetMask: subnetMask)
        } else {
            // Single IP address - use /32 mask
            return NEIPv4Route(destinationAddress: target, subnetMask: "255.255.255.255")
        }
    }

    /// Convert CIDR prefix to subnet mask
    private func cidrToSubnetMask(_ prefix: Int) -> String {
        let mask = prefix == 0 ? 0 : ~(UInt32.max >> prefix)
        return [
            (mask >> 24) & 0xFF,
            (mask >> 16) & 0xFF,
            (mask >> 8) & 0xFF,
            mask & 0xFF
        ].map { String($0) }.joined(separator: ".")
    }

    // MARK: - DNS Resolution for Split Tunneling

    /// Resolve a domain name to IPv4 addresses, with caching
    private func resolveDomain(_ domain: String) -> [String] {
        // Check cache first
        if let cached = dnsCache[domain] {
            return cached
        }

        var ips: [String] = []

        // Use getaddrinfo for synchronous DNS resolution
        var hints = addrinfo()
        hints.ai_family = AF_INET    // IPv4 only
        hints.ai_socktype = SOCK_STREAM

        var result: UnsafeMutablePointer<addrinfo>?
        let status = getaddrinfo(domain, nil, &hints, &result)

        if status == 0, let addrList = result {
            var current: UnsafeMutablePointer<addrinfo>? = addrList
            while let addr = current {
                if addr.pointee.ai_family == AF_INET,
                   let sockaddr = addr.pointee.ai_addr {
                    sockaddr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { sockaddrIn in
                        var ipBuffer = [CChar](repeating: 0, count: Int(INET_ADDRSTRLEN))
                        var inAddr = sockaddrIn.pointee.sin_addr
                        inet_ntop(AF_INET, &inAddr, &ipBuffer, socklen_t(INET_ADDRSTRLEN))
                        let ip = String(cString: ipBuffer)
                        if !ips.contains(ip) {
                            ips.append(ip)
                        }
                    }
                }
                current = addr.pointee.ai_next
            }
            freeaddrinfo(addrList)
        } else {
            os_log("DNS resolution failed for '%{public}@': %{public}@",
                   log: log, type: .error, domain, String(cString: gai_strerror(status)))
        }

        if !ips.isEmpty {
            os_log("Resolved '%{public}@' to %d IPs: %{public}@",
                   log: log, type: .info, domain, ips.count, ips.joined(separator: ", "))
            dnsCache[domain] = ips
        }

        return ips
    }

    // MARK: - Split Tunneling

    /// Load split tunnel rules from shared UserDefaults
    private func loadSplitTunnelRules() {
        guard let defaults = UserDefaults(suiteName: appGroup) else {
            os_log("Failed to access app group defaults for split tunneling", log: log, type: .error)
            return
        }

        splitTunnelMode = defaults.string(forKey: "splitTunnelMode") ?? "exclude"
        splitTunnelRules = defaults.array(forKey: "splitTunnelRules") as? [[String: Any]] ?? []

        os_log("Loaded split tunnel config - mode: %{public}@, rules: %d",
               log: log, type: .info, splitTunnelMode, splitTunnelRules.count)
    }

    /// Reload split tunnel rules and apply new tunnel settings
    private func reloadSplitTunnelRules() {
        dnsCache.removeAll()
        loadSplitTunnelRules()

        // Recreate tunnel settings with new rules
        let settings = createTunnelSettings()

        setTunnelNetworkSettings(settings) { [weak self] error in
            if let error = error {
                os_log("Failed to update tunnel settings: %{public}@",
                       log: self?.log ?? .default, type: .error, error.localizedDescription)
            } else {
                os_log("Split tunnel rules reloaded successfully", log: self?.log ?? .default, type: .info)
            }
        }
    }

    // MARK: - Packet Handling

    private func startPacketHandling() {
        os_log("Starting packet handling", log: log, type: .info)

        // Read packets from the tunnel interface
        readPackets()
    }

    private func readPackets() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self = self, self.isConnected else { return }

            // Process packets on dedicated queue
            self.packetQueue.async {
                self.handlePackets(packets, protocols: protocols)
            }

            // Continue reading immediately (don't wait for processing)
            self.readPackets()
        }
    }

    private func handlePackets(_ packets: [Data], protocols: [NSNumber]) {
        guard let vpnClient = vpnClient else { return }

        var responsePackets: [Data] = []
        var responseProtocols: [NSNumber] = []

        for (packet, proto) in zip(packets, protocols) {
            // Apply bandwidth limiting if configured
            if let limiter = bandwidthLimiter {
                let delay = limiter.consumeTokens(bytes: packet.count)
                if delay > 0 {
                    // Rate limited - wait before processing
                    Thread.sleep(forTimeInterval: delay)
                }
            }

            do {
                // Tunnel packet through the P2P network
                let responseData = try vpnClient.tunnelPacket(packet: [UInt8](packet))

                // Also rate limit response
                if let limiter = bandwidthLimiter {
                    let delay = limiter.consumeTokens(bytes: responseData.count)
                    if delay > 0 {
                        Thread.sleep(forTimeInterval: delay)
                    }
                }

                // Collect response
                responsePackets.append(Data(responseData))
                responseProtocols.append(proto)

            } catch let error as TunnelCraftError {
                switch error {
                case .timeout:
                    os_log("Packet timed out", log: log, type: .debug)
                case .insufficientCredits:
                    os_log("Insufficient credits for packet", log: log, type: .error)
                    // Could trigger notification to user here
                default:
                    os_log("Packet tunnel error: %{public}@", log: log, type: .error, error.localizedDescription)
                }
            } catch {
                os_log("Packet tunnel error: %{public}@", log: log, type: .error, error.localizedDescription)
            }
        }

        // Write all responses back at once
        if !responsePackets.isEmpty {
            packetFlow.writePackets(responsePackets, withProtocols: responseProtocols)
        }
    }

    // MARK: - Sleep/Wake

    override func sleep(completionHandler: @escaping () -> Void) {
        os_log("Tunnel going to sleep", log: log, type: .info)
        completionHandler()
    }

    override func wake() {
        os_log("Tunnel waking up", log: log, type: .info)

        // Reload settings in case they changed
        let sharedDefaults = UserDefaults(suiteName: "group.com.tunnelcraft.vpn")
        let bandwidthLimitMbps = sharedDefaults?.integer(forKey: "bandwidthLimitMbps") ?? 0

        if bandwidthLimitMbps > 0 {
            bandwidthLimiter = BandwidthLimiter(mbps: bandwidthLimitMbps)
        } else {
            bandwidthLimiter = nil
        }

        // Verify connection is still valid
        if let client = vpnClient, !client.isConnected() {
            os_log("Connection lost during sleep, reconnecting...", log: log, type: .info)
            do {
                try client.start()
            } catch {
                os_log("Failed to reconnect: %{public}@", log: log, type: .error, error.localizedDescription)
            }
        }
    }

    // MARK: - App Messages

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        // Handle messages from the main app
        guard let message = String(data: messageData, encoding: .utf8) else {
            completionHandler?(nil)
            return
        }

        os_log("Received app message: %{public}@", log: log, type: .debug, message)

        if message.hasPrefix("setCredits:") {
            let creditsStr = message.replacingOccurrences(of: "setCredits:", with: "")
            if let credits = UInt64(creditsStr) {
                vpnClient?.setCredits(credits: credits)
                completionHandler?("OK".data(using: .utf8))
                return
            }
        }

        if message.hasPrefix("setPrivacyLevel:") {
            let levelStr = message.replacingOccurrences(of: "setPrivacyLevel:", with: "")
            let level: PrivacyLevel
            switch levelStr.lowercased() {
            case "direct": level = .direct
            case "light": level = .light
            case "paranoid": level = .paranoid
            default: level = .standard
            }
            vpnClient?.setPrivacyLevel(level: level)
            completionHandler?("OK".data(using: .utf8))
            return
        }

        if message.hasPrefix("setBandwidthLimit:") {
            let mbpsStr = message.replacingOccurrences(of: "setBandwidthLimit:", with: "")
            if let mbps = Int(mbpsStr), mbps > 0 {
                bandwidthLimiter = BandwidthLimiter(mbps: mbps)
            } else {
                bandwidthLimiter = nil
            }
            completionHandler?("OK".data(using: .utf8))
            return
        }

        if message == "reloadSplitTunnelRules" {
            reloadSplitTunnelRules()
            completionHandler?("OK".data(using: .utf8))
            return
        }

        if message == "getStats" {
            if let stats = vpnClient?.getStats() {
                let response = """
                {"bytesSent":\(stats.bytesSent),"bytesReceived":\(stats.bytesReceived),"uptimeSecs":\(stats.uptimeSecs)}
                """
                completionHandler?(response.data(using: .utf8))
                return
            }
        }

        if message == "getSplitTunnelConfig" {
            let response = """
            {"mode":"\(splitTunnelMode)","rulesCount":\(splitTunnelRules.count)}
            """
            completionHandler?(response.data(using: .utf8))
            return
        }

        completionHandler?(nil)
    }
}

// MARK: - Bandwidth Limiter

/// Token bucket rate limiter for bandwidth control
class BandwidthLimiter {
    private var tokens: Double
    private let maxTokens: Double
    private let refillRate: Double // tokens per second (bytes per second)
    private var lastRefill: Date
    private let lock = NSLock()

    /// Initialize with bandwidth limit in Mbps
    init(mbps: Int) {
        // Convert Mbps to bytes per second
        let bytesPerSecond = Double(mbps) * 1_000_000 / 8

        // Token bucket: max burst = 1 second of data
        self.maxTokens = bytesPerSecond
        self.tokens = bytesPerSecond
        self.refillRate = bytesPerSecond
        self.lastRefill = Date()
    }

    /// Consume tokens for sending/receiving bytes
    /// Returns delay in seconds if rate limited, 0 otherwise
    func consumeTokens(bytes: Int) -> TimeInterval {
        lock.lock()
        defer { lock.unlock() }

        // Refill tokens based on time elapsed
        let now = Date()
        let elapsed = now.timeIntervalSince(lastRefill)
        tokens = min(maxTokens, tokens + elapsed * refillRate)
        lastRefill = now

        let required = Double(bytes)

        if tokens >= required {
            // Have enough tokens, consume and proceed
            tokens -= required
            return 0
        } else {
            // Not enough tokens, calculate wait time
            let deficit = required - tokens
            let waitTime = deficit / refillRate

            // Consume all available tokens
            tokens = 0

            return waitTime
        }
    }
}
