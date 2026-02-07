//! TunnelCraft CLI
//!
//! Command-line interface for the TunnelCraft VPN client and node operator.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use libp2p::{Multiaddr, PeerId};
use tracing::info;

use tunnelcraft_app::{AppBuilder, AppType, ImplementationMatrix};
use tunnelcraft_client::{NodeConfig, NodeMode, NodeType, TunnelCraftNode};
use tunnelcraft_core::HopMode;
use tunnelcraft_ipc_client::{IpcClient, DEFAULT_SOCKET_PATH};
use tunnelcraft_keystore::{expand_path, load_or_generate_libp2p_keypair};

/// TunnelCraft - Decentralized Trustless VPN
#[derive(Parser)]
#[command(name = "tunnelcraft")]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Socket path for daemon communication
    #[arg(long, default_value = DEFAULT_SOCKET_PATH)]
    socket: PathBuf,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Connect to the TunnelCraft network
    Connect {
        /// Number of relay hops (0-3)
        #[arg(short = 'n', long, default_value = "2")]
        hops: u8,

        /// Preferred exit region (na, eu, ap, sa, af, me, oc)
        #[arg(long)]
        exit_region: Option<String>,
    },

    /// Disconnect from the network
    Disconnect,

    /// Show connection status
    Status,

    /// Show node statistics (relay/exit metrics)
    Stats,

    /// Get or set the node mode
    Mode {
        /// Mode to set (client, node, both). Omit to show current mode.
        mode: Option<String>,
    },

    /// List available exit nodes
    Exits,

    /// Get or set the privacy level
    Privacy {
        /// Privacy level to set (direct, light, standard, paranoid). Omit to show current.
        level: Option<String>,
    },

    /// Toggle local peer discovery
    Discovery {
        /// Enable or disable (on/off). Omit to show current.
        state: Option<String>,
    },

    /// Show or manage credits
    Credits {
        #[command(subcommand)]
        action: Option<CreditsAction>,
    },

    /// Make an HTTP request through the tunnel (for testing)
    Request {
        /// HTTP method
        #[arg(short, long, default_value = "GET")]
        method: String,

        /// URL to request
        url: String,

        /// Request body (for POST/PUT)
        #[arg(short, long)]
        body: Option<String>,

        /// Request headers (key:value format)
        #[arg(short = 'H', long)]
        header: Vec<String>,
    },

    /// Start the daemon (usually run by system service)
    Daemon {
        /// Run as a bootstrap node (relay-only, no exit, no settlement)
        #[arg(long)]
        bootstrap: bool,

        /// Listen port for bootstrap mode
        #[arg(long, default_value = "9000")]
        port: u16,
    },

    /// Run in standalone mode (SDK direct, no daemon)
    Run {
        /// Number of relay hops (0-3)
        #[arg(short = 'n', long, default_value = "2")]
        hops: u8,

        /// Bootstrap peer address
        #[arg(short, long)]
        bootstrap: Option<String>,

        /// Listen address for libp2p
        #[arg(short, long, default_value = "/ip4/0.0.0.0/tcp/0")]
        listen: String,
    },

    /// Fetch a URL using SDK directly (standalone mode)
    Fetch {
        /// URL to fetch
        url: String,

        /// Number of relay hops (0-3)
        #[arg(short = 'n', long, default_value = "2")]
        hops: u8,

        /// Bootstrap peer address
        #[arg(short, long)]
        bootstrap: Option<String>,
    },

    /// Run as a network node (relay/exit) to earn credits
    Node {
        #[command(subcommand)]
        mode: NodeSubcommand,
    },

    /// Show connection history
    History,

    /// Show earnings history
    Earnings,

    /// Run a speed test
    Speedtest,

    /// Set bandwidth limit (in kbps)
    Bandwidth {
        /// Bandwidth limit in kbps (omit to show current, 0 to remove limit)
        limit: Option<u64>,
    },

    /// Key management
    Key {
        #[command(subcommand)]
        action: KeyAction,
    },

    /// Developer tools and diagnostics
    Dev {
        #[command(subcommand)]
        action: DevAction,
    },
}

#[derive(Subcommand)]
enum NodeSubcommand {
    /// Run as relay node only
    Relay {
        /// Listen address
        #[arg(short, long, default_value = "/ip4/0.0.0.0/tcp/9000")]
        listen: String,

        /// Bootstrap peer (format: <peer_id>@<multiaddr>)
        #[arg(short, long)]
        bootstrap: Vec<String>,

        /// Path to keypair file
        #[arg(long, default_value = "~/.tunnelcraft/node.key")]
        keyfile: PathBuf,

        /// Allow being last hop (required for settlement)
        #[arg(long)]
        allow_last_hop: bool,
    },

    /// Run as exit node (also relays)
    Exit {
        /// Listen address
        #[arg(short, long, default_value = "/ip4/0.0.0.0/tcp/9000")]
        listen: String,

        /// Bootstrap peer (format: <peer_id>@<multiaddr>)
        #[arg(short, long)]
        bootstrap: Vec<String>,

        /// Path to keypair file
        #[arg(long, default_value = "~/.tunnelcraft/node.key")]
        keyfile: PathBuf,

        /// HTTP request timeout in seconds
        #[arg(long, default_value = "30")]
        timeout: u64,
    },

    /// Run as full node (relay + exit)
    Full {
        /// Listen address
        #[arg(short, long, default_value = "/ip4/0.0.0.0/tcp/9000")]
        listen: String,

        /// Bootstrap peer (format: <peer_id>@<multiaddr>)
        #[arg(short, long)]
        bootstrap: Vec<String>,

        /// Path to keypair file
        #[arg(long, default_value = "~/.tunnelcraft/node.key")]
        keyfile: PathBuf,

        /// HTTP request timeout in seconds
        #[arg(long, default_value = "30")]
        timeout: u64,
    },

    /// Show node information
    Info {
        /// Path to keypair file
        #[arg(long, default_value = "~/.tunnelcraft/node.key")]
        keyfile: PathBuf,
    },
}

#[derive(Subcommand)]
enum CreditsAction {
    /// Show current credit balance
    Show,
    /// Purchase credits
    Buy {
        /// Amount of credits to purchase
        amount: u64,
    },
}

#[derive(Subcommand)]
enum KeyAction {
    /// Export private key (encrypted)
    Export {
        /// Path to export the key to
        path: String,

        /// Password to encrypt the key
        #[arg(short, long)]
        password: String,
    },
    /// Import private key (encrypted)
    Import {
        /// Path to import the key from
        path: String,

        /// Password to decrypt the key
        #[arg(short, long)]
        password: String,
    },
}

#[derive(Subcommand)]
enum DevAction {
    /// Show feature implementation matrix
    Matrix,
    /// Show implementation gaps report
    Gaps,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize app with standard startup sequence
    let app_type = match &cli.command {
        Commands::Daemon { .. } => AppType::Daemon,
        Commands::Node { .. } => AppType::Node,
        _ => AppType::Cli,
    };

    let _app = AppBuilder::new()
        .name("tunnelcraft")
        .version(env!("CARGO_PKG_VERSION"))
        .app_type(app_type)
        .verbose(cli.verbose)
        .build()
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    match cli.command {
        Commands::Connect { hops, exit_region } => {
            connect(&cli.socket, hops, exit_region).await?;
        }
        Commands::Disconnect => {
            disconnect(&cli.socket).await?;
        }
        Commands::Status => {
            status(&cli.socket).await?;
        }
        Commands::Stats => {
            stats(&cli.socket).await?;
        }
        Commands::Mode { mode } => {
            mode_cmd(&cli.socket, mode).await?;
        }
        Commands::Exits => {
            exits(&cli.socket).await?;
        }
        Commands::Privacy { level } => {
            privacy_cmd(&cli.socket, level).await?;
        }
        Commands::Discovery { state } => {
            discovery_cmd(&cli.socket, state).await?;
        }
        Commands::Credits { action } => {
            credits(&cli.socket, action).await?;
        }
        Commands::Request {
            method,
            url,
            body,
            header,
        } => {
            request(&cli.socket, &method, &url, body, header).await?;
        }
        Commands::Daemon { bootstrap, port } => {
            run_daemon(bootstrap, port).await?;
        }
        Commands::Run {
            hops,
            bootstrap,
            listen,
        } => {
            run_standalone(hops, bootstrap, listen).await?;
        }
        Commands::Fetch {
            url,
            hops,
            bootstrap,
        } => {
            fetch_standalone(&url, hops, bootstrap).await?;
        }
        Commands::Node { mode } => {
            run_node(mode).await?;
        }
        Commands::History => {
            history(&cli.socket).await?;
        }
        Commands::Earnings => {
            earnings_history(&cli.socket).await?;
        }
        Commands::Speedtest => {
            speedtest(&cli.socket).await?;
        }
        Commands::Bandwidth { limit } => {
            bandwidth_cmd(&cli.socket, limit).await?;
        }
        Commands::Key { action } => {
            key_cmd(&cli.socket, action).await?;
        }
        Commands::Dev { action } => {
            run_dev(action);
        }
    }

    Ok(())
}

// ============================================================================
// Developer Tools
// ============================================================================

fn run_dev(action: DevAction) {
    match action {
        DevAction::Matrix => {
            let matrix = ImplementationMatrix::current();
            matrix.print_matrix();
        }
        DevAction::Gaps => {
            let matrix = ImplementationMatrix::current();
            matrix.print_gaps_report();
        }
    }
}

// ============================================================================
// IPC Commands (using shared ipc-client crate)
// ============================================================================

async fn connect(socket: &PathBuf, hops: u8, exit_region: Option<String>) -> Result<()> {
    info!("Connecting to TunnelCraft network with {} hops...", hops);

    let client = IpcClient::new(socket.clone());

    // Set exit region preference before connecting
    if let Some(ref region) = exit_region {
        client.set_exit_node(region, None, None).await
            .context("Failed to set exit region")?;
        println!("Exit region set to: {}", region);
    }

    let result = client.connect_vpn(hops).await?;

    if result.connected {
        println!("Connected to TunnelCraft network");
        if let Some(exit) = result.exit_node {
            println!("Exit node: {}", exit);
        }
    } else {
        println!("Connection initiated...");
    }

    Ok(())
}

async fn disconnect(socket: &PathBuf) -> Result<()> {
    info!("Disconnecting from TunnelCraft network...");

    let client = IpcClient::new(socket.clone());
    client.disconnect().await?;

    println!("Disconnected from TunnelCraft network");
    Ok(())
}

async fn status(socket: &PathBuf) -> Result<()> {
    let client = IpcClient::new(socket.clone());

    // Use raw send_request to get the full status including new fields
    let result = client.send_request("status", None).await?;

    println!("TunnelCraft Status");
    println!("==================");
    println!("State:         {}", result.get("state").and_then(|v| v.as_str()).unwrap_or("unknown"));
    println!("Connected:     {}", result.get("connected").and_then(|v| v.as_bool()).unwrap_or(false));

    if let Some(mode) = result.get("mode").and_then(|v| v.as_str()) {
        println!("Mode:          {}", mode);
    }
    if let Some(privacy) = result.get("privacy_level").and_then(|v| v.as_str()) {
        println!("Privacy:       {}", privacy);
    }
    if let Some(exit) = result.get("exit_node").and_then(|v| v.as_str()) {
        println!("Exit node:     {}", exit);
    }
    if let Some(peers) = result.get("peer_count").and_then(|v| v.as_u64()) {
        println!("Peers:         {}", peers);
    }
    if let Some(shards) = result.get("shards_relayed").and_then(|v| v.as_u64()) {
        println!("Shards relayed:{}", shards);
    }
    if let Some(exited) = result.get("requests_exited").and_then(|v| v.as_u64()) {
        println!("Requests exited:{}", exited);
    }
    if let Some(credits) = result.get("credits").and_then(|v| v.as_u64()) {
        println!("Credits:       {}", credits);
        if credits <= 20 {
            eprintln!("\x1b[31mCRITICAL: Credit balance critically low!\x1b[0m");
        } else if credits <= 100 {
            eprintln!("\x1b[33mWARNING: Credits running low.\x1b[0m");
        }
    }

    Ok(())
}

async fn stats(socket: &PathBuf) -> Result<()> {
    let client = IpcClient::new(socket.clone());
    let result = client.get_node_stats().await?;

    println!("TunnelCraft Node Statistics");
    println!("===========================");
    println!("Shards relayed:   {}", result.shards_relayed);
    println!("Requests exited:  {}", result.requests_exited);
    println!("Peers connected:  {}", result.peers_connected);
    println!("Credits earned:   {}", result.credits_earned);
    println!("Credits spent:    {}", result.credits_spent);
    println!("Bytes sent:       {}", format_bytes(result.bytes_sent));
    println!("Bytes received:   {}", format_bytes(result.bytes_received));
    println!("Bytes relayed:    {}", format_bytes(result.bytes_relayed));

    Ok(())
}

fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        return format!("{} B", bytes);
    }
    if bytes < 1024 * 1024 {
        return format!("{:.1} KB", bytes as f64 / 1024.0);
    }
    if bytes < 1024 * 1024 * 1024 {
        return format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0));
    }
    format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
}

async fn mode_cmd(socket: &PathBuf, mode: Option<String>) -> Result<()> {
    let client = IpcClient::new(socket.clone());

    match mode {
        Some(new_mode) => {
            client.set_mode(&new_mode).await
                .context("Failed to set mode")?;
            println!("Mode set to: {}", new_mode);
        }
        None => {
            let result = client.send_request("status", None).await?;
            let current_mode = result.get("mode")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            println!("Current mode: {}", current_mode);
        }
    }

    Ok(())
}

async fn exits(socket: &PathBuf) -> Result<()> {
    let client = IpcClient::new(socket.clone());
    let result = client.get_available_exits().await?;

    if result.exits.is_empty() {
        println!("No exit nodes available. Connect to the network first.");
        return Ok(());
    }

    println!("Available Exit Nodes");
    println!("====================");
    println!("{:<12} {:<8} {:<15} {:<8} {:<8} {:<10}",
        "Pubkey", "Region", "City", "Score", "Load", "Latency");
    println!("{}", "-".repeat(65));

    for exit in &result.exits {
        let city = exit.city.as_deref().unwrap_or("-");
        let cc = exit.country_code.as_deref().unwrap_or("-");
        let latency = exit.latency_ms
            .map(|l| format!("{}ms", l))
            .unwrap_or_else(|| "-".to_string());
        let pubkey_short = if exit.pubkey.len() > 10 {
            format!("{}...", &exit.pubkey[..10])
        } else {
            exit.pubkey.clone()
        };

        println!("{:<12} {:<3}/{:<4} {:<15} {:<8} {:<7}% {:<10}",
            pubkey_short, cc, exit.region, city, exit.score, exit.load, latency);
    }

    println!("\n{} exit node(s) available", result.exits.len());
    Ok(())
}

async fn privacy_cmd(socket: &PathBuf, level: Option<String>) -> Result<()> {
    let client = IpcClient::new(socket.clone());

    match level {
        Some(new_level) => {
            client.set_privacy_level(&new_level).await
                .context("Failed to set privacy level")?;
            let hops = match new_level.as_str() {
                "direct" => 0,
                "light" => 1,
                "standard" => 2,
                "paranoid" => 3,
                _ => 0,
            };
            println!("Privacy level set to: {} ({} hops)", new_level, hops);
        }
        None => {
            let result = client.send_request("status", None).await?;
            let current = result.get("privacy_level")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            println!("Current privacy level: {}", current);
        }
    }

    Ok(())
}

async fn discovery_cmd(socket: &PathBuf, state: Option<String>) -> Result<()> {
    let client = IpcClient::new(socket.clone());

    match state {
        Some(s) => {
            let enabled = match s.to_lowercase().as_str() {
                "on" | "true" | "enable" | "yes" | "1" => true,
                "off" | "false" | "disable" | "no" | "0" => false,
                _ => {
                    eprintln!("Invalid state: {}. Use on/off.", s);
                    return Ok(());
                }
            };
            client.set_local_discovery(enabled).await
                .context("Failed to set local discovery")?;
            println!("Local discovery: {}", if enabled { "enabled" } else { "disabled" });
        }
        None => {
            println!("Local discovery: use 'tunnelcraft discovery on/off' to toggle");
        }
    }

    Ok(())
}

async fn credits(socket: &PathBuf, action: Option<CreditsAction>) -> Result<()> {
    let client = IpcClient::new(socket.clone());

    match action {
        Some(CreditsAction::Buy { amount }) => {
            info!("Purchasing {} credits...", amount);
            let result = client.purchase_credits(amount).await?;
            println!("Purchase result: {}", result);
        }
        Some(CreditsAction::Show) | None => {
            let result = client.get_credits().await?;
            println!("Current credits: {}", result.credits);

            if result.credits <= 20 {
                eprintln!("\x1b[31mCRITICAL: Credit balance is critically low! Purchase credits to continue using the network.\x1b[0m");
            } else if result.credits <= 100 {
                eprintln!("\x1b[33mWARNING: Credit balance is running low. Consider purchasing more credits.\x1b[0m");
            }
        }
    }

    Ok(())
}

async fn request(
    socket: &PathBuf,
    method: &str,
    url: &str,
    body: Option<String>,
    headers: Vec<String>,
) -> Result<()> {
    info!("Making {} request to {}", method, url);

    let client = IpcClient::new(socket.clone());

    // Build headers map
    let headers_map: std::collections::HashMap<String, String> = headers
        .iter()
        .filter_map(|h| {
            let parts: Vec<&str> = h.splitn(2, ':').collect();
            if parts.len() == 2 {
                Some((parts[0].trim().to_string(), parts[1].trim().to_string()))
            } else {
                None
            }
        })
        .collect();

    let params = serde_json::json!({
        "method": method,
        "url": url,
        "body": body,
        "headers": headers_map,
    });

    let result = client.send_request("request", Some(params)).await?;

    if let Some(status) = result.get("status") {
        println!("Status: {}", status);
    }
    if let Some(body) = result.get("body") {
        println!("\n{}", body);
    }

    Ok(())
}

// ============================================================================
// New Feature Commands
// ============================================================================

async fn history(socket: &PathBuf) -> Result<()> {
    let client = IpcClient::new(socket.clone());
    let result = client.get_connection_history().await?;

    println!("Connection History");
    println!("==================");

    if result.entries.is_empty() {
        println!("No connection history yet.");
        return Ok(());
    }

    println!("{:<4} {:<20} {:<12} {:<12} {:<12}", "ID", "Connected", "Duration", "Sent", "Received");
    println!("{}", "-".repeat(60));

    for entry in &result.entries {
        let duration = entry.duration_secs
            .map(|d| format!("{}s", d))
            .unwrap_or_else(|| "active".to_string());
        println!("{:<4} {:<20} {:<12} {:<12} {:<12}",
            entry.id,
            entry.connected_at,
            duration,
            format_bytes(entry.bytes_sent),
            format_bytes(entry.bytes_received),
        );
    }

    println!("\n{} connection(s)", result.entries.len());
    Ok(())
}

async fn earnings_history(socket: &PathBuf) -> Result<()> {
    let client = IpcClient::new(socket.clone());
    let result = client.get_earnings_history().await?;

    println!("Earnings History");
    println!("================");

    if result.entries.is_empty() {
        println!("No earnings yet.");
        return Ok(());
    }

    println!("{:<4} {:<12} {:<10} {:<12} {:<8}", "ID", "Timestamp", "Type", "Credits", "Shards");
    println!("{}", "-".repeat(50));

    for entry in &result.entries {
        println!("{:<4} {:<12} {:<10} {:<12} {:<8}",
            entry.id,
            entry.timestamp,
            entry.entry_type,
            entry.credits_earned,
            entry.shards_count,
        );
    }

    println!("\n{} earning(s)", result.entries.len());
    Ok(())
}

async fn speedtest(socket: &PathBuf) -> Result<()> {
    println!("Running speed test...");

    let client = IpcClient::new(socket.clone());
    let result = client.run_speed_test().await?;

    println!("Speed Test Results");
    println!("==================");
    println!("Download:  {:.1} Mbps", result.result.download_mbps);
    println!("Upload:    {:.1} Mbps", result.result.upload_mbps);
    println!("Latency:   {} ms", result.result.latency_ms);
    println!("Jitter:    {} ms", result.result.jitter_ms);

    Ok(())
}

async fn bandwidth_cmd(socket: &PathBuf, limit: Option<u64>) -> Result<()> {
    let client = IpcClient::new(socket.clone());

    match limit {
        Some(0) => {
            client.set_bandwidth_limit(None).await?;
            println!("Bandwidth limit removed (unlimited)");
        }
        Some(kbps) => {
            client.set_bandwidth_limit(Some(kbps)).await?;
            println!("Bandwidth limit set to {} kbps ({:.1} Mbps)", kbps, kbps as f64 / 1000.0);
        }
        None => {
            println!("Usage: tunnelcraft bandwidth <limit_kbps>");
            println!("  Set to 0 to remove limit");
            println!("  Example: tunnelcraft bandwidth 5000  (5 Mbps)");
        }
    }

    Ok(())
}

async fn key_cmd(socket: &PathBuf, action: KeyAction) -> Result<()> {
    let client = IpcClient::new(socket.clone());

    match action {
        KeyAction::Export { path, password } => {
            let result = client.export_key(&path, &password).await?;
            println!("Key exported to: {}", result.path);
            println!("Public key: {}", result.public_key);
        }
        KeyAction::Import { path, password } => {
            let result = client.import_key(&path, &password).await?;
            println!("Key imported successfully");
            println!("Public key: {}", result.public_key);
            println!("Note: Restart the daemon to use the new key");
        }
    }

    Ok(())
}

// ============================================================================
// Daemon
// ============================================================================

async fn run_daemon(bootstrap: bool, port: u16) -> Result<()> {
    use tunnelcraft_daemon::{DaemonService, IpcConfig, IpcServer};

    if bootstrap {
        info!("Starting TunnelCraft BOOTSTRAP node on port {}...", port);

        // In bootstrap mode, run a relay-only node with no exit or settlement
        let keyfile = PathBuf::from("~/.tunnelcraft/bootstrap.key");
        let listen = format!("/ip4/0.0.0.0/tcp/{}", port);

        let libp2p_keypair = load_or_generate_libp2p_keypair(&keyfile)
            .map_err(|e| anyhow::anyhow!("Failed to load keypair: {}", e))?;
        let peer_id = PeerId::from(libp2p_keypair.public());

        println!("Bootstrap node Peer ID: {}", peer_id);
        println!("Listening on: {}", listen);
        println!("Share this address with peers:");
        println!("  /ip4/<YOUR_PUBLIC_IP>/tcp/{}/p2p/{}", port, peer_id);

        let listen_addr: Multiaddr = listen.parse().context("Invalid listen address")?;

        let config = NodeConfig {
            mode: NodeMode::Node,
            node_type: NodeType::Relay,
            listen_addr,
            bootstrap_peers: Vec::new(),
            allow_last_hop: false,
            request_timeout: Duration::from_secs(30),
            libp2p_keypair: Some(libp2p_keypair),
            ..Default::default()
        };

        let mut node = TunnelCraftNode::new(config)?;
        node.start().await?;

        info!("Bootstrap node running. Press Ctrl+C to stop.");

        tokio::select! {
            _ = node.run() => {}
            _ = tokio::signal::ctrl_c() => {}
        }

        node.stop().await;
        return Ok(());
    }

    info!("Starting TunnelCraft daemon...");

    let config = IpcConfig::default();
    let service = DaemonService::new().map_err(|e| anyhow::anyhow!("{}", e))?;

    info!("IPC server listening on {:?}", config.socket_path);

    let mut server = IpcServer::new(config);
    server
        .start(service)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    // Wait for shutdown
    tokio::signal::ctrl_c().await?;
    server.stop().await;

    Ok(())
}

// ============================================================================
// Standalone Mode (direct SDK usage)
// ============================================================================

async fn run_standalone(hops: u8, bootstrap: Option<String>, listen: String) -> Result<()> {
    info!("Running in standalone mode with {} hops", hops);

    let hop_mode = match hops {
        0 => HopMode::Direct,
        1 => HopMode::Light,
        2 => HopMode::Standard,
        _ => HopMode::Paranoid,
    };

    let listen_addr: Multiaddr = listen.parse().context("Invalid listen address")?;

    let mut bootstrap_peers = Vec::new();
    if let Some(peer_str) = bootstrap {
        if let Some((peer_id_str, addr_str)) = peer_str.split_once('@') {
            let peer_id: PeerId = peer_id_str.parse().context("Invalid peer ID")?;
            let addr: Multiaddr = addr_str.parse().context("Invalid address")?;
            bootstrap_peers.push((peer_id, addr));
        }
    }

    let config = NodeConfig {
        mode: NodeMode::Client,
        hop_mode,
        listen_addr,
        bootstrap_peers,
        ..Default::default()
    };

    let mut node = TunnelCraftNode::new(config)?;
    node.start().await?;

    info!("Node connected. Press Ctrl+C to stop.");

    // Wait for shutdown
    tokio::signal::ctrl_c().await?;
    node.stop().await;

    Ok(())
}

async fn fetch_standalone(url: &str, hops: u8, bootstrap: Option<String>) -> Result<()> {
    info!("Fetching {} with {} hops", url, hops);

    let hop_mode = match hops {
        0 => HopMode::Direct,
        1 => HopMode::Light,
        2 => HopMode::Standard,
        _ => HopMode::Paranoid,
    };

    let mut bootstrap_peers = Vec::new();
    if let Some(peer_str) = bootstrap {
        if let Some((peer_id_str, addr_str)) = peer_str.split_once('@') {
            let peer_id: PeerId = peer_id_str.parse().context("Invalid peer ID")?;
            let addr: Multiaddr = addr_str.parse().context("Invalid address")?;
            bootstrap_peers.push((peer_id, addr));
        }
    }

    let config = NodeConfig {
        mode: NodeMode::Client,
        hop_mode,
        bootstrap_peers,
        ..Default::default()
    };

    let mut node = TunnelCraftNode::new(config)?;
    node.start().await?;

    // Wait for exit node discovery before making the request
    node.wait_for_exit(std::time::Duration::from_secs(15)).await?;

    info!("Node connected, making request...");

    match node.get(url).await {
        Ok(response) => {
            println!("Status: {}", response.status);
            println!("\n{}", String::from_utf8_lossy(&response.body));
        }
        Err(e) => {
            eprintln!("Request failed: {}", e);
        }
    }

    node.stop().await;
    Ok(())
}

// ============================================================================
// Node Operations (using TunnelCraftNode directly)
// ============================================================================

async fn run_node(mode: NodeSubcommand) -> Result<()> {
    match mode {
        NodeSubcommand::Relay {
            listen,
            bootstrap,
            keyfile,
            allow_last_hop,
        } => {
            run_node_with_config(NodeType::Relay, &listen, &bootstrap, &keyfile, allow_last_hop, 30)
                .await
        }
        NodeSubcommand::Exit {
            listen,
            bootstrap,
            keyfile,
            timeout,
        } => run_node_with_config(NodeType::Exit, &listen, &bootstrap, &keyfile, true, timeout).await,
        NodeSubcommand::Full {
            listen,
            bootstrap,
            keyfile,
            timeout,
        } => run_node_with_config(NodeType::Full, &listen, &bootstrap, &keyfile, true, timeout).await,
        NodeSubcommand::Info { keyfile } => show_node_info(&keyfile),
    }
}

fn show_node_info(keyfile: &PathBuf) -> Result<()> {
    let keypair = load_or_generate_libp2p_keypair(keyfile)
        .map_err(|e| anyhow::anyhow!("Failed to load keypair: {}", e))?;
    let peer_id = PeerId::from(keypair.public());

    println!("TunnelCraft Node Information");
    println!("============================");
    println!("Peer ID: {}", peer_id);
    println!("Keyfile: {:?}", expand_path(keyfile));

    Ok(())
}

async fn run_node_with_config(
    node_type: NodeType,
    listen: &str,
    bootstrap: &[String],
    keyfile: &PathBuf,
    allow_last_hop: bool,
    timeout_secs: u64,
) -> Result<()> {
    info!("Starting TunnelCraft node in {:?} mode", node_type);

    // Load or generate libp2p keypair using shared keystore
    let libp2p_keypair = load_or_generate_libp2p_keypair(keyfile)
        .map_err(|e| anyhow::anyhow!("Failed to load keypair: {}", e))?;
    let peer_id = PeerId::from(libp2p_keypair.public());
    info!("Node Peer ID: {}", peer_id);

    // Parse listen address
    let listen_addr: Multiaddr = listen.parse().context("Invalid listen address")?;

    // Parse bootstrap peers
    let bootstrap_peers = parse_bootstrap_peers(bootstrap)?;

    // Map NodeType to enable_exit flag
    let enable_exit = matches!(node_type, NodeType::Exit | NodeType::Full);

    // Create node config using TunnelCraftNode
    let config = NodeConfig {
        mode: NodeMode::Node,
        node_type,
        listen_addr,
        bootstrap_peers,
        allow_last_hop,
        enable_exit,
        request_timeout: Duration::from_secs(timeout_secs),
        libp2p_keypair: Some(libp2p_keypair),
        ..Default::default()
    };

    // Create and start node
    let mut node = TunnelCraftNode::new(config)?;
    node.start().await?;

    info!(
        "Node running on {}. Press Ctrl+C to stop.",
        listen
    );

    // Run the node event loop until Ctrl+C
    tokio::select! {
        _ = node.run() => {}
        _ = tokio::signal::ctrl_c() => {}
    }

    // Print stats
    let stats = node.stats();
    info!("Shards relayed: {}", stats.shards_relayed);
    info!("Requests exited: {}", stats.requests_exited);

    node.stop().await;
    Ok(())
}

/// Parse bootstrap peer strings in format "peer_id@multiaddr"
fn parse_bootstrap_peers(peers: &[String]) -> Result<Vec<(PeerId, Multiaddr)>> {
    let mut result = Vec::new();
    for peer_str in peers {
        if let Some((peer_id_str, addr_str)) = peer_str.split_once('@') {
            let peer_id: PeerId = peer_id_str
                .parse()
                .context("Invalid peer ID in bootstrap")?;
            let addr: Multiaddr = addr_str.parse().context("Invalid address in bootstrap")?;
            result.push((peer_id, addr));
        } else {
            tracing::warn!(
                "Invalid bootstrap format: {}. Expected: <peer_id>@<multiaddr>",
                peer_str
            );
        }
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cli_parsing() {
        use clap::CommandFactory;
        Cli::command().debug_assert();
    }

    #[test]
    fn test_connect_with_hops() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let matches = cmd.try_get_matches_from(vec!["tunnelcraft", "connect", "-n", "3"]);
        assert!(matches.is_ok());
    }

    #[test]
    fn test_connect_with_exit_region() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let matches = cmd.try_get_matches_from(vec!["tunnelcraft", "connect", "--exit-region", "eu"]);
        assert!(matches.is_ok());
    }

    #[test]
    fn test_stats_command() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let matches = cmd.try_get_matches_from(vec!["tunnelcraft", "stats"]);
        assert!(matches.is_ok());
    }

    #[test]
    fn test_mode_command() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let matches = cmd.try_get_matches_from(vec!["tunnelcraft", "mode", "client"]);
        assert!(matches.is_ok());
    }

    #[test]
    fn test_mode_show() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let matches = cmd.try_get_matches_from(vec!["tunnelcraft", "mode"]);
        assert!(matches.is_ok());
    }

    #[test]
    fn test_exits_command() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let matches = cmd.try_get_matches_from(vec!["tunnelcraft", "exits"]);
        assert!(matches.is_ok());
    }

    #[test]
    fn test_privacy_command() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let matches = cmd.try_get_matches_from(vec!["tunnelcraft", "privacy", "standard"]);
        assert!(matches.is_ok());
    }

    #[test]
    fn test_privacy_show() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let matches = cmd.try_get_matches_from(vec!["tunnelcraft", "privacy"]);
        assert!(matches.is_ok());
    }

    #[test]
    fn test_discovery_command() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let matches = cmd.try_get_matches_from(vec!["tunnelcraft", "discovery", "on"]);
        assert!(matches.is_ok());
    }

    #[test]
    fn test_run_standalone() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let matches = cmd.try_get_matches_from(vec![
            "tunnelcraft",
            "run",
            "-n",
            "2",
            "-b",
            "12D3KooWQNV9B3aYrwqXfzQA9K6c1AzPLQVLyZsyYqNqXcT7Th5E@/ip4/127.0.0.1/tcp/9000",
        ]);
        assert!(matches.is_ok());
    }

    #[test]
    fn test_fetch_standalone() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let matches = cmd.try_get_matches_from(vec![
            "tunnelcraft",
            "fetch",
            "https://example.com",
            "-n",
            "1",
        ]);
        assert!(matches.is_ok());
    }

    #[test]
    fn test_credits_show() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let matches = cmd.try_get_matches_from(vec!["tunnelcraft", "credits", "show"]);
        assert!(matches.is_ok());
    }

    #[test]
    fn test_credits_buy() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let matches = cmd.try_get_matches_from(vec!["tunnelcraft", "credits", "buy", "100"]);
        assert!(matches.is_ok());
    }

    #[test]
    fn test_request_with_headers() {
        use clap::CommandFactory;
        let cmd = Cli::command();
        let matches = cmd.try_get_matches_from(vec![
            "tunnelcraft",
            "request",
            "-m",
            "POST",
            "https://api.example.com/data",
            "-H",
            "Content-Type: application/json",
            "-b",
            "{\"key\": \"value\"}",
        ]);
        assert!(matches.is_ok());
    }

    #[test]
    fn test_parse_bootstrap_peers() {
        let peers = vec![
            "12D3KooWQNV9B3aYrwqXfzQA9K6c1AzPLQVLyZsyYqNqXcT7Th5E@/ip4/127.0.0.1/tcp/9000"
                .to_string(),
        ];
        let result = parse_bootstrap_peers(&peers);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 1);
    }

    #[test]
    fn test_parse_bootstrap_peers_invalid() {
        let peers = vec!["invalid_format".to_string()];
        let result = parse_bootstrap_peers(&peers);
        assert!(result.is_ok());
        assert_eq!(result.unwrap().len(), 0); // Invalid format is skipped with warning
    }
}
