# Building TunnelCraft

This guide covers building TunnelCraft for all supported platforms.

## Prerequisites

### All Platforms
- **Rust** 1.75+ with cargo
- **Node.js** 18+ with npm
- **Git**

### macOS
- Xcode Command Line Tools (`xcode-select --install`)
- For iOS: Full Xcode 15+, Apple Developer account

### Windows
- Visual Studio Build Tools (for native compilation)
- Or: Cross-compile from macOS using Wine (electron-builder handles this automatically)

### Linux
- Build essentials: `sudo apt install build-essential pkg-config libssl-dev`

---

## Quick Start

```bash
# Clone and setup
git clone https://github.com/craftec/tunnelcraft.git
cd tunnelcraft

# Build Rust daemon
cargo build --release

# Desktop app
cd apps/desktop
npm install
npm run dev       # Development mode
npm run package   # Build for current platform
```

---

## Desktop App (Electron)

Location: `apps/desktop/`

### Development
```bash
cd apps/desktop
npm install
npm run dev
```

### Production Builds

#### macOS
```bash
npm run package:mac
```
**Output:** `dist/TunnelCraft-*.dmg`, `dist/TunnelCraft-*.zip`

**Requirements:**
- For unsigned builds: Works out of the box
- For signed/notarized builds:
  - Apple Developer account ($99/year)
  - Set `APPLE_ID`, `APPLE_APP_SPECIFIC_PASSWORD` environment variables
  - The notarization script is at `scripts/notarize.js`

#### Windows
```bash
npm run package:win
```
**Output:** `dist/TunnelCraft Setup *.exe`, `dist/TunnelCraft-*-portable.exe`

**Requirements:**
- Icon file: `build/icon.ico` (256x256 recommended)
- Cross-compilation from macOS works via Wine (auto-installed by electron-builder)
- For signed builds: Windows code signing certificate

#### Linux
```bash
npm run package:linux
```
**Output:** `dist/TunnelCraft-*.AppImage`, `dist/tunnelcraft_*.deb`, `dist/tunnelcraft-*.rpm`

#### All Platforms
```bash
npm run package:all  # Builds for macOS, Windows, and Linux
```

### Missing Icons

The `build/` directory needs app icons:
- `icon.icns` - macOS icon (required for DMG)
- `icon.ico` - Windows icon (required for EXE)
- `icons/` - Linux icons (multiple PNG sizes)

**To generate icons from a source PNG:**
```bash
# macOS (from 1024x1024 PNG):
mkdir icon.iconset
sips -z 16 16 icon.png --out icon.iconset/icon_16x16.png
sips -z 32 32 icon.png --out icon.iconset/icon_32x32.png
# ... repeat for 64, 128, 256, 512, 1024
iconutil -c icns icon.iconset

# Windows: Use an online converter or ImageMagick
convert icon.png -define icon:auto-resize=256,128,64,48,32,16 icon.ico
```

---

## iOS App (React Native + Network Extension)

Location: `apps/mobile/`

### Prerequisites
- macOS with Xcode 15+
- CocoaPods: `sudo gem install cocoapods`
- Apple Developer account (Network Extensions require it)

### Setup
```bash
cd apps/mobile
npm install
cd ios && pod install && cd ..
```

### Build UniFFI XCFramework
The Rust library must be compiled for iOS targets:

```bash
cd apps/mobile/ios
./build-rust.sh
```

This script:
1. Builds for `aarch64-apple-ios` (device)
2. Builds for `aarch64-apple-ios-sim` and `x86_64-apple-ios` (simulator)
3. Generates Swift bindings via UniFFI
4. Creates `TunnelCraftUniFFI.xcframework`

### Development
```bash
# Simulator (VPN extension runs in fallback mode)
npm run ios

# Device (requires provisioning profile with Network Extension capability)
# Open in Xcode: apps/mobile/ios/TunnelCraft.xcworkspace
```

### Production Build
1. Open `apps/mobile/ios/TunnelCraft.xcworkspace` in Xcode
2. Select "Any iOS Device (arm64)"
3. Product → Archive
4. Distribute via App Store Connect or Ad Hoc

### Network Extension Requirements

**Apple Developer Account Setup:**
1. Create App IDs for both the main app and VPN extension:
   - `com.tunnelcraft.TunnelCraft`
   - `com.tunnelcraft.TunnelCraft.TunnelCraftVPN`
2. Enable "Network Extensions" capability for both
3. Enable "Personal VPN" and "Packet Tunnel" capabilities
4. Create App Group: `group.com.tunnelcraft.vpn`
5. Generate provisioning profiles

**Xcode Configuration:**
1. Signing & Capabilities → Add "Network Extensions"
2. Add "App Groups" with `group.com.tunnelcraft.vpn`
3. Ensure both targets (main app + extension) share the same App Group

### iOS Architecture

```
apps/mobile/ios/
├── TunnelCraft/                    # Main React Native app
│   ├── NativeModules/              # Swift bridges to React Native
│   │   ├── VPNManager.swift        # Manages NETunnelProviderManager
│   │   └── TunnelCraftVPNModule.swift
│   └── TunnelCraftVPN/             # Embedded extension code
│       └── PacketTunnelProvider.swift
├── TunnelCraftVPN/                 # Network Extension target
│   ├── Info.plist
│   └── TunnelCraftVPN.entitlements
└── TunnelCraftCore/                # Swift Package for UniFFI bindings
    ├── Package.swift
    ├── Frameworks/
    │   └── TunnelCraftUniFFI.xcframework
    └── Sources/
        └── Generated/              # Auto-generated Swift from UniFFI
```

---

## CLI Tool

Location: `apps/cli/`

```bash
cargo build --release -p tunnelcraft-cli
./target/release/tunnelcraft-cli --help
```

---

## Rust Daemon

The core daemon handles P2P networking and VPN tunneling.

```bash
# Build daemon
cargo build --release -p tunnelcraft-daemon

# Run daemon
./target/release/tunnelcraft-daemon

# Run tests
cargo test --workspace
```

### Cross-Compilation

**For Windows (from macOS):**
```bash
rustup target add x86_64-pc-windows-gnu
cargo build --release --target x86_64-pc-windows-gnu -p tunnelcraft-daemon
```

**For Linux (from macOS):**
```bash
# Requires cross-compilation toolchain
rustup target add x86_64-unknown-linux-gnu
# Note: May need linker setup or Docker-based build
```

---

## Troubleshooting

### macOS: "App is damaged" / Gatekeeper issues
```bash
xattr -cr /Applications/TunnelCraft.app
```

### Windows: Missing DLLs
Ensure Visual C++ Redistributable is installed.

### iOS: VPN fails to start
- Verify Network Extension capability in provisioning profile
- Check entitlements match App ID
- Simulator only supports fallback mode (no real VPN)

### Rust build fails
```bash
# Clean and rebuild
cargo clean
cargo build --release
```

---

## Release Checklist

- [ ] Update version in `Cargo.toml`, `apps/desktop/package.json`, `apps/mobile/package.json`
- [ ] Build and test on all platforms
- [ ] For macOS: Notarize the DMG
- [ ] For Windows: Sign the EXE
- [ ] For iOS: Submit to App Store with proper screenshots
- [ ] Create GitHub release with artifacts

---

## Current Build Status

| Platform | Status | Output |
|----------|--------|--------|
| macOS DMG (Universal) | ✅ Working | `dist/TunnelCraft-0.1.0.dmg` (801MB) |
| macOS DMG (ARM64) | ✅ Working | `dist/TunnelCraft-0.1.0-arm64.dmg` (1.0GB) |
| macOS ZIP | ✅ Working | `dist/TunnelCraft-0.1.0-mac.zip` (747MB) |
| Windows Portable | ✅ Working | `dist/win-unpacked/TunnelCraft.exe` (169MB) |
| Windows NSIS Installer | ⚠️ Needs icon.ico | Add `build/icon.ico` then re-run |
| Linux AppImage | 🔲 Not tested | Run `npm run package:linux` |
| iOS | ⚠️ Manual Xcode | Requires Apple Developer + Network Extension capability |
| Android | 🔲 Not implemented | - |

### To Complete Windows Installer

1. Create `apps/desktop/build/icon.ico` (256x256 or larger)
2. Run `npm run package:win`

### To Build for iOS

1. Ensure Apple Developer enrollment with Network Extension capability
2. Run `cd apps/mobile/ios && ./build-rust.sh` to build UniFFI xcframework
3. Open `TunnelCraft.xcworkspace` in Xcode
4. Configure signing with your provisioning profiles
5. Build and archive
