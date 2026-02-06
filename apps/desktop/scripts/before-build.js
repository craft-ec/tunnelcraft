/**
 * Pre-build script
 * 
 * Runs before electron-builder packages the app.
 * Used to build the Rust daemon if needed.
 */

const { execSync } = require('child_process');
const path = require('path');
const fs = require('fs');

exports.default = async function beforeBuild(context) {
  const { electronPlatformName, arch } = context;
  
  console.log(`Pre-build for ${electronPlatformName} (${arch})`);

  const projectRoot = path.resolve(__dirname, '../../..');
  const daemonPath = path.join(projectRoot, 'target/release/tunnelcraft-daemon');

  // Check if daemon exists
  if (!fs.existsSync(daemonPath)) {
    console.log('Daemon not found, building...');
    
    try {
      // Build the daemon
      execSync('cargo build --release -p tunnelcraft-daemon', {
        cwd: projectRoot,
        stdio: 'inherit',
      });
      console.log('Daemon built successfully');
    } catch (error) {
      console.error('Failed to build daemon:', error);
      throw error;
    }
  } else {
    console.log('Daemon already built');
  }

  // Platform-specific setup
  switch (electronPlatformName) {
    case 'darwin':
      await setupMacOS(context, projectRoot);
      break;
    case 'win32':
      await setupWindows(context, projectRoot);
      break;
    case 'linux':
      await setupLinux(context, projectRoot);
      break;
  }
};

async function setupMacOS(context, projectRoot) {
  console.log('Setting up macOS build...');
  
  // Ensure daemon is executable
  const daemonPath = path.join(projectRoot, 'target/release/tunnelcraft-daemon');
  if (fs.existsSync(daemonPath)) {
    fs.chmodSync(daemonPath, '755');
  }
}

async function setupWindows(context, projectRoot) {
  console.log('Setting up Windows build...');
  
  // Windows daemon would be tunnelcraft-daemon.exe
  const daemonPath = path.join(projectRoot, 'target/release/tunnelcraft-daemon.exe');
  
  if (!fs.existsSync(daemonPath)) {
    console.log('Windows daemon not found. Cross-compilation may be required.');
  }
}

async function setupLinux(context, projectRoot) {
  console.log('Setting up Linux build...');
  
  // Ensure daemon is executable
  const daemonPath = path.join(projectRoot, 'target/release/tunnelcraft-daemon');
  if (fs.existsSync(daemonPath)) {
    fs.chmodSync(daemonPath, '755');
  }
}
