/**
 * TunnelCraft Context Exports
 *
 * Provides both mock (TunnelContext) and native (NativeTunnelContext) implementations.
 * Use NativeTunnelContext for production, TunnelContext for development/testing.
 */

export {
  TunnelProvider,
  TunnelContext,
  useTunnel,
  type TunnelContextType,
  type PrivacyLevel,
  type ConnectionState,
  type ExitRegion,
  type ExitSelection,
  type ExitSelectionType,
  type AvailableExit,
  type NodeStats,
  type DetectedLocation,
} from './TunnelContext';

export {
  NativeTunnelProvider,
  useNativeTunnel,
} from './NativeTunnelContext';

// Helper to determine if native modules are available
import { NativeModules, Platform } from 'react-native';

export const isNativeVPNAvailable = (): boolean => {
  if (Platform.OS === 'ios') {
    return !!NativeModules.TunnelCraftVPN;
  }
  if (Platform.OS === 'android') {
    return !!NativeModules.TunnelCraftVPN;
  }
  return false;
};

// Recommended: Use this to get the appropriate provider based on environment
export const getRecommendedProvider = () => {
  if (__DEV__) {
    // Use mock in development for faster iteration
    console.log('[TunnelCraft] Using mock TunnelProvider (development mode)');
    const { TunnelProvider } = require('./TunnelContext');
    return TunnelProvider;
  }
  
  if (isNativeVPNAvailable()) {
    console.log('[TunnelCraft] Using NativeTunnelProvider (native module available)');
    const { NativeTunnelProvider } = require('./NativeTunnelContext');
    return NativeTunnelProvider;
  }
  
  console.log('[TunnelCraft] Using mock TunnelProvider (native module not available)');
  const { TunnelProvider } = require('./TunnelContext');
  return TunnelProvider;
};
