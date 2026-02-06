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
import { LogService } from '../services/LogService';

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
    LogService.info('Context', 'Using mock TunnelProvider (development mode)');
    const { TunnelProvider } = require('./TunnelContext');
    return TunnelProvider;
  }

  if (isNativeVPNAvailable()) {
    LogService.info('Context', 'Using NativeTunnelProvider (native module available)');
    const { NativeTunnelProvider } = require('./NativeTunnelContext');
    return NativeTunnelProvider;
  }

  LogService.info('Context', 'Using mock TunnelProvider (native module not available)');
  const { TunnelProvider } = require('./TunnelContext');
  return TunnelProvider;
};
