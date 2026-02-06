/**
 * Home Screen - Single Page Design
 *
 * All VPN controls on one screen with collapsible sections:
 * - Connection (orb, mode toggle, connect button)
 * - Exit Node (current exit with scoring, change exit)
 * - Statistics (bytes, shards, credits, uptime)
 * - Settings (privacy level, other config)
 */

import React, { useState, useCallback } from 'react';
import {
  View,
  ScrollView,
  StyleSheet,
  StatusBar,
  Text,
  TouchableOpacity,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { theme, modeColors, palette } from '../theme';
import { typography, spacing } from '../theme/typography';
import { useTunnel, NodeStats, PrivacyLevel } from '../context/TunnelContext';
import { NodeMode } from '../theme/colors';

// Components
import { CollapsibleSection } from '../components/CollapsibleSection';
import { ConnectionOrb } from '../components/ConnectionOrb';
import { ExitNodeSection, ExitNodeInfo } from '../components/ExitNodeSection';

// Icons as text (replace with actual icons in production)
const Icons = {
  connection: '◉',
  exit: '↗',
  stats: '◎',
  settings: '⚙',
  shield: '🛡',
};

// Mock exit data with scoring (in real app, from TunnelContext)
const mockCurrentExit: ExitNodeInfo = {
  id: '1',
  pubkey: 'abc123...',
  countryCode: 'DE',
  countryName: 'Germany',
  city: 'Frankfurt',
  region: 'eu',
  score: 28,
  loadPercent: 35,
  latencyMs: 45,
  uplinkKbps: 15000,
  downlinkKbps: 42000,
  uptimeSecs: 86400 * 3, // 3 days
  isTrusted: true,
};

const mockAvailableExits: ExitNodeInfo[] = [
  { ...mockCurrentExit },
  {
    id: '2', pubkey: 'def456...', countryCode: 'NL', countryName: 'Netherlands',
    city: 'Amsterdam', region: 'eu', score: 32, loadPercent: 42,
    latencyMs: 52, uplinkKbps: 12000, downlinkKbps: 38000, uptimeSecs: 172800, isTrusted: true,
  },
  {
    id: '3', pubkey: 'ghi789...', countryCode: 'US', countryName: 'United States',
    city: 'New York', region: 'na', score: 45, loadPercent: 65,
    latencyMs: 85, uplinkKbps: 8000, downlinkKbps: 25000, uptimeSecs: 43200, isTrusted: true,
  },
  {
    id: '4', pubkey: 'jkl012...', countryCode: 'JP', countryName: 'Japan',
    city: 'Tokyo', region: 'ap', score: 58, loadPercent: 55,
    latencyMs: 180, uplinkKbps: 20000, downlinkKbps: 50000, uptimeSecs: 259200, isTrusted: false,
  },
  {
    id: '5', pubkey: 'mno345...', countryCode: 'SG', countryName: 'Singapore',
    city: 'Singapore', region: 'ap', score: 42, loadPercent: 28,
    latencyMs: 165, uplinkKbps: 18000, downlinkKbps: 45000, uptimeSecs: 604800, isTrusted: true,
  },
];

export function HomeScreen() {
  const {
    mode,
    setMode,
    isConnected,
    connectionState,
    stats,
    privacyLevel,
    setPrivacyLevel,
    toggleConnection,
    credits,
    setExitSelection,
  } = useTunnel();
  const [currentExit, setCurrentExit] = useState<ExitNodeInfo | null>(mockCurrentExit);
  const colors = modeColors[mode];

  const showClient = mode === 'client' || mode === 'both';
  const showNode = mode === 'node' || mode === 'both';

  const handleChangeExit = useCallback((exit: ExitNodeInfo) => {
    setCurrentExit(exit);
    // Wire through to native bridge via context
    setExitSelection({
      type: exit.countryCode ? 'country' : 'region',
      region: (exit.region || 'auto') as import('../context/TunnelContext').ExitRegion,
      countryCode: exit.countryCode,
    });
  }, [setExitSelection]);

  return (
    <View style={styles.container}>
      <StatusBar barStyle="light-content" backgroundColor={theme.background.primary} />

      {/* Subtle background glow when connected */}
      {isConnected && (
        <View style={[styles.backgroundGlow, { backgroundColor: colors.glow }]} />
      )}

      <SafeAreaView style={styles.safeArea} edges={['top']}>
        <ScrollView
          style={styles.scroll}
          contentContainerStyle={styles.scrollContent}
          showsVerticalScrollIndicator={false}
        >
          {/* Header */}
          <View style={styles.header}>
            <View>
              <Text style={styles.logo}>TunnelCraft</Text>
              <Text style={styles.tagline}>Decentralized VPN</Text>
            </View>
            <View style={styles.creditsContainer}>
              <Text style={styles.creditsLabel}>Credits</Text>
              <Text style={[styles.creditsValue, { color: colors.primary }]}>
                {credits.toLocaleString()}
              </Text>
            </View>
          </View>

          {/* Credit Warning */}
          {credits <= 20 && (
            <View style={[styles.creditWarning, styles.creditWarningCritical]}>
              <Text style={styles.creditWarningText}>
                Credits critically low — top up to continue sending requests
              </Text>
            </View>
          )}
          {credits > 20 && credits <= 100 && (
            <View style={[styles.creditWarning, styles.creditWarningLow]}>
              <Text style={[styles.creditWarningText, { color: palette.amber[500] }]}>
                Credits running low
              </Text>
            </View>
          )}

          {/* Connection Section - Always expanded by default */}
          <CollapsibleSection
            title="Connection"
            subtitle={connectionState === 'connected' ? 'Protected' : 'Not connected'}
            icon={<Text style={styles.sectionIcon}>{Icons.connection}</Text>}
            badge={mode.charAt(0).toUpperCase() + mode.slice(1)}
            badgeColor={colors.primary}
            defaultExpanded={true}
          >
            {/* Connection Orb */}
            <View style={styles.orbContainer}>
              <ConnectionOrb />
            </View>

            {/* Mode Selector */}
            <View style={styles.modeSelector}>
              <Text style={styles.modeSelectorLabel}>Operating Mode</Text>
              <View style={styles.modeButtons}>
                {(['client', 'node', 'both'] as NodeMode[]).map((m) => (
                  <TouchableOpacity
                    key={m}
                    style={[
                      styles.modeButton,
                      mode === m && { backgroundColor: modeColors[m].primary },
                    ]}
                    onPress={() => setMode(m)}
                    activeOpacity={0.7}
                  >
                    <Text style={[
                      styles.modeButtonText,
                      mode === m && styles.modeButtonTextActive,
                    ]}>
                      {m === 'both' ? 'Both' : m.charAt(0).toUpperCase() + m.slice(1)}
                    </Text>
                  </TouchableOpacity>
                ))}
              </View>
              <View style={styles.modeDescription}>
                <Text style={styles.modeDescriptionText}>
                  {mode === 'client' && 'Use VPN only • Spend credits'}
                  {mode === 'node' && 'Help network only • Earn credits'}
                  {mode === 'both' && 'Use VPN + help network • Earn & spend'}
                </Text>
              </View>
            </View>
          </CollapsibleSection>

          {/* Exit Node Section - Only in Client/Both mode */}
          {showClient && (
            <CollapsibleSection
              title="Exit Node"
              subtitle={currentExit ? `${currentExit.city}, ${currentExit.countryCode}` : 'Not selected'}
              icon={<Text style={styles.sectionIcon}>{Icons.exit}</Text>}
              badge={currentExit ? `Score: ${currentExit.score}` : undefined}
              badgeColor={currentExit && currentExit.score <= 40 ? palette.cyan[500] : palette.amber[500]}
              defaultExpanded={false}
            >
              <ExitNodeSection
                currentExit={currentExit}
                availableExits={mockAvailableExits}
                onChangeExit={handleChangeExit}
              />
            </CollapsibleSection>
          )}

          {/* Statistics Section */}
          <CollapsibleSection
            title="Statistics"
            subtitle={`Uptime: ${formatUptime(stats.uptimeSecs)}`}
            icon={<Text style={styles.sectionIcon}>{Icons.stats}</Text>}
            defaultExpanded={false}
          >
            <StatsGrid stats={stats} mode={mode} colors={colors} />
          </CollapsibleSection>

          {/* Settings Section */}
          <CollapsibleSection
            title="Settings"
            subtitle={showClient ? `Privacy: ${privacyLevel}` : 'Node settings'}
            icon={<Text style={styles.sectionIcon}>{Icons.settings}</Text>}
            defaultExpanded={false}
          >
            {showClient && (
              <View style={styles.settingGroup}>
                <Text style={styles.settingLabel}>Privacy Level</Text>
                <View style={styles.privacyButtons}>
                  {(['direct', 'light', 'standard', 'paranoid'] as PrivacyLevel[]).map((level) => (
                    <TouchableOpacity
                      key={level}
                      style={[
                        styles.privacyButton,
                        privacyLevel === level && { backgroundColor: colors.primary },
                      ]}
                      onPress={() => setPrivacyLevel(level)}
                      activeOpacity={0.7}
                    >
                      <Text style={[
                        styles.privacyButtonText,
                        privacyLevel === level && styles.privacyButtonTextActive,
                      ]}>
                        {level.charAt(0).toUpperCase() + level.slice(1)}
                      </Text>
                      <Text style={[
                        styles.privacyButtonHops,
                        privacyLevel === level && styles.privacyButtonHopsActive,
                      ]}>
                        {level === 'direct' ? '0 hops' :
                         level === 'light' ? '1 hop' :
                         level === 'standard' ? '2 hops' : '3 hops'}
                      </Text>
                    </TouchableOpacity>
                  ))}
                </View>
              </View>
            )}

            {/* Node uptime display */}
            {showNode && (
              <View style={styles.settingGroup}>
                <Text style={styles.settingLabel}>Node Status</Text>
                <View style={styles.nodeStatus}>
                  <View style={styles.nodeStatusRow}>
                    <Text style={styles.nodeStatusLabel}>Your Uptime</Text>
                    <Text style={styles.nodeStatusValue}>{formatUptime(stats.uptimeSecs)}</Text>
                  </View>
                  <View style={styles.nodeStatusRow}>
                    <Text style={styles.nodeStatusLabel}>Peers Connected</Text>
                    <Text style={styles.nodeStatusValue}>{stats.connectedPeers}</Text>
                  </View>
                  <View style={styles.nodeStatusRow}>
                    <Text style={styles.nodeStatusLabel}>Shards Relayed</Text>
                    <Text style={styles.nodeStatusValue}>{stats.shardsRelayed.toLocaleString()}</Text>
                  </View>
                </View>
              </View>
            )}
          </CollapsibleSection>

          {/* Bottom spacing */}
          <View style={styles.bottomSpacer} />
        </ScrollView>
      </SafeAreaView>
    </View>
  );
}

// Stats Grid Component
interface StatsGridProps {
  stats: NodeStats;
  mode: NodeMode;
  colors: { primary: string; primaryLight: string };
}

function StatsGrid({ stats, mode, colors }: StatsGridProps) {
  const showClient = mode === 'client' || mode === 'both';
  const showNode = mode === 'node' || mode === 'both';

  return (
    <View style={styles.statsGrid}>
      {showClient && (
        <>
          <StatCard
            label="Downloaded"
            value={formatBytes(stats.bytesReceived)}
            color={colors.primary}
          />
          <StatCard
            label="Uploaded"
            value={formatBytes(stats.bytesSent)}
            color={colors.primaryLight}
          />
          <StatCard
            label="Spent"
            value={stats.creditsSpent.toString()}
            unit="credits"
            color={palette.error}
          />
        </>
      )}
      {showNode && (
        <>
          <StatCard
            label="Relayed"
            value={stats.shardsRelayed.toLocaleString()}
            unit="shards"
            color={palette.amber[500]}
          />
          <StatCard
            label="Exited"
            value={stats.requestsExited.toString()}
            unit="requests"
            color={palette.amber[400]}
          />
          <StatCard
            label="Earned"
            value={stats.creditsEarned.toString()}
            unit="credits"
            color={palette.success}
          />
        </>
      )}
      <StatCard
        label="Peers"
        value={stats.connectedPeers.toString()}
        color={palette.violet[400]}
      />
      <StatCard
        label="Uptime"
        value={formatUptime(stats.uptimeSecs)}
        color={theme.text.secondary}
      />
    </View>
  );
}

interface StatCardProps {
  label: string;
  value: string;
  unit?: string;
  color: string;
}

function StatCard({ label, value, unit, color }: StatCardProps) {
  return (
    <View style={styles.statCard}>
      <Text style={styles.statLabel}>{label}</Text>
      <Text style={[styles.statValue, { color }]}>{value}</Text>
      {unit && <Text style={styles.statUnit}>{unit}</Text>}
    </View>
  );
}

// Utility functions
function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)} MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(2)} GB`;
}

function formatUptime(secs: number): string {
  if (secs < 60) return `${secs}s`;
  if (secs < 3600) return `${Math.floor(secs / 60)}m`;
  if (secs < 86400) return `${Math.floor(secs / 3600)}h ${Math.floor((secs % 3600) / 60)}m`;
  const days = Math.floor(secs / 86400);
  const hours = Math.floor((secs % 86400) / 3600);
  return `${days}d ${hours}h`;
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: theme.background.primary,
  },

  backgroundGlow: {
    position: 'absolute',
    top: -150,
    left: -100,
    right: -100,
    height: 500,
    borderRadius: 250,
    opacity: 0.12,
  },

  safeArea: {
    flex: 1,
  },

  scroll: {
    flex: 1,
  },

  scrollContent: {
    paddingBottom: spacing['4xl'],
  },

  // Header
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    paddingHorizontal: spacing.xl,
    paddingTop: spacing.lg,
    paddingBottom: spacing.xl,
  },

  logo: {
    ...typography.headingLarge,
    color: theme.text.primary,
    fontWeight: '700',
    letterSpacing: -0.5,
  },

  tagline: {
    ...typography.bodySmall,
    color: theme.text.tertiary,
    marginTop: spacing.xs,
  },

  creditsContainer: {
    alignItems: 'flex-end',
  },

  creditsLabel: {
    ...typography.labelSmall,
    color: theme.text.tertiary,
    textTransform: 'uppercase',
    letterSpacing: 0.5,
  },

  creditsValue: {
    ...typography.headingSmall,
    fontFamily: 'JetBrainsMono-Bold',
    marginTop: 2,
  },

  // Section icon
  sectionIcon: {
    fontSize: 18,
    color: theme.text.secondary,
  },

  // Connection section
  orbContainer: {
    alignItems: 'center',
    marginBottom: spacing.xl,
  },

  modeSelector: {
    marginTop: spacing.md,
  },

  modeSelectorLabel: {
    ...typography.labelSmall,
    color: theme.text.tertiary,
    textTransform: 'uppercase',
    letterSpacing: 0.5,
    marginBottom: spacing.sm,
  },

  modeButtons: {
    flexDirection: 'row',
    gap: spacing.sm,
  },

  modeButton: {
    flex: 1,
    paddingVertical: spacing.md,
    borderRadius: 10,
    backgroundColor: theme.background.tertiary,
    alignItems: 'center',
  },

  modeButtonText: {
    ...typography.bodyMedium,
    color: theme.text.secondary,
    fontWeight: '600',
  },

  modeButtonTextActive: {
    color: theme.text.inverse,
  },

  modeDescription: {
    marginTop: spacing.sm,
    alignItems: 'center',
  },

  modeDescriptionText: {
    ...typography.bodySmall,
    color: theme.text.tertiary,
  },

  // Settings
  settingGroup: {
    marginBottom: spacing.lg,
  },

  settingLabel: {
    ...typography.labelSmall,
    color: theme.text.tertiary,
    textTransform: 'uppercase',
    letterSpacing: 0.5,
    marginBottom: spacing.sm,
  },

  privacyButtons: {
    gap: spacing.sm,
  },

  privacyButton: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: spacing.md,
    paddingHorizontal: spacing.lg,
    borderRadius: 10,
    backgroundColor: theme.background.tertiary,
  },

  privacyButtonText: {
    ...typography.bodyMedium,
    color: theme.text.secondary,
    fontWeight: '600',
  },

  privacyButtonTextActive: {
    color: theme.text.inverse,
  },

  privacyButtonHops: {
    ...typography.bodySmall,
    color: theme.text.tertiary,
  },

  privacyButtonHopsActive: {
    color: 'rgba(255,255,255,0.7)',
  },

  nodeStatus: {
    backgroundColor: theme.background.tertiary,
    borderRadius: 12,
    padding: spacing.lg,
  },

  nodeStatusRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    paddingVertical: spacing.sm,
  },

  nodeStatusLabel: {
    ...typography.bodyMedium,
    color: theme.text.secondary,
  },

  nodeStatusValue: {
    ...typography.bodyMedium,
    color: theme.text.primary,
    fontFamily: 'JetBrainsMono-Regular',
  },

  // Stats Grid
  statsGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: spacing.sm,
  },

  statCard: {
    width: '48%',
    backgroundColor: theme.background.tertiary,
    borderRadius: 12,
    padding: spacing.md,
  },

  statLabel: {
    ...typography.labelSmall,
    color: theme.text.tertiary,
    textTransform: 'uppercase',
    letterSpacing: 0.5,
    marginBottom: spacing.xs,
  },

  statValue: {
    ...typography.headingSmall,
    fontFamily: 'JetBrainsMono-Bold',
  },

  statUnit: {
    ...typography.bodySmall,
    color: theme.text.tertiary,
    marginTop: 2,
  },

  creditWarning: {
    marginHorizontal: spacing.lg,
    marginBottom: spacing.md,
    padding: spacing.md,
    borderRadius: 10,
    borderWidth: 1,
  },
  creditWarningLow: {
    backgroundColor: 'rgba(234, 179, 8, 0.08)',
    borderColor: 'rgba(234, 179, 8, 0.2)',
  },
  creditWarningCritical: {
    backgroundColor: 'rgba(239, 68, 68, 0.08)',
    borderColor: 'rgba(239, 68, 68, 0.2)',
  },
  creditWarningText: {
    ...typography.bodySmall,
    color: palette.error,
    fontWeight: '600',
    textAlign: 'center',
  },

  bottomSpacer: {
    height: spacing.xl,
  },
});
