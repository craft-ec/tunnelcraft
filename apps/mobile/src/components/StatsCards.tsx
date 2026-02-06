/**
 * Stats Cards Component
 *
 * Displays network statistics in beautiful animated cards
 * that adapt based on the current mode
 */

import React, { useMemo } from 'react';
import { View, Text, StyleSheet } from 'react-native';
import { modeColors, theme, palette } from '../theme';
import { typography, spacing, radius } from '../theme/typography';
import { shadows } from '../theme';
import { useTunnel } from '../context/TunnelContext';

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(1)) + ' ' + sizes[i];
}

function formatDuration(seconds: number): string {
  if (seconds < 60) return `${seconds}s`;
  if (seconds < 3600) {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${mins}m ${secs}s`;
  }
  const hours = Math.floor(seconds / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  return `${hours}h ${mins}m`;
}

function formatNumber(num: number): string {
  if (num >= 1000000) return (num / 1000000).toFixed(1) + 'M';
  if (num >= 1000) return (num / 1000).toFixed(1) + 'K';
  return num.toString();
}

interface StatCardProps {
  label: string;
  value: string;
  icon: string;
  color?: string;
  trend?: 'up' | 'down' | 'neutral';
  secondary?: string;
}

function StatCard({ label, value, icon, color, trend, secondary }: StatCardProps) {
  return (
    <View style={[styles.card, { borderLeftColor: color || theme.border.default }]}>
      <View style={styles.cardHeader}>
        <Text style={styles.cardIcon}>{icon}</Text>
        <Text style={styles.cardLabel}>{label}</Text>
      </View>
      <Text style={[styles.cardValue, color ? { color } : undefined]}>{value}</Text>
      {secondary && <Text style={styles.cardSecondary}>{secondary}</Text>}
      {trend && trend !== 'neutral' && (
        <View style={[styles.trendBadge, { backgroundColor: trend === 'up' ? palette.success + '20' : palette.error + '20' }]}>
          <Text style={[styles.trendText, { color: trend === 'up' ? palette.success : palette.error }]}>
            {trend === 'up' ? '↑' : '↓'}
          </Text>
        </View>
      )}
    </View>
  );
}

export function StatsCards() {
  const { mode, stats, isConnected, credits } = useTunnel();
  const colors = modeColors[mode];

  const clientStats = useMemo(
    () => [
      {
        label: 'Data Sent',
        value: formatBytes(stats.bytesSent),
        icon: '📤',
        color: colors.primary,
      },
      {
        label: 'Data Received',
        value: formatBytes(stats.bytesReceived),
        icon: '📥',
        color: colors.primary,
      },
    ],
    [stats.bytesSent, stats.bytesReceived, colors.primary]
  );

  const nodeStats = useMemo(
    () => [
      {
        label: 'Shards Relayed',
        value: formatNumber(stats.shardsRelayed),
        icon: '🔀',
        color: palette.amber[500],
      },
      {
        label: 'Requests Exited',
        value: formatNumber(stats.requestsExited),
        icon: '🌐',
        color: palette.amber[500],
      },
    ],
    [stats.shardsRelayed, stats.requestsExited]
  );

  const networkStats = useMemo(
    () => [
      {
        label: 'Connected Peers',
        value: stats.connectedPeers.toString(),
        icon: '👥',
        secondary: 'on the network',
      },
      {
        label: 'Uptime',
        value: formatDuration(stats.uptimeSecs),
        icon: '⏱️',
        secondary: 'this session',
      },
    ],
    [stats.connectedPeers, stats.uptimeSecs]
  );

  if (!isConnected) {
    return (
      <View style={styles.emptyContainer}>
        <Text style={styles.emptyIcon}>📊</Text>
        <Text style={styles.emptyText}>Connect to see your stats</Text>
      </View>
    );
  }

  return (
    <View style={styles.container}>
      {/* Credits overview */}
      <View style={styles.creditsCard}>
        <View style={styles.creditsHeader}>
          <Text style={styles.creditsLabel}>Credit Balance</Text>
          <View style={styles.creditsFlow}>
            {(mode === 'client' || mode === 'both') && (
              <View style={styles.flowBadge}>
                <Text style={[styles.flowText, { color: palette.error }]}>
                  -{stats.creditsSpent}
                </Text>
              </View>
            )}
            {(mode === 'node' || mode === 'both') && (
              <View style={styles.flowBadge}>
                <Text style={[styles.flowText, { color: palette.success }]}>
                  +{stats.creditsEarned}
                </Text>
              </View>
            )}
          </View>
        </View>
        <Text style={[styles.creditsValue, { color: colors.primary }]}>
          {formatNumber(credits)}
        </Text>
        <Text style={styles.creditsUnit}>credits available</Text>
      </View>

      {/* Client stats */}
      {(mode === 'client' || mode === 'both') && (
        <View style={styles.section}>
          <Text style={styles.sectionTitle}>📡 Your Traffic</Text>
          <View style={styles.cardRow}>
            {clientStats.map((stat, i) => (
              <StatCard key={i} {...stat} />
            ))}
          </View>
        </View>
      )}

      {/* Node stats */}
      {(mode === 'node' || mode === 'both') && (
        <View style={styles.section}>
          <Text style={styles.sectionTitle}>🌐 Network Contribution</Text>
          <View style={styles.cardRow}>
            {nodeStats.map((stat, i) => (
              <StatCard key={i} {...stat} />
            ))}
          </View>
        </View>
      )}

      {/* Network stats */}
      <View style={styles.section}>
        <Text style={styles.sectionTitle}>🔗 Network Status</Text>
        <View style={styles.cardRow}>
          {networkStats.map((stat, i) => (
            <StatCard key={i} {...stat} />
          ))}
        </View>
      </View>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    paddingHorizontal: spacing.xl,
    paddingBottom: spacing['3xl'],
  },
  emptyContainer: {
    alignItems: 'center',
    justifyContent: 'center',
    paddingVertical: spacing['3xl'],
  },
  emptyIcon: {
    fontSize: 48,
    marginBottom: spacing.md,
    opacity: 0.5,
  },
  emptyText: {
    ...typography.bodyMedium,
    color: theme.text.tertiary,
  },
  creditsCard: {
    backgroundColor: theme.background.tertiary,
    borderRadius: radius.xl,
    padding: spacing.xl,
    marginBottom: spacing.xl,
    alignItems: 'center',
    ...shadows.md,
  },
  creditsHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    width: '100%',
    marginBottom: spacing.md,
  },
  creditsLabel: {
    ...typography.labelSmall,
    color: theme.text.tertiary,
  },
  creditsFlow: {
    flexDirection: 'row',
    gap: spacing.sm,
  },
  flowBadge: {
    paddingHorizontal: spacing.sm,
    paddingVertical: spacing.xs,
    borderRadius: radius.full,
    backgroundColor: theme.background.elevated,
  },
  flowText: {
    ...typography.monoSmall,
    fontWeight: '600',
  },
  creditsValue: {
    ...typography.monoLarge,
    fontSize: 48,
    lineHeight: 56,
  },
  creditsUnit: {
    ...typography.bodySmall,
    color: theme.text.tertiary,
    marginTop: spacing.xs,
  },
  section: {
    marginBottom: spacing.xl,
  },
  sectionTitle: {
    ...typography.labelMedium,
    color: theme.text.secondary,
    marginBottom: spacing.md,
  },
  cardRow: {
    flexDirection: 'row',
    gap: spacing.md,
  },
  card: {
    flex: 1,
    backgroundColor: theme.background.tertiary,
    borderRadius: radius.lg,
    padding: spacing.lg,
    borderLeftWidth: 3,
    ...shadows.sm,
  },
  cardHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: spacing.sm,
  },
  cardIcon: {
    fontSize: 16,
    marginRight: spacing.xs,
  },
  cardLabel: {
    ...typography.labelSmall,
    color: theme.text.tertiary,
    textTransform: 'none',
  },
  cardValue: {
    ...typography.monoMedium,
    color: theme.text.primary,
  },
  cardSecondary: {
    ...typography.bodySmall,
    color: theme.text.tertiary,
    marginTop: spacing.xs,
  },
  trendBadge: {
    position: 'absolute',
    top: spacing.sm,
    right: spacing.sm,
    paddingHorizontal: spacing.xs,
    paddingVertical: 2,
    borderRadius: radius.sm,
  },
  trendText: {
    ...typography.labelSmall,
    fontWeight: '700',
  },
});
