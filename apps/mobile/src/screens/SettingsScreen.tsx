/**
 * Settings Screen
 *
 * Configuration options including privacy level, node settings, and account
 */

import React from 'react';
import {
  View,
  ScrollView,
  StyleSheet,
  StatusBar,
  Text,
  Pressable,
  Switch,
  Alert,
  Platform,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { theme, modeColors, palette } from '../theme';
import { typography, spacing, radius } from '../theme/typography';
import { useTunnel } from '../context/TunnelContext';
import { PrivacySelector } from '../components/PrivacySelector';

interface SettingRowProps {
  icon: string;
  label: string;
  value?: string;
  onPress?: () => void;
  rightElement?: React.ReactNode;
}

function SettingRow({ icon, label, value, onPress, rightElement }: SettingRowProps) {
  const content = (
    <View style={styles.settingRow}>
      <View style={styles.settingLeft}>
        <Text style={styles.settingIcon}>{icon}</Text>
        <Text style={styles.settingLabel}>{label}</Text>
      </View>
      {rightElement || (
        <View style={styles.settingRight}>
          {value && <Text style={styles.settingValue}>{value}</Text>}
          {onPress && <Text style={styles.chevron}>›</Text>}
        </View>
      )}
    </View>
  );

  if (onPress) {
    return (
      <Pressable
        onPress={onPress}
        style={({ pressed }) => [pressed && styles.pressed]}
      >
        {content}
      </Pressable>
    );
  }

  return content;
}

interface SettingSectionProps {
  title: string;
  children: React.ReactNode;
}

function SettingSection({ title, children }: SettingSectionProps) {
  return (
    <View style={styles.section}>
      <Text style={styles.sectionTitle}>{title}</Text>
      <View style={styles.sectionContent}>{children}</View>
    </View>
  );
}

export function SettingsScreen() {
  const { mode, setMode, isConnected, stats, credits, purchaseCredits } = useTunnel();

  const isRelay = mode === 'node' || mode === 'both';
  const isExit = mode === 'both';

  const handleRelayToggle = (enabled: boolean) => {
    if (enabled) {
      setMode(isExit ? 'both' : 'node');
    } else {
      setMode('client');
    }
  };

  const handleExitToggle = (enabled: boolean) => {
    if (enabled) {
      setMode('both');
    } else {
      setMode('node');
    }
  };

  const handlePurchaseCredits = () => {
    if (Platform.OS === 'ios') {
      Alert.prompt(
        'Purchase Credits',
        'Enter amount:',
        async (text) => {
          const amount = parseInt(text || '', 10);
          if (!isNaN(amount) && amount > 0) {
            await purchaseCredits(amount);
          }
        },
        'plain-text',
        '',
        'number-pad',
      );
    } else {
      Alert.alert('Purchase Credits', 'Select amount:', [
        { text: '100', onPress: () => purchaseCredits(100) },
        { text: '500', onPress: () => purchaseCredits(500) },
        { text: '1000', onPress: () => purchaseCredits(1000) },
        { text: 'Cancel', style: 'cancel' },
      ]);
    }
  };
  const colors = modeColors[mode];

  return (
    <View style={styles.container}>
      <StatusBar barStyle="light-content" backgroundColor={theme.background.primary} />

      <SafeAreaView style={styles.safeArea} edges={['top']}>
        <ScrollView
          style={styles.scroll}
          contentContainerStyle={styles.scrollContent}
          showsVerticalScrollIndicator={false}
        >
          {/* Header */}
          <View style={styles.header}>
            <Text style={styles.title}>Settings</Text>
            <Text style={styles.subtitle}>Configure your TunnelCraft experience</Text>
          </View>

          {/* Privacy Level */}
          <PrivacySelector />

          {/* Node Settings */}
          <SettingSection title="Node Configuration">
            <SettingRow
              icon="🌐"
              label="Node Type"
              value={mode === 'node' || mode === 'both' ? 'Full Node' : 'Client Only'}
            />
            <SettingRow
              icon="🔄"
              label="Allow Relay"
              rightElement={
                <Switch
                  value={isRelay}
                  onValueChange={handleRelayToggle}
                  trackColor={{ false: theme.background.elevated, true: colors.primary + '60' }}
                  thumbColor={isRelay ? colors.primary : theme.text.tertiary}
                  disabled={isConnected}
                />
              }
            />
            <SettingRow
              icon="🚪"
              label="Allow Exit"
              rightElement={
                <Switch
                  value={isExit}
                  onValueChange={handleExitToggle}
                  trackColor={{ false: theme.background.elevated, true: colors.primary + '60' }}
                  thumbColor={isExit ? colors.primary : theme.text.tertiary}
                  disabled={isConnected || !isRelay}
                />
              }
            />
          </SettingSection>

          {/* Network */}
          <SettingSection title="Network">
            <SettingRow
              icon="👥"
              label="Connected Peers"
              value={stats.connectedPeers.toString()}
            />
            <SettingRow
              icon="🔗"
              label="Bootstrap Nodes"
              value="Default"
              onPress={() => {}}
            />
            <SettingRow
              icon="📡"
              label="Local Discovery"
              rightElement={
                <Switch
                  value={true}
                  onValueChange={() => {}}
                  trackColor={{ false: theme.background.elevated, true: palette.success + '60' }}
                  thumbColor={palette.success}
                />
              }
            />
          </SettingSection>

          {/* Account */}
          <SettingSection title="Account">
            <SettingRow
              icon="💰"
              label="Credit Balance"
              value={credits.toLocaleString()}
            />
            <SettingRow
              icon="📈"
              label="Earnings History"
              onPress={() => {}}
            />
            <SettingRow
              icon="💳"
              label="Purchase Credits"
              onPress={handlePurchaseCredits}
            />
            <SettingRow
              icon="🔑"
              label="Export Keys"
              onPress={() => {}}
            />
          </SettingSection>

          {/* About */}
          <SettingSection title="About">
            <SettingRow
              icon="📖"
              label="Documentation"
              onPress={() => {}}
            />
            <SettingRow
              icon="💬"
              label="Community"
              onPress={() => {}}
            />
            <SettingRow
              icon="🐛"
              label="Report Issue"
              onPress={() => {}}
            />
            <SettingRow
              icon="ℹ️"
              label="Version"
              value="1.0.0"
            />
          </SettingSection>

          {/* Footer */}
          <View style={styles.footer}>
            <Text style={styles.footerText}>
              TunnelCraft • Decentralized VPN Network
            </Text>
            <Text style={styles.footerSubtext}>
              Privacy through fragmentation
            </Text>
          </View>
        </ScrollView>
      </SafeAreaView>
    </View>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: theme.background.primary,
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
  header: {
    paddingHorizontal: spacing.xl,
    paddingTop: spacing.lg,
    paddingBottom: spacing.xl,
  },
  title: {
    ...typography.displaySmall,
    color: theme.text.primary,
  },
  subtitle: {
    ...typography.bodyMedium,
    color: theme.text.tertiary,
    marginTop: spacing.xs,
  },
  section: {
    marginBottom: spacing.xl,
  },
  sectionTitle: {
    ...typography.labelSmall,
    color: theme.text.tertiary,
    paddingHorizontal: spacing.xl,
    marginBottom: spacing.md,
  },
  sectionContent: {
    backgroundColor: theme.background.tertiary,
    marginHorizontal: spacing.lg,
    borderRadius: radius.lg,
    overflow: 'hidden',
  },
  settingRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: spacing.lg,
    paddingHorizontal: spacing.lg,
    borderBottomWidth: 1,
    borderBottomColor: theme.border.subtle,
  },
  settingLeft: {
    flexDirection: 'row',
    alignItems: 'center',
    flex: 1,
  },
  settingIcon: {
    fontSize: 20,
    marginRight: spacing.md,
  },
  settingLabel: {
    ...typography.bodyMedium,
    color: theme.text.primary,
  },
  settingRight: {
    flexDirection: 'row',
    alignItems: 'center',
  },
  settingValue: {
    ...typography.bodyMedium,
    color: theme.text.tertiary,
    marginRight: spacing.xs,
  },
  chevron: {
    ...typography.headingMedium,
    color: theme.text.tertiary,
  },
  pressed: {
    opacity: 0.7,
  },
  footer: {
    alignItems: 'center',
    paddingTop: spacing['2xl'],
    paddingBottom: spacing.xl,
  },
  footerText: {
    ...typography.labelMedium,
    color: theme.text.tertiary,
  },
  footerSubtext: {
    ...typography.bodySmall,
    color: theme.text.tertiary,
    marginTop: spacing.xs,
    fontStyle: 'italic',
  },
});
