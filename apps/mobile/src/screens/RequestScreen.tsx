/**
 * Request Screen
 *
 * Send HTTP requests through the TunnelCraft network
 */

import React, { useState, useCallback } from 'react';
import {
  View,
  ScrollView,
  StyleSheet,
  StatusBar,
  Text,
  TextInput,
  Pressable,
  FlatList,
} from 'react-native';
import { SafeAreaView } from 'react-native-safe-area-context';
import { theme, modeColors } from '../theme';
import { typography, spacing, radius } from '../theme/typography';
import { useTunnel } from '../context/TunnelContext';

type HttpMethod = 'GET' | 'POST';

interface HistoryItem {
  id: number;
  method: HttpMethod;
  url: string;
  status: number;
  body: string;
  timestamp: number;
}

export function RequestScreen() {
  const { mode, isConnected, request } = useTunnel();
  const colors = modeColors[mode];

  const [method, setMethod] = useState<HttpMethod>('GET');
  const [url, setUrl] = useState('');
  const [requestBody, setRequestBody] = useState('');
  const [isLoading, setIsLoading] = useState(false);
  const [response, setResponse] = useState<{ status: number; body: string } | null>(null);
  const [history, setHistory] = useState<HistoryItem[]>([]);
  const [nextId, setNextId] = useState(1);

  const handleSend = useCallback(async () => {
    if (!url.trim() || !isConnected) return;
    setIsLoading(true);
    setResponse(null);

    try {
      const res = await request(method, url.trim(), method === 'POST' ? requestBody : undefined);
      setResponse(res);

      const item: HistoryItem = {
        id: nextId,
        method,
        url: url.trim(),
        status: res.status,
        body: res.body,
        timestamp: Date.now(),
      };
      setNextId((n) => n + 1);
      setHistory((prev) => [item, ...prev].slice(0, 5));
    } catch (err) {
      setResponse({
        status: 0,
        body: (err as Error).message || 'Request failed',
      });
    } finally {
      setIsLoading(false);
    }
  }, [url, method, requestBody, isConnected, request, nextId]);

  const handleHistoryPress = useCallback((item: HistoryItem) => {
    setMethod(item.method);
    setUrl(item.url);
    setResponse({ status: item.status, body: item.body });
  }, []);

  const isSuccess = response && response.status >= 200 && response.status < 300;

  return (
    <View style={styles.container}>
      <StatusBar barStyle="light-content" backgroundColor={theme.background.primary} />

      <SafeAreaView style={styles.safeArea} edges={['top']}>
        <ScrollView
          style={styles.scroll}
          contentContainerStyle={styles.scrollContent}
          showsVerticalScrollIndicator={false}
          keyboardShouldPersistTaps="handled"
        >
          {/* Header */}
          <View style={styles.header}>
            <Text style={styles.title}>Request</Text>
            <Text style={styles.subtitle}>Send HTTP requests through the tunnel</Text>
          </View>

          {!isConnected && (
            <View style={styles.disconnectedBanner}>
              <Text style={styles.disconnectedText}>
                Connect to the network to send requests
              </Text>
            </View>
          )}

          {/* Method Selector */}
          <View style={styles.card}>
            <Text style={styles.cardLabel}>Method</Text>
            <View style={styles.methodRow}>
              {(['GET', 'POST'] as HttpMethod[]).map((m) => (
                <Pressable
                  key={m}
                  style={[
                    styles.methodButton,
                    method === m && { backgroundColor: colors.primary },
                  ]}
                  onPress={() => setMethod(m)}
                >
                  <Text
                    style={[
                      styles.methodButtonText,
                      method === m && styles.methodButtonTextActive,
                    ]}
                  >
                    {m}
                  </Text>
                </Pressable>
              ))}
            </View>

            {/* URL Input */}
            <Text style={[styles.cardLabel, { marginTop: spacing.lg }]}>URL</Text>
            <TextInput
              style={styles.urlInput}
              value={url}
              onChangeText={setUrl}
              placeholder="https://example.com"
              placeholderTextColor={theme.text.tertiary}
              autoCapitalize="none"
              autoCorrect={false}
              keyboardType="url"
              returnKeyType="send"
              onSubmitEditing={handleSend}
            />

            {/* Body Input (POST only) */}
            {method === 'POST' && (
              <>
                <Text style={[styles.cardLabel, { marginTop: spacing.lg }]}>Body</Text>
                <TextInput
                  style={[styles.urlInput, styles.bodyInput]}
                  value={requestBody}
                  onChangeText={setRequestBody}
                  placeholder="Request body (JSON, text, etc.)"
                  placeholderTextColor={theme.text.tertiary}
                  multiline
                  numberOfLines={3}
                  textAlignVertical="top"
                />
              </>
            )}

            {/* Send Button */}
            <Pressable
              style={[
                styles.sendButton,
                { backgroundColor: colors.primary },
                (!isConnected || isLoading || !url.trim()) && styles.sendButtonDisabled,
              ]}
              onPress={handleSend}
              disabled={!isConnected || isLoading || !url.trim()}
            >
              <Text style={styles.sendButtonText}>
                {isLoading ? 'Sending...' : 'Send Request'}
              </Text>
            </Pressable>
          </View>

          {/* Response */}
          {response && (
            <View style={styles.card}>
              <View style={styles.responseHeader}>
                <View
                  style={[
                    styles.statusBadge,
                    {
                      backgroundColor: isSuccess
                        ? 'rgba(34, 197, 94, 0.2)'
                        : 'rgba(239, 68, 68, 0.2)',
                    },
                  ]}
                >
                  <Text
                    style={[
                      styles.statusBadgeText,
                      { color: isSuccess ? '#22c55e' : '#ef4444' },
                    ]}
                  >
                    {response.status || 'ERR'}
                  </Text>
                </View>
                <Text style={styles.responseLabel}>Response</Text>
              </View>
              <ScrollView
                style={styles.responseBody}
                nestedScrollEnabled
                showsVerticalScrollIndicator
              >
                <Text style={styles.responseBodyText}>{response.body}</Text>
              </ScrollView>
            </View>
          )}

          {/* History */}
          {history.length > 0 && (
            <View style={styles.card}>
              <Text style={styles.cardLabel}>Recent Requests</Text>
              {history.map((item) => (
                <Pressable
                  key={item.id}
                  style={({ pressed }) => [
                    styles.historyItem,
                    pressed && { opacity: 0.7 },
                  ]}
                  onPress={() => handleHistoryPress(item)}
                >
                  <View
                    style={[
                      styles.historyMethod,
                      item.method === 'POST' && styles.historyMethodPost,
                    ]}
                  >
                    <Text style={styles.historyMethodText}>{item.method}</Text>
                  </View>
                  <Text style={styles.historyUrl} numberOfLines={1}>
                    {item.url}
                  </Text>
                  <Text
                    style={[
                      styles.historyStatus,
                      {
                        color:
                          item.status >= 200 && item.status < 300
                            ? '#22c55e'
                            : '#ef4444',
                      },
                    ]}
                  >
                    {item.status || 'ERR'}
                  </Text>
                </Pressable>
              ))}
            </View>
          )}

          <View style={styles.bottomSpacer} />
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
  disconnectedBanner: {
    marginHorizontal: spacing.lg,
    marginBottom: spacing.lg,
    padding: spacing.lg,
    backgroundColor: 'rgba(239, 68, 68, 0.1)',
    borderRadius: radius.lg,
    alignItems: 'center',
  },
  disconnectedText: {
    ...typography.bodyMedium,
    color: '#ef4444',
  },
  card: {
    backgroundColor: theme.background.tertiary,
    marginHorizontal: spacing.lg,
    marginBottom: spacing.lg,
    borderRadius: radius.lg,
    padding: spacing.lg,
  },
  cardLabel: {
    ...typography.labelSmall,
    color: theme.text.tertiary,
    textTransform: 'uppercase',
    letterSpacing: 0.5,
    marginBottom: spacing.sm,
  },
  methodRow: {
    flexDirection: 'row',
    gap: spacing.sm,
  },
  methodButton: {
    flex: 1,
    paddingVertical: spacing.md,
    borderRadius: 10,
    backgroundColor: theme.background.secondary,
    alignItems: 'center',
  },
  methodButtonText: {
    ...typography.bodyMedium,
    color: theme.text.secondary,
    fontWeight: '600',
  },
  methodButtonTextActive: {
    color: theme.text.inverse,
  },
  urlInput: {
    backgroundColor: theme.background.secondary,
    borderRadius: 10,
    paddingHorizontal: spacing.lg,
    paddingVertical: spacing.md,
    color: theme.text.primary,
    fontSize: 14,
  },
  bodyInput: {
    minHeight: 80,
    fontFamily: 'JetBrainsMono-Regular',
  },
  sendButton: {
    marginTop: spacing.lg,
    paddingVertical: spacing.lg,
    borderRadius: 10,
    alignItems: 'center',
  },
  sendButtonDisabled: {
    opacity: 0.5,
  },
  sendButtonText: {
    ...typography.bodyMedium,
    color: theme.text.inverse,
    fontWeight: '700',
  },
  responseHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.sm,
    marginBottom: spacing.md,
  },
  statusBadge: {
    paddingHorizontal: spacing.sm,
    paddingVertical: 2,
    borderRadius: 4,
  },
  statusBadgeText: {
    fontSize: 12,
    fontWeight: '700',
    fontFamily: 'JetBrainsMono-Bold',
  },
  responseLabel: {
    ...typography.labelSmall,
    color: theme.text.tertiary,
  },
  responseBody: {
    backgroundColor: theme.background.secondary,
    borderRadius: 10,
    padding: spacing.md,
    maxHeight: 200,
  },
  responseBodyText: {
    ...typography.bodySmall,
    color: theme.text.primary,
    fontFamily: 'JetBrainsMono-Regular',
  },
  historyItem: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: spacing.sm,
    paddingVertical: spacing.sm,
    borderBottomWidth: 1,
    borderBottomColor: theme.border.subtle,
  },
  historyMethod: {
    backgroundColor: 'rgba(59, 130, 246, 0.15)',
    paddingHorizontal: 6,
    paddingVertical: 2,
    borderRadius: 4,
  },
  historyMethodPost: {
    backgroundColor: 'rgba(168, 85, 247, 0.15)',
  },
  historyMethodText: {
    fontSize: 10,
    fontWeight: '700',
    fontFamily: 'JetBrainsMono-Bold',
    color: theme.text.secondary,
  },
  historyUrl: {
    ...typography.bodySmall,
    color: theme.text.secondary,
    flex: 1,
  },
  historyStatus: {
    fontSize: 12,
    fontWeight: '600',
    fontFamily: 'JetBrainsMono-Bold',
  },
  bottomSpacer: {
    height: spacing.xl,
  },
});
