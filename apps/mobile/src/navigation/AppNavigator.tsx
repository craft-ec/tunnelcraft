/**
 * App Navigator
 *
 * Bottom tab navigation with Home, Stats, and Settings
 */

import React from 'react';
import { View, Text, StyleSheet, Pressable } from 'react-native';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import { NavigationContainer } from '@react-navigation/native';
import { useSafeAreaInsets } from 'react-native-safe-area-context';
import { theme, modeColors } from '../theme';
import { typography, spacing, radius } from '../theme/typography';
import { useTunnel } from '../context/TunnelContext';
import { HomeScreen } from '../screens/HomeScreen';
import { RequestScreen } from '../screens/RequestScreen';
import { SettingsScreen } from '../screens/SettingsScreen';

const Tab = createBottomTabNavigator();

interface TabIconProps {
  icon: string;
  label: string;
  focused: boolean;
  color: string;
}

function TabIcon({ icon, label, focused, color }: TabIconProps) {
  return (
    <View style={styles.tabIcon}>
      <Text style={[styles.tabIconEmoji, focused && { transform: [{ scale: 1.1 }] }]}>
        {icon}
      </Text>
      <Text style={[styles.tabLabel, { color: focused ? color : theme.text.tertiary }]}>
        {label}
      </Text>
    </View>
  );
}

function CustomTabBar({ state, descriptors, navigation }: {
  state: any;
  descriptors: any;
  navigation: any;
}) {
  const insets = useSafeAreaInsets();
  const { mode, isConnected } = useTunnel();
  const colors = modeColors[mode];

  return (
    <View
      style={[
        styles.tabBar,
        { paddingBottom: Math.max(insets.bottom, spacing.md) },
      ]}
    >
      {/* Connection indicator line */}
      {isConnected && (
        <View style={[styles.connectionLine, { backgroundColor: colors.primary }]} />
      )}

      <View style={styles.tabBarInner}>
        {state.routes.map((route: any, index: number) => {
          const { options } = descriptors[route.key];
          const focused = state.index === index;

          const onPress = () => {
            const event = navigation.emit({
              type: 'tabPress',
              target: route.key,
              canPreventDefault: true,
            });

            if (!focused && !event.defaultPrevented) {
              navigation.navigate(route.name);
            }
          };

          let icon = '🏠';
          let label = route.name;

          if (route.name === 'Home') {
            icon = '🏠';
            label = 'Home';
          } else if (route.name === 'Request') {
            icon = '⚡';
            label = 'Request';
          } else if (route.name === 'Settings') {
            icon = '⚙️';
            label = 'Settings';
          }

          return (
            <Pressable
              key={route.key}
              onPress={onPress}
              style={[styles.tabButton, focused && styles.tabButtonFocused]}
            >
              <TabIcon
                icon={icon}
                label={label}
                focused={focused}
                color={colors.primary}
              />
            </Pressable>
          );
        })}
      </View>
    </View>
  );
}

export function AppNavigator() {
  return (
    <NavigationContainer
      theme={{
        dark: true,
        colors: {
          primary: theme.text.primary,
          background: theme.background.primary,
          card: theme.background.secondary,
          text: theme.text.primary,
          border: theme.border.subtle,
          notification: theme.text.primary,
        },
      }}
    >
      <Tab.Navigator
        tabBar={(props) => <CustomTabBar {...props} />}
        screenOptions={{
          headerShown: false,
        }}
      >
        <Tab.Screen name="Home" component={HomeScreen} />
        <Tab.Screen name="Request" component={RequestScreen} />
        <Tab.Screen name="Settings" component={SettingsScreen} />
      </Tab.Navigator>
    </NavigationContainer>
  );
}

const styles = StyleSheet.create({
  tabBar: {
    backgroundColor: theme.background.secondary,
    borderTopWidth: 1,
    borderTopColor: theme.border.subtle,
    paddingTop: spacing.sm,
    position: 'relative',
  },
  connectionLine: {
    position: 'absolute',
    top: 0,
    left: spacing.xl,
    right: spacing.xl,
    height: 2,
    borderRadius: 1,
  },
  tabBarInner: {
    flexDirection: 'row',
    justifyContent: 'space-around',
    alignItems: 'center',
  },
  tabButton: {
    flex: 1,
    alignItems: 'center',
    paddingVertical: spacing.sm,
  },
  tabButtonFocused: {
    // Add focused styles if needed
  },
  tabIcon: {
    alignItems: 'center',
  },
  tabIconEmoji: {
    fontSize: 24,
    marginBottom: spacing.xs,
  },
  tabLabel: {
    ...typography.labelSmall,
    textTransform: 'none',
  },
});
