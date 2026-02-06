/**
 * TunnelCraft Mobile App
 *
 * A decentralized P2P VPN with unified Client/Node/Both mode support
 */

import React from 'react';
import { View, StyleSheet } from 'react-native';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import { getRecommendedProvider } from './context';
import { AppNavigator } from './navigation/AppNavigator';

const Provider = getRecommendedProvider();

function App() {
  return (
    <View style={styles.root}>
      <SafeAreaProvider>
        <Provider>
          <AppNavigator />
        </Provider>
      </SafeAreaProvider>
    </View>
  );
}

const styles = StyleSheet.create({
  root: {
    flex: 1,
  },
});

export default App;
