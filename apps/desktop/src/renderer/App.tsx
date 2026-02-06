import React from 'react';
import { VPNProvider } from './context/VPNContext';
import { TitleBar } from './components/TitleBar';
import { StatusCard } from './components/StatusCard';
import { ConnectButton } from './components/ConnectButton';
import { PrivacyLevelSelector } from './components/PrivacyLevelSelector';
import { ModeSelector } from './components/ModeSelector';
import { CreditPanel } from './components/CreditPanel';
import { StatsPanel } from './components/StatsPanel';
import { RequestPanel } from './components/RequestPanel';
import './styles/App.css';

const App: React.FC = () => {
  return (
    <VPNProvider>
      <div className="app">
        <TitleBar />
        <main className="main-content">
          <StatusCard />
          <ConnectButton />
          <ModeSelector />
          <PrivacyLevelSelector />
          <CreditPanel />
          <StatsPanel />
          <RequestPanel />
        </main>
      </div>
    </VPNProvider>
  );
};

export default App;
