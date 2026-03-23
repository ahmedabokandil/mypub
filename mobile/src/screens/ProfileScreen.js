import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  Alert,
  ScrollView,
  StatusBar,
  Switch,
  Linking,
} from 'react-native';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { useAuth } from '../context/AuthContext';
import { getClient } from '../api/client';

const DARK_MODE_KEY = '@dark_mode';

const ProfileScreen = () => {
  const { user, serverUrl, logout, clearServerUrl } = useAuth();
  const [darkMode, setDarkMode] = useState(false);

  useEffect(() => {
    loadDarkMode();
  }, []);

  const loadDarkMode = async () => {
    try {
      const stored = await AsyncStorage.getItem(DARK_MODE_KEY);
      if (stored !== null) setDarkMode(JSON.parse(stored));
    } catch (e) {
      // ignore
    }
  };

  const toggleDarkMode = async (value) => {
    setDarkMode(value);
    await AsyncStorage.setItem(DARK_MODE_KEY, JSON.stringify(value));
  };

  const handleLogout = () => {
    Alert.alert('Logout', 'Are you sure you want to logout?', [
      { text: 'Cancel', style: 'cancel' },
      {
        text: 'Logout',
        style: 'destructive',
        onPress: logout,
      },
    ]);
  };

  const handleChangeServer = () => {
    Alert.alert(
      'Change Server',
      'This will log you out and reset the server connection. Continue?',
      [
        { text: 'Cancel', style: 'cancel' },
        {
          text: 'Continue',
          style: 'destructive',
          onPress: clearServerUrl,
        },
      ]
    );
  };

  const handle2FASetup = () => {
    if (serverUrl) {
      const url = `${serverUrl}/settings/security`;
      Alert.alert(
        'Two-Factor Authentication',
        'You will be redirected to the web app to set up 2FA with a QR code.',
        [
          { text: 'Cancel', style: 'cancel' },
          {
            text: 'Open in Browser',
            onPress: () => Linking.openURL(url),
          },
        ]
      );
    } else {
      Alert.alert('Error', 'Server URL not configured');
    }
  };

  const handleExportData = async () => {
    try {
      const client = getClient();
      const res = await client.get('/api/export');
      Alert.alert(
        'Export Data',
        'Your data export has been initiated. Check your email for the download link.',
        [{ text: 'OK' }]
      );
    } catch (err) {
      // If export endpoint doesn't exist, show info
      Alert.alert(
        'Export Data',
        'Data export is available through the web interface. Visit your server URL in a browser to export your data.',
        [
          { text: 'Cancel', style: 'cancel' },
          {
            text: 'Open Web',
            onPress: () => {
              if (serverUrl) Linking.openURL(serverUrl);
            },
          },
        ]
      );
    }
  };

  const bg = darkMode ? '#0f172a' : '#f8fafc';
  const cardBg = darkMode ? '#1e293b' : '#ffffff';
  const textPrimary = darkMode ? '#f1f5f9' : '#1e293b';
  const textSecondary = darkMode ? '#94a3b8' : '#334155';
  const textMuted = darkMode ? '#64748b' : '#64748b';
  const dividerColor = darkMode ? '#334155' : '#f1f5f9';
  const cardShadow = darkMode ? 'transparent' : '#000';

  return (
    <View style={[styles.container, { backgroundColor: bg }]}>
      <StatusBar
        barStyle={darkMode ? 'light-content' : 'light-content'}
        backgroundColor="#6366f1"
      />
      <View style={styles.header}>
        <View style={styles.avatarCircle}>
          <Text style={styles.avatarText}>
            {(user?.name || 'U').charAt(0).toUpperCase()}
          </Text>
        </View>
        <Text style={styles.userName}>{user?.name || 'User'}</Text>
        <Text style={styles.userEmail}>{user?.email || ''}</Text>
      </View>

      <ScrollView contentContainerStyle={styles.content}>
        <View style={[styles.card, { backgroundColor: cardBg, shadowColor: cardShadow }]}>
          <Text style={[styles.cardTitle, { color: textMuted }]}>Account</Text>

          <View style={styles.infoRow}>
            <Text style={[styles.infoLabel, { color: textSecondary }]}>Name</Text>
            <Text style={[styles.infoValue, { color: textMuted }]}>{user?.name || '-'}</Text>
          </View>

          <View style={[styles.divider, { backgroundColor: dividerColor }]} />

          <View style={styles.infoRow}>
            <Text style={[styles.infoLabel, { color: textSecondary }]}>Email</Text>
            <Text style={[styles.infoValue, { color: textMuted }]}>{user?.email || '-'}</Text>
          </View>
        </View>

        <View style={[styles.card, { backgroundColor: cardBg, shadowColor: cardShadow }]}>
          <Text style={[styles.cardTitle, { color: textMuted }]}>Preferences</Text>

          <View style={styles.settingRow}>
            <Text style={[styles.infoLabel, { color: textSecondary }]}>Dark Mode</Text>
            <Switch
              value={darkMode}
              onValueChange={toggleDarkMode}
              trackColor={{ false: '#e2e8f0', true: '#818cf8' }}
              thumbColor={darkMode ? '#6366f1' : '#f4f4f5'}
            />
          </View>
        </View>

        <View style={[styles.card, { backgroundColor: cardBg, shadowColor: cardShadow }]}>
          <Text style={[styles.cardTitle, { color: textMuted }]}>Security</Text>

          <TouchableOpacity style={styles.actionRow} onPress={handle2FASetup}>
            <Text style={styles.actionText}>Set Up 2FA</Text>
            <Text style={styles.arrow}>-></Text>
          </TouchableOpacity>

          <View style={[styles.divider, { backgroundColor: dividerColor }]} />

          <View style={styles.infoRow}>
            <Text style={[styles.infoLabel, { color: textSecondary }]}>2FA Status</Text>
            <View style={[styles.statusBadge, user?.twoFactorEnabled ? styles.statusBadgeActive : styles.statusBadgeInactive]}>
              <Text style={[styles.statusText, user?.twoFactorEnabled ? styles.statusTextActive : styles.statusTextInactive]}>
                {user?.twoFactorEnabled ? 'Enabled' : 'Disabled'}
              </Text>
            </View>
          </View>
        </View>

        <View style={[styles.card, { backgroundColor: cardBg, shadowColor: cardShadow }]}>
          <Text style={[styles.cardTitle, { color: textMuted }]}>Data</Text>

          <TouchableOpacity style={styles.actionRow} onPress={handleExportData}>
            <Text style={styles.actionText}>Export My Data</Text>
            <Text style={styles.arrow}>-></Text>
          </TouchableOpacity>
        </View>

        <View style={[styles.card, { backgroundColor: cardBg, shadowColor: cardShadow }]}>
          <Text style={[styles.cardTitle, { color: textMuted }]}>Server</Text>

          <View style={styles.infoRow}>
            <Text style={[styles.infoLabel, { color: textSecondary }]}>URL</Text>
            <Text style={[styles.infoValue, { color: textMuted }]} numberOfLines={1}>
              {serverUrl || '-'}
            </Text>
          </View>

          <View style={[styles.divider, { backgroundColor: dividerColor }]} />

          <TouchableOpacity
            style={styles.actionRow}
            onPress={handleChangeServer}
          >
            <Text style={styles.actionText}>Change Server</Text>
            <Text style={styles.arrow}>-></Text>
          </TouchableOpacity>
        </View>

        <View style={[styles.card, { backgroundColor: cardBg, shadowColor: cardShadow }]}>
          <Text style={[styles.cardTitle, { color: textMuted }]}>App</Text>

          <View style={styles.infoRow}>
            <Text style={[styles.infoLabel, { color: textSecondary }]}>Version</Text>
            <Text style={[styles.infoValue, { color: textMuted }]}>1.0.0</Text>
          </View>

          <View style={[styles.divider, { backgroundColor: dividerColor }]} />

          <View style={styles.infoRow}>
            <Text style={[styles.infoLabel, { color: textSecondary }]}>Name</Text>
            <Text style={[styles.infoValue, { color: textMuted }]}>RemindFlow</Text>
          </View>
        </View>

        <TouchableOpacity style={styles.logoutButton} onPress={handleLogout}>
          <Text style={styles.logoutButtonText}>Logout</Text>
        </TouchableOpacity>

        <View style={{ height: 32 }} />
      </ScrollView>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f8fafc',
  },
  header: {
    backgroundColor: '#6366f1',
    paddingTop: 60,
    paddingBottom: 32,
    alignItems: 'center',
    borderBottomLeftRadius: 30,
    borderBottomRightRadius: 30,
    shadowColor: '#6366f1',
    shadowOffset: { width: 0, height: 8 },
    shadowOpacity: 0.3,
    shadowRadius: 16,
    elevation: 10,
  },
  avatarCircle: {
    width: 80,
    height: 80,
    borderRadius: 40,
    backgroundColor: 'rgba(255,255,255,0.2)',
    justifyContent: 'center',
    alignItems: 'center',
    marginBottom: 14,
  },
  avatarText: {
    color: '#ffffff',
    fontSize: 32,
    fontWeight: '700',
  },
  userName: {
    fontSize: 22,
    fontWeight: '700',
    color: '#ffffff',
  },
  userEmail: {
    fontSize: 14,
    color: 'rgba(255,255,255,0.8)',
    marginTop: 4,
  },
  content: {
    padding: 16,
    paddingTop: 24,
  },
  card: {
    backgroundColor: '#ffffff',
    borderRadius: 16,
    padding: 18,
    marginBottom: 14,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.06,
    shadowRadius: 8,
    elevation: 3,
  },
  cardTitle: {
    fontSize: 13,
    fontWeight: '700',
    color: '#64748b',
    textTransform: 'uppercase',
    letterSpacing: 0.5,
    marginBottom: 14,
  },
  infoRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: 6,
  },
  settingRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: 4,
  },
  infoLabel: {
    fontSize: 15,
    color: '#334155',
    fontWeight: '500',
  },
  infoValue: {
    fontSize: 15,
    color: '#64748b',
    maxWidth: '60%',
    textAlign: 'right',
  },
  divider: {
    height: 1,
    backgroundColor: '#f1f5f9',
    marginVertical: 10,
  },
  actionRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: 6,
  },
  actionText: {
    fontSize: 15,
    color: '#6366f1',
    fontWeight: '600',
  },
  arrow: {
    fontSize: 16,
    color: '#6366f1',
    fontWeight: '600',
  },
  statusBadge: {
    paddingHorizontal: 10,
    paddingVertical: 4,
    borderRadius: 8,
  },
  statusBadgeActive: {
    backgroundColor: '#f0fdf4',
  },
  statusBadgeInactive: {
    backgroundColor: '#fef2f2',
  },
  statusText: {
    fontSize: 12,
    fontWeight: '700',
  },
  statusTextActive: {
    color: '#16a34a',
  },
  statusTextInactive: {
    color: '#dc2626',
  },
  logoutButton: {
    backgroundColor: '#fef2f2',
    borderWidth: 1.5,
    borderColor: '#fecaca',
    borderRadius: 14,
    padding: 16,
    alignItems: 'center',
    marginTop: 8,
  },
  logoutButtonText: {
    color: '#dc2626',
    fontSize: 16,
    fontWeight: '700',
  },
});

export default ProfileScreen;
