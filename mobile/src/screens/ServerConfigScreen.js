import React, { useState } from 'react';
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  StyleSheet,
  ActivityIndicator,
  KeyboardAvoidingView,
  Platform,
  ScrollView,
  StatusBar,
} from 'react-native';
import { useAuth } from '../context/AuthContext';
import { testConnection } from '../api/client';

const ServerConfigScreen = () => {
  const { setServerUrl } = useAuth();
  const [url, setUrl] = useState('');
  const [testing, setTesting] = useState(false);
  const [connecting, setConnecting] = useState(false);
  const [testResult, setTestResult] = useState(null);
  const [error, setError] = useState('');

  const handleTestConnection = async () => {
    if (!url.trim()) {
      setError('Please enter a server URL');
      return;
    }
    setTesting(true);
    setError('');
    setTestResult(null);

    const result = await testConnection(url.trim());
    setTesting(false);

    if (result.success) {
      setTestResult('Connection successful!');
    } else {
      setError(result.error || 'Could not connect to server');
    }
  };

  const handleConnect = async () => {
    if (!url.trim()) {
      setError('Please enter a server URL');
      return;
    }
    setConnecting(true);
    setError('');

    try {
      const result = await testConnection(url.trim());
      if (result.success) {
        await setServerUrl(url.trim());
      } else {
        setError(result.error || 'Could not connect to server');
      }
    } catch (err) {
      setError('Failed to save server configuration');
    } finally {
      setConnecting(false);
    }
  };

  return (
    <View style={styles.container}>
      <StatusBar barStyle="light-content" backgroundColor="#6366f1" />
      <View style={styles.header}>
        <View style={styles.logoContainer}>
          <View style={styles.logoCircle}>
            <Text style={styles.logoIcon}>🔔</Text>
          </View>
          <Text style={styles.logoText}>RemindFlow</Text>
          <Text style={styles.logoSubtext}>Task & Reminder Management</Text>
        </View>
      </View>

      <KeyboardAvoidingView
        behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
        style={styles.formWrapper}
      >
        <ScrollView
          contentContainerStyle={styles.formContainer}
          keyboardShouldPersistTaps="handled"
        >
          <View style={styles.card}>
            <Text style={styles.cardTitle}>Connect to Server</Text>
            <Text style={styles.cardSubtitle}>
              Enter the URL of your RemindFlow backend server
            </Text>

            <View style={styles.inputContainer}>
              <Text style={styles.label}>Server URL</Text>
              <TextInput
                style={styles.input}
                value={url}
                onChangeText={(text) => {
                  setUrl(text);
                  setError('');
                  setTestResult(null);
                }}
                placeholder="https://myserver.com"
                placeholderTextColor="#94a3b8"
                autoCapitalize="none"
                autoCorrect={false}
                keyboardType="url"
              />
            </View>

            {error ? (
              <View style={styles.errorContainer}>
                <Text style={styles.errorText}>{error}</Text>
              </View>
            ) : null}

            {testResult ? (
              <View style={styles.successContainer}>
                <Text style={styles.successText}>{testResult}</Text>
              </View>
            ) : null}

            <TouchableOpacity
              style={styles.testButton}
              onPress={handleTestConnection}
              disabled={testing}
              activeOpacity={0.7}
            >
              {testing ? (
                <ActivityIndicator color="#6366f1" size="small" />
              ) : (
                <Text style={styles.testButtonText}>Test Connection</Text>
              )}
            </TouchableOpacity>

            <TouchableOpacity
              style={styles.connectButton}
              onPress={handleConnect}
              disabled={connecting}
              activeOpacity={0.7}
            >
              {connecting ? (
                <ActivityIndicator color="#ffffff" size="small" />
              ) : (
                <Text style={styles.connectButtonText}>Connect</Text>
              )}
            </TouchableOpacity>
          </View>
        </ScrollView>
      </KeyboardAvoidingView>
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
    paddingBottom: 40,
    borderBottomLeftRadius: 30,
    borderBottomRightRadius: 30,
    shadowColor: '#6366f1',
    shadowOffset: { width: 0, height: 8 },
    shadowOpacity: 0.3,
    shadowRadius: 16,
    elevation: 10,
  },
  logoContainer: {
    alignItems: 'center',
  },
  logoCircle: {
    width: 72,
    height: 72,
    borderRadius: 36,
    backgroundColor: 'rgba(255,255,255,0.2)',
    justifyContent: 'center',
    alignItems: 'center',
    marginBottom: 12,
  },
  logoIcon: {
    fontSize: 32,
  },
  logoText: {
    fontSize: 28,
    fontWeight: '800',
    color: '#ffffff',
    letterSpacing: 0.5,
  },
  logoSubtext: {
    fontSize: 14,
    color: 'rgba(255,255,255,0.8)',
    marginTop: 4,
  },
  formWrapper: {
    flex: 1,
  },
  formContainer: {
    padding: 24,
    paddingTop: 32,
  },
  card: {
    backgroundColor: '#ffffff',
    borderRadius: 20,
    padding: 24,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.08,
    shadowRadius: 12,
    elevation: 5,
  },
  cardTitle: {
    fontSize: 22,
    fontWeight: '700',
    color: '#1e293b',
    marginBottom: 6,
  },
  cardSubtitle: {
    fontSize: 14,
    color: '#64748b',
    marginBottom: 24,
    lineHeight: 20,
  },
  inputContainer: {
    marginBottom: 16,
  },
  label: {
    fontSize: 14,
    fontWeight: '600',
    color: '#374151',
    marginBottom: 8,
  },
  input: {
    borderWidth: 1.5,
    borderColor: '#e2e8f0',
    borderRadius: 12,
    padding: 14,
    fontSize: 16,
    color: '#1e293b',
    backgroundColor: '#f8fafc',
  },
  errorContainer: {
    backgroundColor: '#fef2f2',
    borderRadius: 10,
    padding: 12,
    marginBottom: 12,
  },
  errorText: {
    color: '#dc2626',
    fontSize: 13,
    fontWeight: '500',
  },
  successContainer: {
    backgroundColor: '#f0fdf4',
    borderRadius: 10,
    padding: 12,
    marginBottom: 12,
  },
  successText: {
    color: '#16a34a',
    fontSize: 13,
    fontWeight: '500',
  },
  testButton: {
    borderWidth: 2,
    borderColor: '#6366f1',
    borderRadius: 12,
    padding: 14,
    alignItems: 'center',
    marginBottom: 12,
  },
  testButtonText: {
    color: '#6366f1',
    fontSize: 16,
    fontWeight: '700',
  },
  connectButton: {
    backgroundColor: '#6366f1',
    borderRadius: 12,
    padding: 16,
    alignItems: 'center',
    shadowColor: '#6366f1',
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.3,
    shadowRadius: 8,
    elevation: 4,
  },
  connectButtonText: {
    color: '#ffffff',
    fontSize: 16,
    fontWeight: '700',
  },
});

export default ServerConfigScreen;
