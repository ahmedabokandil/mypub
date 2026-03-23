import React, { createContext, useState, useEffect, useContext } from 'react';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { initializeClient, getClient, setBaseURL, setAuthToken } from '../api/client';

const AuthContext = createContext({});

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [token, setTokenState] = useState(null);
  const [serverUrl, setServerUrlState] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    loadStoredAuth();
  }, []);

  const loadStoredAuth = async () => {
    try {
      const { url, token: storedToken } = await initializeClient();
      const storedUser = await AsyncStorage.getItem('user');

      if (url) {
        setServerUrlState(url);
      }

      if (storedToken && storedUser) {
        setTokenState(storedToken);
        setUser(JSON.parse(storedUser));

        // Validate token
        try {
          const client = getClient();
          const res = await client.get('/api/auth/me');
          setUser(res.data.user || res.data);
        } catch (err) {
          // Token invalid, clear auth
          await AsyncStorage.multiRemove(['token', 'user']);
          setAuthToken('');
          setTokenState(null);
          setUser(null);
        }
      }
    } catch (err) {
      console.error('Error loading auth:', err);
    } finally {
      setLoading(false);
    }
  };

  const setServerUrl = async (url) => {
    const cleanUrl = url.replace(/\/+$/, '');
    setBaseURL(cleanUrl);
    await AsyncStorage.setItem('serverUrl', cleanUrl);
    setServerUrlState(cleanUrl);
  };

  const login = async (email, password) => {
    const client = getClient();
    const res = await client.post('/api/auth/login', { email, password });
    const { token: newToken, user: userData } = res.data;

    await AsyncStorage.setItem('token', newToken);
    await AsyncStorage.setItem('user', JSON.stringify(userData));
    setAuthToken(newToken);
    setTokenState(newToken);
    setUser(userData);
  };

  const register = async (name, email, password) => {
    const client = getClient();
    const res = await client.post('/api/auth/register', { name, email, password });
    const { token: newToken, user: userData } = res.data;

    await AsyncStorage.setItem('token', newToken);
    await AsyncStorage.setItem('user', JSON.stringify(userData));
    setAuthToken(newToken);
    setTokenState(newToken);
    setUser(userData);
  };

  const logout = async () => {
    await AsyncStorage.multiRemove(['token', 'user']);
    setAuthToken('');
    setTokenState(null);
    setUser(null);
  };

  const clearServerUrl = async () => {
    await AsyncStorage.multiRemove(['serverUrl', 'token', 'user']);
    setBaseURL('');
    setAuthToken('');
    setServerUrlState(null);
    setTokenState(null);
    setUser(null);
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        token,
        serverUrl,
        loading,
        setServerUrl,
        login,
        register,
        logout,
        clearServerUrl,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => useContext(AuthContext);

export default AuthContext;
