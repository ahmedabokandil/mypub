import axios from 'axios';
import AsyncStorage from '@react-native-async-storage/async-storage';

let client = null;
let currentBaseURL = '';
let currentToken = '';

export const setBaseURL = (url) => {
  currentBaseURL = url ? url.replace(/\/+$/, '') : '';
  client = null;
};

export const setAuthToken = (token) => {
  currentToken = token || '';
  client = null;
};

export const getClient = () => {
  if (!client) {
    client = axios.create({
      baseURL: currentBaseURL,
      timeout: 15000,
      headers: {
        'Content-Type': 'application/json',
      },
    });

    client.interceptors.request.use(
      (config) => {
        if (currentToken) {
          config.headers.Authorization = `Bearer ${currentToken}`;
        }
        return config;
      },
      (error) => Promise.reject(error)
    );

    client.interceptors.response.use(
      (response) => response,
      (error) => {
        if (error.response?.status === 401) {
          AsyncStorage.multiRemove(['token', 'user']);
        }
        return Promise.reject(error);
      }
    );
  }
  return client;
};

export const initializeClient = async () => {
  const url = await AsyncStorage.getItem('serverUrl');
  const token = await AsyncStorage.getItem('token');
  if (url) {
    currentBaseURL = url.replace(/\/+$/, '');
    currentToken = token || '';
    client = null;
  }
  return { url, token };
};

export const testConnection = async (url) => {
  try {
    const testClient = axios.create({
      baseURL: url.replace(/\/+$/, ''),
      timeout: 10000,
    });
    const response = await testClient.get('/api/health');
    return { success: true, data: response.data };
  } catch (error) {
    return {
      success: false,
      error: error.response?.data?.message || error.message || 'Connection failed',
    };
  }
};
