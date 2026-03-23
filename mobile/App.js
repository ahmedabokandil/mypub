import React from 'react';
import { ActivityIndicator, View, StyleSheet } from 'react-native';
import { NavigationContainer } from '@react-navigation/native';
import { createNativeStackNavigator } from '@react-navigation/native-stack';
import { createBottomTabNavigator } from '@react-navigation/bottom-tabs';
import { SafeAreaProvider } from 'react-native-safe-area-context';
import { GestureHandlerRootView } from 'react-native-gesture-handler';

import { AuthProvider, useAuth } from './src/context/AuthContext';

import ServerConfigScreen from './src/screens/ServerConfigScreen';
import LoginScreen from './src/screens/LoginScreen';
import RegisterScreen from './src/screens/RegisterScreen';
import DashboardScreen from './src/screens/DashboardScreen';
import BoardScreen from './src/screens/BoardScreen';
import TaskDetailScreen from './src/screens/TaskDetailScreen';
import NotificationsScreen from './src/screens/NotificationsScreen';
import ProfileScreen from './src/screens/ProfileScreen';
import SearchScreen from './src/screens/SearchScreen';
import CalendarScreen from './src/screens/CalendarScreen';
import AnalyticsScreen from './src/screens/AnalyticsScreen';
import ChatScreen from './src/screens/ChatScreen';

const AuthStack = createNativeStackNavigator();
const MainStack = createNativeStackNavigator();
const Tab = createBottomTabNavigator();

const TAB_ICONS = {
  Dashboard: { active: '🏠', inactive: '🏡' },
  Search: { active: '🔍', inactive: '🔍' },
  Calendar: { active: '📅', inactive: '📅' },
  Analytics: { active: '📊', inactive: '📊' },
  Notifications: { active: '🔔', inactive: '🔕' },
  Profile: { active: '👤', inactive: '👤' },
};

function TabIcon({ routeName, focused }) {
  const icons = TAB_ICONS[routeName] || { active: '●', inactive: '○' };
  return (
    <View style={tabStyles.iconContainer}>
      <View style={[tabStyles.iconCircle, focused && tabStyles.iconCircleActive]}>
        <View style={tabStyles.iconInner}>
          <ActivityIndicator
            size={0}
            style={{ display: 'none' }}
          />
        </View>
      </View>
    </View>
  );
}

function HomeTabs() {
  return (
    <Tab.Navigator
      screenOptions={({ route }) => ({
        headerShown: false,
        tabBarStyle: {
          backgroundColor: '#ffffff',
          borderTopWidth: 0,
          height: 64,
          paddingBottom: 8,
          paddingTop: 8,
          shadowColor: '#000',
          shadowOffset: { width: 0, height: -4 },
          shadowOpacity: 0.06,
          shadowRadius: 12,
          elevation: 10,
        },
        tabBarActiveTintColor: '#6366f1',
        tabBarInactiveTintColor: '#94a3b8',
        tabBarLabelStyle: {
          fontSize: 10,
          fontWeight: '600',
        },
        tabBarIcon: ({ focused }) => {
          const icons = TAB_ICONS[route.name];
          const icon = focused ? icons?.active : icons?.inactive;
          return (
            <View style={{ alignItems: 'center' }}>
              <View
                style={[
                  {
                    width: 32,
                    height: 32,
                    borderRadius: 10,
                    justifyContent: 'center',
                    alignItems: 'center',
                  },
                  focused && { backgroundColor: '#eef2ff' },
                ]}
              >
                <View>
                  <ActivityIndicator size={0} style={{ display: 'none' }} />
                </View>
              </View>
            </View>
          );
        },
      })}
    >
      <Tab.Screen
        name="Dashboard"
        component={DashboardScreen}
        options={{
          tabBarIcon: ({ focused }) => (
            <TabLabel emoji="🏠" focused={focused} />
          ),
        }}
      />
      <Tab.Screen
        name="Search"
        component={SearchScreen}
        options={{
          tabBarIcon: ({ focused }) => (
            <TabLabel emoji="🔍" focused={focused} />
          ),
        }}
      />
      <Tab.Screen
        name="Calendar"
        component={CalendarScreen}
        options={{
          tabBarIcon: ({ focused }) => (
            <TabLabel emoji="📅" focused={focused} />
          ),
        }}
      />
      <Tab.Screen
        name="Analytics"
        component={AnalyticsScreen}
        options={{
          tabBarIcon: ({ focused }) => (
            <TabLabel emoji="📊" focused={focused} />
          ),
        }}
      />
      <Tab.Screen
        name="Notifications"
        component={NotificationsScreen}
        options={{
          tabBarIcon: ({ focused }) => (
            <TabLabel emoji="🔔" focused={focused} />
          ),
        }}
      />
      <Tab.Screen
        name="Profile"
        component={ProfileScreen}
        options={{
          tabBarIcon: ({ focused }) => (
            <TabLabel emoji="👤" focused={focused} />
          ),
        }}
      />
    </Tab.Navigator>
  );
}

function TabLabel({ emoji, focused }) {
  return (
    <View
      style={[
        tabStyles.tabIconWrap,
        focused && tabStyles.tabIconWrapActive,
      ]}
    >
      <View>
        <ActivityIndicator size={0} style={{ position: 'absolute', opacity: 0 }} />
        <View style={tabStyles.emojiWrap}>
          <EmojiText emoji={emoji} />
        </View>
      </View>
    </View>
  );
}

function EmojiText({ emoji }) {
  const Text = require('react-native').Text;
  return <Text style={{ fontSize: 20 }}>{emoji}</Text>;
}

function MainNavigator() {
  return (
    <MainStack.Navigator screenOptions={{ headerShown: false }}>
      <MainStack.Screen name="HomeTabs" component={HomeTabs} />
      <MainStack.Screen
        name="Board"
        component={BoardScreen}
        options={{ animation: 'slide_from_right' }}
      />
      <MainStack.Screen
        name="TaskDetail"
        component={TaskDetailScreen}
        options={{ animation: 'slide_from_right' }}
      />
      <MainStack.Screen
        name="Chat"
        component={ChatScreen}
        options={{ animation: 'slide_from_right' }}
      />
    </MainStack.Navigator>
  );
}

function AuthNavigator() {
  return (
    <AuthStack.Navigator screenOptions={{ headerShown: false }}>
      <AuthStack.Screen name="Login" component={LoginScreen} />
      <AuthStack.Screen
        name="Register"
        component={RegisterScreen}
        options={{ animation: 'slide_from_right' }}
      />
    </AuthStack.Navigator>
  );
}

function AppNavigator() {
  const { user, token, serverUrl, loading } = useAuth();

  if (loading) {
    return (
      <View style={styles.loadingContainer}>
        <ActivityIndicator size="large" color="#6366f1" />
      </View>
    );
  }

  if (!serverUrl) {
    return <ServerConfigScreen />;
  }

  if (!token || !user) {
    return (
      <NavigationContainer>
        <AuthNavigator />
      </NavigationContainer>
    );
  }

  return (
    <NavigationContainer>
      <MainNavigator />
    </NavigationContainer>
  );
}

export default function App() {
  return (
    <GestureHandlerRootView style={{ flex: 1 }}>
      <SafeAreaProvider>
        <AuthProvider>
          <AppNavigator />
        </AuthProvider>
      </SafeAreaProvider>
    </GestureHandlerRootView>
  );
}

const styles = StyleSheet.create({
  loadingContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: '#f8fafc',
  },
});

const tabStyles = StyleSheet.create({
  tabIconWrap: {
    width: 36,
    height: 36,
    borderRadius: 12,
    justifyContent: 'center',
    alignItems: 'center',
  },
  tabIconWrapActive: {
    backgroundColor: '#eef2ff',
  },
  emojiWrap: {
    justifyContent: 'center',
    alignItems: 'center',
  },
  iconContainer: {},
  iconCircle: {
    width: 32,
    height: 32,
    borderRadius: 10,
    justifyContent: 'center',
    alignItems: 'center',
  },
  iconCircleActive: {
    backgroundColor: '#eef2ff',
  },
  iconInner: {},
});
