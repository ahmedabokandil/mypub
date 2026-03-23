import React, { useState, useEffect, useCallback } from 'react';
import {
  View,
  Text,
  FlatList,
  TouchableOpacity,
  StyleSheet,
  ActivityIndicator,
  RefreshControl,
  StatusBar,
} from 'react-native';
import { formatDistanceToNow } from 'date-fns';
import { getClient } from '../api/client';

const NOTIFICATION_ICONS = {
  task_assigned: '📋',
  task_due: '⏰',
  comment: '💬',
  mention: '📢',
  reminder: '🔔',
  board_invite: '📨',
  default: '🔔',
};

const NotificationsScreen = () => {
  const [notifications, setNotifications] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const fetchNotifications = useCallback(async () => {
    try {
      const client = getClient();
      const res = await client.get('/api/notifications');
      setNotifications(res.data.notifications || res.data || []);
    } catch (err) {
      console.error('Error fetching notifications:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchNotifications();
  }, [fetchNotifications]);

  const onRefresh = () => {
    setRefreshing(true);
    fetchNotifications();
  };

  const markAsRead = async (notificationId) => {
    try {
      const client = getClient();
      await client.put(`/api/notifications/${notificationId}/read`);
      setNotifications((prev) =>
        prev.map((n) =>
          n._id === notificationId ? { ...n, read: true } : n
        )
      );
    } catch (err) {
      console.error('Error marking notification as read:', err);
    }
  };

  const markAllAsRead = async () => {
    try {
      const client = getClient();
      await client.put('/api/notifications/read-all');
      setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
    } catch (err) {
      console.error('Error marking all as read:', err);
    }
  };

  const unreadCount = notifications.filter((n) => !n.read).length;

  const renderNotification = ({ item }) => {
    const icon =
      NOTIFICATION_ICONS[item.type] || NOTIFICATION_ICONS.default;
    const timeAgo = item.createdAt
      ? formatDistanceToNow(new Date(item.createdAt), { addSuffix: true })
      : '';

    return (
      <TouchableOpacity
        style={[styles.notificationItem, !item.read && styles.unreadItem]}
        onPress={() => markAsRead(item._id)}
        activeOpacity={0.7}
      >
        <View style={[styles.iconContainer, !item.read && styles.unreadIconContainer]}>
          <Text style={styles.icon}>{icon}</Text>
        </View>
        <View style={styles.notificationContent}>
          <Text style={[styles.notificationTitle, !item.read && styles.unreadText]}>
            {item.title || item.message}
          </Text>
          {item.message && item.title ? (
            <Text style={styles.notificationMessage} numberOfLines={2}>
              {item.message}
            </Text>
          ) : null}
          <Text style={styles.timeAgo}>{timeAgo}</Text>
        </View>
        {!item.read ? <View style={styles.unreadDot} /> : null}
      </TouchableOpacity>
    );
  };

  if (loading) {
    return (
      <View style={styles.loadingContainer}>
        <ActivityIndicator size="large" color="#6366f1" />
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <StatusBar barStyle="dark-content" backgroundColor="#f8fafc" />
      <View style={styles.header}>
        <View>
          <Text style={styles.headerTitle}>Notifications</Text>
          {unreadCount > 0 ? (
            <Text style={styles.headerSubtitle}>
              {unreadCount} unread
            </Text>
          ) : null}
        </View>
        {unreadCount > 0 ? (
          <TouchableOpacity
            style={styles.markAllButton}
            onPress={markAllAsRead}
          >
            <Text style={styles.markAllText}>Mark all read</Text>
          </TouchableOpacity>
        ) : null}
      </View>

      <FlatList
        data={notifications}
        renderItem={renderNotification}
        keyExtractor={(item) => item._id}
        contentContainerStyle={styles.listContainer}
        refreshControl={
          <RefreshControl
            refreshing={refreshing}
            onRefresh={onRefresh}
            colors={['#6366f1']}
            tintColor="#6366f1"
          />
        }
        ListEmptyComponent={
          <View style={styles.emptyContainer}>
            <Text style={styles.emptyIcon}>🔔</Text>
            <Text style={styles.emptyTitle}>No Notifications</Text>
            <Text style={styles.emptyText}>
              You're all caught up! Notifications will appear here.
            </Text>
          </View>
        }
      />
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f8fafc',
  },
  loadingContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: '#f8fafc',
  },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingHorizontal: 20,
    paddingTop: 56,
    paddingBottom: 16,
    backgroundColor: '#f8fafc',
  },
  headerTitle: {
    fontSize: 28,
    fontWeight: '800',
    color: '#1e293b',
  },
  headerSubtitle: {
    fontSize: 13,
    color: '#6366f1',
    fontWeight: '600',
    marginTop: 2,
  },
  markAllButton: {
    backgroundColor: '#eef2ff',
    paddingHorizontal: 14,
    paddingVertical: 8,
    borderRadius: 10,
  },
  markAllText: {
    color: '#6366f1',
    fontWeight: '700',
    fontSize: 13,
  },
  listContainer: {
    padding: 16,
    paddingBottom: 32,
  },
  notificationItem: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#ffffff',
    borderRadius: 14,
    padding: 14,
    marginBottom: 10,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 1 },
    shadowOpacity: 0.04,
    shadowRadius: 4,
    elevation: 2,
  },
  unreadItem: {
    backgroundColor: '#fafafe',
    borderWidth: 1,
    borderColor: '#e0e7ff',
  },
  iconContainer: {
    width: 44,
    height: 44,
    borderRadius: 14,
    backgroundColor: '#f1f5f9',
    justifyContent: 'center',
    alignItems: 'center',
    marginRight: 12,
  },
  unreadIconContainer: {
    backgroundColor: '#eef2ff',
  },
  icon: {
    fontSize: 20,
  },
  notificationContent: {
    flex: 1,
  },
  notificationTitle: {
    fontSize: 14,
    fontWeight: '500',
    color: '#334155',
    lineHeight: 20,
  },
  unreadText: {
    fontWeight: '700',
    color: '#1e293b',
  },
  notificationMessage: {
    fontSize: 13,
    color: '#64748b',
    marginTop: 2,
    lineHeight: 18,
  },
  timeAgo: {
    fontSize: 12,
    color: '#94a3b8',
    marginTop: 4,
  },
  unreadDot: {
    width: 10,
    height: 10,
    borderRadius: 5,
    backgroundColor: '#6366f1',
    marginLeft: 8,
  },
  emptyContainer: {
    alignItems: 'center',
    paddingTop: 80,
  },
  emptyIcon: {
    fontSize: 48,
    marginBottom: 16,
  },
  emptyTitle: {
    fontSize: 20,
    fontWeight: '700',
    color: '#1e293b',
    marginBottom: 8,
  },
  emptyText: {
    fontSize: 14,
    color: '#64748b',
    textAlign: 'center',
    maxWidth: 250,
    lineHeight: 20,
  },
});

export default NotificationsScreen;
