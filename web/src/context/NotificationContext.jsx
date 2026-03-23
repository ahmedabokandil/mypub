import { createContext, useContext, useState, useEffect, useCallback, useRef } from 'react';
import api from '../api/axios';
import { useAuth } from './AuthContext';

const NotificationContext = createContext(null);

export function NotificationProvider({ children }) {
  const { token } = useAuth();
  const [notifications, setNotifications] = useState([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const prevCountRef = useRef(0);

  useEffect(() => {
    if ('Notification' in window && Notification.permission === 'default') {
      Notification.requestPermission();
    }
  }, []);

  const fetchNotifications = useCallback(async () => {
    if (!token) return;
    try {
      const res = await api.get('/api/notifications');
      const data = res.data.notifications || res.data || [];
      setNotifications(data);
      const newUnread = data.filter((n) => !n.read).length;

      if (newUnread > prevCountRef.current && 'Notification' in window && Notification.permission === 'granted') {
        const latest = data.find((n) => !n.read);
        if (latest) {
          new Notification('RemindFlow', {
            body: latest.message || latest.title || 'You have a new notification',
            icon: '/favicon.svg',
          });
        }
      }
      prevCountRef.current = newUnread;
      setUnreadCount(newUnread);
    } catch (err) {
      console.error('Failed to fetch notifications:', err);
    }
  }, [token]);

  useEffect(() => {
    if (!token) {
      setNotifications([]);
      setUnreadCount(0);
      return;
    }
    fetchNotifications();
    const interval = setInterval(fetchNotifications, 30000);
    return () => clearInterval(interval);
  }, [token, fetchNotifications]);

  const markAsRead = async (id) => {
    try {
      await api.patch(`/api/notifications/${id}/read`);
      setNotifications((prev) =>
        prev.map((n) => (n._id === id ? { ...n, read: true } : n))
      );
      setUnreadCount((prev) => Math.max(0, prev - 1));
    } catch (err) {
      console.error('Failed to mark notification as read:', err);
    }
  };

  const markAllAsRead = async () => {
    try {
      await api.patch('/api/notifications/read-all');
      setNotifications((prev) => prev.map((n) => ({ ...n, read: true })));
      setUnreadCount(0);
    } catch (err) {
      console.error('Failed to mark all as read:', err);
    }
  };

  return (
    <NotificationContext.Provider value={{ notifications, unreadCount, fetchNotifications, markAsRead, markAllAsRead }}>
      {children}
    </NotificationContext.Provider>
  );
}

export function useNotifications() {
  const context = useContext(NotificationContext);
  if (!context) throw new Error('useNotifications must be used within NotificationProvider');
  return context;
}
