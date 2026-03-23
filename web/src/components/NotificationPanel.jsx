import { motion, AnimatePresence } from 'framer-motion';
import { Bell, Check, CheckCheck, Inbox } from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import { useNotifications } from '../context/NotificationContext';

export default function NotificationPanel({ isOpen, onClose }) {
  const { notifications, markAsRead, markAllAsRead, unreadCount } = useNotifications();

  return (
    <AnimatePresence>
      {isOpen && (
        <>
          <div className="fixed inset-0 z-40" onClick={onClose} />
          <motion.div
            initial={{ opacity: 0, y: -10, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -10, scale: 0.95 }}
            transition={{ duration: 0.15 }}
            className="absolute right-0 top-full mt-2 w-96 bg-white rounded-2xl shadow-2xl border border-slate-100 z-50 overflow-hidden"
          >
            <div className="p-4 border-b border-slate-100 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Bell className="w-5 h-5 text-primary-600" />
                <h3 className="font-semibold text-slate-800">Notifications</h3>
                {unreadCount > 0 && (
                  <span className="px-2 py-0.5 bg-primary-100 text-primary-700 text-xs font-medium rounded-full">
                    {unreadCount} new
                  </span>
                )}
              </div>
              {unreadCount > 0 && (
                <button
                  onClick={markAllAsRead}
                  className="text-xs text-primary-600 hover:text-primary-700 font-medium flex items-center gap-1 transition-colors"
                >
                  <CheckCheck className="w-3.5 h-3.5" />
                  Mark all read
                </button>
              )}
            </div>

            <div className="max-h-96 overflow-y-auto scrollbar-thin">
              {notifications.length === 0 ? (
                <div className="p-8 text-center">
                  <div className="w-16 h-16 bg-slate-100 rounded-full flex items-center justify-center mx-auto mb-3">
                    <Inbox className="w-8 h-8 text-slate-300" />
                  </div>
                  <p className="text-slate-500 font-medium">No notifications yet</p>
                  <p className="text-slate-400 text-sm mt-1">We'll let you know when something comes up</p>
                </div>
              ) : (
                notifications.map((notification) => (
                  <div
                    key={notification._id}
                    onClick={() => !notification.read && markAsRead(notification._id)}
                    className={`p-4 border-b border-slate-50 hover:bg-slate-50 transition-colors cursor-pointer ${
                      !notification.read ? 'bg-primary-50/50' : ''
                    }`}
                  >
                    <div className="flex gap-3">
                      <div className={`w-2 h-2 rounded-full mt-2 flex-shrink-0 ${
                        !notification.read ? 'bg-primary-500' : 'bg-transparent'
                      }`} />
                      <div className="flex-1 min-w-0">
                        <p className={`text-sm ${!notification.read ? 'font-semibold text-slate-800' : 'text-slate-600'}`}>
                          {notification.title || notification.message}
                        </p>
                        {notification.message && notification.title && (
                          <p className="text-xs text-slate-500 mt-0.5 truncate">{notification.message}</p>
                        )}
                        <p className="text-xs text-slate-400 mt-1">
                          {notification.createdAt
                            ? formatDistanceToNow(new Date(notification.createdAt), { addSuffix: true })
                            : 'Just now'}
                        </p>
                      </div>
                      {!notification.read && (
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            markAsRead(notification._id);
                          }}
                          className="p-1 hover:bg-primary-100 rounded-lg transition-colors self-start"
                          title="Mark as read"
                        >
                          <Check className="w-3.5 h-3.5 text-primary-600" />
                        </button>
                      )}
                    </div>
                  </div>
                ))
              )}
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>
  );
}
