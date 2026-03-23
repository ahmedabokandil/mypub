import { useState, useRef, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { Bell, LogOut, ChevronDown, Zap, User, LayoutDashboard } from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useNotifications } from '../context/NotificationContext';
import NotificationPanel from './NotificationPanel';

export default function Navbar() {
  const { user, logout } = useAuth();
  const { unreadCount } = useNotifications();
  const [notifOpen, setNotifOpen] = useState(false);
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const navigate = useNavigate();
  const userMenuRef = useRef(null);
  const notifRef = useRef(null);

  useEffect(() => {
    const handleClick = (e) => {
      if (userMenuRef.current && !userMenuRef.current.contains(e.target)) {
        setUserMenuOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, []);

  const handleLogout = () => {
    logout();
    navigate('/login');
  };

  const initials = user?.name
    ? user.name.split(' ').map((n) => n[0]).join('').toUpperCase().slice(0, 2)
    : 'U';

  return (
    <nav className="sticky top-0 z-30 bg-gradient-to-r from-indigo-600 via-indigo-700 to-purple-700 shadow-lg shadow-indigo-500/20">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16">
          {/* Logo */}
          <Link to="/" className="flex items-center gap-2.5 group">
            <div className="w-9 h-9 bg-white/15 backdrop-blur-sm rounded-xl flex items-center justify-center group-hover:bg-white/25 transition-colors">
              <Zap className="w-5 h-5 text-white" />
            </div>
            <span className="text-xl font-bold text-white tracking-tight">RemindFlow</span>
          </Link>

          {/* Right side */}
          <div className="flex items-center gap-3">
            {/* Dashboard link */}
            <Link
              to="/"
              className="hidden sm:flex items-center gap-1.5 px-3 py-2 text-white/70 hover:text-white hover:bg-white/10 rounded-xl transition-all text-sm font-medium"
            >
              <LayoutDashboard className="w-4 h-4" />
              Dashboard
            </Link>

            {/* Notifications */}
            <div className="relative" ref={notifRef}>
              <button
                onClick={() => {
                  setNotifOpen(!notifOpen);
                  setUserMenuOpen(false);
                }}
                className="relative p-2.5 text-white/70 hover:text-white hover:bg-white/10 rounded-xl transition-all"
              >
                <Bell className="w-5 h-5" />
                {unreadCount > 0 && (
                  <motion.span
                    initial={{ scale: 0 }}
                    animate={{ scale: 1 }}
                    className="absolute -top-0.5 -right-0.5 w-5 h-5 bg-red-500 text-white text-xs font-bold rounded-full flex items-center justify-center ring-2 ring-indigo-700"
                  >
                    {unreadCount > 9 ? '9+' : unreadCount}
                  </motion.span>
                )}
              </button>
              <NotificationPanel isOpen={notifOpen} onClose={() => setNotifOpen(false)} />
            </div>

            {/* User menu */}
            <div className="relative" ref={userMenuRef}>
              <button
                onClick={() => {
                  setUserMenuOpen(!userMenuOpen);
                  setNotifOpen(false);
                }}
                className="flex items-center gap-2 pl-2 pr-3 py-1.5 hover:bg-white/10 rounded-xl transition-all"
              >
                <div className="w-8 h-8 bg-white/20 rounded-lg flex items-center justify-center text-white text-sm font-semibold">
                  {initials}
                </div>
                <span className="hidden sm:block text-sm font-medium text-white/90 max-w-[120px] truncate">
                  {user?.name || 'User'}
                </span>
                <ChevronDown className={`w-4 h-4 text-white/50 transition-transform ${userMenuOpen ? 'rotate-180' : ''}`} />
              </button>

              <AnimatePresence>
                {userMenuOpen && (
                  <motion.div
                    initial={{ opacity: 0, y: -10, scale: 0.95 }}
                    animate={{ opacity: 1, y: 0, scale: 1 }}
                    exit={{ opacity: 0, y: -10, scale: 0.95 }}
                    transition={{ duration: 0.15 }}
                    className="absolute right-0 top-full mt-2 w-56 bg-white rounded-xl shadow-2xl border border-slate-100 z-50 overflow-hidden"
                  >
                    <div className="p-3 border-b border-slate-100">
                      <p className="text-sm font-semibold text-slate-800 truncate">{user?.name}</p>
                      <p className="text-xs text-slate-500 truncate">{user?.email}</p>
                    </div>
                    <div className="p-1.5">
                      <Link
                        to="/"
                        onClick={() => setUserMenuOpen(false)}
                        className="flex items-center gap-2.5 px-3 py-2 text-sm text-slate-600 hover:bg-slate-50 rounded-lg transition-colors"
                      >
                        <LayoutDashboard className="w-4 h-4" />
                        Dashboard
                      </Link>
                      <button
                        onClick={handleLogout}
                        className="w-full flex items-center gap-2.5 px-3 py-2 text-sm text-red-600 hover:bg-red-50 rounded-lg transition-colors"
                      >
                        <LogOut className="w-4 h-4" />
                        Sign out
                      </button>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </div>
        </div>
      </div>
    </nav>
  );
}
