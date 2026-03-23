import { useState, useRef, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Bell, LogOut, ChevronDown, Zap, LayoutDashboard, Search, Calendar,
  BarChart3, Shield, Moon, Sun, Star
} from 'lucide-react';
import { useAuth } from '../context/AuthContext';
import { useNotifications } from '../context/NotificationContext';
import { useTheme } from '../context/ThemeContext';
import NotificationPanel from './NotificationPanel';

export default function Navbar() {
  const { user, logout } = useAuth();
  const { unreadCount } = useNotifications();
  const { theme, toggleTheme } = useTheme();
  const [notifOpen, setNotifOpen] = useState(false);
  const [userMenuOpen, setUserMenuOpen] = useState(false);
  const [navMenuOpen, setNavMenuOpen] = useState(false);
  const navigate = useNavigate();
  const userMenuRef = useRef(null);
  const notifRef = useRef(null);
  const navMenuRef = useRef(null);

  useEffect(() => {
    const handleClick = (e) => {
      if (userMenuRef.current && !userMenuRef.current.contains(e.target)) {
        setUserMenuOpen(false);
      }
      if (navMenuRef.current && !navMenuRef.current.contains(e.target)) {
        setNavMenuOpen(false);
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
    <nav className="sticky top-0 z-30 bg-gradient-to-r from-indigo-600 via-indigo-700 to-purple-700 dark:from-gray-900 dark:via-gray-900 dark:to-gray-800 shadow-lg shadow-indigo-500/20 dark:shadow-gray-900/50">
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
          <div className="flex items-center gap-2 sm:gap-3">
            {/* Dashboard link */}
            <Link
              to="/"
              className="hidden sm:flex items-center gap-1.5 px-3 py-2 text-white/70 hover:text-white hover:bg-white/10 rounded-xl transition-all text-sm font-medium"
            >
              <LayoutDashboard className="w-4 h-4" />
              Dashboard
            </Link>

            {/* Nav dropdown (Calendar, Analytics) */}
            <div className="relative hidden sm:block" ref={navMenuRef}>
              <button
                onClick={() => {
                  setNavMenuOpen(!navMenuOpen);
                  setNotifOpen(false);
                  setUserMenuOpen(false);
                }}
                className="flex items-center gap-1 px-3 py-2 text-white/70 hover:text-white hover:bg-white/10 rounded-xl transition-all text-sm font-medium"
              >
                More
                <ChevronDown className={`w-3.5 h-3.5 transition-transform ${navMenuOpen ? 'rotate-180' : ''}`} />
              </button>

              <AnimatePresence>
                {navMenuOpen && (
                  <motion.div
                    initial={{ opacity: 0, y: -10, scale: 0.95 }}
                    animate={{ opacity: 1, y: 0, scale: 1 }}
                    exit={{ opacity: 0, y: -10, scale: 0.95 }}
                    transition={{ duration: 0.15 }}
                    className="absolute right-0 top-full mt-2 w-48 bg-white dark:bg-gray-800 rounded-xl shadow-2xl border border-slate-100 dark:border-gray-700 z-50 overflow-hidden"
                  >
                    <div className="p-1.5">
                      <Link
                        to="/calendar"
                        onClick={() => setNavMenuOpen(false)}
                        className="flex items-center gap-2.5 px-3 py-2 text-sm text-slate-600 dark:text-gray-300 hover:bg-slate-50 dark:hover:bg-gray-700 rounded-lg transition-colors"
                      >
                        <Calendar className="w-4 h-4" />
                        Calendar
                      </Link>
                      <Link
                        to="/analytics"
                        onClick={() => setNavMenuOpen(false)}
                        className="flex items-center gap-2.5 px-3 py-2 text-sm text-slate-600 dark:text-gray-300 hover:bg-slate-50 dark:hover:bg-gray-700 rounded-lg transition-colors"
                      >
                        <BarChart3 className="w-4 h-4" />
                        Analytics
                      </Link>
                      {user?.role === 'admin' && (
                        <Link
                          to="/admin"
                          onClick={() => setNavMenuOpen(false)}
                          className="flex items-center gap-2.5 px-3 py-2 text-sm text-slate-600 dark:text-gray-300 hover:bg-slate-50 dark:hover:bg-gray-700 rounded-lg transition-colors"
                        >
                          <Shield className="w-4 h-4" />
                          Admin
                        </Link>
                      )}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>

            {/* Search */}
            <Link
              to="/search"
              className="p-2.5 text-white/70 hover:text-white hover:bg-white/10 rounded-xl transition-all"
              title="Search (Ctrl+K)"
            >
              <Search className="w-5 h-5" />
            </Link>

            {/* Dark mode toggle */}
            <button
              onClick={toggleTheme}
              className="p-2.5 text-white/70 hover:text-white hover:bg-white/10 rounded-xl transition-all"
              title="Toggle dark mode"
            >
              {theme === 'dark' ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
            </button>

            {/* Notifications */}
            <div className="relative" ref={notifRef}>
              <button
                onClick={() => {
                  setNotifOpen(!notifOpen);
                  setUserMenuOpen(false);
                  setNavMenuOpen(false);
                }}
                className="relative p-2.5 text-white/70 hover:text-white hover:bg-white/10 rounded-xl transition-all"
              >
                <Bell className="w-5 h-5" />
                {unreadCount > 0 && (
                  <motion.span
                    initial={{ scale: 0 }}
                    animate={{ scale: 1 }}
                    className="absolute -top-0.5 -right-0.5 w-5 h-5 bg-red-500 text-white text-xs font-bold rounded-full flex items-center justify-center ring-2 ring-indigo-700 dark:ring-gray-900"
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
                  setNavMenuOpen(false);
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
                    className="absolute right-0 top-full mt-2 w-56 bg-white dark:bg-gray-800 rounded-xl shadow-2xl border border-slate-100 dark:border-gray-700 z-50 overflow-hidden"
                  >
                    <div className="p-3 border-b border-slate-100 dark:border-gray-700">
                      <p className="text-sm font-semibold text-slate-800 dark:text-gray-200 truncate">{user?.name}</p>
                      <p className="text-xs text-slate-500 dark:text-gray-400 truncate">{user?.email}</p>
                    </div>
                    <div className="p-1.5">
                      <Link
                        to="/"
                        onClick={() => setUserMenuOpen(false)}
                        className="flex items-center gap-2.5 px-3 py-2 text-sm text-slate-600 dark:text-gray-300 hover:bg-slate-50 dark:hover:bg-gray-700 rounded-lg transition-colors"
                      >
                        <LayoutDashboard className="w-4 h-4" />
                        Dashboard
                      </Link>
                      <Link
                        to="/calendar"
                        onClick={() => setUserMenuOpen(false)}
                        className="flex items-center gap-2.5 px-3 py-2 text-sm text-slate-600 dark:text-gray-300 hover:bg-slate-50 dark:hover:bg-gray-700 rounded-lg transition-colors sm:hidden"
                      >
                        <Calendar className="w-4 h-4" />
                        Calendar
                      </Link>
                      <Link
                        to="/analytics"
                        onClick={() => setUserMenuOpen(false)}
                        className="flex items-center gap-2.5 px-3 py-2 text-sm text-slate-600 dark:text-gray-300 hover:bg-slate-50 dark:hover:bg-gray-700 rounded-lg transition-colors sm:hidden"
                      >
                        <BarChart3 className="w-4 h-4" />
                        Analytics
                      </Link>
                      {user?.role === 'admin' && (
                        <Link
                          to="/admin"
                          onClick={() => setUserMenuOpen(false)}
                          className="flex items-center gap-2.5 px-3 py-2 text-sm text-slate-600 dark:text-gray-300 hover:bg-slate-50 dark:hover:bg-gray-700 rounded-lg transition-colors"
                        >
                          <Shield className="w-4 h-4" />
                          Admin Panel
                        </Link>
                      )}
                      <button
                        onClick={handleLogout}
                        className="w-full flex items-center gap-2.5 px-3 py-2 text-sm text-red-600 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-colors"
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
