import { useState, useEffect, useCallback } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Keyboard } from 'lucide-react';
import { useNavigate } from 'react-router-dom';
import { useTheme } from '../context/ThemeContext';

const shortcuts = [
  { keys: ['Ctrl', 'K'], description: 'Focus search', action: 'search' },
  { keys: ['/'], description: 'Focus search', action: 'search' },
  { keys: ['Ctrl', 'N'], description: 'New task', action: 'new-task' },
  { keys: ['Ctrl', 'B'], description: 'New board', action: 'new-board' },
  { keys: ['D'], description: 'Toggle dark mode', action: 'dark-mode' },
  { keys: ['?'], description: 'Show shortcuts help', action: 'help' },
  { keys: ['Esc'], description: 'Close modals', action: 'escape' },
];

export default function KeyboardShortcuts({ onNewTask, onNewBoard }) {
  const [showHelp, setShowHelp] = useState(false);
  const navigate = useNavigate();
  const { toggleTheme } = useTheme();

  const handleKeyDown = useCallback((e) => {
    const target = e.target;
    const isInput = target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable;

    // Ctrl+K always works
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
      e.preventDefault();
      navigate('/search');
      return;
    }

    // Ctrl+N
    if ((e.ctrlKey || e.metaKey) && e.key === 'n') {
      e.preventDefault();
      if (onNewTask) onNewTask();
      return;
    }

    // Ctrl+B
    if ((e.ctrlKey || e.metaKey) && e.key === 'b') {
      e.preventDefault();
      if (onNewBoard) onNewBoard();
      return;
    }

    // Skip single-key shortcuts if in an input
    if (isInput) return;

    if (e.key === '/' && !e.ctrlKey && !e.metaKey) {
      e.preventDefault();
      navigate('/search');
      return;
    }

    if (e.key === 'd' && !e.ctrlKey && !e.metaKey) {
      toggleTheme();
      return;
    }

    if (e.key === '?' && !e.ctrlKey && !e.metaKey) {
      e.preventDefault();
      setShowHelp(true);
      return;
    }

    if (e.key === 'Escape') {
      setShowHelp(false);
    }
  }, [navigate, toggleTheme, onNewTask, onNewBoard]);

  useEffect(() => {
    document.addEventListener('keydown', handleKeyDown);
    return () => document.removeEventListener('keydown', handleKeyDown);
  }, [handleKeyDown]);

  return (
    <AnimatePresence>
      {showHelp && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4"
          onClick={() => setShowHelp(false)}
        >
          <motion.div
            initial={{ opacity: 0, y: 20, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: 20, scale: 0.95 }}
            onClick={(e) => e.stopPropagation()}
            className="w-full max-w-md bg-white dark:bg-gray-800 rounded-2xl shadow-2xl overflow-hidden"
          >
            <div className="bg-gradient-to-r from-indigo-600 to-purple-600 px-6 py-4 flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Keyboard className="w-5 h-5 text-white" />
                <h2 className="text-lg font-bold text-white">Keyboard Shortcuts</h2>
              </div>
              <button
                onClick={() => setShowHelp(false)}
                className="p-1.5 hover:bg-white/20 rounded-lg transition-colors"
              >
                <X className="w-5 h-5 text-white" />
              </button>
            </div>
            <div className="p-4 space-y-2">
              {shortcuts.map((shortcut) => (
                <div
                  key={shortcut.description}
                  className="flex items-center justify-between py-2.5 px-3 rounded-xl hover:bg-slate-50 dark:hover:bg-gray-700/50"
                >
                  <span className="text-sm text-slate-700 dark:text-gray-300">{shortcut.description}</span>
                  <div className="flex items-center gap-1">
                    {shortcut.keys.map((key, i) => (
                      <span key={i}>
                        <kbd className="px-2 py-1 bg-slate-100 dark:bg-gray-700 border border-slate-200 dark:border-gray-600 rounded-md text-xs font-mono font-semibold text-slate-600 dark:text-gray-400">
                          {key}
                        </kbd>
                        {i < shortcut.keys.length - 1 && <span className="text-slate-400 mx-0.5">+</span>}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}
