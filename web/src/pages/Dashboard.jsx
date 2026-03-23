import { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Plus, Users, CheckSquare, Clock, X, Palette, LayoutGrid, Loader2,
  Star, Archive, ArchiveRestore, Calendar, BarChart3, Search, Shield,
  LayoutDashboard
} from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import api from '../api/axios';
import { useAuth } from '../context/AuthContext';
import Navbar from '../components/Navbar';
import toast from 'react-hot-toast';

const boardColors = [
  '#6366f1', '#8b5cf6', '#ec4899', '#ef4444', '#f59e0b',
  '#10b981', '#06b6d4', '#3b82f6', '#f97316', '#84cc16',
];

const boardTemplates = [
  { name: 'Blank Board', description: 'Start from scratch', columns: ['todo', 'in_progress', 'review', 'done'] },
  { name: 'Sprint Board', description: 'Agile sprint workflow', columns: ['backlog', 'todo', 'in_progress', 'testing', 'done'] },
  { name: 'Simple Kanban', description: 'Basic To Do / Doing / Done', columns: ['todo', 'doing', 'done'] },
];

export default function Dashboard() {
  const { user } = useAuth();
  const [boards, setBoards] = useState([]);
  const [loading, setLoading] = useState(true);
  const [createOpen, setCreateOpen] = useState(false);
  const [newBoard, setNewBoard] = useState({ name: '', description: '', color: '#6366f1' });
  const [creating, setCreating] = useState(false);
  const [selectedTemplate, setSelectedTemplate] = useState(0);
  const [showArchived, setShowArchived] = useState(false);
  const [favorites, setFavorites] = useState(() => {
    try {
      return JSON.parse(localStorage.getItem('favoriteBoards') || '[]');
    } catch { return []; }
  });
  const navigate = useNavigate();

  useEffect(() => {
    fetchBoards();
  }, []);

  const fetchBoards = async () => {
    try {
      const res = await api.get('/api/boards');
      setBoards(res.data.boards || res.data || []);
    } catch (err) {
      toast.error('Failed to load boards');
    } finally {
      setLoading(false);
    }
  };

  const handleCreate = async (e) => {
    e.preventDefault();
    if (!newBoard.name.trim()) {
      toast.error('Please enter a board name');
      return;
    }
    setCreating(true);
    try {
      const template = boardTemplates[selectedTemplate];
      const res = await api.post('/api/boards', {
        ...newBoard,
        columns: template.columns,
      });
      const board = res.data.board || res.data;
      setBoards((prev) => [...prev, board]);
      setCreateOpen(false);
      setNewBoard({ name: '', description: '', color: '#6366f1' });
      setSelectedTemplate(0);
      toast.success('Board created!');
      navigate(`/board/${board._id}`);
    } catch (err) {
      toast.error(err.response?.data?.message || 'Failed to create board');
    } finally {
      setCreating(false);
    }
  };

  const toggleFavorite = (boardId) => {
    setFavorites((prev) => {
      const updated = prev.includes(boardId) ? prev.filter((id) => id !== boardId) : [...prev, boardId];
      localStorage.setItem('favoriteBoards', JSON.stringify(updated));
      return updated;
    });
  };

  const displayBoards = showArchived
    ? boards.filter((b) => b.archived)
    : boards.filter((b) => !b.archived);

  const favoriteBoards = boards.filter((b) => favorites.includes(b._id) && !b.archived);

  const container = {
    hidden: { opacity: 0 },
    show: {
      opacity: 1,
      transition: { staggerChildren: 0.06 },
    },
  };

  const item = {
    hidden: { opacity: 0, y: 20 },
    show: { opacity: 1, y: 0 },
  };

  const sidebarLinks = [
    { to: '/', label: 'Dashboard', icon: LayoutDashboard, active: true },
    { to: '/calendar', label: 'Calendar', icon: Calendar },
    { to: '/analytics', label: 'Analytics', icon: BarChart3 },
    { to: '/search', label: 'Search', icon: Search },
    ...(user?.role === 'admin' ? [{ to: '/admin', label: 'Admin', icon: Shield }] : []),
  ];

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-gray-900">
      <Navbar />

      <div className="flex">
        {/* Sidebar */}
        <aside className="hidden lg:flex flex-col w-56 min-h-[calc(100vh-64px)] bg-white dark:bg-gray-800 border-r border-slate-100 dark:border-gray-700 p-4">
          <nav className="space-y-1">
            {sidebarLinks.map((link) => (
              <Link
                key={link.to}
                to={link.to}
                className={`flex items-center gap-2.5 px-3 py-2.5 text-sm font-medium rounded-xl transition-colors ${
                  link.active
                    ? 'bg-indigo-50 dark:bg-indigo-900/20 text-indigo-700 dark:text-indigo-400'
                    : 'text-slate-600 dark:text-gray-400 hover:bg-slate-50 dark:hover:bg-gray-700'
                }`}
              >
                <link.icon className="w-4.5 h-4.5" />
                {link.label}
              </Link>
            ))}
          </nav>

          {/* Favorite boards in sidebar */}
          {favoriteBoards.length > 0 && (
            <div className="mt-6 pt-4 border-t border-slate-100 dark:border-gray-700">
              <h4 className="text-xs font-semibold text-slate-400 dark:text-gray-500 uppercase tracking-wider mb-2 px-3">
                Favorites
              </h4>
              <div className="space-y-0.5">
                {favoriteBoards.slice(0, 5).map((board) => (
                  <Link
                    key={board._id}
                    to={`/board/${board._id}`}
                    className="flex items-center gap-2 px-3 py-2 text-sm text-slate-600 dark:text-gray-400 hover:bg-slate-50 dark:hover:bg-gray-700 rounded-lg transition-colors"
                  >
                    <div className="w-2.5 h-2.5 rounded-sm" style={{ backgroundColor: board.color || '#6366f1' }} />
                    <span className="truncate">{board.name}</span>
                  </Link>
                ))}
              </div>
            </div>
          )}
        </aside>

        {/* Main content */}
        <main className="flex-1 max-w-6xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          {/* Favorite boards section */}
          {favoriteBoards.length > 0 && (
            <div className="mb-8">
              <h2 className="text-lg font-semibold text-slate-800 dark:text-white mb-3 flex items-center gap-2">
                <Star className="w-5 h-5 text-amber-500" fill="currentColor" />
                Favorite Boards
              </h2>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
                {favoriteBoards.map((board) => (
                  <Link
                    key={board._id}
                    to={`/board/${board._id}`}
                    className="group bg-white dark:bg-gray-800 rounded-xl shadow-sm border border-slate-100 dark:border-gray-700 overflow-hidden hover:shadow-md hover:-translate-y-0.5 transition-all"
                  >
                    <div className="h-1.5" style={{ backgroundColor: board.color || '#6366f1' }} />
                    <div className="p-3.5">
                      <h3 className="text-sm font-semibold text-slate-800 dark:text-gray-200 group-hover:text-indigo-600 dark:group-hover:text-indigo-400 truncate">
                        {board.name}
                      </h3>
                    </div>
                  </Link>
                ))}
              </div>
            </div>
          )}

          {/* Header */}
          <div className="flex items-center justify-between mb-8">
            <div>
              <h1 className="text-2xl sm:text-3xl font-bold text-slate-800 dark:text-white">My Boards</h1>
              <p className="text-slate-500 dark:text-gray-400 mt-1">Manage your projects and tasks</p>
            </div>
            <div className="flex items-center gap-3">
              <button
                onClick={() => setShowArchived(!showArchived)}
                className={`flex items-center gap-1.5 px-3 py-2 text-sm font-medium rounded-xl border transition-colors ${
                  showArchived
                    ? 'bg-amber-50 dark:bg-amber-900/20 text-amber-700 dark:text-amber-400 border-amber-200 dark:border-amber-700'
                    : 'bg-white dark:bg-gray-800 text-slate-600 dark:text-gray-400 border-slate-200 dark:border-gray-700 hover:bg-slate-50 dark:hover:bg-gray-700'
                }`}
              >
                {showArchived ? <ArchiveRestore className="w-4 h-4" /> : <Archive className="w-4 h-4" />}
                <span className="hidden sm:inline">{showArchived ? 'Archived' : 'Archive'}</span>
              </button>
              <button
                onClick={() => setCreateOpen(true)}
                className="flex items-center gap-2 px-4 py-2.5 bg-gradient-to-r from-indigo-600 to-purple-600 text-white font-medium rounded-xl hover:shadow-lg hover:shadow-indigo-500/25 transition-all"
              >
                <Plus className="w-5 h-5" />
                <span className="hidden sm:inline">New Board</span>
              </button>
            </div>
          </div>

          {/* Loading */}
          {loading ? (
            <div className="flex items-center justify-center py-32">
              <div className="flex flex-col items-center gap-4">
                <Loader2 className="w-10 h-10 text-indigo-500 animate-spin" />
                <p className="text-slate-500 dark:text-gray-400 font-medium">Loading your boards...</p>
              </div>
            </div>
          ) : displayBoards.length === 0 ? (
            /* Empty state */
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              className="text-center py-32"
            >
              <div className="w-20 h-20 bg-indigo-100 dark:bg-indigo-900/30 rounded-2xl flex items-center justify-center mx-auto mb-4">
                <LayoutGrid className="w-10 h-10 text-indigo-400" />
              </div>
              <h3 className="text-xl font-semibold text-slate-700 dark:text-gray-300 mb-2">
                {showArchived ? 'No archived boards' : 'No boards yet'}
              </h3>
              <p className="text-slate-500 dark:text-gray-400 mb-6 max-w-sm mx-auto">
                {showArchived
                  ? 'Archived boards will appear here.'
                  : 'Create your first board to start organizing tasks and collaborating with your team.'}
              </p>
              {!showArchived && (
                <button
                  onClick={() => setCreateOpen(true)}
                  className="inline-flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-indigo-600 to-purple-600 text-white font-semibold rounded-xl hover:shadow-lg hover:shadow-indigo-500/25 transition-all"
                >
                  <Plus className="w-5 h-5" />
                  Create Your First Board
                </button>
              )}
            </motion.div>
          ) : (
            /* Board grid */
            <motion.div
              variants={container}
              initial="hidden"
              animate="show"
              className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6"
            >
              {displayBoards.map((board) => (
                <motion.div key={board._id} variants={item} className="relative">
                  {/* Favorite star */}
                  <button
                    onClick={(e) => {
                      e.preventDefault();
                      e.stopPropagation();
                      toggleFavorite(board._id);
                    }}
                    className="absolute top-5 right-4 z-10 p-1 hover:scale-110 transition-transform"
                  >
                    <Star
                      className={`w-4.5 h-4.5 ${
                        favorites.includes(board._id)
                          ? 'text-amber-400 fill-amber-400'
                          : 'text-slate-300 dark:text-gray-600 hover:text-amber-300'
                      }`}
                    />
                  </button>
                  <Link
                    to={`/board/${board._id}`}
                    className="group block bg-white dark:bg-gray-800 rounded-2xl shadow-sm border border-slate-100 dark:border-gray-700 overflow-hidden hover:shadow-lg hover:-translate-y-1 transition-all duration-300"
                  >
                    {/* Color bar */}
                    <div
                      className="h-2"
                      style={{ backgroundColor: board.color || '#6366f1' }}
                    />
                    <div className="p-5">
                      <div className="flex items-start justify-between mb-3">
                        <div
                          className="w-10 h-10 rounded-xl flex items-center justify-center"
                          style={{ backgroundColor: (board.color || '#6366f1') + '15' }}
                        >
                          <LayoutGrid
                            className="w-5 h-5"
                            style={{ color: board.color || '#6366f1' }}
                          />
                        </div>
                      </div>
                      <h3 className="text-lg font-semibold text-slate-800 dark:text-gray-200 group-hover:text-indigo-600 dark:group-hover:text-indigo-400 transition-colors mb-1 truncate">
                        {board.name}
                      </h3>
                      {board.description && (
                        <p className="text-sm text-slate-500 dark:text-gray-400 line-clamp-2 mb-4">
                          {board.description}
                        </p>
                      )}
                      <div className="flex items-center gap-4 text-sm text-slate-400 dark:text-gray-500 pt-3 border-t border-slate-50 dark:border-gray-700">
                        <span className="flex items-center gap-1">
                          <Users className="w-3.5 h-3.5" />
                          {board.members?.length || 1}
                        </span>
                        <span className="flex items-center gap-1">
                          <CheckSquare className="w-3.5 h-3.5" />
                          {board.taskCount ?? board.tasks?.length ?? 0}
                        </span>
                        {board.updatedAt && (
                          <span className="flex items-center gap-1 ml-auto">
                            <Clock className="w-3.5 h-3.5" />
                            {formatDistanceToNow(new Date(board.updatedAt), { addSuffix: true })}
                          </span>
                        )}
                      </div>
                    </div>
                  </Link>
                </motion.div>
              ))}

              {/* Create board card */}
              {!showArchived && (
                <motion.div variants={item}>
                  <button
                    onClick={() => setCreateOpen(true)}
                    className="w-full h-full min-h-[200px] bg-white dark:bg-gray-800 rounded-2xl border-2 border-dashed border-slate-200 dark:border-gray-600 flex flex-col items-center justify-center gap-3 text-slate-400 dark:text-gray-500 hover:border-indigo-400 dark:hover:border-indigo-500 hover:text-indigo-500 hover:bg-indigo-50/30 dark:hover:bg-indigo-900/10 transition-all duration-300 group"
                  >
                    <div className="w-12 h-12 border-2 border-current rounded-xl flex items-center justify-center group-hover:scale-110 transition-transform">
                      <Plus className="w-6 h-6" />
                    </div>
                    <span className="font-medium text-sm">Create New Board</span>
                  </button>
                </motion.div>
              )}
            </motion.div>
          )}
        </main>
      </div>

      {/* Create board modal */}
      <AnimatePresence>
        {createOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4"
            onClick={() => setCreateOpen(false)}
          >
            <motion.div
              initial={{ opacity: 0, y: 20, scale: 0.95 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: 20, scale: 0.95 }}
              transition={{ type: 'spring', damping: 25, stiffness: 300 }}
              onClick={(e) => e.stopPropagation()}
              className="w-full max-w-md bg-white dark:bg-gray-800 rounded-2xl shadow-2xl overflow-hidden"
            >
              <div className="bg-gradient-to-r from-indigo-600 to-purple-600 px-6 py-4 flex items-center justify-between">
                <h2 className="text-lg font-bold text-white">Create Board</h2>
                <button
                  onClick={() => setCreateOpen(false)}
                  className="p-1.5 hover:bg-white/20 rounded-lg transition-colors"
                >
                  <X className="w-5 h-5 text-white" />
                </button>
              </div>

              <form onSubmit={handleCreate} className="p-6 space-y-5">
                {/* Template selector */}
                <div>
                  <label className="block text-sm font-medium text-slate-700 dark:text-gray-300 mb-1.5">Template</label>
                  <div className="grid grid-cols-3 gap-2">
                    {boardTemplates.map((tpl, i) => (
                      <button
                        key={tpl.name}
                        type="button"
                        onClick={() => setSelectedTemplate(i)}
                        className={`p-2.5 text-left rounded-xl border-2 transition-all text-xs ${
                          selectedTemplate === i
                            ? 'border-indigo-500 bg-indigo-50 dark:bg-indigo-900/20'
                            : 'border-slate-200 dark:border-gray-600 hover:border-indigo-300 dark:hover:border-indigo-700'
                        }`}
                      >
                        <p className="font-medium text-slate-700 dark:text-gray-300 truncate">{tpl.name}</p>
                        <p className="text-slate-400 dark:text-gray-500 truncate mt-0.5">{tpl.description}</p>
                      </button>
                    ))}
                  </div>
                </div>

                <div>
                  <label className="block text-sm font-medium text-slate-700 dark:text-gray-300 mb-1.5">Board Name</label>
                  <input
                    type="text"
                    value={newBoard.name}
                    onChange={(e) => setNewBoard({ ...newBoard, name: e.target.value })}
                    placeholder="e.g., Q1 Product Launch"
                    autoFocus
                    className="w-full px-4 py-3 bg-slate-50 dark:bg-gray-700 border border-slate-200 dark:border-gray-600 rounded-xl text-slate-800 dark:text-gray-200 placeholder-slate-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-slate-700 dark:text-gray-300 mb-1.5">Description</label>
                  <textarea
                    value={newBoard.description}
                    onChange={(e) => setNewBoard({ ...newBoard, description: e.target.value })}
                    placeholder="What's this board about?"
                    rows={3}
                    className="w-full px-4 py-3 bg-slate-50 dark:bg-gray-700 border border-slate-200 dark:border-gray-600 rounded-xl text-slate-700 dark:text-gray-300 placeholder-slate-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all resize-none"
                  />
                </div>

                <div>
                  <label className="flex items-center gap-1.5 text-sm font-medium text-slate-700 dark:text-gray-300 mb-2">
                    <Palette className="w-4 h-4" />
                    Color
                  </label>
                  <div className="flex gap-2 flex-wrap">
                    {boardColors.map((color) => (
                      <button
                        key={color}
                        type="button"
                        onClick={() => setNewBoard({ ...newBoard, color })}
                        className={`w-9 h-9 rounded-xl transition-all ${
                          newBoard.color === color
                            ? 'ring-2 ring-offset-2 ring-indigo-500 scale-110'
                            : 'hover:scale-110'
                        }`}
                        style={{ backgroundColor: color }}
                      />
                    ))}
                  </div>
                </div>

                <div className="flex gap-3 pt-2">
                  <button
                    type="button"
                    onClick={() => setCreateOpen(false)}
                    className="flex-1 py-3 bg-slate-100 dark:bg-gray-700 text-slate-600 dark:text-gray-300 font-medium rounded-xl hover:bg-slate-200 dark:hover:bg-gray-600 transition-colors"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={creating || !newBoard.name.trim()}
                    className="flex-1 py-3 bg-gradient-to-r from-indigo-600 to-purple-600 text-white font-semibold rounded-xl hover:shadow-lg hover:shadow-indigo-500/25 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {creating ? (
                      <span className="flex items-center justify-center gap-2">
                        <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                        Creating...
                      </span>
                    ) : (
                      'Create Board'
                    )}
                  </button>
                </div>
              </form>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
