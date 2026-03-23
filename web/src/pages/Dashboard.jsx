import { useState, useEffect } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Plus, Users, CheckSquare, Clock, X, Palette, LayoutGrid, Loader2
} from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import api from '../api/axios';
import Navbar from '../components/Navbar';
import toast from 'react-hot-toast';

const boardColors = [
  '#6366f1', '#8b5cf6', '#ec4899', '#ef4444', '#f59e0b',
  '#10b981', '#06b6d4', '#3b82f6', '#f97316', '#84cc16',
];

export default function Dashboard() {
  const [boards, setBoards] = useState([]);
  const [loading, setLoading] = useState(true);
  const [createOpen, setCreateOpen] = useState(false);
  const [newBoard, setNewBoard] = useState({ name: '', description: '', color: '#6366f1' });
  const [creating, setCreating] = useState(false);
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
      const res = await api.post('/api/boards', newBoard);
      const board = res.data.board || res.data;
      setBoards((prev) => [...prev, board]);
      setCreateOpen(false);
      setNewBoard({ name: '', description: '', color: '#6366f1' });
      toast.success('Board created!');
      navigate(`/board/${board._id}`);
    } catch (err) {
      toast.error(err.response?.data?.message || 'Failed to create board');
    } finally {
      setCreating(false);
    }
  };

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

  return (
    <div className="min-h-screen bg-slate-50">
      <Navbar />

      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="flex items-center justify-between mb-8">
          <div>
            <h1 className="text-2xl sm:text-3xl font-bold text-slate-800">My Boards</h1>
            <p className="text-slate-500 mt-1">Manage your projects and tasks</p>
          </div>
          <button
            onClick={() => setCreateOpen(true)}
            className="flex items-center gap-2 px-4 py-2.5 bg-gradient-to-r from-indigo-600 to-purple-600 text-white font-medium rounded-xl hover:shadow-lg hover:shadow-indigo-500/25 transition-all"
          >
            <Plus className="w-5 h-5" />
            <span className="hidden sm:inline">New Board</span>
          </button>
        </div>

        {/* Loading */}
        {loading ? (
          <div className="flex items-center justify-center py-32">
            <div className="flex flex-col items-center gap-4">
              <Loader2 className="w-10 h-10 text-indigo-500 animate-spin" />
              <p className="text-slate-500 font-medium">Loading your boards...</p>
            </div>
          </div>
        ) : boards.length === 0 ? (
          /* Empty state */
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            className="text-center py-32"
          >
            <div className="w-20 h-20 bg-indigo-100 rounded-2xl flex items-center justify-center mx-auto mb-4">
              <LayoutGrid className="w-10 h-10 text-indigo-400" />
            </div>
            <h3 className="text-xl font-semibold text-slate-700 mb-2">No boards yet</h3>
            <p className="text-slate-500 mb-6 max-w-sm mx-auto">
              Create your first board to start organizing tasks and collaborating with your team.
            </p>
            <button
              onClick={() => setCreateOpen(true)}
              className="inline-flex items-center gap-2 px-6 py-3 bg-gradient-to-r from-indigo-600 to-purple-600 text-white font-semibold rounded-xl hover:shadow-lg hover:shadow-indigo-500/25 transition-all"
            >
              <Plus className="w-5 h-5" />
              Create Your First Board
            </button>
          </motion.div>
        ) : (
          /* Board grid */
          <motion.div
            variants={container}
            initial="hidden"
            animate="show"
            className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-6"
          >
            {boards.map((board) => (
              <motion.div key={board._id} variants={item}>
                <Link
                  to={`/board/${board._id}`}
                  className="group block bg-white rounded-2xl shadow-sm border border-slate-100 overflow-hidden hover:shadow-lg hover:-translate-y-1 transition-all duration-300"
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
                    <h3 className="text-lg font-semibold text-slate-800 group-hover:text-indigo-600 transition-colors mb-1 truncate">
                      {board.name}
                    </h3>
                    {board.description && (
                      <p className="text-sm text-slate-500 line-clamp-2 mb-4">
                        {board.description}
                      </p>
                    )}
                    <div className="flex items-center gap-4 text-sm text-slate-400 pt-3 border-t border-slate-50">
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
            <motion.div variants={item}>
              <button
                onClick={() => setCreateOpen(true)}
                className="w-full h-full min-h-[200px] bg-white rounded-2xl border-2 border-dashed border-slate-200 flex flex-col items-center justify-center gap-3 text-slate-400 hover:border-indigo-400 hover:text-indigo-500 hover:bg-indigo-50/30 transition-all duration-300 group"
              >
                <div className="w-12 h-12 border-2 border-current rounded-xl flex items-center justify-center group-hover:scale-110 transition-transform">
                  <Plus className="w-6 h-6" />
                </div>
                <span className="font-medium text-sm">Create New Board</span>
              </button>
            </motion.div>
          </motion.div>
        )}
      </main>

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
              className="w-full max-w-md bg-white rounded-2xl shadow-2xl overflow-hidden"
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
                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-1.5">Board Name</label>
                  <input
                    type="text"
                    value={newBoard.name}
                    onChange={(e) => setNewBoard({ ...newBoard, name: e.target.value })}
                    placeholder="e.g., Q1 Product Launch"
                    autoFocus
                    className="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-xl text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all"
                  />
                </div>

                <div>
                  <label className="block text-sm font-medium text-slate-700 mb-1.5">Description</label>
                  <textarea
                    value={newBoard.description}
                    onChange={(e) => setNewBoard({ ...newBoard, description: e.target.value })}
                    placeholder="What's this board about?"
                    rows={3}
                    className="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-xl text-slate-700 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all resize-none"
                  />
                </div>

                <div>
                  <label className="flex items-center gap-1.5 text-sm font-medium text-slate-700 mb-2">
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
                    className="flex-1 py-3 bg-slate-100 text-slate-600 font-medium rounded-xl hover:bg-slate-200 transition-colors"
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
