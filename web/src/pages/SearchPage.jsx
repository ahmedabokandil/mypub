import { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  Search, Filter, Calendar, Tag, Users, Loader2, X, Archive
} from 'lucide-react';
import { format } from 'date-fns';
import api from '../api/axios';
import Navbar from '../components/Navbar';

const priorityConfig = {
  urgent: { color: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400', dot: 'bg-red-500' },
  high: { color: 'bg-red-50 text-red-600 dark:bg-red-900/20 dark:text-red-400', dot: 'bg-red-400' },
  medium: { color: 'bg-amber-50 text-amber-600 dark:bg-amber-900/20 dark:text-amber-400', dot: 'bg-amber-400' },
  low: { color: 'bg-green-50 text-green-600 dark:bg-green-900/20 dark:text-green-400', dot: 'bg-green-400' },
};

export default function SearchPage() {
  const navigate = useNavigate();
  const [query, setQuery] = useState('');
  const [results, setResults] = useState([]);
  const [boards, setBoards] = useState([]);
  const [loading, setLoading] = useState(false);
  const [searched, setSearched] = useState(false);
  const [showFilters, setShowFilters] = useState(false);
  const [filters, setFilters] = useState({
    priority: '',
    boardId: '',
    dateFrom: '',
    dateTo: '',
    showArchived: false,
  });

  useEffect(() => {
    fetchBoards();
  }, []);

  const fetchBoards = async () => {
    try {
      const res = await api.get('/api/boards');
      setBoards(res.data.boards || res.data || []);
    } catch {}
  };

  const doSearch = useCallback(async (searchQuery, searchFilters) => {
    if (!searchQuery.trim() && !searchFilters.priority && !searchFilters.boardId) return;
    setLoading(true);
    setSearched(true);
    try {
      const params = { q: searchQuery };
      if (searchFilters.priority) params.priority = searchFilters.priority;
      if (searchFilters.boardId) params.boardId = searchFilters.boardId;
      if (searchFilters.dateFrom) params.dateFrom = searchFilters.dateFrom;
      if (searchFilters.dateTo) params.dateTo = searchFilters.dateTo;
      if (searchFilters.showArchived) params.showArchived = true;

      const res = await api.get('/api/search', { params });
      setResults(res.data.results || res.data.tasks || res.data || []);
    } catch {
      // If search API doesn't exist, search locally
      try {
        const boardsRes = await api.get('/api/boards');
        const allBoards = boardsRes.data.boards || boardsRes.data || [];
        const allTasks = [];
        for (const board of allBoards) {
          if (searchFilters.boardId && board._id !== searchFilters.boardId) continue;
          try {
            const bRes = await api.get(`/api/boards/${board._id}`);
            const bData = bRes.data.board || bRes.data;
            const bTasks = (bData.tasks || []).map((t) => ({ ...t, boardName: board.name, boardId: board._id }));
            allTasks.push(...bTasks);
          } catch {}
        }
        const filtered = allTasks.filter((t) => {
          if (searchQuery && !t.title?.toLowerCase().includes(searchQuery.toLowerCase()) && !t.description?.toLowerCase().includes(searchQuery.toLowerCase())) return false;
          if (searchFilters.priority && t.priority !== searchFilters.priority) return false;
          return true;
        });
        setResults(filtered);
      } catch {
        setResults([]);
      }
    } finally {
      setLoading(false);
    }
  }, []);

  // Debounced search
  useEffect(() => {
    const timer = setTimeout(() => {
      if (query.trim()) {
        doSearch(query, filters);
      }
    }, 300);
    return () => clearTimeout(timer);
  }, [query, filters, doSearch]);

  const clearFilters = () => {
    setFilters({ priority: '', boardId: '', dateFrom: '', dateTo: '', showArchived: false });
  };

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-gray-900">
      <Navbar />
      <main className="max-w-5xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-8">
          <h1 className="text-2xl sm:text-3xl font-bold text-slate-800 dark:text-white mb-4">Search</h1>

          {/* Search input */}
          <div className="relative">
            <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-400" />
            <input
              type="text"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Search tasks, descriptions, labels..."
              autoFocus
              className="w-full pl-12 pr-12 py-4 bg-white dark:bg-gray-800 border border-slate-200 dark:border-gray-700 rounded-2xl text-slate-800 dark:text-gray-200 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 text-lg shadow-sm transition-all"
            />
            <button
              onClick={() => setShowFilters(!showFilters)}
              className={`absolute right-3 top-1/2 -translate-y-1/2 p-2 rounded-xl transition-colors ${showFilters ? 'bg-indigo-100 text-indigo-600 dark:bg-indigo-900/30 dark:text-indigo-400' : 'hover:bg-slate-100 dark:hover:bg-gray-700 text-slate-400'}`}
            >
              <Filter className="w-5 h-5" />
            </button>
          </div>

          {/* Filters */}
          {showFilters && (
            <motion.div
              initial={{ opacity: 0, height: 0 }}
              animate={{ opacity: 1, height: 'auto' }}
              exit={{ opacity: 0, height: 0 }}
              className="mt-4 p-4 bg-white dark:bg-gray-800 rounded-2xl border border-slate-200 dark:border-gray-700 shadow-sm"
            >
              <div className="flex items-center justify-between mb-3">
                <h3 className="text-sm font-semibold text-slate-700 dark:text-gray-300">Filters</h3>
                <button onClick={clearFilters} className="text-xs text-indigo-600 dark:text-indigo-400 hover:text-indigo-700 font-medium">
                  Clear all
                </button>
              </div>
              <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
                <div>
                  <label className="block text-xs font-medium text-slate-500 dark:text-gray-400 mb-1">Priority</label>
                  <select
                    value={filters.priority}
                    onChange={(e) => setFilters({ ...filters, priority: e.target.value })}
                    className="w-full px-3 py-2 bg-slate-50 dark:bg-gray-700 border border-slate-200 dark:border-gray-600 rounded-xl text-sm text-slate-700 dark:text-gray-300 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                  >
                    <option value="">All</option>
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                    <option value="urgent">Urgent</option>
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-500 dark:text-gray-400 mb-1">Board</label>
                  <select
                    value={filters.boardId}
                    onChange={(e) => setFilters({ ...filters, boardId: e.target.value })}
                    className="w-full px-3 py-2 bg-slate-50 dark:bg-gray-700 border border-slate-200 dark:border-gray-600 rounded-xl text-sm text-slate-700 dark:text-gray-300 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                  >
                    <option value="">All Boards</option>
                    {boards.map((b) => (
                      <option key={b._id} value={b._id}>{b.name}</option>
                    ))}
                  </select>
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-500 dark:text-gray-400 mb-1">Date From</label>
                  <input
                    type="date"
                    value={filters.dateFrom}
                    onChange={(e) => setFilters({ ...filters, dateFrom: e.target.value })}
                    className="w-full px-3 py-2 bg-slate-50 dark:bg-gray-700 border border-slate-200 dark:border-gray-600 rounded-xl text-sm text-slate-700 dark:text-gray-300 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-slate-500 dark:text-gray-400 mb-1">Date To</label>
                  <input
                    type="date"
                    value={filters.dateTo}
                    onChange={(e) => setFilters({ ...filters, dateTo: e.target.value })}
                    className="w-full px-3 py-2 bg-slate-50 dark:bg-gray-700 border border-slate-200 dark:border-gray-600 rounded-xl text-sm text-slate-700 dark:text-gray-300 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                  />
                </div>
              </div>
              <label className="flex items-center gap-2 mt-3 cursor-pointer">
                <input
                  type="checkbox"
                  checked={filters.showArchived}
                  onChange={(e) => setFilters({ ...filters, showArchived: e.target.checked })}
                  className="rounded border-slate-300 text-indigo-600 focus:ring-indigo-500"
                />
                <span className="text-sm text-slate-600 dark:text-gray-400 flex items-center gap-1">
                  <Archive className="w-3.5 h-3.5" /> Show archived
                </span>
              </label>
            </motion.div>
          )}
        </div>

        {/* Results */}
        {loading ? (
          <div className="flex items-center justify-center py-20">
            <Loader2 className="w-8 h-8 text-indigo-500 animate-spin" />
          </div>
        ) : !searched ? (
          <div className="text-center py-20">
            <Search className="w-12 h-12 text-slate-300 dark:text-gray-600 mx-auto mb-3" />
            <p className="text-slate-400 dark:text-gray-500 text-lg">Start typing to search tasks</p>
          </div>
        ) : results.length === 0 ? (
          <div className="text-center py-20">
            <Search className="w-12 h-12 text-slate-300 dark:text-gray-600 mx-auto mb-3" />
            <p className="text-slate-500 dark:text-gray-400 text-lg font-medium">No results found</p>
            <p className="text-slate-400 dark:text-gray-500 text-sm mt-1">Try different keywords or filters</p>
          </div>
        ) : (
          <div className="space-y-3">
            <p className="text-sm text-slate-500 dark:text-gray-400 mb-4">{results.length} result{results.length !== 1 ? 's' : ''} found</p>
            {results.map((task) => {
              const pConfig = priorityConfig[task.priority] || priorityConfig.medium;
              return (
                <motion.div
                  key={task._id}
                  initial={{ opacity: 0, y: 10 }}
                  animate={{ opacity: 1, y: 0 }}
                  onClick={() => navigate(`/board/${task.boardId || task.board}`)}
                  className="bg-white dark:bg-gray-800 rounded-2xl shadow-sm border border-slate-100 dark:border-gray-700 p-4 hover:shadow-md hover:-translate-y-0.5 transition-all cursor-pointer"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <span className={`w-2 h-2 rounded-full flex-shrink-0 ${pConfig.dot}`} />
                        <h3 className="text-sm font-semibold text-slate-800 dark:text-gray-200 truncate">{task.title}</h3>
                      </div>
                      {task.description && (
                        <p className="text-xs text-slate-500 dark:text-gray-400 line-clamp-2 ml-4">{task.description}</p>
                      )}
                      <div className="flex items-center gap-3 mt-2 ml-4 flex-wrap">
                        {task.boardName && (
                          <span className="text-xs text-indigo-600 dark:text-indigo-400 bg-indigo-50 dark:bg-indigo-900/20 px-2 py-0.5 rounded-full font-medium">{task.boardName}</span>
                        )}
                        <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${pConfig.color}`}>
                          {(task.priority || 'medium').charAt(0).toUpperCase() + (task.priority || 'medium').slice(1)}
                        </span>
                        <span className="text-xs text-slate-400 dark:text-gray-500 capitalize">{task.status?.replace('_', ' ')}</span>
                        {task.dueDate && (
                          <span className="text-xs text-slate-400 dark:text-gray-500 flex items-center gap-1">
                            <Calendar className="w-3 h-3" />
                            {format(new Date(task.dueDate), 'MMM d')}
                          </span>
                        )}
                        {task.labels && task.labels.length > 0 && (
                          <div className="flex gap-1">
                            {task.labels.slice(0, 3).map((label, i) => (
                              <span key={i} className="text-xs px-1.5 py-0.5 rounded-full" style={{ backgroundColor: (label.color || '#6366f1') + '20', color: label.color || '#6366f1' }}>
                                {label.name || label}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    </div>
                  </div>
                </motion.div>
              );
            })}
          </div>
        )}
      </main>
    </div>
  );
}
