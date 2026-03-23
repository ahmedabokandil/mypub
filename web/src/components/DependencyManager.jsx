import { useState, useEffect } from 'react';
import { Lock, Unlock, X, Search, ArrowRight, Link2 } from 'lucide-react';
import api from '../api/axios';
import toast from 'react-hot-toast';

export default function DependencyManager({ boardId, taskId, tasks = [] }) {
  const [blockedBy, setBlockedBy] = useState([]);
  const [blocks, setBlocks] = useState([]);
  const [searchQuery, setSearchQuery] = useState('');
  const [searchResults, setSearchResults] = useState([]);
  const [addingType, setAddingType] = useState(null); // 'blockedBy' | 'blocks'
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchDependencies();
  }, [boardId, taskId]);

  const fetchDependencies = async () => {
    try {
      const res = await api.get(`/api/boards/${boardId}/tasks/${taskId}/dependencies`);
      setBlockedBy(res.data.blockedBy || []);
      setBlocks(res.data.blocks || []);
    } catch {
      setBlockedBy([]);
      setBlocks([]);
    } finally {
      setLoading(false);
    }
  };

  const handleSearch = (query) => {
    setSearchQuery(query);
    if (!query.trim()) {
      setSearchResults([]);
      return;
    }
    const results = tasks.filter(
      (t) =>
        t._id !== taskId &&
        t.title.toLowerCase().includes(query.toLowerCase()) &&
        !blockedBy.some((d) => (d._id || d) === t._id) &&
        !blocks.some((d) => (d._id || d) === t._id)
    );
    setSearchResults(results.slice(0, 5));
  };

  const addDependency = async (depTaskId, type) => {
    try {
      await api.post(`/api/boards/${boardId}/tasks/${taskId}/dependencies`, {
        dependencyTaskId: depTaskId,
        type,
      });
      fetchDependencies();
      setSearchQuery('');
      setSearchResults([]);
      setAddingType(null);
      toast.success('Dependency added');
    } catch (err) {
      toast.error(err.response?.data?.message || 'Failed to add dependency');
    }
  };

  const removeDependency = async (depTaskId, type) => {
    try {
      await api.delete(`/api/boards/${boardId}/tasks/${taskId}/dependencies/${depTaskId}`, {
        data: { type },
      });
      if (type === 'blockedBy') {
        setBlockedBy((prev) => prev.filter((d) => (d._id || d) !== depTaskId));
      } else {
        setBlocks((prev) => prev.filter((d) => (d._id || d) !== depTaskId));
      }
      toast.success('Dependency removed');
    } catch {
      toast.error('Failed to remove dependency');
    }
  };

  if (loading) {
    return <div className="text-sm text-slate-400 dark:text-gray-500 py-2">Loading dependencies...</div>;
  }

  return (
    <div>
      <label className="block text-sm font-medium text-slate-700 dark:text-gray-300 mb-2 flex items-center gap-1">
        <Link2 className="w-4 h-4" />
        Dependencies
      </label>

      {/* Blocked by */}
      <div className="mb-3">
        <div className="flex items-center justify-between mb-1.5">
          <span className="text-xs font-medium text-slate-500 dark:text-gray-400 flex items-center gap-1">
            <Lock className="w-3 h-3" />
            Blocked by
          </span>
          <button
            onClick={() => setAddingType(addingType === 'blockedBy' ? null : 'blockedBy')}
            className="text-xs text-indigo-600 dark:text-indigo-400 hover:text-indigo-700 font-medium"
          >
            + Add
          </button>
        </div>
        {blockedBy.length > 0 ? (
          <div className="space-y-1.5">
            {blockedBy.map((dep) => (
              <div
                key={dep._id || dep}
                className="flex items-center justify-between p-2 bg-red-50 dark:bg-red-900/20 rounded-lg border border-red-100 dark:border-red-800/30"
              >
                <span className="text-sm text-red-700 dark:text-red-400 flex items-center gap-1.5 truncate">
                  <Lock className="w-3 h-3 flex-shrink-0" />
                  {dep.title || dep._id || dep}
                </span>
                <button
                  onClick={() => removeDependency(dep._id || dep, 'blockedBy')}
                  className="p-1 hover:bg-red-100 dark:hover:bg-red-900/40 rounded transition-colors"
                >
                  <X className="w-3.5 h-3.5 text-red-400" />
                </button>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-xs text-slate-400 dark:text-gray-500 py-1">No blocking dependencies</p>
        )}
      </div>

      {/* Blocks */}
      <div className="mb-3">
        <div className="flex items-center justify-between mb-1.5">
          <span className="text-xs font-medium text-slate-500 dark:text-gray-400 flex items-center gap-1">
            <ArrowRight className="w-3 h-3" />
            Blocks
          </span>
          <button
            onClick={() => setAddingType(addingType === 'blocks' ? null : 'blocks')}
            className="text-xs text-indigo-600 dark:text-indigo-400 hover:text-indigo-700 font-medium"
          >
            + Add
          </button>
        </div>
        {blocks.length > 0 ? (
          <div className="space-y-1.5">
            {blocks.map((dep) => (
              <div
                key={dep._id || dep}
                className="flex items-center justify-between p-2 bg-amber-50 dark:bg-amber-900/20 rounded-lg border border-amber-100 dark:border-amber-800/30"
              >
                <span className="text-sm text-amber-700 dark:text-amber-400 flex items-center gap-1.5 truncate">
                  <Unlock className="w-3 h-3 flex-shrink-0" />
                  {dep.title || dep._id || dep}
                </span>
                <button
                  onClick={() => removeDependency(dep._id || dep, 'blocks')}
                  className="p-1 hover:bg-amber-100 dark:hover:bg-amber-900/40 rounded transition-colors"
                >
                  <X className="w-3.5 h-3.5 text-amber-400" />
                </button>
              </div>
            ))}
          </div>
        ) : (
          <p className="text-xs text-slate-400 dark:text-gray-500 py-1">Not blocking any tasks</p>
        )}
      </div>

      {/* Search to add */}
      {addingType && (
        <div className="mt-2 p-3 bg-slate-50 dark:bg-gray-700 rounded-xl border border-slate-200 dark:border-gray-600">
          <p className="text-xs text-slate-500 dark:text-gray-400 mb-2">
            Add {addingType === 'blockedBy' ? '"blocked by"' : '"blocks"'} dependency:
          </p>
          <div className="relative">
            <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-slate-400" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => handleSearch(e.target.value)}
              placeholder="Search tasks..."
              autoFocus
              className="w-full pl-8 pr-3 py-2 bg-white dark:bg-gray-600 border border-slate-200 dark:border-gray-500 rounded-lg text-sm text-slate-700 dark:text-gray-300 placeholder-slate-400 focus:outline-none focus:ring-1 focus:ring-indigo-500"
            />
          </div>
          {searchResults.length > 0 && (
            <div className="mt-2 space-y-1">
              {searchResults.map((t) => (
                <button
                  key={t._id}
                  onClick={() => addDependency(t._id, addingType)}
                  className="w-full text-left p-2 text-sm text-slate-700 dark:text-gray-300 hover:bg-indigo-50 dark:hover:bg-indigo-900/30 rounded-lg transition-colors truncate"
                >
                  {t.title}
                </button>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}
