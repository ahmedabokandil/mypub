import { useState, useEffect } from 'react';
import { Plus, Trash2, CheckSquare, Square, GripVertical } from 'lucide-react';
import api from '../api/axios';
import toast from 'react-hot-toast';

export default function SubtaskList({ boardId, taskId }) {
  const [checklist, setChecklist] = useState([]);
  const [subtasks, setSubtasks] = useState([]);
  const [newItem, setNewItem] = useState('');
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchData();
  }, [boardId, taskId]);

  const fetchData = async () => {
    try {
      const res = await api.get(`/api/boards/${boardId}/tasks/${taskId}/subtasks`);
      const data = res.data;
      setChecklist(data.checklist || []);
      setSubtasks(data.subtasks || []);
    } catch (err) {
      // API might not exist yet, use empty defaults
      setChecklist([]);
      setSubtasks([]);
    } finally {
      setLoading(false);
    }
  };

  const addChecklistItem = async () => {
    if (!newItem.trim()) return;
    const item = { text: newItem.trim(), completed: false, id: Date.now().toString() };
    const updated = [...checklist, item];
    setChecklist(updated);
    setNewItem('');
    try {
      await api.put(`/api/boards/${boardId}/tasks/${taskId}/checklist`, { checklist: updated });
    } catch (err) {
      toast.error('Failed to add item');
    }
  };

  const toggleItem = async (index) => {
    const updated = checklist.map((item, i) =>
      i === index ? { ...item, completed: !item.completed } : item
    );
    setChecklist(updated);
    try {
      await api.put(`/api/boards/${boardId}/tasks/${taskId}/checklist`, { checklist: updated });
    } catch (err) {
      toast.error('Failed to update item');
    }
  };

  const deleteItem = async (index) => {
    const updated = checklist.filter((_, i) => i !== index);
    setChecklist(updated);
    try {
      await api.put(`/api/boards/${boardId}/tasks/${taskId}/checklist`, { checklist: updated });
    } catch (err) {
      toast.error('Failed to delete item');
    }
  };

  const completedCount = checklist.filter((i) => i.completed).length;
  const totalCount = checklist.length;
  const progress = totalCount > 0 ? (completedCount / totalCount) * 100 : 0;

  if (loading) {
    return <div className="text-sm text-slate-400 dark:text-gray-500 py-2">Loading subtasks...</div>;
  }

  return (
    <div>
      <label className="block text-sm font-medium text-slate-700 dark:text-gray-300 mb-2 flex items-center gap-1">
        <CheckSquare className="w-4 h-4" />
        Checklist
        {totalCount > 0 && (
          <span className="ml-1 text-xs text-slate-500 dark:text-gray-400">
            {completedCount}/{totalCount}
          </span>
        )}
      </label>

      {/* Progress bar */}
      {totalCount > 0 && (
        <div className="w-full h-2 bg-slate-100 dark:bg-gray-700 rounded-full mb-3 overflow-hidden">
          <div
            className="h-full bg-gradient-to-r from-indigo-500 to-purple-500 rounded-full transition-all duration-300"
            style={{ width: `${progress}%` }}
          />
        </div>
      )}

      {/* Checklist items */}
      <div className="space-y-1.5 mb-3">
        {checklist.map((item, index) => (
          <div
            key={item.id || index}
            className="flex items-center gap-2 group p-2 rounded-lg hover:bg-slate-50 dark:hover:bg-gray-700/50 transition-colors"
          >
            <GripVertical className="w-3.5 h-3.5 text-slate-300 dark:text-gray-600 opacity-0 group-hover:opacity-100 cursor-grab" />
            <button onClick={() => toggleItem(index)} className="flex-shrink-0">
              {item.completed ? (
                <CheckSquare className="w-4.5 h-4.5 text-indigo-500" />
              ) : (
                <Square className="w-4.5 h-4.5 text-slate-400 dark:text-gray-500" />
              )}
            </button>
            <span
              className={`flex-1 text-sm ${
                item.completed
                  ? 'text-slate-400 dark:text-gray-500 line-through'
                  : 'text-slate-700 dark:text-gray-300'
              }`}
            >
              {item.text}
            </span>
            <button
              onClick={() => deleteItem(index)}
              className="p-1 opacity-0 group-hover:opacity-100 hover:bg-red-50 dark:hover:bg-red-900/30 rounded transition-all"
            >
              <Trash2 className="w-3.5 h-3.5 text-red-400" />
            </button>
          </div>
        ))}
      </div>

      {/* Add new item */}
      <div className="flex gap-2">
        <input
          type="text"
          value={newItem}
          onChange={(e) => setNewItem(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && addChecklistItem()}
          placeholder="Add checklist item..."
          className="flex-1 px-3 py-2 bg-slate-50 dark:bg-gray-700 border border-slate-200 dark:border-gray-600 rounded-lg text-sm text-slate-700 dark:text-gray-300 placeholder-slate-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all"
        />
        <button
          onClick={addChecklistItem}
          disabled={!newItem.trim()}
          className="p-2 bg-indigo-50 dark:bg-indigo-900/30 text-indigo-600 dark:text-indigo-400 rounded-lg hover:bg-indigo-100 dark:hover:bg-indigo-900/50 transition-colors disabled:opacity-50"
        >
          <Plus className="w-4 h-4" />
        </button>
      </div>

      {/* Subtasks (child tasks) */}
      {subtasks.length > 0 && (
        <div className="mt-4">
          <label className="block text-sm font-medium text-slate-700 dark:text-gray-300 mb-2">
            Subtasks
          </label>
          <div className="space-y-2">
            {subtasks.map((sub) => (
              <div
                key={sub._id}
                className="flex items-center gap-2 p-2.5 bg-slate-50 dark:bg-gray-700 rounded-lg border border-slate-100 dark:border-gray-600"
              >
                <div
                  className={`w-2 h-2 rounded-full ${
                    sub.status === 'done' ? 'bg-green-500' : sub.status === 'in_progress' ? 'bg-blue-500' : 'bg-slate-400'
                  }`}
                />
                <span className={`text-sm flex-1 ${sub.status === 'done' ? 'text-slate-400 line-through' : 'text-slate-700 dark:text-gray-300'}`}>
                  {sub.title}
                </span>
                <span className="text-xs text-slate-400 dark:text-gray-500 capitalize">{sub.status?.replace('_', ' ')}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
