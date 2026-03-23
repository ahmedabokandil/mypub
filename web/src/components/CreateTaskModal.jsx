import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { X, Calendar, AlertTriangle, Clock, AlignLeft, Type } from 'lucide-react';
import api from '../api/axios';
import toast from 'react-hot-toast';

const priorityOptions = [
  { value: 'low', label: 'Low', color: 'bg-green-100 text-green-700', dot: 'bg-green-500' },
  { value: 'medium', label: 'Medium', color: 'bg-amber-100 text-amber-700', dot: 'bg-amber-500' },
  { value: 'high', label: 'High', color: 'bg-red-100 text-red-700', dot: 'bg-red-500' },
  { value: 'urgent', label: 'Urgent', color: 'bg-red-200 text-red-800', dot: 'bg-red-600' },
];

export default function CreateTaskModal({ boardId, column, columns, onClose, onCreate }) {
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [dueDate, setDueDate] = useState('');
  const [priority, setPriority] = useState('medium');
  const [selectedColumn, setSelectedColumn] = useState(column || '');
  const [reminderEnabled, setReminderEnabled] = useState(false);
  const [reminder, setReminder] = useState('');
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!title.trim()) {
      toast.error('Please enter a task title');
      return;
    }
    setLoading(true);
    try {
      const payload = {
        title,
        description,
        priority,
        status: selectedColumn,
        dueDate: dueDate || undefined,
        reminder: reminderEnabled && reminder ? reminder : undefined,
      };
      const res = await api.post(`/api/boards/${boardId}/tasks`, payload);
      toast.success('Task created!');
      if (onCreate) onCreate(res.data.task || res.data);
      onClose();
    } catch (err) {
      toast.error(err.response?.data?.message || 'Failed to create task');
    } finally {
      setLoading(false);
    }
  };

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4"
        onClick={onClose}
      >
        <motion.div
          initial={{ opacity: 0, y: 20, scale: 0.95 }}
          animate={{ opacity: 1, y: 0, scale: 1 }}
          exit={{ opacity: 0, y: 20, scale: 0.95 }}
          transition={{ type: 'spring', damping: 25, stiffness: 300 }}
          onClick={(e) => e.stopPropagation()}
          className="w-full max-w-lg bg-white rounded-2xl shadow-2xl overflow-hidden"
        >
          {/* Header */}
          <div className="bg-gradient-to-r from-indigo-600 to-purple-600 px-6 py-4 flex items-center justify-between">
            <h2 className="text-lg font-bold text-white">Create New Task</h2>
            <button
              onClick={onClose}
              className="p-1.5 hover:bg-white/20 rounded-lg transition-colors"
            >
              <X className="w-5 h-5 text-white" />
            </button>
          </div>

          <form onSubmit={handleSubmit} className="p-6 space-y-5">
            {/* Title */}
            <div>
              <label className="flex items-center gap-1.5 text-sm font-medium text-slate-700 mb-1.5">
                <Type className="w-4 h-4" />
                Title
              </label>
              <input
                type="text"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                placeholder="What needs to be done?"
                autoFocus
                className="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-xl text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all"
              />
            </div>

            {/* Description */}
            <div>
              <label className="flex items-center gap-1.5 text-sm font-medium text-slate-700 mb-1.5">
                <AlignLeft className="w-4 h-4" />
                Description
              </label>
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Add more details..."
                rows={3}
                className="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-xl text-slate-700 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all resize-none"
              />
            </div>

            {/* Priority & Column row */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {/* Priority */}
              <div>
                <label className="flex items-center gap-1.5 text-sm font-medium text-slate-700 mb-1.5">
                  <AlertTriangle className="w-4 h-4" />
                  Priority
                </label>
                <div className="flex gap-1.5 flex-wrap">
                  {priorityOptions.map((opt) => (
                    <button
                      key={opt.value}
                      type="button"
                      onClick={() => setPriority(opt.value)}
                      className={`flex items-center gap-1.5 px-3 py-1.5 text-sm font-medium rounded-lg border-2 transition-all ${
                        priority === opt.value
                          ? `${opt.color} border-current`
                          : 'bg-slate-50 text-slate-500 border-transparent hover:bg-slate-100'
                      }`}
                    >
                      <span className={`w-2 h-2 rounded-full ${opt.dot}`} />
                      {opt.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Column */}
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1.5">Column</label>
                <select
                  value={selectedColumn}
                  onChange={(e) => setSelectedColumn(e.target.value)}
                  className="w-full px-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-slate-700 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all"
                >
                  {(columns || ['todo', 'in_progress', 'review', 'done']).map((col) => (
                    <option key={col} value={col}>
                      {col.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase())}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* Due date */}
            <div>
              <label className="flex items-center gap-1.5 text-sm font-medium text-slate-700 mb-1.5">
                <Calendar className="w-4 h-4" />
                Due Date
              </label>
              <input
                type="datetime-local"
                value={dueDate}
                onChange={(e) => setDueDate(e.target.value)}
                className="w-full px-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-slate-700 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all"
              />
            </div>

            {/* Reminder */}
            <div>
              <div className="flex items-center gap-2 mb-1.5">
                <Clock className="w-4 h-4 text-slate-700" />
                <label className="text-sm font-medium text-slate-700">Reminder</label>
                <button
                  type="button"
                  onClick={() => setReminderEnabled(!reminderEnabled)}
                  className={`relative w-10 h-5 rounded-full transition-colors ${
                    reminderEnabled ? 'bg-indigo-600' : 'bg-slate-300'
                  }`}
                >
                  <span
                    className={`absolute top-0.5 left-0.5 w-4 h-4 bg-white rounded-full shadow transition-transform ${
                      reminderEnabled ? 'translate-x-5' : ''
                    }`}
                  />
                </button>
              </div>
              {reminderEnabled && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: 'auto' }}
                  exit={{ opacity: 0, height: 0 }}
                >
                  <input
                    type="datetime-local"
                    value={reminder}
                    onChange={(e) => setReminder(e.target.value)}
                    className="w-full px-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-slate-700 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all"
                  />
                </motion.div>
              )}
            </div>

            {/* Submit */}
            <div className="flex gap-3 pt-2">
              <button
                type="button"
                onClick={onClose}
                className="flex-1 py-3 bg-slate-100 text-slate-600 font-medium rounded-xl hover:bg-slate-200 transition-colors"
              >
                Cancel
              </button>
              <button
                type="submit"
                disabled={loading || !title.trim()}
                className="flex-1 py-3 bg-gradient-to-r from-indigo-600 to-purple-600 text-white font-semibold rounded-xl hover:shadow-lg hover:shadow-indigo-500/25 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? (
                  <span className="flex items-center justify-center gap-2">
                    <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    Creating...
                  </span>
                ) : (
                  'Create Task'
                )}
              </button>
            </div>
          </form>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
}
