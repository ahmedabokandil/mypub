import { useState, useEffect } from 'react';
import { RefreshCw, Calendar } from 'lucide-react';
import { format, addDays, addWeeks, addMonths } from 'date-fns';
import api from '../api/axios';
import toast from 'react-hot-toast';

export default function RecurringTaskConfig({ boardId, taskId, initialConfig }) {
  const [enabled, setEnabled] = useState(initialConfig?.enabled || false);
  const [pattern, setPattern] = useState(initialConfig?.pattern || 'daily');
  const [interval, setInterval_] = useState(initialConfig?.interval || 1);
  const [saving, setSaving] = useState(false);

  const getNextOccurrence = () => {
    const now = new Date();
    switch (pattern) {
      case 'daily': return addDays(now, interval);
      case 'weekly': return addWeeks(now, interval);
      case 'monthly': return addMonths(now, interval);
      default: return addDays(now, interval);
    }
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      await api.put(`/api/boards/${boardId}/tasks/${taskId}/recurring`, {
        enabled,
        pattern,
        interval: interval,
        nextOccurrence: enabled ? getNextOccurrence().toISOString() : null,
      });
      toast.success(enabled ? 'Recurring schedule saved' : 'Recurring disabled');
    } catch (err) {
      toast.error(err.response?.data?.message || 'Failed to save recurring config');
    } finally {
      setSaving(false);
    }
  };

  const handleToggle = () => {
    const newEnabled = !enabled;
    setEnabled(newEnabled);
  };

  return (
    <div>
      <label className="block text-sm font-medium text-slate-700 dark:text-gray-300 mb-2 flex items-center gap-1">
        <RefreshCw className="w-4 h-4" />
        Recurring Task
      </label>

      {/* Toggle */}
      <div className="flex items-center justify-between p-3 bg-slate-50 dark:bg-gray-700 rounded-xl border border-slate-100 dark:border-gray-600 mb-3">
        <span className="text-sm text-slate-700 dark:text-gray-300">Repeat this task</span>
        <button
          onClick={handleToggle}
          className={`w-11 h-6 rounded-full transition-colors relative ${
            enabled ? 'bg-indigo-600' : 'bg-slate-300 dark:bg-gray-500'
          }`}
        >
          <span
            className={`absolute top-0.5 w-5 h-5 bg-white rounded-full shadow transition-transform ${
              enabled ? 'translate-x-5.5 left-0' : 'left-0.5'
            }`}
            style={{ transform: enabled ? 'translateX(22px)' : 'translateX(0)' }}
          />
        </button>
      </div>

      {enabled && (
        <div className="space-y-3">
          {/* Pattern */}
          <div>
            <label className="block text-xs font-medium text-slate-500 dark:text-gray-400 mb-1">Pattern</label>
            <div className="flex gap-2">
              {['daily', 'weekly', 'monthly'].map((p) => (
                <button
                  key={p}
                  onClick={() => setPattern(p)}
                  className={`flex-1 py-2 text-sm font-medium rounded-lg border transition-all ${
                    pattern === p
                      ? 'bg-indigo-50 dark:bg-indigo-900/30 text-indigo-600 dark:text-indigo-400 border-indigo-200 dark:border-indigo-700'
                      : 'bg-white dark:bg-gray-700 text-slate-600 dark:text-gray-400 border-slate-200 dark:border-gray-600 hover:bg-slate-50 dark:hover:bg-gray-600'
                  }`}
                >
                  {p.charAt(0).toUpperCase() + p.slice(1)}
                </button>
              ))}
            </div>
          </div>

          {/* Interval */}
          <div>
            <label className="block text-xs font-medium text-slate-500 dark:text-gray-400 mb-1">
              Every {interval} {pattern === 'daily' ? 'day' : pattern === 'weekly' ? 'week' : 'month'}{interval > 1 ? 's' : ''}
            </label>
            <input
              type="number"
              value={interval}
              onChange={(e) => setInterval_(Math.max(1, parseInt(e.target.value) || 1))}
              min={1}
              max={365}
              className="w-full px-3 py-2 bg-white dark:bg-gray-700 border border-slate-200 dark:border-gray-600 rounded-lg text-sm text-slate-700 dark:text-gray-300 focus:outline-none focus:ring-1 focus:ring-indigo-500"
            />
          </div>

          {/* Next occurrence */}
          <div className="flex items-center gap-2 p-2.5 bg-indigo-50 dark:bg-indigo-900/20 rounded-lg">
            <Calendar className="w-4 h-4 text-indigo-500" />
            <span className="text-sm text-indigo-700 dark:text-indigo-400">
              Next: {format(getNextOccurrence(), 'MMM d, yyyy')}
            </span>
          </div>

          {/* Save */}
          <button
            onClick={handleSave}
            disabled={saving}
            className="w-full py-2 bg-indigo-600 text-white text-sm font-medium rounded-lg hover:bg-indigo-700 transition-colors disabled:opacity-50"
          >
            {saving ? 'Saving...' : 'Save Schedule'}
          </button>
        </div>
      )}

      {!enabled && initialConfig?.enabled && (
        <button
          onClick={handleSave}
          disabled={saving}
          className="w-full py-2 bg-slate-100 dark:bg-gray-700 text-slate-600 dark:text-gray-300 text-sm font-medium rounded-lg hover:bg-slate-200 dark:hover:bg-gray-600 transition-colors disabled:opacity-50"
        >
          {saving ? 'Saving...' : 'Save (Disable Recurring)'}
        </button>
      )}
    </div>
  );
}
