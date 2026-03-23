import { useState, useEffect, useRef } from 'react';
import { Play, Square, Trash2, Clock, Timer } from 'lucide-react';
import { format } from 'date-fns';
import api from '../api/axios';
import toast from 'react-hot-toast';

export default function TimeTracker({ boardId, taskId }) {
  const [entries, setEntries] = useState([]);
  const [running, setRunning] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const [description, setDescription] = useState('');
  const startTimeRef = useRef(null);
  const intervalRef = useRef(null);

  useEffect(() => {
    fetchEntries();
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [boardId, taskId]);

  const fetchEntries = async () => {
    try {
      const res = await api.get(`/api/boards/${boardId}/tasks/${taskId}/time-entries`);
      setEntries(res.data.entries || res.data || []);
    } catch {
      setEntries([]);
    }
  };

  const startTimer = () => {
    startTimeRef.current = Date.now();
    setRunning(true);
    setElapsed(0);
    intervalRef.current = setInterval(() => {
      setElapsed(Math.floor((Date.now() - startTimeRef.current) / 1000));
    }, 1000);
  };

  const stopTimer = async () => {
    if (intervalRef.current) clearInterval(intervalRef.current);
    const duration = Math.floor((Date.now() - startTimeRef.current) / 1000);
    setRunning(false);

    if (duration < 1) return;

    const entry = {
      date: new Date().toISOString(),
      duration,
      description: description || 'Time tracked',
    };

    try {
      const res = await api.post(`/api/boards/${boardId}/tasks/${taskId}/time-entries`, entry);
      setEntries((prev) => [...prev, res.data.entry || res.data || entry]);
      setDescription('');
      setElapsed(0);
      toast.success('Time entry saved');
    } catch {
      // Save locally if API fails
      setEntries((prev) => [...prev, { ...entry, _id: Date.now().toString() }]);
      setDescription('');
      setElapsed(0);
    }
  };

  const deleteEntry = async (entryId) => {
    try {
      await api.delete(`/api/boards/${boardId}/tasks/${taskId}/time-entries/${entryId}`);
      setEntries((prev) => prev.filter((e) => (e._id || e.id) !== entryId));
      toast.success('Entry deleted');
    } catch {
      setEntries((prev) => prev.filter((e) => (e._id || e.id) !== entryId));
    }
  };

  const formatDuration = (seconds) => {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    return `${String(h).padStart(2, '0')}:${String(m).padStart(2, '0')}:${String(s).padStart(2, '0')}`;
  };

  const formatDurationShort = (seconds) => {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    if (h > 0) return `${h}h ${m}m`;
    return `${m}m`;
  };

  const totalTime = entries.reduce((sum, e) => sum + (e.duration || 0), 0);

  return (
    <div>
      <label className="block text-sm font-medium text-slate-700 dark:text-gray-300 mb-2 flex items-center gap-1">
        <Timer className="w-4 h-4" />
        Time Tracking
        {totalTime > 0 && (
          <span className="ml-1 text-xs text-slate-500 dark:text-gray-400">
            Total: {formatDurationShort(totalTime)}
          </span>
        )}
      </label>

      {/* Timer controls */}
      <div className="flex items-center gap-3 mb-3 p-3 bg-slate-50 dark:bg-gray-700 rounded-xl border border-slate-100 dark:border-gray-600">
        <button
          onClick={running ? stopTimer : startTimer}
          className={`p-2.5 rounded-xl transition-all ${
            running
              ? 'bg-red-500 hover:bg-red-600 text-white shadow-lg shadow-red-500/25'
              : 'bg-indigo-500 hover:bg-indigo-600 text-white shadow-lg shadow-indigo-500/25'
          }`}
        >
          {running ? <Square className="w-4 h-4" /> : <Play className="w-4 h-4" />}
        </button>

        <div className="flex-1">
          <div className={`text-2xl font-mono font-bold ${running ? 'text-red-600 dark:text-red-400' : 'text-slate-700 dark:text-gray-300'}`}>
            {formatDuration(elapsed)}
          </div>
          {running && (
            <input
              type="text"
              value={description}
              onChange={(e) => setDescription(e.target.value)}
              placeholder="What are you working on?"
              className="w-full mt-1 px-2 py-1 text-xs bg-white dark:bg-gray-600 border border-slate-200 dark:border-gray-500 rounded-lg text-slate-700 dark:text-gray-300 placeholder-slate-400 dark:placeholder-gray-500 focus:outline-none focus:ring-1 focus:ring-indigo-500"
            />
          )}
        </div>
      </div>

      {/* Time entries */}
      {entries.length > 0 && (
        <div className="space-y-2">
          {entries.map((entry) => (
            <div
              key={entry._id || entry.id}
              className="flex items-center justify-between p-2.5 bg-white dark:bg-gray-700 rounded-lg border border-slate-100 dark:border-gray-600 group"
            >
              <div className="flex items-center gap-2 min-w-0">
                <Clock className="w-3.5 h-3.5 text-slate-400 dark:text-gray-500 flex-shrink-0" />
                <div className="min-w-0">
                  <p className="text-sm font-medium text-slate-700 dark:text-gray-300 truncate">
                    {entry.description || 'Time tracked'}
                  </p>
                  <p className="text-xs text-slate-400 dark:text-gray-500">
                    {entry.date ? format(new Date(entry.date), 'MMM d, h:mm a') : 'Recently'}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <span className="text-sm font-medium text-indigo-600 dark:text-indigo-400">
                  {formatDurationShort(entry.duration || 0)}
                </span>
                <button
                  onClick={() => deleteEntry(entry._id || entry.id)}
                  className="p-1 opacity-0 group-hover:opacity-100 hover:bg-red-50 dark:hover:bg-red-900/30 rounded transition-all"
                >
                  <Trash2 className="w-3.5 h-3.5 text-red-400" />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
