import { useState, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  ChevronLeft, ChevronRight, Calendar as CalendarIcon, Loader2, X
} from 'lucide-react';
import {
  startOfMonth, endOfMonth, startOfWeek, endOfWeek, eachDayOfInterval,
  format, isSameMonth, isSameDay, isToday, addMonths, subMonths
} from 'date-fns';
import api from '../api/axios';
import Navbar from '../components/Navbar';
import toast from 'react-hot-toast';

const priorityColors = {
  urgent: 'bg-red-500',
  high: 'bg-red-400',
  medium: 'bg-amber-400',
  low: 'bg-green-400',
};

const priorityBgColors = {
  urgent: 'bg-red-50 dark:bg-red-900/20 text-red-700 dark:text-red-400 border-red-200 dark:border-red-800',
  high: 'bg-red-50 dark:bg-red-900/20 text-red-600 dark:text-red-400 border-red-100 dark:border-red-800',
  medium: 'bg-amber-50 dark:bg-amber-900/20 text-amber-700 dark:text-amber-400 border-amber-200 dark:border-amber-800',
  low: 'bg-green-50 dark:bg-green-900/20 text-green-700 dark:text-green-400 border-green-200 dark:border-green-800',
};

export default function CalendarPage() {
  const [currentMonth, setCurrentMonth] = useState(new Date());
  const [boards, setBoards] = useState([]);
  const [selectedBoardId, setSelectedBoardId] = useState('all');
  const [tasks, setTasks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [selectedDate, setSelectedDate] = useState(null);
  const [selectedTask, setSelectedTask] = useState(null);

  useEffect(() => {
    fetchBoards();
  }, []);

  useEffect(() => {
    fetchTasks();
  }, [selectedBoardId]);

  const fetchBoards = async () => {
    try {
      const res = await api.get('/api/boards');
      setBoards(res.data.boards || res.data || []);
    } catch {
      toast.error('Failed to load boards');
    }
  };

  const fetchTasks = async () => {
    setLoading(true);
    try {
      if (selectedBoardId === 'all') {
        const res = await api.get('/api/boards');
        const allBoards = res.data.boards || res.data || [];
        const allTasks = [];
        for (const board of allBoards) {
          try {
            const bRes = await api.get(`/api/boards/${board._id}`);
            const bData = bRes.data.board || bRes.data;
            const bTasks = (bData.tasks || []).map((t) => ({ ...t, boardName: board.name, boardColor: board.color }));
            allTasks.push(...bTasks);
          } catch {}
        }
        setTasks(allTasks);
      } else {
        const res = await api.get(`/api/boards/${selectedBoardId}`);
        const data = res.data.board || res.data;
        const board = boards.find((b) => b._id === selectedBoardId);
        setTasks((data.tasks || []).map((t) => ({ ...t, boardName: board?.name, boardColor: board?.color })));
      }
    } catch {
      toast.error('Failed to load tasks');
    } finally {
      setLoading(false);
    }
  };

  const monthStart = startOfMonth(currentMonth);
  const monthEnd = endOfMonth(currentMonth);
  const calStart = startOfWeek(monthStart);
  const calEnd = endOfWeek(monthEnd);
  const days = eachDayOfInterval({ start: calStart, end: calEnd });

  const getTasksForDay = (day) => {
    return tasks.filter((t) => t.dueDate && isSameDay(new Date(t.dueDate), day));
  };

  const selectedDayTasks = selectedDate ? getTasksForDay(selectedDate) : [];

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-gray-900">
      <Navbar />
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between mb-8 gap-4">
          <div>
            <h1 className="text-2xl sm:text-3xl font-bold text-slate-800 dark:text-white">Calendar</h1>
            <p className="text-slate-500 dark:text-gray-400 mt-1">View your tasks by due date</p>
          </div>
          <div className="flex items-center gap-3">
            <select
              value={selectedBoardId}
              onChange={(e) => setSelectedBoardId(e.target.value)}
              className="px-4 py-2.5 bg-white dark:bg-gray-800 border border-slate-200 dark:border-gray-700 rounded-xl text-sm text-slate-700 dark:text-gray-300 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500"
            >
              <option value="all">All Boards</option>
              {boards.map((b) => (
                <option key={b._id} value={b._id}>{b.name}</option>
              ))}
            </select>
          </div>
        </div>

        {/* Month nav */}
        <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-sm border border-slate-100 dark:border-gray-700 overflow-hidden">
          <div className="flex items-center justify-between p-4 sm:p-6 border-b border-slate-100 dark:border-gray-700">
            <button
              onClick={() => setCurrentMonth(subMonths(currentMonth, 1))}
              className="p-2 hover:bg-slate-100 dark:hover:bg-gray-700 rounded-xl transition-colors"
            >
              <ChevronLeft className="w-5 h-5 text-slate-600 dark:text-gray-400" />
            </button>
            <h2 className="text-lg sm:text-xl font-bold text-slate-800 dark:text-white">
              {format(currentMonth, 'MMMM yyyy')}
            </h2>
            <button
              onClick={() => setCurrentMonth(addMonths(currentMonth, 1))}
              className="p-2 hover:bg-slate-100 dark:hover:bg-gray-700 rounded-xl transition-colors"
            >
              <ChevronRight className="w-5 h-5 text-slate-600 dark:text-gray-400" />
            </button>
          </div>

          {loading ? (
            <div className="flex items-center justify-center py-32">
              <Loader2 className="w-8 h-8 text-indigo-500 animate-spin" />
            </div>
          ) : (
            <>
              {/* Day headers */}
              <div className="grid grid-cols-7 border-b border-slate-100 dark:border-gray-700">
                {['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'].map((d) => (
                  <div key={d} className="py-3 text-center text-xs font-semibold text-slate-500 dark:text-gray-400 uppercase tracking-wider">
                    {d}
                  </div>
                ))}
              </div>

              {/* Calendar grid */}
              <div className="grid grid-cols-7">
                {days.map((day, i) => {
                  const dayTasks = getTasksForDay(day);
                  const isCurrentMonth = isSameMonth(day, currentMonth);
                  const isTodayDate = isToday(day);
                  const isSelected = selectedDate && isSameDay(day, selectedDate);

                  return (
                    <button
                      key={i}
                      onClick={() => setSelectedDate(day)}
                      className={`min-h-[80px] sm:min-h-[110px] p-1.5 sm:p-2 border-b border-r border-slate-50 dark:border-gray-700/50 text-left transition-colors relative ${
                        !isCurrentMonth ? 'bg-slate-50/50 dark:bg-gray-900/50' : 'hover:bg-indigo-50/50 dark:hover:bg-indigo-900/10'
                      } ${isSelected ? 'bg-indigo-50 dark:bg-indigo-900/20 ring-2 ring-inset ring-indigo-300 dark:ring-indigo-600' : ''}`}
                    >
                      <span
                        className={`inline-flex items-center justify-center w-7 h-7 text-sm font-medium rounded-full ${
                          isTodayDate
                            ? 'bg-indigo-600 text-white'
                            : isCurrentMonth
                            ? 'text-slate-700 dark:text-gray-300'
                            : 'text-slate-300 dark:text-gray-600'
                        }`}
                      >
                        {format(day, 'd')}
                      </span>
                      <div className="mt-1 space-y-0.5">
                        {dayTasks.slice(0, 3).map((task) => (
                          <div
                            key={task._id}
                            className={`text-xs px-1.5 py-0.5 rounded truncate font-medium cursor-pointer ${priorityBgColors[task.priority] || priorityBgColors.medium}`}
                            onClick={(e) => {
                              e.stopPropagation();
                              setSelectedTask(task);
                            }}
                          >
                            <span className="hidden sm:inline">{task.title}</span>
                            <span className={`sm:hidden w-2 h-2 rounded-full inline-block ${priorityColors[task.priority] || priorityColors.medium}`} />
                          </div>
                        ))}
                        {dayTasks.length > 3 && (
                          <div className="text-xs text-slate-400 dark:text-gray-500 px-1 font-medium">
                            +{dayTasks.length - 3} more
                          </div>
                        )}
                      </div>
                    </button>
                  );
                })}
              </div>
            </>
          )}
        </div>

        {/* Selected date panel */}
        <AnimatePresence>
          {selectedDate && (
            <motion.div
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: 20 }}
              className="mt-6 bg-white dark:bg-gray-800 rounded-2xl shadow-sm border border-slate-100 dark:border-gray-700 p-6"
            >
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-bold text-slate-800 dark:text-white">
                  {format(selectedDate, 'EEEE, MMMM d, yyyy')}
                </h3>
                <button
                  onClick={() => setSelectedDate(null)}
                  className="p-1.5 hover:bg-slate-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
                >
                  <X className="w-4 h-4 text-slate-400" />
                </button>
              </div>
              {selectedDayTasks.length === 0 ? (
                <div className="text-center py-8">
                  <CalendarIcon className="w-8 h-8 text-slate-300 dark:text-gray-600 mx-auto mb-2" />
                  <p className="text-sm text-slate-400 dark:text-gray-500">No tasks due on this day</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {selectedDayTasks.map((task) => (
                    <div
                      key={task._id}
                      onClick={() => setSelectedTask(task)}
                      className="flex items-center gap-3 p-3 rounded-xl border border-slate-100 dark:border-gray-700 hover:bg-slate-50 dark:hover:bg-gray-700/50 cursor-pointer transition-colors"
                    >
                      <div className={`w-3 h-3 rounded-full flex-shrink-0 ${priorityColors[task.priority] || priorityColors.medium}`} />
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-medium text-slate-800 dark:text-gray-200 truncate">{task.title}</p>
                        <div className="flex items-center gap-2 mt-0.5">
                          {task.boardName && (
                            <span className="text-xs text-slate-400 dark:text-gray-500">{task.boardName}</span>
                          )}
                          <span className="text-xs text-slate-400 dark:text-gray-500 capitalize">
                            {task.status?.replace('_', ' ')}
                          </span>
                        </div>
                      </div>
                      <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${priorityBgColors[task.priority] || priorityBgColors.medium}`}>
                        {task.priority ? task.priority.charAt(0).toUpperCase() + task.priority.slice(1) : 'Medium'}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </motion.div>
          )}
        </AnimatePresence>

        {/* Task detail modal */}
        <AnimatePresence>
          {selectedTask && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4"
              onClick={() => setSelectedTask(null)}
            >
              <motion.div
                initial={{ opacity: 0, scale: 0.95 }}
                animate={{ opacity: 1, scale: 1 }}
                exit={{ opacity: 0, scale: 0.95 }}
                onClick={(e) => e.stopPropagation()}
                className="w-full max-w-md bg-white dark:bg-gray-800 rounded-2xl shadow-2xl p-6"
              >
                <div className="flex items-start justify-between mb-4">
                  <h3 className="text-lg font-bold text-slate-800 dark:text-white">{selectedTask.title}</h3>
                  <button
                    onClick={() => setSelectedTask(null)}
                    className="p-1.5 hover:bg-slate-100 dark:hover:bg-gray-700 rounded-lg transition-colors"
                  >
                    <X className="w-4 h-4 text-slate-400" />
                  </button>
                </div>
                {selectedTask.description && (
                  <p className="text-sm text-slate-600 dark:text-gray-400 mb-4">{selectedTask.description}</p>
                )}
                <div className="space-y-2 text-sm">
                  <div className="flex justify-between">
                    <span className="text-slate-500 dark:text-gray-400">Priority</span>
                    <span className={`px-2 py-0.5 rounded-full text-xs font-medium ${priorityBgColors[selectedTask.priority] || priorityBgColors.medium}`}>
                      {selectedTask.priority ? selectedTask.priority.charAt(0).toUpperCase() + selectedTask.priority.slice(1) : 'Medium'}
                    </span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-500 dark:text-gray-400">Status</span>
                    <span className="text-slate-700 dark:text-gray-300 capitalize">{selectedTask.status?.replace('_', ' ')}</span>
                  </div>
                  {selectedTask.dueDate && (
                    <div className="flex justify-between">
                      <span className="text-slate-500 dark:text-gray-400">Due Date</span>
                      <span className="text-slate-700 dark:text-gray-300">{format(new Date(selectedTask.dueDate), 'MMM d, yyyy h:mm a')}</span>
                    </div>
                  )}
                  {selectedTask.boardName && (
                    <div className="flex justify-between">
                      <span className="text-slate-500 dark:text-gray-400">Board</span>
                      <span className="text-slate-700 dark:text-gray-300">{selectedTask.boardName}</span>
                    </div>
                  )}
                </div>
              </motion.div>
            </motion.div>
          )}
        </AnimatePresence>
      </main>
    </div>
  );
}
