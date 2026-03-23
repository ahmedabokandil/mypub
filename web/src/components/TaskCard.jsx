import { useState } from 'react';
import { Calendar, Paperclip, MessageSquare, AlertTriangle, Clock, Lock, RefreshCw, Timer, CheckSquare } from 'lucide-react';
import { format, isPast, isToday } from 'date-fns';
import TaskDetailModal from './TaskDetailModal';

const priorityConfig = {
  urgent: { color: 'bg-red-100 text-red-700 border-red-200 dark:bg-red-900/30 dark:text-red-400 dark:border-red-800', dot: 'bg-red-500' },
  high: { color: 'bg-red-50 text-red-600 border-red-100 dark:bg-red-900/20 dark:text-red-400 dark:border-red-800', dot: 'bg-red-400' },
  medium: { color: 'bg-amber-50 text-amber-600 border-amber-100 dark:bg-amber-900/20 dark:text-amber-400 dark:border-amber-800', dot: 'bg-amber-400' },
  low: { color: 'bg-green-50 text-green-600 border-green-100 dark:bg-green-900/20 dark:text-green-400 dark:border-green-800', dot: 'bg-green-400' },
};

export default function TaskCard({ task, boardId, columns, onUpdate, provided, allTasks = [] }) {
  const [detailOpen, setDetailOpen] = useState(false);

  const priority = priorityConfig[task.priority] || priorityConfig.medium;
  const dueDate = task.dueDate ? new Date(task.dueDate) : null;
  const overdue = dueDate && isPast(dueDate) && !isToday(dueDate) && task.status !== 'done';

  // Subtask progress
  const checklist = task.checklist || [];
  const checklistCompleted = checklist.filter((i) => i.completed).length;
  const checklistTotal = checklist.length;

  // Time tracked
  const totalTimeTracked = (task.timeEntries || []).reduce((sum, e) => sum + (e.duration || 0), 0);
  const formatTimeShort = (seconds) => {
    const h = Math.floor(seconds / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    if (h > 0) return `${h}h ${m}m`;
    return `${m}m`;
  };

  // Dependencies
  const isBlocked = (task.blockedBy || task.dependencies?.blockedBy || []).length > 0;

  // Assignees
  const assignees = task.assignees || [];

  // Recurring
  const isRecurring = task.recurring?.enabled;

  return (
    <>
      <div
        ref={provided?.innerRef}
        {...(provided?.draggableProps || {})}
        {...(provided?.dragHandleProps || {})}
        onClick={() => setDetailOpen(true)}
        className={`group bg-white dark:bg-gray-800 rounded-xl p-4 shadow-sm border border-slate-100 dark:border-gray-700 hover:shadow-md hover:-translate-y-0.5 transition-all duration-200 cursor-pointer ${
          isBlocked ? 'opacity-75 border-red-200 dark:border-red-800' : ''
        }`}
      >
        {/* Blocked indicator */}
        {isBlocked && (
          <div className="flex items-center gap-1 text-xs text-red-500 dark:text-red-400 font-medium mb-2">
            <Lock className="w-3 h-3" />
            Blocked
          </div>
        )}

        {/* Labels */}
        {task.labels && task.labels.length > 0 && (
          <div className="flex flex-wrap gap-1.5 mb-3">
            {task.labels.map((label, i) => (
              <span
                key={i}
                className="px-2 py-0.5 text-xs font-medium rounded-full"
                style={{
                  backgroundColor: (label.color || '#6366f1') + '20',
                  color: label.color || '#6366f1',
                }}
              >
                {label.name || label}
              </span>
            ))}
          </div>
        )}

        {/* Title */}
        <h4 className="text-sm font-semibold text-slate-800 dark:text-gray-200 mb-2 line-clamp-2 group-hover:text-indigo-700 dark:group-hover:text-indigo-400 transition-colors">
          {task.title}
        </h4>

        {/* Description preview */}
        {task.description && (
          <p className="text-xs text-slate-500 dark:text-gray-400 mb-3 line-clamp-2">{task.description}</p>
        )}

        {/* Subtask progress */}
        {checklistTotal > 0 && (
          <div className="mb-3">
            <div className="flex items-center gap-1.5 mb-1">
              <CheckSquare className="w-3 h-3 text-slate-400 dark:text-gray-500" />
              <span className="text-xs text-slate-500 dark:text-gray-400 font-medium">
                {checklistCompleted}/{checklistTotal} subtasks
              </span>
            </div>
            <div className="w-full h-1.5 bg-slate-100 dark:bg-gray-700 rounded-full overflow-hidden">
              <div
                className="h-full bg-indigo-500 rounded-full transition-all"
                style={{ width: `${(checklistCompleted / checklistTotal) * 100}%` }}
              />
            </div>
          </div>
        )}

        {/* Meta row */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2 flex-wrap">
            {/* Priority badge */}
            <span className={`inline-flex items-center gap-1 px-2 py-0.5 text-xs font-medium rounded-full border ${priority.color}`}>
              <span className={`w-1.5 h-1.5 rounded-full ${priority.dot}`} />
              {task.priority ? task.priority.charAt(0).toUpperCase() + task.priority.slice(1) : 'Medium'}
            </span>

            {/* Due date */}
            {dueDate && (
              <span className={`inline-flex items-center gap-1 text-xs font-medium ${overdue ? 'text-red-600 dark:text-red-400' : 'text-slate-500 dark:text-gray-400'}`}>
                {overdue ? <AlertTriangle className="w-3 h-3" /> : <Calendar className="w-3 h-3" />}
                {format(dueDate, 'MMM d')}
              </span>
            )}
          </div>

          <div className="flex items-center gap-2 text-slate-400 dark:text-gray-500">
            {/* Time tracked */}
            {totalTimeTracked > 0 && (
              <span className="inline-flex items-center gap-0.5 text-xs">
                <Timer className="w-3 h-3" />
                {formatTimeShort(totalTimeTracked)}
              </span>
            )}
            {/* Recurring */}
            {isRecurring && (
              <RefreshCw className="w-3 h-3 text-indigo-400" />
            )}
            {/* Attachments count */}
            {task.attachments && task.attachments.length > 0 && (
              <span className="inline-flex items-center gap-0.5 text-xs">
                <Paperclip className="w-3 h-3" />
                {task.attachments.length}
              </span>
            )}
            {/* Comments count */}
            {task.comments && task.comments.length > 0 && (
              <span className="inline-flex items-center gap-0.5 text-xs">
                <MessageSquare className="w-3 h-3" />
                {task.comments.length}
              </span>
            )}
          </div>
        </div>

        {/* Assignee avatars + reminder */}
        <div className="flex items-center justify-between mt-2">
          {assignees.length > 0 && (
            <div className="flex -space-x-1.5">
              {assignees.slice(0, 4).map((a, i) => (
                <div
                  key={a._id || i}
                  className="w-6 h-6 bg-gradient-to-br from-indigo-400 to-purple-500 rounded-full border-2 border-white dark:border-gray-800 flex items-center justify-center text-white text-[10px] font-semibold"
                  title={a.name || a.email}
                >
                  {(a.name || a.email || 'U').charAt(0).toUpperCase()}
                </div>
              ))}
              {assignees.length > 4 && (
                <div className="w-6 h-6 bg-slate-200 dark:bg-gray-600 rounded-full border-2 border-white dark:border-gray-800 flex items-center justify-center text-slate-600 dark:text-gray-300 text-[10px] font-semibold">
                  +{assignees.length - 4}
                </div>
              )}
            </div>
          )}

          {task.reminder && (
            <div className="flex items-center gap-1 text-xs text-indigo-500 dark:text-indigo-400">
              <Clock className="w-3 h-3" />
              Reminder
            </div>
          )}
        </div>
      </div>

      {/* Detail modal */}
      {detailOpen && (
        <TaskDetailModal
          task={task}
          boardId={boardId}
          columns={columns}
          onClose={() => setDetailOpen(false)}
          onUpdate={onUpdate}
          allTasks={allTasks}
        />
      )}
    </>
  );
}
