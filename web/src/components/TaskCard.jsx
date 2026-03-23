import { useState } from 'react';
import { motion } from 'framer-motion';
import { Calendar, Paperclip, MessageSquare, AlertTriangle, Clock } from 'lucide-react';
import { format, isPast, isToday } from 'date-fns';
import TaskDetailModal from './TaskDetailModal';

const priorityConfig = {
  urgent: { color: 'bg-red-100 text-red-700 border-red-200', dot: 'bg-red-500' },
  high: { color: 'bg-red-50 text-red-600 border-red-100', dot: 'bg-red-400' },
  medium: { color: 'bg-amber-50 text-amber-600 border-amber-100', dot: 'bg-amber-400' },
  low: { color: 'bg-green-50 text-green-600 border-green-100', dot: 'bg-green-400' },
};

export default function TaskCard({ task, boardId, columns, onUpdate, provided }) {
  const [detailOpen, setDetailOpen] = useState(false);

  const priority = priorityConfig[task.priority] || priorityConfig.medium;
  const dueDate = task.dueDate ? new Date(task.dueDate) : null;
  const overdue = dueDate && isPast(dueDate) && !isToday(dueDate) && task.status !== 'done';

  return (
    <>
      <div
        ref={provided?.innerRef}
        {...(provided?.draggableProps || {})}
        {...(provided?.dragHandleProps || {})}
        onClick={() => setDetailOpen(true)}
        className="group bg-white rounded-xl p-4 shadow-sm border border-slate-100 hover:shadow-md hover:-translate-y-0.5 transition-all duration-200 cursor-pointer"
      >
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
        <h4 className="text-sm font-semibold text-slate-800 mb-2 line-clamp-2 group-hover:text-indigo-700 transition-colors">
          {task.title}
        </h4>

        {/* Description preview */}
        {task.description && (
          <p className="text-xs text-slate-500 mb-3 line-clamp-2">{task.description}</p>
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
              <span className={`inline-flex items-center gap-1 text-xs font-medium ${overdue ? 'text-red-600' : 'text-slate-500'}`}>
                {overdue ? <AlertTriangle className="w-3 h-3" /> : <Calendar className="w-3 h-3" />}
                {format(dueDate, 'MMM d')}
              </span>
            )}
          </div>

          <div className="flex items-center gap-2 text-slate-400">
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

        {/* Reminder indicator */}
        {task.reminder && (
          <div className="mt-2 flex items-center gap-1 text-xs text-indigo-500">
            <Clock className="w-3 h-3" />
            Reminder set
          </div>
        )}
      </div>

      {/* Detail modal */}
      {detailOpen && (
        <TaskDetailModal
          task={task}
          boardId={boardId}
          columns={columns}
          onClose={() => setDetailOpen(false)}
          onUpdate={onUpdate}
        />
      )}
    </>
  );
}
