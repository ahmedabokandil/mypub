import { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  X, Calendar, Tag, Paperclip, MessageSquare, Trash2, Download,
  Upload, Link as LinkIcon, Clock, AlertTriangle, Send, ExternalLink,
  Archive, UserPlus, Users
} from 'lucide-react';
import { format } from 'date-fns';
import { marked } from 'marked';
import ReactPlayer from 'react-player';
import api from '../api/axios';
import { useAuth } from '../context/AuthContext';
import SubtaskList from './SubtaskList';
import TimeTracker from './TimeTracker';
import DependencyManager from './DependencyManager';
import RecurringTaskConfig from './RecurringTaskConfig';
import LinkPreview from './LinkPreview';
import toast from 'react-hot-toast';

const priorityOptions = [
  { value: 'low', label: 'Low', color: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-400' },
  { value: 'medium', label: 'Medium', color: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-400' },
  { value: 'high', label: 'High', color: 'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-400' },
  { value: 'urgent', label: 'Urgent', color: 'bg-red-200 text-red-800 dark:bg-red-900/40 dark:text-red-300' },
];

export default function TaskDetailModal({ task, boardId, columns, onClose, onUpdate, allTasks = [] }) {
  const { user } = useAuth();
  const [title, setTitle] = useState(task.title || '');
  const [description, setDescription] = useState(task.description || '');
  const [dueDate, setDueDate] = useState(task.dueDate ? task.dueDate.slice(0, 16) : '');
  const [priority, setPriority] = useState(task.priority || 'medium');
  const [reminder, setReminder] = useState(task.reminder ? task.reminder.slice(0, 16) : '');
  const [comments, setComments] = useState(task.comments || []);
  const [attachments, setAttachments] = useState(task.attachments || []);
  const [embeds, setEmbeds] = useState(task.embeds || []);
  const [labels, setLabels] = useState(task.labels || []);
  const [assignees, setAssignees] = useState(task.assignees || []);
  const [newComment, setNewComment] = useState('');
  const [newEmbed, setNewEmbed] = useState('');
  const [newLabel, setNewLabel] = useState('');
  const [newAssigneeEmail, setNewAssigneeEmail] = useState('');
  const [saving, setSaving] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [editingDesc, setEditingDesc] = useState(false);
  const [showAssigneeInput, setShowAssigneeInput] = useState(false);
  const fileInputRef = useRef(null);

  const isYouTube = (url) => /(?:youtube\.com|youtu\.be)/.test(url);

  const renderMarkdown = (text) => {
    if (!text) return '';
    try {
      return marked(text, { breaks: true, gfm: true });
    } catch {
      return text;
    }
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      const res = await api.put(`/api/boards/${boardId}/tasks/${task._id}`, {
        title,
        description,
        dueDate: dueDate || null,
        priority,
        reminder: reminder || null,
        labels,
        embeds,
        assignees,
      });
      toast.success('Task updated');
      if (onUpdate) onUpdate(res.data.task || res.data);
    } catch (err) {
      toast.error(err.response?.data?.message || 'Failed to update task');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!window.confirm('Delete this task? This cannot be undone.')) return;
    try {
      await api.delete(`/api/boards/${boardId}/tasks/${task._id}`);
      toast.success('Task deleted');
      if (onUpdate) onUpdate(null);
      onClose();
    } catch (err) {
      toast.error('Failed to delete task');
    }
  };

  const handleArchive = async () => {
    try {
      const res = await api.put(`/api/boards/${boardId}/tasks/${task._id}`, {
        archived: true,
      });
      toast.success('Task archived');
      if (onUpdate) onUpdate(res.data.task || res.data);
      onClose();
    } catch {
      toast.error('Failed to archive task');
    }
  };

  const handleAddComment = async () => {
    if (!newComment.trim()) return;
    try {
      const res = await api.post(`/api/boards/${boardId}/tasks/${task._id}/comments`, {
        text: newComment,
      });
      const comment = res.data.comment || res.data;
      setComments((prev) => [...prev, comment]);
      setNewComment('');
      toast.success('Comment added');
    } catch (err) {
      toast.error('Failed to add comment');
    }
  };

  const handleFileUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setUploading(true);
    try {
      const formData = new FormData();
      formData.append('file', file);
      const res = await api.post(`/api/boards/${boardId}/tasks/${task._id}/attachments`, formData, {
        headers: { 'Content-Type': 'multipart/form-data' },
      });
      const attachment = res.data.attachment || res.data;
      setAttachments((prev) => [...prev, attachment]);
      toast.success('File uploaded');
    } catch (err) {
      toast.error('Failed to upload file');
    } finally {
      setUploading(false);
    }
  };

  const handleDeleteAttachment = async (attachmentId) => {
    try {
      await api.delete(`/api/boards/${boardId}/tasks/${task._id}/attachments/${attachmentId}`);
      setAttachments((prev) => prev.filter((a) => a._id !== attachmentId));
      toast.success('Attachment deleted');
    } catch (err) {
      toast.error('Failed to delete attachment');
    }
  };

  const handleAddEmbed = () => {
    if (!newEmbed.trim()) return;
    try { new URL(newEmbed); } catch {
      toast.error('Please enter a valid URL');
      return;
    }
    setEmbeds((prev) => [...prev, { url: newEmbed }]);
    setNewEmbed('');
  };

  const handleRemoveEmbed = (index) => {
    setEmbeds((prev) => prev.filter((_, i) => i !== index));
  };

  const handleAddLabel = () => {
    if (!newLabel.trim()) return;
    const colors = ['#6366f1', '#ec4899', '#f59e0b', '#10b981', '#3b82f6', '#8b5cf6', '#ef4444'];
    const color = colors[labels.length % colors.length];
    setLabels((prev) => [...prev, { name: newLabel, color }]);
    setNewLabel('');
  };

  const handleRemoveLabel = (index) => {
    setLabels((prev) => prev.filter((_, i) => i !== index));
  };

  const handleAddAssignee = async () => {
    if (!newAssigneeEmail.trim()) return;
    try {
      const res = await api.post(`/api/boards/${boardId}/tasks/${task._id}/assignees`, {
        email: newAssigneeEmail,
      });
      const assignee = res.data.assignee || res.data;
      setAssignees((prev) => [...prev, assignee]);
      setNewAssigneeEmail('');
      setShowAssigneeInput(false);
      toast.success('Assignee added');
    } catch (err) {
      // Add locally for now
      setAssignees((prev) => [...prev, { email: newAssigneeEmail, name: newAssigneeEmail }]);
      setNewAssigneeEmail('');
      setShowAssigneeInput(false);
    }
  };

  const handleRemoveAssignee = async (assigneeId) => {
    try {
      await api.delete(`/api/boards/${boardId}/tasks/${task._id}/assignees/${assigneeId}`);
    } catch {}
    setAssignees((prev) => prev.filter((a) => (a._id || a.email) !== assigneeId));
  };

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex justify-end"
        onClick={onClose}
      >
        <motion.div
          initial={{ x: '100%' }}
          animate={{ x: 0 }}
          exit={{ x: '100%' }}
          transition={{ type: 'spring', damping: 30, stiffness: 300 }}
          onClick={(e) => e.stopPropagation()}
          className="w-full max-w-2xl bg-white dark:bg-gray-800 h-full overflow-y-auto shadow-2xl"
        >
          {/* Header */}
          <div className="sticky top-0 bg-white/80 dark:bg-gray-800/80 backdrop-blur-md border-b border-slate-100 dark:border-gray-700 px-6 py-4 flex items-center justify-between z-10">
            <h2 className="text-lg font-bold text-slate-800 dark:text-white">Task Details</h2>
            <div className="flex items-center gap-2">
              <button
                onClick={handleSave}
                disabled={saving}
                className="px-4 py-2 bg-gradient-to-r from-indigo-600 to-purple-600 text-white text-sm font-medium rounded-xl hover:shadow-lg hover:shadow-indigo-500/25 transition-all disabled:opacity-50"
              >
                {saving ? 'Saving...' : 'Save Changes'}
              </button>
              <button
                onClick={onClose}
                className="p-2 hover:bg-slate-100 dark:hover:bg-gray-700 rounded-xl transition-colors"
              >
                <X className="w-5 h-5 text-slate-500 dark:text-gray-400" />
              </button>
            </div>
          </div>

          <div className="p-6 space-y-6">
            {/* Title */}
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-gray-300 mb-1.5">Title</label>
              <input
                type="text"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                className="w-full px-4 py-3 bg-slate-50 dark:bg-gray-700 border border-slate-200 dark:border-gray-600 rounded-xl text-slate-800 dark:text-gray-200 font-medium focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all"
              />
            </div>

            {/* Description with markdown */}
            <div>
              <div className="flex items-center justify-between mb-1.5">
                <label className="block text-sm font-medium text-slate-700 dark:text-gray-300">Description</label>
                <button
                  onClick={() => setEditingDesc(!editingDesc)}
                  className="text-xs text-indigo-600 dark:text-indigo-400 hover:text-indigo-700 font-medium"
                >
                  {editingDesc ? 'Preview' : 'Edit'}
                </button>
              </div>
              {editingDesc ? (
                <textarea
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  rows={6}
                  placeholder="Add a description... (Markdown supported)"
                  className="w-full px-4 py-3 bg-slate-50 dark:bg-gray-700 border border-slate-200 dark:border-gray-600 rounded-xl text-slate-700 dark:text-gray-300 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all resize-none font-mono text-sm"
                />
              ) : description ? (
                <div
                  className="prose max-w-none px-4 py-3 bg-slate-50 dark:bg-gray-700 border border-slate-200 dark:border-gray-600 rounded-xl text-slate-700 dark:text-gray-300 min-h-[80px] cursor-pointer"
                  onClick={() => setEditingDesc(true)}
                  dangerouslySetInnerHTML={{ __html: renderMarkdown(description) }}
                />
              ) : (
                <button
                  onClick={() => setEditingDesc(true)}
                  className="w-full px-4 py-3 bg-slate-50 dark:bg-gray-700 border border-slate-200 dark:border-gray-600 rounded-xl text-slate-400 dark:text-gray-500 text-sm text-left"
                >
                  Add a description...
                </button>
              )}
            </div>

            {/* Priority & Due Date row */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-gray-300 mb-1.5">
                  <AlertTriangle className="w-4 h-4 inline mr-1" />
                  Priority
                </label>
                <div className="flex gap-2 flex-wrap">
                  {priorityOptions.map((opt) => (
                    <button
                      key={opt.value}
                      onClick={() => setPriority(opt.value)}
                      className={`px-3 py-1.5 text-sm font-medium rounded-lg border-2 transition-all ${
                        priority === opt.value
                          ? `${opt.color} border-current`
                          : 'bg-slate-50 dark:bg-gray-700 text-slate-500 dark:text-gray-400 border-transparent hover:bg-slate-100 dark:hover:bg-gray-600'
                      }`}
                    >
                      {opt.label}
                    </button>
                  ))}
                </div>
              </div>

              <div>
                <label className="block text-sm font-medium text-slate-700 dark:text-gray-300 mb-1.5">
                  <Calendar className="w-4 h-4 inline mr-1" />
                  Due Date
                </label>
                <input
                  type="datetime-local"
                  value={dueDate}
                  onChange={(e) => setDueDate(e.target.value)}
                  className="w-full px-4 py-2.5 bg-slate-50 dark:bg-gray-700 border border-slate-200 dark:border-gray-600 rounded-xl text-slate-700 dark:text-gray-300 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all"
                />
              </div>
            </div>

            {/* Reminder */}
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-gray-300 mb-1.5">
                <Clock className="w-4 h-4 inline mr-1" />
                Reminder
              </label>
              <input
                type="datetime-local"
                value={reminder}
                onChange={(e) => setReminder(e.target.value)}
                className="w-full px-4 py-2.5 bg-slate-50 dark:bg-gray-700 border border-slate-200 dark:border-gray-600 rounded-xl text-slate-700 dark:text-gray-300 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all"
              />
            </div>

            {/* Assignees */}
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-gray-300 mb-1.5 flex items-center gap-1">
                <Users className="w-4 h-4" />
                Assignees
              </label>
              <div className="flex flex-wrap gap-2 mb-2">
                {assignees.map((assignee, i) => (
                  <span
                    key={assignee._id || i}
                    className="inline-flex items-center gap-1.5 px-2.5 py-1 bg-indigo-50 dark:bg-indigo-900/20 text-indigo-700 dark:text-indigo-400 text-xs font-medium rounded-full"
                  >
                    <span className="w-5 h-5 bg-indigo-200 dark:bg-indigo-800 rounded-full flex items-center justify-center text-indigo-700 dark:text-indigo-300 text-xs font-semibold">
                      {(assignee.name || assignee.email || 'U').charAt(0).toUpperCase()}
                    </span>
                    {assignee.name || assignee.email}
                    <button onClick={() => handleRemoveAssignee(assignee._id || assignee.email)} className="hover:opacity-70">
                      <X className="w-3 h-3" />
                    </button>
                  </span>
                ))}
              </div>
              {showAssigneeInput ? (
                <div className="flex gap-2">
                  <input
                    type="email"
                    value={newAssigneeEmail}
                    onChange={(e) => setNewAssigneeEmail(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && handleAddAssignee()}
                    placeholder="Email address..."
                    autoFocus
                    className="flex-1 px-3 py-2 bg-slate-50 dark:bg-gray-700 border border-slate-200 dark:border-gray-600 rounded-lg text-sm text-slate-700 dark:text-gray-300 placeholder-slate-400 focus:outline-none focus:ring-1 focus:ring-indigo-500"
                  />
                  <button onClick={handleAddAssignee} className="px-3 py-2 bg-indigo-50 dark:bg-indigo-900/20 text-indigo-600 dark:text-indigo-400 text-sm font-medium rounded-lg hover:bg-indigo-100 dark:hover:bg-indigo-900/30">Add</button>
                  <button onClick={() => { setShowAssigneeInput(false); setNewAssigneeEmail(''); }} className="px-3 py-2 text-slate-500 text-sm">Cancel</button>
                </div>
              ) : (
                <button
                  onClick={() => setShowAssigneeInput(true)}
                  className="text-sm text-indigo-600 dark:text-indigo-400 hover:text-indigo-700 font-medium flex items-center gap-1"
                >
                  <UserPlus className="w-3.5 h-3.5" />
                  Add assignee
                </button>
              )}
            </div>

            {/* Labels */}
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-gray-300 mb-1.5">
                <Tag className="w-4 h-4 inline mr-1" />
                Labels
              </label>
              <div className="flex flex-wrap gap-2 mb-2">
                {labels.map((label, i) => (
                  <span
                    key={i}
                    className="inline-flex items-center gap-1 px-2.5 py-1 text-xs font-medium rounded-full"
                    style={{ backgroundColor: (label.color || '#6366f1') + '20', color: label.color || '#6366f1' }}
                  >
                    {label.name || label}
                    <button onClick={() => handleRemoveLabel(i)} className="hover:opacity-70">
                      <X className="w-3 h-3" />
                    </button>
                  </span>
                ))}
              </div>
              <div className="flex gap-2">
                <input
                  type="text"
                  value={newLabel}
                  onChange={(e) => setNewLabel(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleAddLabel()}
                  placeholder="Add label..."
                  className="flex-1 px-3 py-2 bg-slate-50 dark:bg-gray-700 border border-slate-200 dark:border-gray-600 rounded-lg text-sm text-slate-700 dark:text-gray-300 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all"
                />
                <button
                  onClick={handleAddLabel}
                  className="px-3 py-2 bg-slate-100 dark:bg-gray-600 hover:bg-slate-200 dark:hover:bg-gray-500 text-slate-600 dark:text-gray-300 text-sm font-medium rounded-lg transition-colors"
                >
                  Add
                </button>
              </div>
            </div>

            <hr className="border-slate-100 dark:border-gray-700" />

            {/* Subtask List */}
            <SubtaskList boardId={boardId} taskId={task._id} />

            <hr className="border-slate-100 dark:border-gray-700" />

            {/* Time Tracker */}
            <TimeTracker boardId={boardId} taskId={task._id} />

            <hr className="border-slate-100 dark:border-gray-700" />

            {/* Dependencies */}
            <DependencyManager boardId={boardId} taskId={task._id} tasks={allTasks} />

            <hr className="border-slate-100 dark:border-gray-700" />

            {/* Recurring Task Config */}
            <RecurringTaskConfig
              boardId={boardId}
              taskId={task._id}
              initialConfig={task.recurring}
            />

            <hr className="border-slate-100 dark:border-gray-700" />

            {/* Attachments */}
            <div>
              <div className="flex items-center justify-between mb-3">
                <label className="text-sm font-medium text-slate-700 dark:text-gray-300 flex items-center gap-1">
                  <Paperclip className="w-4 h-4" />
                  Attachments
                  {attachments.length > 0 && (
                    <span className="ml-1 px-1.5 py-0.5 bg-slate-100 dark:bg-gray-700 text-slate-500 dark:text-gray-400 text-xs rounded-full">
                      {attachments.length}
                    </span>
                  )}
                </label>
                <button
                  onClick={() => fileInputRef.current?.click()}
                  disabled={uploading}
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-indigo-50 dark:bg-indigo-900/20 text-indigo-600 dark:text-indigo-400 text-sm font-medium rounded-lg hover:bg-indigo-100 dark:hover:bg-indigo-900/30 transition-colors disabled:opacity-50"
                >
                  <Upload className="w-3.5 h-3.5" />
                  {uploading ? 'Uploading...' : 'Upload'}
                </button>
                <input ref={fileInputRef} type="file" onChange={handleFileUpload} className="hidden" />
              </div>
              {attachments.length > 0 ? (
                <div className="space-y-2">
                  {attachments.map((att) => (
                    <div
                      key={att._id || att.url}
                      className="flex items-center justify-between p-3 bg-slate-50 dark:bg-gray-700 rounded-xl border border-slate-100 dark:border-gray-600"
                    >
                      <div className="flex items-center gap-2 min-w-0">
                        <Paperclip className="w-4 h-4 text-slate-400 dark:text-gray-500 flex-shrink-0" />
                        <span className="text-sm text-slate-700 dark:text-gray-300 truncate">{att.filename || att.name || 'File'}</span>
                      </div>
                      <div className="flex items-center gap-1">
                        <a href={att.url} download target="_blank" rel="noopener noreferrer" className="p-1.5 hover:bg-slate-200 dark:hover:bg-gray-600 rounded-lg transition-colors">
                          <Download className="w-4 h-4 text-slate-500 dark:text-gray-400" />
                        </a>
                        <button onClick={() => handleDeleteAttachment(att._id)} className="p-1.5 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-colors">
                          <Trash2 className="w-4 h-4 text-red-400" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-slate-400 dark:text-gray-500 text-center py-3">No attachments yet</p>
              )}
            </div>

            <hr className="border-slate-100 dark:border-gray-700" />

            {/* Embeds with LinkPreview */}
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-gray-300 mb-2 flex items-center gap-1">
                <LinkIcon className="w-4 h-4" />
                Embeds & Links
              </label>
              <div className="flex gap-2 mb-3">
                <input
                  type="url"
                  value={newEmbed}
                  onChange={(e) => setNewEmbed(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleAddEmbed()}
                  placeholder="Paste a URL..."
                  className="flex-1 px-3 py-2 bg-slate-50 dark:bg-gray-700 border border-slate-200 dark:border-gray-600 rounded-lg text-sm text-slate-700 dark:text-gray-300 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all"
                />
                <button
                  onClick={handleAddEmbed}
                  className="px-3 py-2 bg-slate-100 dark:bg-gray-600 hover:bg-slate-200 dark:hover:bg-gray-500 text-slate-600 dark:text-gray-300 text-sm font-medium rounded-lg transition-colors"
                >
                  Add
                </button>
              </div>
              {embeds.length > 0 && (
                <div className="space-y-3">
                  {embeds.map((embed, i) => (
                    <div key={i} className="relative">
                      <LinkPreview url={embed.url || embed} />
                      <button
                        onClick={() => handleRemoveEmbed(i)}
                        className="absolute top-2 right-2 p-1 bg-white dark:bg-gray-800 rounded-full shadow hover:bg-red-50 dark:hover:bg-red-900/20 transition-colors"
                      >
                        <Trash2 className="w-3.5 h-3.5 text-red-400" />
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>

            <hr className="border-slate-100 dark:border-gray-700" />

            {/* Comments */}
            <div>
              <label className="block text-sm font-medium text-slate-700 dark:text-gray-300 mb-3 flex items-center gap-1">
                <MessageSquare className="w-4 h-4" />
                Comments
                {comments.length > 0 && (
                  <span className="ml-1 px-1.5 py-0.5 bg-slate-100 dark:bg-gray-700 text-slate-500 dark:text-gray-400 text-xs rounded-full">
                    {comments.length}
                  </span>
                )}
              </label>
              <div className="space-y-3 mb-4">
                {comments.length === 0 && (
                  <p className="text-sm text-slate-400 dark:text-gray-500 text-center py-3">No comments yet. Start the conversation!</p>
                )}
                {comments.map((comment, i) => (
                  <div key={comment._id || i} className="flex gap-3">
                    <div className="w-8 h-8 bg-indigo-100 dark:bg-indigo-900/30 rounded-lg flex items-center justify-center text-indigo-700 dark:text-indigo-400 text-xs font-semibold flex-shrink-0">
                      {(comment.user?.name || comment.userName || 'U').charAt(0).toUpperCase()}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-baseline gap-2">
                        <span className="text-sm font-semibold text-slate-700 dark:text-gray-300">
                          {comment.user?.name || comment.userName || 'User'}
                        </span>
                        <span className="text-xs text-slate-400 dark:text-gray-500">
                          {comment.createdAt ? format(new Date(comment.createdAt), 'MMM d, h:mm a') : 'Just now'}
                        </span>
                      </div>
                      <p className="text-sm text-slate-600 dark:text-gray-400 mt-0.5">{comment.text || comment.content}</p>
                    </div>
                  </div>
                ))}
              </div>
              <div className="flex gap-2">
                <div className="w-8 h-8 bg-indigo-100 dark:bg-indigo-900/30 rounded-lg flex items-center justify-center text-indigo-700 dark:text-indigo-400 text-xs font-semibold flex-shrink-0">
                  {user?.name?.charAt(0)?.toUpperCase() || 'U'}
                </div>
                <div className="flex-1 flex gap-2">
                  <input
                    type="text"
                    value={newComment}
                    onChange={(e) => setNewComment(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && handleAddComment()}
                    placeholder="Write a comment..."
                    className="flex-1 px-3 py-2 bg-slate-50 dark:bg-gray-700 border border-slate-200 dark:border-gray-600 rounded-lg text-sm text-slate-700 dark:text-gray-300 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all"
                  />
                  <button
                    onClick={handleAddComment}
                    disabled={!newComment.trim()}
                    className="p-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    <Send className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </div>

            <hr className="border-slate-100 dark:border-gray-700" />

            {/* Actions */}
            <div className="flex gap-3 justify-end">
              <button
                onClick={handleArchive}
                className="flex items-center gap-2 px-4 py-2 text-amber-600 dark:text-amber-400 bg-amber-50 dark:bg-amber-900/20 hover:bg-amber-100 dark:hover:bg-amber-900/30 text-sm font-medium rounded-xl transition-colors"
              >
                <Archive className="w-4 h-4" />
                Archive
              </button>
              <button
                onClick={handleDelete}
                className="flex items-center gap-2 px-4 py-2 text-red-600 bg-red-50 dark:bg-red-900/20 hover:bg-red-100 dark:hover:bg-red-900/30 text-sm font-medium rounded-xl transition-colors"
              >
                <Trash2 className="w-4 h-4" />
                Delete Task
              </button>
            </div>
          </div>
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
}
