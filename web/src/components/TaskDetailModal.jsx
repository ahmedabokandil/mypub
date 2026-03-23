import { useState, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import {
  X, Calendar, Tag, Paperclip, MessageSquare, Trash2, Download,
  Upload, Link as LinkIcon, Clock, AlertTriangle, Send, Play, ExternalLink
} from 'lucide-react';
import { format } from 'date-fns';
import ReactPlayer from 'react-player';
import api from '../api/axios';
import { useAuth } from '../context/AuthContext';
import toast from 'react-hot-toast';

const priorityOptions = [
  { value: 'low', label: 'Low', color: 'bg-green-100 text-green-700' },
  { value: 'medium', label: 'Medium', color: 'bg-amber-100 text-amber-700' },
  { value: 'high', label: 'High', color: 'bg-red-100 text-red-700' },
  { value: 'urgent', label: 'Urgent', color: 'bg-red-200 text-red-800' },
];

export default function TaskDetailModal({ task, boardId, columns, onClose, onUpdate }) {
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
  const [newComment, setNewComment] = useState('');
  const [newEmbed, setNewEmbed] = useState('');
  const [newLabel, setNewLabel] = useState('');
  const [saving, setSaving] = useState(false);
  const [uploading, setUploading] = useState(false);
  const fileInputRef = useRef(null);

  const isYouTube = (url) => {
    return /(?:youtube\.com|youtu\.be)/.test(url);
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
    try {
      new URL(newEmbed);
    } catch {
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
          className="w-full max-w-2xl bg-white h-full overflow-y-auto shadow-2xl"
        >
          {/* Header */}
          <div className="sticky top-0 bg-white/80 backdrop-blur-md border-b border-slate-100 px-6 py-4 flex items-center justify-between z-10">
            <h2 className="text-lg font-bold text-slate-800">Task Details</h2>
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
                className="p-2 hover:bg-slate-100 rounded-xl transition-colors"
              >
                <X className="w-5 h-5 text-slate-500" />
              </button>
            </div>
          </div>

          <div className="p-6 space-y-6">
            {/* Title */}
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1.5">Title</label>
              <input
                type="text"
                value={title}
                onChange={(e) => setTitle(e.target.value)}
                className="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-xl text-slate-800 font-medium focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all"
              />
            </div>

            {/* Description */}
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1.5">Description</label>
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                rows={4}
                placeholder="Add a description..."
                className="w-full px-4 py-3 bg-slate-50 border border-slate-200 rounded-xl text-slate-700 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all resize-none"
              />
            </div>

            {/* Priority & Due Date row */}
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              {/* Priority */}
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1.5">
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
                          : 'bg-slate-50 text-slate-500 border-transparent hover:bg-slate-100'
                      }`}
                    >
                      {opt.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Due date */}
              <div>
                <label className="block text-sm font-medium text-slate-700 mb-1.5">
                  <Calendar className="w-4 h-4 inline mr-1" />
                  Due Date
                </label>
                <input
                  type="datetime-local"
                  value={dueDate}
                  onChange={(e) => setDueDate(e.target.value)}
                  className="w-full px-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-slate-700 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all"
                />
              </div>
            </div>

            {/* Reminder */}
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1.5">
                <Clock className="w-4 h-4 inline mr-1" />
                Reminder
              </label>
              <input
                type="datetime-local"
                value={reminder}
                onChange={(e) => setReminder(e.target.value)}
                className="w-full px-4 py-2.5 bg-slate-50 border border-slate-200 rounded-xl text-slate-700 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all"
              />
            </div>

            {/* Labels */}
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-1.5">
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
                  className="flex-1 px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm text-slate-700 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all"
                />
                <button
                  onClick={handleAddLabel}
                  className="px-3 py-2 bg-slate-100 hover:bg-slate-200 text-slate-600 text-sm font-medium rounded-lg transition-colors"
                >
                  Add
                </button>
              </div>
            </div>

            {/* Divider */}
            <hr className="border-slate-100" />

            {/* Attachments */}
            <div>
              <div className="flex items-center justify-between mb-3">
                <label className="text-sm font-medium text-slate-700 flex items-center gap-1">
                  <Paperclip className="w-4 h-4" />
                  Attachments
                  {attachments.length > 0 && (
                    <span className="ml-1 px-1.5 py-0.5 bg-slate-100 text-slate-500 text-xs rounded-full">
                      {attachments.length}
                    </span>
                  )}
                </label>
                <button
                  onClick={() => fileInputRef.current?.click()}
                  disabled={uploading}
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-indigo-50 text-indigo-600 text-sm font-medium rounded-lg hover:bg-indigo-100 transition-colors disabled:opacity-50"
                >
                  <Upload className="w-3.5 h-3.5" />
                  {uploading ? 'Uploading...' : 'Upload'}
                </button>
                <input
                  ref={fileInputRef}
                  type="file"
                  onChange={handleFileUpload}
                  className="hidden"
                />
              </div>
              {attachments.length > 0 ? (
                <div className="space-y-2">
                  {attachments.map((att) => (
                    <div
                      key={att._id || att.url}
                      className="flex items-center justify-between p-3 bg-slate-50 rounded-xl border border-slate-100"
                    >
                      <div className="flex items-center gap-2 min-w-0">
                        <Paperclip className="w-4 h-4 text-slate-400 flex-shrink-0" />
                        <span className="text-sm text-slate-700 truncate">{att.filename || att.name || 'File'}</span>
                      </div>
                      <div className="flex items-center gap-1">
                        <a
                          href={att.url}
                          download
                          target="_blank"
                          rel="noopener noreferrer"
                          className="p-1.5 hover:bg-slate-200 rounded-lg transition-colors"
                        >
                          <Download className="w-4 h-4 text-slate-500" />
                        </a>
                        <button
                          onClick={() => handleDeleteAttachment(att._id)}
                          className="p-1.5 hover:bg-red-50 rounded-lg transition-colors"
                        >
                          <Trash2 className="w-4 h-4 text-red-400" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-sm text-slate-400 text-center py-3">No attachments yet</p>
              )}
            </div>

            {/* Divider */}
            <hr className="border-slate-100" />

            {/* Embeds */}
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-2 flex items-center gap-1">
                <LinkIcon className="w-4 h-4" />
                Embeds & Links
              </label>
              <div className="flex gap-2 mb-3">
                <input
                  type="url"
                  value={newEmbed}
                  onChange={(e) => setNewEmbed(e.target.value)}
                  onKeyDown={(e) => e.key === 'Enter' && handleAddEmbed()}
                  placeholder="Paste a URL (YouTube, website, etc.)..."
                  className="flex-1 px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm text-slate-700 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all"
                />
                <button
                  onClick={handleAddEmbed}
                  className="px-3 py-2 bg-slate-100 hover:bg-slate-200 text-slate-600 text-sm font-medium rounded-lg transition-colors"
                >
                  Add
                </button>
              </div>
              {embeds.length > 0 && (
                <div className="space-y-3">
                  {embeds.map((embed, i) => (
                    <div key={i} className="rounded-xl border border-slate-100 overflow-hidden">
                      {isYouTube(embed.url || embed) ? (
                        <div className="aspect-video">
                          <ReactPlayer
                            url={embed.url || embed}
                            width="100%"
                            height="100%"
                            controls
                            light
                          />
                        </div>
                      ) : (
                        <div className="flex items-center justify-between p-3 bg-slate-50">
                          <a
                            href={embed.url || embed}
                            target="_blank"
                            rel="noopener noreferrer"
                            className="flex items-center gap-2 text-sm text-indigo-600 hover:text-indigo-700 truncate"
                          >
                            <ExternalLink className="w-4 h-4 flex-shrink-0" />
                            {embed.url || embed}
                          </a>
                        </div>
                      )}
                      <div className="flex justify-end p-1.5 bg-white border-t border-slate-50">
                        <button
                          onClick={() => handleRemoveEmbed(i)}
                          className="p-1 hover:bg-red-50 rounded-lg transition-colors"
                        >
                          <Trash2 className="w-3.5 h-3.5 text-red-400" />
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Divider */}
            <hr className="border-slate-100" />

            {/* Comments */}
            <div>
              <label className="block text-sm font-medium text-slate-700 mb-3 flex items-center gap-1">
                <MessageSquare className="w-4 h-4" />
                Comments
                {comments.length > 0 && (
                  <span className="ml-1 px-1.5 py-0.5 bg-slate-100 text-slate-500 text-xs rounded-full">
                    {comments.length}
                  </span>
                )}
              </label>

              {/* Comment list */}
              <div className="space-y-3 mb-4">
                {comments.length === 0 && (
                  <p className="text-sm text-slate-400 text-center py-3">No comments yet. Start the conversation!</p>
                )}
                {comments.map((comment, i) => (
                  <div key={comment._id || i} className="flex gap-3">
                    <div className="w-8 h-8 bg-indigo-100 rounded-lg flex items-center justify-center text-indigo-700 text-xs font-semibold flex-shrink-0">
                      {(comment.user?.name || comment.userName || 'U').charAt(0).toUpperCase()}
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-baseline gap-2">
                        <span className="text-sm font-semibold text-slate-700">
                          {comment.user?.name || comment.userName || 'User'}
                        </span>
                        <span className="text-xs text-slate-400">
                          {comment.createdAt
                            ? format(new Date(comment.createdAt), 'MMM d, h:mm a')
                            : 'Just now'}
                        </span>
                      </div>
                      <p className="text-sm text-slate-600 mt-0.5">{comment.text || comment.content}</p>
                    </div>
                  </div>
                ))}
              </div>

              {/* Add comment */}
              <div className="flex gap-2">
                <div className="w-8 h-8 bg-indigo-100 rounded-lg flex items-center justify-center text-indigo-700 text-xs font-semibold flex-shrink-0">
                  {user?.name?.charAt(0)?.toUpperCase() || 'U'}
                </div>
                <div className="flex-1 flex gap-2">
                  <input
                    type="text"
                    value={newComment}
                    onChange={(e) => setNewComment(e.target.value)}
                    onKeyDown={(e) => e.key === 'Enter' && handleAddComment()}
                    placeholder="Write a comment..."
                    className="flex-1 px-3 py-2 bg-slate-50 border border-slate-200 rounded-lg text-sm text-slate-700 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all"
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

            {/* Divider */}
            <hr className="border-slate-100" />

            {/* Delete */}
            <div className="flex justify-end">
              <button
                onClick={handleDelete}
                className="flex items-center gap-2 px-4 py-2 text-red-600 bg-red-50 hover:bg-red-100 text-sm font-medium rounded-xl transition-colors"
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
