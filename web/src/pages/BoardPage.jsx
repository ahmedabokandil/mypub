import { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { DragDropContext, Droppable, Draggable } from '@hello-pangea/dnd';
import {
  Plus, Users, ArrowLeft, UserPlus, X, Loader2, Mail,
  MessageCircle, Activity, Trash2
} from 'lucide-react';
import api from '../api/axios';
import { useSocket } from '../context/SocketContext';
import Navbar from '../components/Navbar';
import TaskCard from '../components/TaskCard';
import CreateTaskModal from '../components/CreateTaskModal';
import ChatPanel from '../components/ChatPanel';
import ActivityLog from '../components/ActivityLog';
import ExportMenu from '../components/ExportMenu';
import toast from 'react-hot-toast';

const defaultColumnConfig = {
  todo: { title: 'To Do', color: 'bg-slate-100 text-slate-700 dark:bg-slate-800 dark:text-slate-300', accent: 'bg-slate-400', border: 'border-slate-200' },
  in_progress: { title: 'In Progress', color: 'bg-blue-100 text-blue-700 dark:bg-blue-900/30 dark:text-blue-300', accent: 'bg-blue-500', border: 'border-blue-200' },
  review: { title: 'Review', color: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300', accent: 'bg-amber-500', border: 'border-amber-200' },
  done: { title: 'Done', color: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300', accent: 'bg-green-500', border: 'border-green-200' },
};

const defaultColumnOrder = ['todo', 'in_progress', 'review', 'done'];

const dynamicAccentColors = ['bg-purple-500', 'bg-cyan-500', 'bg-pink-500', 'bg-orange-500', 'bg-teal-500', 'bg-lime-500'];

export default function BoardPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const { socket, joinBoard, leaveBoard } = useSocket();
  const [board, setBoard] = useState(null);
  const [tasks, setTasks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [createModalOpen, setCreateModalOpen] = useState(false);
  const [createColumn, setCreateColumn] = useState('todo');
  const [memberModalOpen, setMemberModalOpen] = useState(false);
  const [memberEmail, setMemberEmail] = useState('');
  const [addingMember, setAddingMember] = useState(false);
  const [chatOpen, setChatOpen] = useState(false);
  const [activityOpen, setActivityOpen] = useState(false);
  const [columnOrder, setColumnOrder] = useState(defaultColumnOrder);
  const [columnConfig, setColumnConfig] = useState(defaultColumnConfig);
  const [newColumnName, setNewColumnName] = useState('');
  const [addColumnOpen, setAddColumnOpen] = useState(false);

  const fetchBoard = useCallback(async () => {
    try {
      const res = await api.get(`/api/boards/${id}`);
      const data = res.data.board || res.data;
      setBoard(data);
      setTasks(data.tasks || []);
      // Use custom columns from board if available
      if (data.columns && data.columns.length > 0) {
        setColumnOrder(data.columns);
        const newConfig = { ...defaultColumnConfig };
        data.columns.forEach((col, i) => {
          if (!newConfig[col]) {
            newConfig[col] = {
              title: col.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()),
              color: 'bg-slate-100 text-slate-700 dark:bg-gray-800 dark:text-gray-300',
              accent: dynamicAccentColors[i % dynamicAccentColors.length],
              border: 'border-slate-200',
            };
          }
        });
        setColumnConfig(newConfig);
      }
    } catch (err) {
      toast.error('Failed to load board');
      navigate('/');
    } finally {
      setLoading(false);
    }
  }, [id, navigate]);

  useEffect(() => {
    fetchBoard();
  }, [fetchBoard]);

  // Socket.IO real-time
  useEffect(() => {
    if (!socket || !id) return;
    joinBoard(id);

    const handleTaskMoved = (data) => {
      if (data.boardId === id) {
        setTasks((prev) => prev.map((t) => (t._id === data.taskId ? { ...t, status: data.newStatus } : t)));
      }
    };
    const handleTaskCreated = (data) => {
      if (data.boardId === id) {
        setTasks((prev) => [...prev, data.task]);
      }
    };
    const handleTaskUpdated = (data) => {
      if (data.boardId === id) {
        setTasks((prev) => prev.map((t) => (t._id === data.task._id ? data.task : t)));
      }
    };
    const handleTaskDeleted = (data) => {
      if (data.boardId === id) {
        setTasks((prev) => prev.filter((t) => t._id !== data.taskId));
      }
    };

    socket.on('task-moved', handleTaskMoved);
    socket.on('task-created', handleTaskCreated);
    socket.on('task-updated', handleTaskUpdated);
    socket.on('task-deleted', handleTaskDeleted);

    return () => {
      leaveBoard(id);
      socket.off('task-moved', handleTaskMoved);
      socket.off('task-created', handleTaskCreated);
      socket.off('task-updated', handleTaskUpdated);
      socket.off('task-deleted', handleTaskDeleted);
    };
  }, [socket, id, joinBoard, leaveBoard]);

  const getColumnTasks = (status) => {
    return tasks.filter((t) => t.status === status && !t.archived);
  };

  const handleDragEnd = async (result) => {
    const { source, destination, draggableId } = result;
    if (!destination) return;
    if (source.droppableId === destination.droppableId && source.index === destination.index) return;

    const taskId = draggableId;
    const newStatus = destination.droppableId;

    setTasks((prev) => prev.map((t) => (t._id === taskId ? { ...t, status: newStatus } : t)));

    try {
      await api.put(`/api/boards/${id}/tasks/${taskId}`, {
        status: newStatus,
        position: destination.index,
      });
      if (socket) {
        socket.emit('task-moved', { boardId: id, taskId, newStatus, position: destination.index });
      }
    } catch (err) {
      toast.error('Failed to move task');
      fetchBoard();
    }
  };

  const handleTaskCreate = (newTask) => {
    setTasks((prev) => [...prev, newTask]);
    if (socket) {
      socket.emit('task-created', { boardId: id, task: newTask });
    }
  };

  const handleTaskUpdate = (updatedTask) => {
    if (updatedTask === null) {
      fetchBoard();
      return;
    }
    setTasks((prev) => prev.map((t) => (t._id === updatedTask._id ? updatedTask : t)));
    if (socket) {
      socket.emit('task-updated', { boardId: id, task: updatedTask });
    }
  };

  const handleArchiveTask = async (taskId) => {
    try {
      await api.put(`/api/boards/${id}/tasks/${taskId}`, { archived: true });
      setTasks((prev) => prev.map((t) => (t._id === taskId ? { ...t, archived: true } : t)));
      toast.success('Task archived');
    } catch {
      toast.error('Failed to archive task');
    }
  };

  const handleAddMember = async (e) => {
    e.preventDefault();
    if (!memberEmail.trim()) return;
    setAddingMember(true);
    try {
      await api.post(`/api/boards/${id}/members`, { email: memberEmail });
      toast.success('Member added!');
      setMemberEmail('');
      setMemberModalOpen(false);
      fetchBoard();
    } catch (err) {
      toast.error(err.response?.data?.message || 'Failed to add member');
    } finally {
      setAddingMember(false);
    }
  };

  const handleAddColumn = async () => {
    if (!newColumnName.trim()) return;
    const colKey = newColumnName.trim().toLowerCase().replace(/\s+/g, '_');
    if (columnOrder.includes(colKey)) {
      toast.error('Column already exists');
      return;
    }
    const newOrder = [...columnOrder, colKey];
    setColumnOrder(newOrder);
    setColumnConfig((prev) => ({
      ...prev,
      [colKey]: {
        title: newColumnName.trim(),
        color: 'bg-slate-100 text-slate-700 dark:bg-gray-800 dark:text-gray-300',
        accent: dynamicAccentColors[newOrder.length % dynamicAccentColors.length],
        border: 'border-slate-200',
      },
    }));
    setNewColumnName('');
    setAddColumnOpen(false);
    try {
      await api.put(`/api/boards/${id}`, { columns: newOrder });
      toast.success('Column added');
    } catch {}
  };

  const handleDeleteColumn = async (colKey) => {
    const colTasks = getColumnTasks(colKey);
    if (colTasks.length > 0) {
      toast.error('Move or delete tasks in this column first');
      return;
    }
    const newOrder = columnOrder.filter((c) => c !== colKey);
    setColumnOrder(newOrder);
    try {
      await api.put(`/api/boards/${id}`, { columns: newOrder });
      toast.success('Column removed');
    } catch {}
  };

  const openCreateModal = (col) => {
    setCreateColumn(col);
    setCreateModalOpen(true);
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-50 dark:bg-gray-900">
        <Navbar />
        <div className="flex items-center justify-center py-32">
          <div className="flex flex-col items-center gap-4">
            <Loader2 className="w-10 h-10 text-indigo-500 animate-spin" />
            <p className="text-slate-500 dark:text-gray-400 font-medium">Loading board...</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-gray-900 flex flex-col">
      <Navbar />

      {/* Board header */}
      <div className="bg-white dark:bg-gray-800 border-b border-slate-100 dark:border-gray-700 px-4 sm:px-6 lg:px-8 py-4">
        <div className="max-w-full mx-auto flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-center gap-4">
            <button
              onClick={() => navigate('/')}
              className="p-2 hover:bg-slate-100 dark:hover:bg-gray-700 rounded-xl transition-colors"
            >
              <ArrowLeft className="w-5 h-5 text-slate-500 dark:text-gray-400" />
            </button>
            <div>
              <div className="flex items-center gap-3">
                {board?.color && (
                  <div className="w-4 h-4 rounded-md" style={{ backgroundColor: board.color }} />
                )}
                <h1 className="text-xl sm:text-2xl font-bold text-slate-800 dark:text-white">{board?.name}</h1>
              </div>
              {board?.description && (
                <p className="text-sm text-slate-500 dark:text-gray-400 mt-0.5">{board.description}</p>
              )}
            </div>
          </div>

          <div className="flex items-center gap-2 sm:gap-3 flex-wrap">
            {/* Member avatars */}
            <div className="flex -space-x-2">
              {(board?.members || []).slice(0, 5).map((member, i) => (
                <div
                  key={member._id || member.user?._id || i}
                  className="w-8 h-8 bg-gradient-to-br from-indigo-400 to-purple-500 rounded-full border-2 border-white dark:border-gray-800 flex items-center justify-center text-white text-xs font-semibold"
                  title={member.user?.name || member.name || 'Member'}
                >
                  {(member.user?.name || member.name || 'U').charAt(0).toUpperCase()}
                </div>
              ))}
              {(board?.members?.length || 0) > 5 && (
                <div className="w-8 h-8 bg-slate-200 dark:bg-gray-600 rounded-full border-2 border-white dark:border-gray-800 flex items-center justify-center text-slate-600 dark:text-gray-300 text-xs font-semibold">
                  +{board.members.length - 5}
                </div>
              )}
            </div>

            <button
              onClick={() => setMemberModalOpen(true)}
              className="flex items-center gap-1.5 px-3 py-2 text-sm font-medium text-indigo-600 dark:text-indigo-400 bg-indigo-50 dark:bg-indigo-900/20 hover:bg-indigo-100 dark:hover:bg-indigo-900/30 rounded-xl transition-colors"
            >
              <UserPlus className="w-4 h-4" />
              <span className="hidden sm:inline">Add Member</span>
            </button>

            {/* Chat button */}
            <button
              onClick={() => { setChatOpen(!chatOpen); setActivityOpen(false); }}
              className={`flex items-center gap-1.5 px-3 py-2 text-sm font-medium rounded-xl transition-colors ${
                chatOpen
                  ? 'bg-indigo-600 text-white'
                  : 'text-slate-600 dark:text-gray-300 bg-white dark:bg-gray-700 border border-slate-200 dark:border-gray-600 hover:bg-slate-50 dark:hover:bg-gray-600'
              }`}
            >
              <MessageCircle className="w-4 h-4" />
              <span className="hidden sm:inline">Chat</span>
            </button>

            {/* Activity button */}
            <button
              onClick={() => { setActivityOpen(!activityOpen); setChatOpen(false); }}
              className={`flex items-center gap-1.5 px-3 py-2 text-sm font-medium rounded-xl transition-colors ${
                activityOpen
                  ? 'bg-indigo-600 text-white'
                  : 'text-slate-600 dark:text-gray-300 bg-white dark:bg-gray-700 border border-slate-200 dark:border-gray-600 hover:bg-slate-50 dark:hover:bg-gray-600'
              }`}
            >
              <Activity className="w-4 h-4" />
              <span className="hidden sm:inline">Activity</span>
            </button>

            {/* Export */}
            <ExportMenu boardId={id} />
          </div>
        </div>
      </div>

      {/* Main area */}
      <div className="flex-1 flex overflow-hidden">
        {/* Kanban board */}
        <div className="flex-1 overflow-x-auto px-4 sm:px-6 lg:px-8 py-6">
          <DragDropContext onDragEnd={handleDragEnd}>
            <div className="flex gap-5 min-w-max pb-4">
              {columnOrder.map((colKey) => {
                const config = columnConfig[colKey] || {
                  title: colKey.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase()),
                  color: 'bg-slate-100 text-slate-700',
                  accent: 'bg-slate-400',
                };
                const colTasks = getColumnTasks(colKey);

                return (
                  <div key={colKey} className="w-[320px] flex flex-col">
                    {/* Column header */}
                    <div className="flex items-center justify-between mb-3 px-1">
                      <div className="flex items-center gap-2">
                        <div className={`w-2.5 h-2.5 rounded-full ${config.accent}`} />
                        <h3 className="font-semibold text-slate-700 dark:text-gray-300 text-sm">{config.title}</h3>
                        <span className={`px-2 py-0.5 text-xs font-medium rounded-full ${config.color}`}>
                          {colTasks.length}
                        </span>
                      </div>
                      <div className="flex items-center gap-1">
                        <button
                          onClick={() => openCreateModal(colKey)}
                          className="p-1.5 hover:bg-slate-200 dark:hover:bg-gray-600 rounded-lg transition-colors"
                        >
                          <Plus className="w-4 h-4 text-slate-500 dark:text-gray-400" />
                        </button>
                        {!defaultColumnOrder.includes(colKey) && (
                          <button
                            onClick={() => handleDeleteColumn(colKey)}
                            className="p-1.5 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-colors"
                          >
                            <Trash2 className="w-3.5 h-3.5 text-red-400" />
                          </button>
                        )}
                      </div>
                    </div>

                    {/* Droppable column */}
                    <Droppable droppableId={colKey}>
                      {(provided, snapshot) => (
                        <div
                          ref={provided.innerRef}
                          {...provided.droppableProps}
                          className={`flex-1 kanban-column rounded-xl p-2 space-y-3 transition-colors scrollbar-thin overflow-y-auto ${
                            snapshot.isDraggingOver
                              ? 'bg-indigo-50/50 dark:bg-indigo-900/20 border-2 border-dashed border-indigo-300 dark:border-indigo-600'
                              : 'bg-slate-100/50 dark:bg-gray-800/50 border-2 border-transparent'
                          }`}
                        >
                          {colTasks.map((task, index) => (
                            <Draggable key={task._id} draggableId={task._id} index={index}>
                              {(provided, snapshot) => (
                                <div
                                  ref={provided.innerRef}
                                  {...provided.draggableProps}
                                  {...provided.dragHandleProps}
                                  style={provided.draggableProps.style}
                                >
                                  <TaskCard
                                    task={task}
                                    boardId={id}
                                    columns={columnOrder}
                                    onUpdate={handleTaskUpdate}
                                    allTasks={tasks}
                                  />
                                </div>
                              )}
                            </Draggable>
                          ))}
                          {provided.placeholder}

                          {colTasks.length === 0 && !snapshot.isDraggingOver && (
                            <div className="text-center py-8 px-4">
                              <p className="text-sm text-slate-400 dark:text-gray-500">No tasks yet</p>
                              <button
                                onClick={() => openCreateModal(colKey)}
                                className="mt-2 text-sm text-indigo-500 hover:text-indigo-600 font-medium transition-colors"
                              >
                                + Add a task
                              </button>
                            </div>
                          )}
                        </div>
                      )}
                    </Droppable>
                  </div>
                );
              })}

              {/* Add column */}
              <div className="w-[280px] flex-shrink-0">
                {addColumnOpen ? (
                  <div className="bg-white dark:bg-gray-800 rounded-xl p-3 border border-slate-200 dark:border-gray-700 shadow-sm">
                    <input
                      type="text"
                      value={newColumnName}
                      onChange={(e) => setNewColumnName(e.target.value)}
                      onKeyDown={(e) => e.key === 'Enter' && handleAddColumn()}
                      placeholder="Column name..."
                      autoFocus
                      className="w-full px-3 py-2 bg-slate-50 dark:bg-gray-700 border border-slate-200 dark:border-gray-600 rounded-lg text-sm text-slate-700 dark:text-gray-300 placeholder-slate-400 focus:outline-none focus:ring-1 focus:ring-indigo-500 mb-2"
                    />
                    <div className="flex gap-2">
                      <button
                        onClick={handleAddColumn}
                        className="flex-1 py-2 bg-indigo-600 text-white text-sm font-medium rounded-lg hover:bg-indigo-700"
                      >
                        Add
                      </button>
                      <button
                        onClick={() => { setAddColumnOpen(false); setNewColumnName(''); }}
                        className="flex-1 py-2 bg-slate-100 dark:bg-gray-700 text-slate-600 dark:text-gray-300 text-sm font-medium rounded-lg"
                      >
                        Cancel
                      </button>
                    </div>
                  </div>
                ) : (
                  <button
                    onClick={() => setAddColumnOpen(true)}
                    className="w-full py-3 border-2 border-dashed border-slate-200 dark:border-gray-600 rounded-xl text-sm font-medium text-slate-400 dark:text-gray-500 hover:border-indigo-300 dark:hover:border-indigo-600 hover:text-indigo-500 transition-colors"
                  >
                    + Add Column
                  </button>
                )}
              </div>
            </div>
          </DragDropContext>
        </div>

        {/* Activity sidebar */}
        <AnimatePresence>
          {activityOpen && (
            <motion.div
              initial={{ width: 0, opacity: 0 }}
              animate={{ width: 350, opacity: 1 }}
              exit={{ width: 0, opacity: 0 }}
              className="bg-white dark:bg-gray-800 border-l border-slate-200 dark:border-gray-700 overflow-hidden flex flex-col"
            >
              <div className="p-4 border-b border-slate-100 dark:border-gray-700 flex items-center justify-between">
                <h3 className="font-semibold text-slate-800 dark:text-white flex items-center gap-2">
                  <Activity className="w-4 h-4" />
                  Activity
                </h3>
                <button onClick={() => setActivityOpen(false)} className="p-1 hover:bg-slate-100 dark:hover:bg-gray-700 rounded-lg">
                  <X className="w-4 h-4 text-slate-400" />
                </button>
              </div>
              <div className="flex-1 overflow-y-auto p-4">
                <ActivityLog boardId={id} />
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      {/* Chat panel */}
      <AnimatePresence>
        {chatOpen && (
          <ChatPanel boardId={id} isOpen={chatOpen} onClose={() => setChatOpen(false)} />
        )}
      </AnimatePresence>

      {/* Create task modal */}
      {createModalOpen && (
        <CreateTaskModal
          boardId={id}
          column={createColumn}
          columns={columnOrder}
          onClose={() => setCreateModalOpen(false)}
          onCreate={handleTaskCreate}
        />
      )}

      {/* Add member modal */}
      <AnimatePresence>
        {memberModalOpen && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="fixed inset-0 bg-black/50 backdrop-blur-sm z-50 flex items-center justify-center p-4"
            onClick={() => setMemberModalOpen(false)}
          >
            <motion.div
              initial={{ opacity: 0, y: 20, scale: 0.95 }}
              animate={{ opacity: 1, y: 0, scale: 1 }}
              exit={{ opacity: 0, y: 20, scale: 0.95 }}
              transition={{ type: 'spring', damping: 25, stiffness: 300 }}
              onClick={(e) => e.stopPropagation()}
              className="w-full max-w-sm bg-white dark:bg-gray-800 rounded-2xl shadow-2xl overflow-hidden"
            >
              <div className="bg-gradient-to-r from-indigo-600 to-purple-600 px-6 py-4 flex items-center justify-between">
                <h2 className="text-lg font-bold text-white">Add Member</h2>
                <button
                  onClick={() => setMemberModalOpen(false)}
                  className="p-1.5 hover:bg-white/20 rounded-lg transition-colors"
                >
                  <X className="w-5 h-5 text-white" />
                </button>
              </div>
              <form onSubmit={handleAddMember} className="p-6 space-y-4">
                <div>
                  <label className="block text-sm font-medium text-slate-700 dark:text-gray-300 mb-1.5">Email Address</label>
                  <div className="relative">
                    <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-400" />
                    <input
                      type="email"
                      value={memberEmail}
                      onChange={(e) => setMemberEmail(e.target.value)}
                      placeholder="colleague@example.com"
                      autoFocus
                      className="w-full pl-11 pr-4 py-3 bg-slate-50 dark:bg-gray-700 border border-slate-200 dark:border-gray-600 rounded-xl text-slate-800 dark:text-gray-200 placeholder-slate-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all"
                    />
                  </div>
                </div>
                <div className="flex gap-3">
                  <button
                    type="button"
                    onClick={() => setMemberModalOpen(false)}
                    className="flex-1 py-3 bg-slate-100 dark:bg-gray-700 text-slate-600 dark:text-gray-300 font-medium rounded-xl hover:bg-slate-200 dark:hover:bg-gray-600 transition-colors"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={addingMember || !memberEmail.trim()}
                    className="flex-1 py-3 bg-gradient-to-r from-indigo-600 to-purple-600 text-white font-semibold rounded-xl hover:shadow-lg hover:shadow-indigo-500/25 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                  >
                    {addingMember ? (
                      <span className="flex items-center justify-center gap-2">
                        <div className="w-4 h-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                        Adding...
                      </span>
                    ) : (
                      'Add Member'
                    )}
                  </button>
                </div>
              </form>
            </motion.div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
