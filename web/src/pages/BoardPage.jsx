import { useState, useEffect, useCallback } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { motion, AnimatePresence } from 'framer-motion';
import { DragDropContext, Droppable, Draggable } from 'react-beautiful-dnd';
import {
  Plus, Users, Settings, ArrowLeft, UserPlus, X, Loader2, Mail
} from 'lucide-react';
import api from '../api/axios';
import Navbar from '../components/Navbar';
import TaskCard from '../components/TaskCard';
import CreateTaskModal from '../components/CreateTaskModal';
import toast from 'react-hot-toast';

const columnConfig = {
  todo: { title: 'To Do', color: 'bg-slate-100 text-slate-700', accent: 'bg-slate-400', border: 'border-slate-200' },
  in_progress: { title: 'In Progress', color: 'bg-blue-100 text-blue-700', accent: 'bg-blue-500', border: 'border-blue-200' },
  review: { title: 'Review', color: 'bg-amber-100 text-amber-700', accent: 'bg-amber-500', border: 'border-amber-200' },
  done: { title: 'Done', color: 'bg-green-100 text-green-700', accent: 'bg-green-500', border: 'border-green-200' },
};

const columnOrder = ['todo', 'in_progress', 'review', 'done'];

export default function BoardPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [board, setBoard] = useState(null);
  const [tasks, setTasks] = useState([]);
  const [loading, setLoading] = useState(true);
  const [createModalOpen, setCreateModalOpen] = useState(false);
  const [createColumn, setCreateColumn] = useState('todo');
  const [memberModalOpen, setMemberModalOpen] = useState(false);
  const [memberEmail, setMemberEmail] = useState('');
  const [addingMember, setAddingMember] = useState(false);

  const fetchBoard = useCallback(async () => {
    try {
      const res = await api.get(`/api/boards/${id}`);
      const data = res.data.board || res.data;
      setBoard(data);
      setTasks(data.tasks || []);
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

  const getColumnTasks = (status) => {
    return tasks.filter((t) => t.status === status);
  };

  const handleDragEnd = async (result) => {
    const { source, destination, draggableId } = result;
    if (!destination) return;
    if (source.droppableId === destination.droppableId && source.index === destination.index) return;

    const taskId = draggableId;
    const newStatus = destination.droppableId;

    // Optimistic update
    setTasks((prev) => {
      const updated = prev.map((t) =>
        t._id === taskId ? { ...t, status: newStatus } : t
      );
      return updated;
    });

    try {
      await api.put(`/api/boards/${id}/tasks/${taskId}`, {
        status: newStatus,
        position: destination.index,
      });
    } catch (err) {
      toast.error('Failed to move task');
      fetchBoard(); // revert
    }
  };

  const handleTaskCreate = (newTask) => {
    setTasks((prev) => [...prev, newTask]);
  };

  const handleTaskUpdate = (updatedTask) => {
    if (updatedTask === null) {
      // Task was deleted
      fetchBoard();
      return;
    }
    setTasks((prev) =>
      prev.map((t) => (t._id === updatedTask._id ? updatedTask : t))
    );
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

  const openCreateModal = (col) => {
    setCreateColumn(col);
    setCreateModalOpen(true);
  };

  if (loading) {
    return (
      <div className="min-h-screen bg-slate-50">
        <Navbar />
        <div className="flex items-center justify-center py-32">
          <div className="flex flex-col items-center gap-4">
            <Loader2 className="w-10 h-10 text-indigo-500 animate-spin" />
            <p className="text-slate-500 font-medium">Loading board...</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen bg-slate-50 flex flex-col">
      <Navbar />

      {/* Board header */}
      <div className="bg-white border-b border-slate-100 px-4 sm:px-6 lg:px-8 py-4">
        <div className="max-w-full mx-auto flex items-center justify-between flex-wrap gap-4">
          <div className="flex items-center gap-4">
            <button
              onClick={() => navigate('/')}
              className="p-2 hover:bg-slate-100 rounded-xl transition-colors"
            >
              <ArrowLeft className="w-5 h-5 text-slate-500" />
            </button>
            <div>
              <div className="flex items-center gap-3">
                {board?.color && (
                  <div
                    className="w-4 h-4 rounded-md"
                    style={{ backgroundColor: board.color }}
                  />
                )}
                <h1 className="text-xl sm:text-2xl font-bold text-slate-800">{board?.name}</h1>
              </div>
              {board?.description && (
                <p className="text-sm text-slate-500 mt-0.5">{board.description}</p>
              )}
            </div>
          </div>

          <div className="flex items-center gap-3">
            {/* Member avatars */}
            <div className="flex -space-x-2">
              {(board?.members || []).slice(0, 5).map((member, i) => (
                <div
                  key={member._id || member.user?._id || i}
                  className="w-8 h-8 bg-gradient-to-br from-indigo-400 to-purple-500 rounded-full border-2 border-white flex items-center justify-center text-white text-xs font-semibold"
                  title={member.user?.name || member.name || 'Member'}
                >
                  {(member.user?.name || member.name || 'U').charAt(0).toUpperCase()}
                </div>
              ))}
              {(board?.members?.length || 0) > 5 && (
                <div className="w-8 h-8 bg-slate-200 rounded-full border-2 border-white flex items-center justify-center text-slate-600 text-xs font-semibold">
                  +{board.members.length - 5}
                </div>
              )}
            </div>

            <button
              onClick={() => setMemberModalOpen(true)}
              className="flex items-center gap-1.5 px-3 py-2 text-sm font-medium text-indigo-600 bg-indigo-50 hover:bg-indigo-100 rounded-xl transition-colors"
            >
              <UserPlus className="w-4 h-4" />
              <span className="hidden sm:inline">Add Member</span>
            </button>
          </div>
        </div>
      </div>

      {/* Kanban board */}
      <div className="flex-1 overflow-x-auto px-4 sm:px-6 lg:px-8 py-6">
        <DragDropContext onDragEnd={handleDragEnd}>
          <div className="flex gap-5 min-w-max pb-4">
            {columnOrder.map((colKey) => {
              const config = columnConfig[colKey];
              const colTasks = getColumnTasks(colKey);

              return (
                <div
                  key={colKey}
                  className="w-[320px] flex flex-col"
                >
                  {/* Column header */}
                  <div className="flex items-center justify-between mb-3 px-1">
                    <div className="flex items-center gap-2">
                      <div className={`w-2.5 h-2.5 rounded-full ${config.accent}`} />
                      <h3 className="font-semibold text-slate-700 text-sm">{config.title}</h3>
                      <span className={`px-2 py-0.5 text-xs font-medium rounded-full ${config.color}`}>
                        {colTasks.length}
                      </span>
                    </div>
                    <button
                      onClick={() => openCreateModal(colKey)}
                      className="p-1.5 hover:bg-slate-200 rounded-lg transition-colors"
                    >
                      <Plus className="w-4 h-4 text-slate-500" />
                    </button>
                  </div>

                  {/* Droppable column */}
                  <Droppable droppableId={colKey}>
                    {(provided, snapshot) => (
                      <div
                        ref={provided.innerRef}
                        {...provided.droppableProps}
                        className={`flex-1 kanban-column rounded-xl p-2 space-y-3 transition-colors scrollbar-thin overflow-y-auto ${
                          snapshot.isDraggingOver
                            ? 'bg-indigo-50/50 border-2 border-dashed border-indigo-300'
                            : 'bg-slate-100/50 border-2 border-transparent'
                        }`}
                      >
                        {colTasks.map((task, index) => (
                          <Draggable
                            key={task._id}
                            draggableId={task._id}
                            index={index}
                          >
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
                                />
                              </div>
                            )}
                          </Draggable>
                        ))}
                        {provided.placeholder}

                        {/* Empty state */}
                        {colTasks.length === 0 && !snapshot.isDraggingOver && (
                          <div className="text-center py-8 px-4">
                            <p className="text-sm text-slate-400">No tasks yet</p>
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
          </div>
        </DragDropContext>
      </div>

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
              className="w-full max-w-sm bg-white rounded-2xl shadow-2xl overflow-hidden"
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
                  <label className="block text-sm font-medium text-slate-700 mb-1.5">Email Address</label>
                  <div className="relative">
                    <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-5 h-5 text-slate-400" />
                    <input
                      type="email"
                      value={memberEmail}
                      onChange={(e) => setMemberEmail(e.target.value)}
                      placeholder="colleague@example.com"
                      autoFocus
                      className="w-full pl-11 pr-4 py-3 bg-slate-50 border border-slate-200 rounded-xl text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500 transition-all"
                    />
                  </div>
                </div>
                <div className="flex gap-3">
                  <button
                    type="button"
                    onClick={() => setMemberModalOpen(false)}
                    className="flex-1 py-3 bg-slate-100 text-slate-600 font-medium rounded-xl hover:bg-slate-200 transition-colors"
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
