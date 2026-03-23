import { useState, useEffect } from 'react';
import { motion } from 'framer-motion';
import { Shield, Users, LayoutGrid, CheckSquare, Activity, Trash2, Loader2 } from 'lucide-react';
import { format } from 'date-fns';
import api from '../api/axios';
import Navbar from '../components/Navbar';
import { useAuth } from '../context/AuthContext';
import toast from 'react-hot-toast';
import { useNavigate } from 'react-router-dom';

export default function AdminPage() {
  const { user } = useAuth();
  const navigate = useNavigate();
  const [users, setUsers] = useState([]);
  const [stats, setStats] = useState({ totalUsers: 0, totalBoards: 0, totalTasks: 0, activeToday: 0 });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (user && user.role !== 'admin') {
      toast.error('Access denied');
      navigate('/');
      return;
    }
    fetchData();
  }, [user]);

  const fetchData = async () => {
    try {
      const [usersRes, statsRes] = await Promise.allSettled([
        api.get('/api/admin/users'),
        api.get('/api/admin/stats'),
      ]);
      if (usersRes.status === 'fulfilled') {
        setUsers(usersRes.value.data.users || usersRes.value.data || []);
      }
      if (statsRes.status === 'fulfilled') {
        setStats(statsRes.value.data.stats || statsRes.value.data || stats);
      }
    } catch {
      toast.error('Failed to load admin data');
    } finally {
      setLoading(false);
    }
  };

  const handleRoleChange = async (userId, newRole) => {
    try {
      await api.put(`/api/admin/users/${userId}/role`, { role: newRole });
      setUsers((prev) => prev.map((u) => (u._id === userId ? { ...u, role: newRole } : u)));
      toast.success('Role updated');
    } catch (err) {
      toast.error(err.response?.data?.message || 'Failed to update role');
    }
  };

  const handleDeleteUser = async (userId) => {
    if (!window.confirm('Are you sure you want to delete this user? This action cannot be undone.')) return;
    try {
      await api.delete(`/api/admin/users/${userId}`);
      setUsers((prev) => prev.filter((u) => u._id !== userId));
      toast.success('User deleted');
    } catch (err) {
      toast.error(err.response?.data?.message || 'Failed to delete user');
    }
  };

  const statCards = [
    { label: 'Total Users', value: stats.totalUsers || users.length, icon: Users, gradient: 'from-blue-500 to-cyan-500' },
    { label: 'Total Boards', value: stats.totalBoards, icon: LayoutGrid, gradient: 'from-indigo-500 to-purple-500' },
    { label: 'Total Tasks', value: stats.totalTasks, icon: CheckSquare, gradient: 'from-green-500 to-emerald-500' },
    { label: 'Active Today', value: stats.activeToday, icon: Activity, gradient: 'from-amber-500 to-orange-500' },
  ];

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-gray-900">
      <Navbar />
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        <div className="mb-8">
          <div className="flex items-center gap-3 mb-1">
            <Shield className="w-7 h-7 text-indigo-600 dark:text-indigo-400" />
            <h1 className="text-2xl sm:text-3xl font-bold text-slate-800 dark:text-white">Admin Panel</h1>
          </div>
          <p className="text-slate-500 dark:text-gray-400 ml-10">Manage users and system settings</p>
        </div>

        {loading ? (
          <div className="flex items-center justify-center py-32">
            <Loader2 className="w-10 h-10 text-indigo-500 animate-spin" />
          </div>
        ) : (
          <>
            {/* Stats */}
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
              {statCards.map((stat) => (
                <motion.div
                  key={stat.label}
                  initial={{ opacity: 0, y: 20 }}
                  animate={{ opacity: 1, y: 0 }}
                  className="bg-white dark:bg-gray-800 rounded-2xl shadow-sm border border-slate-100 dark:border-gray-700 p-5 relative overflow-hidden"
                >
                  <div className={`absolute -top-4 -right-4 w-20 h-20 rounded-full blur-2xl opacity-20 bg-gradient-to-br ${stat.gradient}`} />
                  <stat.icon className="w-6 h-6 text-slate-400 dark:text-gray-500 mb-2" />
                  <p className="text-2xl font-bold text-slate-800 dark:text-white">{stat.value}</p>
                  <p className="text-sm text-slate-500 dark:text-gray-400">{stat.label}</p>
                </motion.div>
              ))}
            </div>

            {/* Users table */}
            <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-sm border border-slate-100 dark:border-gray-700 overflow-hidden">
              <div className="px-6 py-4 border-b border-slate-100 dark:border-gray-700">
                <h2 className="text-lg font-semibold text-slate-800 dark:text-white">User Management</h2>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-slate-100 dark:border-gray-700">
                      <th className="text-left px-6 py-3 text-xs font-semibold text-slate-500 dark:text-gray-400 uppercase tracking-wider">Name</th>
                      <th className="text-left px-6 py-3 text-xs font-semibold text-slate-500 dark:text-gray-400 uppercase tracking-wider">Email</th>
                      <th className="text-left px-6 py-3 text-xs font-semibold text-slate-500 dark:text-gray-400 uppercase tracking-wider">Role</th>
                      <th className="text-left px-6 py-3 text-xs font-semibold text-slate-500 dark:text-gray-400 uppercase tracking-wider">Created</th>
                      <th className="text-right px-6 py-3 text-xs font-semibold text-slate-500 dark:text-gray-400 uppercase tracking-wider">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {users.map((u) => (
                      <tr key={u._id} className="border-b border-slate-50 dark:border-gray-700/50 hover:bg-slate-50 dark:hover:bg-gray-700/30 transition-colors">
                        <td className="px-6 py-4">
                          <div className="flex items-center gap-3">
                            <div className="w-8 h-8 bg-gradient-to-br from-indigo-400 to-purple-500 rounded-lg flex items-center justify-center text-white text-sm font-semibold">
                              {(u.name || 'U').charAt(0).toUpperCase()}
                            </div>
                            <span className="text-sm font-medium text-slate-800 dark:text-gray-200">{u.name}</span>
                          </div>
                        </td>
                        <td className="px-6 py-4 text-sm text-slate-500 dark:text-gray-400">{u.email}</td>
                        <td className="px-6 py-4">
                          <select
                            value={u.role || 'user'}
                            onChange={(e) => handleRoleChange(u._id, e.target.value)}
                            disabled={u._id === user?._id}
                            className="px-2.5 py-1 bg-slate-50 dark:bg-gray-700 border border-slate-200 dark:border-gray-600 rounded-lg text-sm text-slate-700 dark:text-gray-300 focus:outline-none focus:ring-1 focus:ring-indigo-500 disabled:opacity-50"
                          >
                            <option value="user">User</option>
                            <option value="admin">Admin</option>
                          </select>
                        </td>
                        <td className="px-6 py-4 text-sm text-slate-500 dark:text-gray-400">
                          {u.createdAt ? format(new Date(u.createdAt), 'MMM d, yyyy') : '-'}
                        </td>
                        <td className="px-6 py-4 text-right">
                          <button
                            onClick={() => handleDeleteUser(u._id)}
                            disabled={u._id === user?._id}
                            className="p-2 text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20 rounded-lg transition-colors disabled:opacity-30 disabled:cursor-not-allowed"
                          >
                            <Trash2 className="w-4 h-4" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              {users.length === 0 && (
                <div className="text-center py-12">
                  <Users className="w-8 h-8 text-slate-300 dark:text-gray-600 mx-auto mb-2" />
                  <p className="text-sm text-slate-400 dark:text-gray-500">No users found</p>
                </div>
              )}
            </div>
          </>
        )}
      </main>
    </div>
  );
}
