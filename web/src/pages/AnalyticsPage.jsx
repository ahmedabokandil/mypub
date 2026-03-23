import { useState, useEffect } from 'react';
import { Loader2, BarChart3, CheckCircle, Clock, AlertTriangle } from 'lucide-react';
import { Chart as ChartJS, ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement, PointElement, LineElement, Filler } from 'chart.js';
import { Doughnut, Bar, Line } from 'react-chartjs-2';
import { format, subDays, differenceInHours, isAfter } from 'date-fns';
import api from '../api/axios';
import Navbar from '../components/Navbar';
import toast from 'react-hot-toast';

ChartJS.register(ArcElement, Tooltip, Legend, CategoryScale, LinearScale, BarElement, PointElement, LineElement, Filler);

export default function AnalyticsPage() {
  const [boards, setBoards] = useState([]);
  const [selectedBoardId, setSelectedBoardId] = useState('all');
  const [tasks, setTasks] = useState([]);
  const [loading, setLoading] = useState(true);

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
            allTasks.push(...(bData.tasks || []));
          } catch {}
        }
        setTasks(allTasks);
      } else {
        const res = await api.get(`/api/boards/${selectedBoardId}`);
        const data = res.data.board || res.data;
        setTasks(data.tasks || []);
      }
    } catch {
      toast.error('Failed to load tasks');
    } finally {
      setLoading(false);
    }
  };

  // Stats
  const totalTasks = tasks.length;
  const completedTasks = tasks.filter((t) => t.status === 'done').length;
  const overdueTasks = tasks.filter((t) => t.dueDate && isAfter(new Date(), new Date(t.dueDate)) && t.status !== 'done').length;
  const doneTasks = tasks.filter((t) => t.status === 'done' && t.completedAt && t.createdAt);
  const avgCompletionTime = doneTasks.length > 0
    ? Math.round(doneTasks.reduce((sum, t) => sum + differenceInHours(new Date(t.completedAt || t.updatedAt), new Date(t.createdAt)), 0) / doneTasks.length)
    : 0;

  // Status chart
  const statusCounts = {};
  tasks.forEach((t) => {
    const s = t.status || 'todo';
    statusCounts[s] = (statusCounts[s] || 0) + 1;
  });
  const statusLabels = Object.keys(statusCounts).map((s) => s.replace('_', ' ').replace(/\b\w/g, (c) => c.toUpperCase()));
  const statusData = {
    labels: statusLabels,
    datasets: [{
      data: Object.values(statusCounts),
      backgroundColor: ['#94a3b8', '#3b82f6', '#f59e0b', '#10b981', '#8b5cf6', '#ec4899'],
      borderWidth: 0,
    }],
  };

  // Priority chart
  const priorityCounts = { low: 0, medium: 0, high: 0, urgent: 0 };
  tasks.forEach((t) => { priorityCounts[t.priority || 'medium']++; });
  const priorityData = {
    labels: ['Low', 'Medium', 'High', 'Urgent'],
    datasets: [{
      label: 'Tasks',
      data: [priorityCounts.low, priorityCounts.medium, priorityCounts.high, priorityCounts.urgent],
      backgroundColor: ['#10b981', '#f59e0b', '#ef4444', '#dc2626'],
      borderRadius: 8,
      borderSkipped: false,
    }],
  };

  // Completion chart (last 30 days)
  const last30Days = Array.from({ length: 30 }, (_, i) => subDays(new Date(), 29 - i));
  const completionData = {
    labels: last30Days.map((d) => format(d, 'MMM d')),
    datasets: [{
      label: 'Completed',
      data: last30Days.map((day) =>
        tasks.filter((t) => t.status === 'done' && t.completedAt && format(new Date(t.completedAt), 'yyyy-MM-dd') === format(day, 'yyyy-MM-dd')).length
          || tasks.filter((t) => t.status === 'done' && t.updatedAt && format(new Date(t.updatedAt), 'yyyy-MM-dd') === format(day, 'yyyy-MM-dd')).length
      ),
      fill: true,
      borderColor: '#6366f1',
      backgroundColor: 'rgba(99, 102, 241, 0.1)',
      tension: 0.4,
      pointRadius: 2,
      pointHoverRadius: 5,
    }],
  };

  // Burndown chart
  const totalForBurndown = tasks.length;
  let remaining = totalForBurndown;
  const burndownData = {
    labels: last30Days.map((d) => format(d, 'MMM d')),
    datasets: [
      {
        label: 'Ideal',
        data: last30Days.map((_, i) => Math.round(totalForBurndown - (totalForBurndown / 29) * i)),
        borderColor: '#94a3b8',
        borderDash: [5, 5],
        pointRadius: 0,
        tension: 0,
      },
      {
        label: 'Actual',
        data: last30Days.map((day) => {
          const completedOnDay = tasks.filter((t) => t.status === 'done' && (t.completedAt || t.updatedAt) && format(new Date(t.completedAt || t.updatedAt), 'yyyy-MM-dd') === format(day, 'yyyy-MM-dd')).length;
          remaining -= completedOnDay;
          return remaining;
        }),
        borderColor: '#6366f1',
        backgroundColor: 'rgba(99, 102, 241, 0.1)',
        fill: true,
        tension: 0.4,
        pointRadius: 2,
      },
    ],
  };

  const chartOptions = {
    responsive: true,
    maintainAspectRatio: false,
    plugins: { legend: { display: false } },
  };

  const lineOptions = {
    ...chartOptions,
    scales: {
      x: { grid: { display: false }, ticks: { maxTicksLimit: 8, font: { size: 11 } } },
      y: { beginAtZero: true, grid: { color: 'rgba(0,0,0,0.05)' }, ticks: { stepSize: 1 } },
    },
  };

  const stats = [
    { label: 'Total Tasks', value: totalTasks, icon: BarChart3, gradient: 'from-indigo-500 to-purple-500', bg: 'bg-indigo-50 dark:bg-indigo-900/20' },
    { label: 'Completed', value: completedTasks, icon: CheckCircle, gradient: 'from-green-500 to-emerald-500', bg: 'bg-green-50 dark:bg-green-900/20' },
    { label: 'Overdue', value: overdueTasks, icon: AlertTriangle, gradient: 'from-red-500 to-pink-500', bg: 'bg-red-50 dark:bg-red-900/20' },
    { label: 'Avg Completion', value: `${avgCompletionTime}h`, icon: Clock, gradient: 'from-amber-500 to-orange-500', bg: 'bg-amber-50 dark:bg-amber-900/20' },
  ];

  return (
    <div className="min-h-screen bg-slate-50 dark:bg-gray-900">
      <Navbar />
      <main className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
        {/* Header */}
        <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between mb-8 gap-4">
          <div>
            <h1 className="text-2xl sm:text-3xl font-bold text-slate-800 dark:text-white">Analytics</h1>
            <p className="text-slate-500 dark:text-gray-400 mt-1">Track your team productivity</p>
          </div>
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

        {loading ? (
          <div className="flex items-center justify-center py-32">
            <Loader2 className="w-10 h-10 text-indigo-500 animate-spin" />
          </div>
        ) : (
          <>
            {/* Stats cards */}
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-8">
              {stats.map((stat) => (
                <div key={stat.label} className="bg-white dark:bg-gray-800 rounded-2xl shadow-sm border border-slate-100 dark:border-gray-700 p-5 relative overflow-hidden">
                  <div className={`absolute top-0 right-0 w-24 h-24 rounded-full blur-2xl opacity-20 bg-gradient-to-br ${stat.gradient}`} />
                  <div className={`w-10 h-10 ${stat.bg} rounded-xl flex items-center justify-center mb-3`}>
                    <stat.icon className="w-5 h-5 text-slate-600 dark:text-gray-400" />
                  </div>
                  <p className="text-2xl font-bold text-slate-800 dark:text-white">{stat.value}</p>
                  <p className="text-sm text-slate-500 dark:text-gray-400">{stat.label}</p>
                </div>
              ))}
            </div>

            {/* Charts grid */}
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
              {/* Status doughnut */}
              <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-sm border border-slate-100 dark:border-gray-700 p-6">
                <h3 className="text-lg font-semibold text-slate-800 dark:text-white mb-4">Tasks by Status</h3>
                <div className="h-[280px] flex items-center justify-center">
                  {totalTasks > 0 ? (
                    <Doughnut data={statusData} options={{ ...chartOptions, cutout: '65%', plugins: { legend: { display: true, position: 'bottom' } } }} />
                  ) : (
                    <p className="text-slate-400 dark:text-gray-500">No data</p>
                  )}
                </div>
              </div>

              {/* Priority bar */}
              <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-sm border border-slate-100 dark:border-gray-700 p-6">
                <h3 className="text-lg font-semibold text-slate-800 dark:text-white mb-4">Tasks by Priority</h3>
                <div className="h-[280px]">
                  <Bar data={priorityData} options={{
                    ...chartOptions,
                    scales: {
                      x: { grid: { display: false } },
                      y: { beginAtZero: true, grid: { color: 'rgba(0,0,0,0.05)' }, ticks: { stepSize: 1 } },
                    },
                  }} />
                </div>
              </div>

              {/* Completion line */}
              <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-sm border border-slate-100 dark:border-gray-700 p-6">
                <h3 className="text-lg font-semibold text-slate-800 dark:text-white mb-4">Tasks Completed (Last 30 Days)</h3>
                <div className="h-[280px]">
                  <Line data={completionData} options={lineOptions} />
                </div>
              </div>

              {/* Burndown */}
              <div className="bg-white dark:bg-gray-800 rounded-2xl shadow-sm border border-slate-100 dark:border-gray-700 p-6">
                <h3 className="text-lg font-semibold text-slate-800 dark:text-white mb-4">Burndown Chart</h3>
                <div className="h-[280px]">
                  <Line data={burndownData} options={{
                    ...lineOptions,
                    plugins: { legend: { display: true, position: 'bottom' } },
                  }} />
                </div>
              </div>
            </div>
          </>
        )}
      </main>
    </div>
  );
}
