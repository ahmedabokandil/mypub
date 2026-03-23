import { useState, useRef, useEffect } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Download, FileText, FileJson, ChevronDown } from 'lucide-react';
import api from '../api/axios';
import toast from 'react-hot-toast';

export default function ExportMenu({ boardId }) {
  const [open, setOpen] = useState(false);
  const menuRef = useRef(null);

  useEffect(() => {
    const handleClick = (e) => {
      if (menuRef.current && !menuRef.current.contains(e.target)) {
        setOpen(false);
      }
    };
    document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, []);

  const exportAs = async (format) => {
    try {
      const res = await api.get(`/api/boards/${boardId}/export`, {
        params: { format },
        responseType: 'blob',
      });

      const blob = new Blob([res.data], {
        type: format === 'csv' ? 'text/csv' : 'application/json',
      });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `board-export.${format}`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      window.URL.revokeObjectURL(url);
      toast.success(`Exported as ${format.toUpperCase()}`);
    } catch {
      // Fallback: export locally
      try {
        const res = await api.get(`/api/boards/${boardId}`);
        const data = res.data.board || res.data;
        const tasks = data.tasks || [];

        if (format === 'json') {
          const blob = new Blob([JSON.stringify(tasks, null, 2)], { type: 'application/json' });
          const url = window.URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = 'board-export.json';
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          window.URL.revokeObjectURL(url);
        } else {
          const headers = ['Title', 'Status', 'Priority', 'Due Date', 'Description'];
          const rows = tasks.map((t) => [
            `"${(t.title || '').replace(/"/g, '""')}"`,
            t.status || '',
            t.priority || '',
            t.dueDate || '',
            `"${(t.description || '').replace(/"/g, '""')}"`,
          ]);
          const csv = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');
          const blob = new Blob([csv], { type: 'text/csv' });
          const url = window.URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = 'board-export.csv';
          document.body.appendChild(a);
          a.click();
          document.body.removeChild(a);
          window.URL.revokeObjectURL(url);
        }
        toast.success(`Exported as ${format.toUpperCase()}`);
      } catch {
        toast.error('Failed to export');
      }
    }
    setOpen(false);
  };

  return (
    <div className="relative" ref={menuRef}>
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center gap-1.5 px-3 py-2 text-sm font-medium text-slate-600 dark:text-gray-300 bg-white dark:bg-gray-700 border border-slate-200 dark:border-gray-600 hover:bg-slate-50 dark:hover:bg-gray-600 rounded-xl transition-colors"
      >
        <Download className="w-4 h-4" />
        <span className="hidden sm:inline">Export</span>
        <ChevronDown className={`w-3.5 h-3.5 transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ opacity: 0, y: -5, scale: 0.95 }}
            animate={{ opacity: 1, y: 0, scale: 1 }}
            exit={{ opacity: 0, y: -5, scale: 0.95 }}
            className="absolute right-0 top-full mt-1.5 w-44 bg-white dark:bg-gray-800 rounded-xl shadow-lg border border-slate-100 dark:border-gray-700 z-20 overflow-hidden"
          >
            <button
              onClick={() => exportAs('csv')}
              className="w-full flex items-center gap-2.5 px-4 py-2.5 text-sm text-slate-700 dark:text-gray-300 hover:bg-slate-50 dark:hover:bg-gray-700 transition-colors"
            >
              <FileText className="w-4 h-4 text-green-500" />
              Export as CSV
            </button>
            <button
              onClick={() => exportAs('json')}
              className="w-full flex items-center gap-2.5 px-4 py-2.5 text-sm text-slate-700 dark:text-gray-300 hover:bg-slate-50 dark:hover:bg-gray-700 transition-colors"
            >
              <FileJson className="w-4 h-4 text-blue-500" />
              Export as JSON
            </button>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
