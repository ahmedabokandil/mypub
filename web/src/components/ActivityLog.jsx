import { useState, useEffect } from 'react';
import {
  Activity, Plus, Edit3, Trash2, ArrowRight, UserPlus, MessageSquare,
  Paperclip, CheckSquare, Clock, Loader2
} from 'lucide-react';
import { formatDistanceToNow } from 'date-fns';
import api from '../api/axios';

const actionIcons = {
  created: Plus,
  updated: Edit3,
  deleted: Trash2,
  moved: ArrowRight,
  'member-added': UserPlus,
  commented: MessageSquare,
  attached: Paperclip,
  completed: CheckSquare,
  default: Activity,
};

const actionColors = {
  created: 'bg-green-100 text-green-600 dark:bg-green-900/30 dark:text-green-400',
  updated: 'bg-blue-100 text-blue-600 dark:bg-blue-900/30 dark:text-blue-400',
  deleted: 'bg-red-100 text-red-600 dark:bg-red-900/30 dark:text-red-400',
  moved: 'bg-amber-100 text-amber-600 dark:bg-amber-900/30 dark:text-amber-400',
  'member-added': 'bg-purple-100 text-purple-600 dark:bg-purple-900/30 dark:text-purple-400',
  commented: 'bg-indigo-100 text-indigo-600 dark:bg-indigo-900/30 dark:text-indigo-400',
  attached: 'bg-cyan-100 text-cyan-600 dark:bg-cyan-900/30 dark:text-cyan-400',
  completed: 'bg-green-100 text-green-600 dark:bg-green-900/30 dark:text-green-400',
  default: 'bg-slate-100 text-slate-600 dark:bg-gray-700 dark:text-gray-400',
};

export default function ActivityLog({ boardId }) {
  const [activities, setActivities] = useState([]);
  const [loading, setLoading] = useState(true);
  const [page, setPage] = useState(1);
  const [hasMore, setHasMore] = useState(true);
  const [loadingMore, setLoadingMore] = useState(false);

  useEffect(() => {
    fetchActivities(1);
  }, [boardId]);

  const fetchActivities = async (pageNum) => {
    const isFirst = pageNum === 1;
    if (isFirst) setLoading(true);
    else setLoadingMore(true);

    try {
      const res = await api.get(`/api/boards/${boardId}/activities`, {
        params: { page: pageNum, limit: 20 },
      });
      const data = res.data.activities || res.data || [];
      if (isFirst) {
        setActivities(data);
      } else {
        setActivities((prev) => [...prev, ...data]);
      }
      setHasMore(data.length >= 20);
      setPage(pageNum);
    } catch {
      if (isFirst) setActivities([]);
    } finally {
      setLoading(false);
      setLoadingMore(false);
    }
  };

  const loadMore = () => {
    fetchActivities(page + 1);
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-8">
        <Loader2 className="w-6 h-6 text-indigo-500 animate-spin" />
      </div>
    );
  }

  if (activities.length === 0) {
    return (
      <div className="text-center py-8">
        <Activity className="w-8 h-8 text-slate-300 dark:text-gray-600 mx-auto mb-2" />
        <p className="text-sm text-slate-400 dark:text-gray-500">No activity yet</p>
      </div>
    );
  }

  return (
    <div>
      <div className="relative">
        {/* Timeline line */}
        <div className="absolute left-4 top-0 bottom-0 w-px bg-slate-200 dark:bg-gray-700" />

        <div className="space-y-4">
          {activities.map((activity, index) => {
            const actionType = activity.action || activity.type || 'default';
            const IconComp = actionIcons[actionType] || actionIcons.default;
            const colorClass = actionColors[actionType] || actionColors.default;

            return (
              <div key={activity._id || index} className="flex gap-3 relative">
                <div className={`relative z-10 w-8 h-8 rounded-full flex items-center justify-center flex-shrink-0 ${colorClass}`}>
                  <IconComp className="w-3.5 h-3.5" />
                </div>
                <div className="flex-1 min-w-0 pt-0.5">
                  <p className="text-sm text-slate-700 dark:text-gray-300">
                    <span className="font-medium">
                      {activity.user?.name || activity.userName || 'Someone'}
                    </span>{' '}
                    {activity.message || activity.description || `${actionType} an item`}
                  </p>
                  <p className="text-xs text-slate-400 dark:text-gray-500 mt-0.5">
                    {activity.createdAt
                      ? formatDistanceToNow(new Date(activity.createdAt), { addSuffix: true })
                      : 'Recently'}
                  </p>
                </div>
              </div>
            );
          })}
        </div>
      </div>

      {hasMore && (
        <button
          onClick={loadMore}
          disabled={loadingMore}
          className="w-full mt-4 py-2 text-sm text-indigo-600 dark:text-indigo-400 hover:bg-indigo-50 dark:hover:bg-indigo-900/20 rounded-lg font-medium transition-colors disabled:opacity-50"
        >
          {loadingMore ? (
            <span className="flex items-center justify-center gap-2">
              <Loader2 className="w-4 h-4 animate-spin" />
              Loading...
            </span>
          ) : (
            'Load more'
          )}
        </button>
      )}
    </div>
  );
}
