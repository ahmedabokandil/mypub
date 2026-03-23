import { useState, useEffect } from 'react';
import { ExternalLink, Loader2, Image } from 'lucide-react';
import ReactPlayer from 'react-player';
import api from '../api/axios';

export default function LinkPreview({ url }) {
  const [preview, setPreview] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);

  const isYouTube = /(?:youtube\.com|youtu\.be)/.test(url);

  useEffect(() => {
    if (isYouTube) {
      setLoading(false);
      return;
    }
    fetchPreview();
  }, [url]);

  const fetchPreview = async () => {
    try {
      const res = await api.get('/api/link-preview', { params: { url } });
      setPreview(res.data);
    } catch {
      setError(true);
    } finally {
      setLoading(false);
    }
  };

  if (isYouTube) {
    return (
      <div className="rounded-xl border border-slate-100 dark:border-gray-700 overflow-hidden">
        <div className="aspect-video">
          <ReactPlayer url={url} width="100%" height="100%" controls light />
        </div>
      </div>
    );
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center py-4">
        <Loader2 className="w-5 h-5 text-slate-400 animate-spin" />
      </div>
    );
  }

  if (error || !preview) {
    return (
      <a
        href={url}
        target="_blank"
        rel="noopener noreferrer"
        className="flex items-center gap-2 p-3 bg-slate-50 dark:bg-gray-700 rounded-xl text-sm text-indigo-600 dark:text-indigo-400 hover:bg-slate-100 dark:hover:bg-gray-600 transition-colors"
      >
        <ExternalLink className="w-4 h-4 flex-shrink-0" />
        <span className="truncate">{url}</span>
      </a>
    );
  }

  return (
    <a
      href={url}
      target="_blank"
      rel="noopener noreferrer"
      className="block rounded-xl border border-slate-100 dark:border-gray-700 overflow-hidden hover:shadow-md transition-shadow group"
    >
      {preview.image && (
        <div className="aspect-[2/1] bg-slate-100 dark:bg-gray-700 overflow-hidden">
          <img
            src={preview.image}
            alt={preview.title || ''}
            className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300"
            onError={(e) => { e.target.style.display = 'none'; }}
          />
        </div>
      )}
      <div className="p-3">
        {preview.title && (
          <h4 className="text-sm font-semibold text-slate-800 dark:text-gray-200 line-clamp-1 mb-0.5">{preview.title}</h4>
        )}
        {preview.description && (
          <p className="text-xs text-slate-500 dark:text-gray-400 line-clamp-2 mb-1">{preview.description}</p>
        )}
        <span className="text-xs text-slate-400 dark:text-gray-500 flex items-center gap-1">
          <ExternalLink className="w-3 h-3" />
          {new URL(url).hostname}
        </span>
      </div>
    </a>
  );
}
