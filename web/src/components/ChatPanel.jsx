import { useState, useEffect, useRef } from 'react';
import { motion } from 'framer-motion';
import { X, Send, MessageCircle, Loader2 } from 'lucide-react';
import { format } from 'date-fns';
import { useAuth } from '../context/AuthContext';
import { useSocket } from '../context/SocketContext';
import api from '../api/axios';

export default function ChatPanel({ boardId, isOpen, onClose }) {
  const { user } = useAuth();
  const { socket } = useSocket();
  const [messages, setMessages] = useState([]);
  const [newMessage, setNewMessage] = useState('');
  const [loading, setLoading] = useState(true);
  const messagesEndRef = useRef(null);
  const inputRef = useRef(null);

  useEffect(() => {
    if (isOpen && boardId) {
      fetchMessages();
    }
  }, [isOpen, boardId]);

  useEffect(() => {
    if (!socket || !isOpen) return;

    const handleMessage = (message) => {
      setMessages((prev) => [...prev, message]);
    };

    socket.on('chat-message', handleMessage);
    return () => {
      socket.off('chat-message', handleMessage);
    };
  }, [socket, isOpen]);

  useEffect(() => {
    scrollToBottom();
  }, [messages]);

  useEffect(() => {
    if (isOpen) {
      setTimeout(() => inputRef.current?.focus(), 200);
    }
  }, [isOpen]);

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  const fetchMessages = async () => {
    setLoading(true);
    try {
      const res = await api.get(`/api/boards/${boardId}/chat`);
      setMessages(res.data.messages || res.data || []);
    } catch {
      setMessages([]);
    } finally {
      setLoading(false);
    }
  };

  const sendMessage = () => {
    if (!newMessage.trim() || !socket) return;

    const message = {
      boardId,
      text: newMessage.trim(),
      user: { _id: user?._id, name: user?.name, email: user?.email },
      createdAt: new Date().toISOString(),
    };

    socket.emit('chat-message', message);
    setMessages((prev) => [...prev, message]);
    setNewMessage('');
  };

  const handleKeyDown = (e) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault();
      sendMessage();
    }
  };

  const initials = (name) => {
    return (name || 'U').split(' ').map((n) => n[0]).join('').toUpperCase().slice(0, 2);
  };

  if (!isOpen) return null;

  return (
    <motion.div
      initial={{ x: '100%' }}
      animate={{ x: 0 }}
      exit={{ x: '100%' }}
      transition={{ type: 'spring', damping: 30, stiffness: 300 }}
      className="fixed top-0 right-0 w-full max-w-sm h-full bg-white dark:bg-gray-800 shadow-2xl z-40 flex flex-col border-l border-slate-200 dark:border-gray-700"
    >
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-slate-100 dark:border-gray-700 bg-gradient-to-r from-indigo-600 to-purple-600">
        <div className="flex items-center gap-2">
          <MessageCircle className="w-5 h-5 text-white" />
          <h3 className="text-base font-semibold text-white">Board Chat</h3>
        </div>
        <button
          onClick={onClose}
          className="p-1.5 hover:bg-white/20 rounded-lg transition-colors"
        >
          <X className="w-5 h-5 text-white" />
        </button>
      </div>

      {/* Messages */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4 scrollbar-thin">
        {loading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="w-6 h-6 text-indigo-500 animate-spin" />
          </div>
        ) : messages.length === 0 ? (
          <div className="text-center py-12">
            <MessageCircle className="w-10 h-10 text-slate-300 dark:text-gray-600 mx-auto mb-2" />
            <p className="text-sm text-slate-400 dark:text-gray-500">No messages yet</p>
            <p className="text-xs text-slate-300 dark:text-gray-600">Start the conversation!</p>
          </div>
        ) : (
          messages.map((msg, i) => {
            const isOwnMessage = msg.user?._id === user?._id;
            return (
              <div key={msg._id || i} className={`flex gap-2.5 ${isOwnMessage ? 'flex-row-reverse' : ''}`}>
                <div className={`w-8 h-8 rounded-full flex items-center justify-center text-xs font-semibold flex-shrink-0 ${
                  isOwnMessage ? 'bg-indigo-100 text-indigo-700 dark:bg-indigo-900/50 dark:text-indigo-300' : 'bg-slate-100 text-slate-600 dark:bg-gray-700 dark:text-gray-300'
                }`}>
                  {initials(msg.user?.name)}
                </div>
                <div className={`max-w-[75%] ${isOwnMessage ? 'text-right' : ''}`}>
                  <div className="flex items-baseline gap-2 mb-0.5">
                    <span className="text-xs font-medium text-slate-700 dark:text-gray-300">{msg.user?.name || 'User'}</span>
                    <span className="text-xs text-slate-400 dark:text-gray-500">
                      {msg.createdAt ? format(new Date(msg.createdAt), 'h:mm a') : ''}
                    </span>
                  </div>
                  <div className={`inline-block px-3 py-2 rounded-2xl text-sm ${
                    isOwnMessage
                      ? 'bg-indigo-600 text-white rounded-br-md'
                      : 'bg-slate-100 dark:bg-gray-700 text-slate-700 dark:text-gray-300 rounded-bl-md'
                  }`}>
                    {msg.text || msg.content}
                  </div>
                </div>
              </div>
            );
          })
        )}
        <div ref={messagesEndRef} />
      </div>

      {/* Input */}
      <div className="p-3 border-t border-slate-100 dark:border-gray-700 bg-white dark:bg-gray-800">
        <div className="flex gap-2">
          <input
            ref={inputRef}
            type="text"
            value={newMessage}
            onChange={(e) => setNewMessage(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Type a message..."
            className="flex-1 px-4 py-2.5 bg-slate-50 dark:bg-gray-700 border border-slate-200 dark:border-gray-600 rounded-xl text-sm text-slate-700 dark:text-gray-300 placeholder-slate-400 dark:placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-indigo-500/20 focus:border-indigo-500"
          />
          <button
            onClick={sendMessage}
            disabled={!newMessage.trim()}
            className="p-2.5 bg-indigo-600 text-white rounded-xl hover:bg-indigo-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <Send className="w-4 h-4" />
          </button>
        </div>
      </div>
    </motion.div>
  );
}
