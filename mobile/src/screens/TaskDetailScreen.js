import React, { useState, useEffect, useCallback } from 'react';
import {
  View,
  Text,
  ScrollView,
  TextInput,
  TouchableOpacity,
  StyleSheet,
  ActivityIndicator,
  Alert,
  Linking,
  KeyboardAvoidingView,
  Platform,
} from 'react-native';
import { format } from 'date-fns';
import { getClient } from '../api/client';
import { useAuth } from '../context/AuthContext';

const PRIORITIES = [
  { value: 'low', label: 'Low', color: '#16a34a', bg: '#f0fdf4' },
  { value: 'medium', label: 'Medium', color: '#ca8a04', bg: '#fefce8' },
  { value: 'high', label: 'High', color: '#ea580c', bg: '#fff7ed' },
  { value: 'urgent', label: 'Urgent', color: '#dc2626', bg: '#fef2f2' },
];

const TaskDetailScreen = ({ route, navigation }) => {
  const { taskId, boardId } = route.params;
  const { user } = useAuth();
  const [task, setTask] = useState(null);
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [priority, setPriority] = useState('medium');
  const [dueDate, setDueDate] = useState('');
  const [reminder, setReminder] = useState('');
  const [newComment, setNewComment] = useState('');
  const [addingComment, setAddingComment] = useState(false);

  const fetchTask = useCallback(async () => {
    try {
      const client = getClient();
      const res = await client.get(`/api/boards/${boardId}/tasks/${taskId}`);
      const taskData = res.data.task || res.data;
      setTask(taskData);
      setTitle(taskData.title || '');
      setDescription(taskData.description || '');
      setPriority(taskData.priority || 'medium');
      setDueDate(taskData.dueDate || '');
      setReminder(taskData.reminder || '');
    } catch (err) {
      console.error('Error fetching task:', err);
    } finally {
      setLoading(false);
    }
  }, [taskId, boardId]);

  useEffect(() => {
    fetchTask();
  }, [fetchTask]);

  const handleSave = async () => {
    setSaving(true);
    try {
      const client = getClient();
      await client.put(`/api/boards/${boardId}/tasks/${taskId}`, {
        title: title.trim(),
        description: description.trim(),
        priority,
        dueDate: dueDate || null,
        reminder: reminder || null,
      });
      Alert.alert('Success', 'Task updated successfully');
    } catch (err) {
      Alert.alert('Error', err.response?.data?.message || 'Failed to update task');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = () => {
    Alert.alert('Delete Task', 'Are you sure you want to delete this task?', [
      { text: 'Cancel', style: 'cancel' },
      {
        text: 'Delete',
        style: 'destructive',
        onPress: async () => {
          try {
            const client = getClient();
            await client.delete(`/api/boards/${boardId}/tasks/${taskId}`);
            navigation.goBack();
          } catch (err) {
            Alert.alert('Error', 'Failed to delete task');
          }
        },
      },
    ]);
  };

  const handleAddComment = async () => {
    if (!newComment.trim()) return;
    setAddingComment(true);
    try {
      const client = getClient();
      await client.post(`/api/boards/${boardId}/tasks/${taskId}/comments`, {
        text: newComment.trim(),
      });
      setNewComment('');
      fetchTask();
    } catch (err) {
      Alert.alert('Error', 'Failed to add comment');
    } finally {
      setAddingComment(false);
    }
  };

  const handleUploadAttachment = () => {
    Alert.alert(
      'Upload Attachment',
      'Document picker functionality requires expo-document-picker. Install it to enable file uploads.',
      [{ text: 'OK' }]
    );
  };

  if (loading) {
    return (
      <View style={styles.loadingContainer}>
        <ActivityIndicator size="large" color="#6366f1" />
      </View>
    );
  }

  if (!task) {
    return (
      <View style={styles.loadingContainer}>
        <Text style={styles.errorText}>Task not found</Text>
      </View>
    );
  }

  const comments = task.comments || [];
  const attachments = task.attachments || [];
  const embeddedUrls = task.embeddedUrls || task.urls || [];

  return (
    <KeyboardAvoidingView
      style={styles.container}
      behavior={Platform.OS === 'ios' ? 'padding' : undefined}
    >
      <View style={styles.header}>
        <TouchableOpacity onPress={() => navigation.goBack()} style={styles.backButton}>
          <Text style={styles.backText}>←</Text>
        </TouchableOpacity>
        <Text style={styles.headerTitle} numberOfLines={1}>
          Task Details
        </Text>
        <TouchableOpacity
          onPress={handleSave}
          style={styles.saveButton}
          disabled={saving}
        >
          {saving ? (
            <ActivityIndicator color="#6366f1" size="small" />
          ) : (
            <Text style={styles.saveText}>Save</Text>
          )}
        </TouchableOpacity>
      </View>

      <ScrollView
        style={styles.scrollView}
        contentContainerStyle={styles.scrollContent}
        keyboardShouldPersistTaps="handled"
      >
        {/* Title */}
        <View style={styles.section}>
          <Text style={styles.sectionLabel}>Title</Text>
          <TextInput
            style={styles.titleInput}
            value={title}
            onChangeText={setTitle}
            placeholder="Task title"
            placeholderTextColor="#94a3b8"
          />
        </View>

        {/* Description */}
        <View style={styles.section}>
          <Text style={styles.sectionLabel}>Description</Text>
          <TextInput
            style={styles.descriptionInput}
            value={description}
            onChangeText={setDescription}
            placeholder="Add a description..."
            placeholderTextColor="#94a3b8"
            multiline
            numberOfLines={4}
          />
        </View>

        {/* Priority */}
        <View style={styles.section}>
          <Text style={styles.sectionLabel}>Priority</Text>
          <View style={styles.priorityRow}>
            {PRIORITIES.map((p) => (
              <TouchableOpacity
                key={p.value}
                style={[
                  styles.priorityOption,
                  priority === p.value && { borderColor: p.color, backgroundColor: p.bg },
                ]}
                onPress={() => setPriority(p.value)}
              >
                <Text
                  style={[
                    styles.priorityText,
                    priority === p.value && { color: p.color },
                  ]}
                >
                  {p.label}
                </Text>
              </TouchableOpacity>
            ))}
          </View>
        </View>

        {/* Due Date */}
        <View style={styles.section}>
          <Text style={styles.sectionLabel}>Due Date</Text>
          <TextInput
            style={styles.input}
            value={dueDate ? format(new Date(dueDate), 'yyyy-MM-dd') : ''}
            onChangeText={setDueDate}
            placeholder="YYYY-MM-DD"
            placeholderTextColor="#94a3b8"
          />
        </View>

        {/* Reminder */}
        <View style={styles.section}>
          <Text style={styles.sectionLabel}>Reminder</Text>
          <TextInput
            style={styles.input}
            value={reminder ? format(new Date(reminder), 'yyyy-MM-dd HH:mm') : ''}
            onChangeText={setReminder}
            placeholder="YYYY-MM-DD HH:mm"
            placeholderTextColor="#94a3b8"
          />
        </View>

        {/* Attachments */}
        <View style={styles.section}>
          <View style={styles.sectionHeader}>
            <Text style={styles.sectionLabel}>Attachments</Text>
            <TouchableOpacity onPress={handleUploadAttachment}>
              <Text style={styles.addButton}>+ Upload</Text>
            </TouchableOpacity>
          </View>
          {attachments.length > 0 ? (
            attachments.map((att, index) => (
              <TouchableOpacity
                key={index}
                style={styles.attachmentItem}
                onPress={() => {
                  if (att.url) Linking.openURL(att.url);
                }}
              >
                <Text style={styles.attachmentIcon}>📎</Text>
                <Text style={styles.attachmentName} numberOfLines={1}>
                  {att.filename || att.name || `Attachment ${index + 1}`}
                </Text>
              </TouchableOpacity>
            ))
          ) : (
            <Text style={styles.emptyText}>No attachments</Text>
          )}
        </View>

        {/* Embedded URLs */}
        {embeddedUrls.length > 0 ? (
          <View style={styles.section}>
            <Text style={styles.sectionLabel}>Links</Text>
            {embeddedUrls.map((url, index) => (
              <TouchableOpacity
                key={index}
                style={styles.linkItem}
                onPress={() => Linking.openURL(typeof url === 'string' ? url : url.url)}
              >
                <Text style={styles.linkIcon}>🔗</Text>
                <Text style={styles.linkText} numberOfLines={1}>
                  {typeof url === 'string' ? url : url.url || url.title}
                </Text>
              </TouchableOpacity>
            ))}
          </View>
        ) : null}

        {/* Comments */}
        <View style={styles.section}>
          <Text style={styles.sectionLabel}>
            Comments ({comments.length})
          </Text>

          {comments.map((comment, index) => (
            <View key={comment._id || index} style={styles.commentItem}>
              <View style={styles.commentHeader}>
                <View style={styles.commentAvatar}>
                  <Text style={styles.commentAvatarText}>
                    {(comment.user?.name || comment.author?.name || 'U')
                      .charAt(0)
                      .toUpperCase()}
                  </Text>
                </View>
                <View style={styles.commentMeta}>
                  <Text style={styles.commentAuthor}>
                    {comment.user?.name || comment.author?.name || 'Unknown'}
                  </Text>
                  {comment.createdAt ? (
                    <Text style={styles.commentDate}>
                      {format(new Date(comment.createdAt), 'MMM d, yyyy HH:mm')}
                    </Text>
                  ) : null}
                </View>
              </View>
              <Text style={styles.commentText}>{comment.text || comment.content}</Text>
            </View>
          ))}

          <View style={styles.commentInputRow}>
            <TextInput
              style={styles.commentInput}
              value={newComment}
              onChangeText={setNewComment}
              placeholder="Add a comment..."
              placeholderTextColor="#94a3b8"
              multiline
            />
            <TouchableOpacity
              style={styles.commentSendButton}
              onPress={handleAddComment}
              disabled={addingComment || !newComment.trim()}
            >
              {addingComment ? (
                <ActivityIndicator color="#ffffff" size="small" />
              ) : (
                <Text style={styles.commentSendText}>Send</Text>
              )}
            </TouchableOpacity>
          </View>
        </View>

        {/* Delete */}
        <TouchableOpacity style={styles.deleteButton} onPress={handleDelete}>
          <Text style={styles.deleteButtonText}>Delete Task</Text>
        </TouchableOpacity>

        <View style={{ height: 40 }} />
      </ScrollView>
    </KeyboardAvoidingView>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f8fafc',
  },
  loadingContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: '#f8fafc',
  },
  errorText: {
    fontSize: 16,
    color: '#64748b',
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: 16,
    paddingTop: 52,
    paddingBottom: 14,
    backgroundColor: '#ffffff',
    borderBottomWidth: 1,
    borderBottomColor: '#e2e8f0',
  },
  backButton: {
    width: 40,
    height: 40,
    borderRadius: 12,
    backgroundColor: '#f1f5f9',
    justifyContent: 'center',
    alignItems: 'center',
  },
  backText: {
    fontSize: 22,
    color: '#1e293b',
    fontWeight: '600',
  },
  headerTitle: {
    fontSize: 18,
    fontWeight: '700',
    color: '#1e293b',
    flex: 1,
    textAlign: 'center',
    marginHorizontal: 12,
  },
  saveButton: {
    paddingHorizontal: 16,
    paddingVertical: 8,
    borderRadius: 10,
    backgroundColor: '#eef2ff',
  },
  saveText: {
    color: '#6366f1',
    fontWeight: '700',
    fontSize: 15,
  },
  scrollView: {
    flex: 1,
  },
  scrollContent: {
    padding: 16,
  },
  section: {
    backgroundColor: '#ffffff',
    borderRadius: 14,
    padding: 16,
    marginBottom: 12,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 1 },
    shadowOpacity: 0.04,
    shadowRadius: 4,
    elevation: 2,
  },
  sectionHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 4,
  },
  sectionLabel: {
    fontSize: 13,
    fontWeight: '700',
    color: '#64748b',
    textTransform: 'uppercase',
    letterSpacing: 0.5,
    marginBottom: 10,
  },
  titleInput: {
    fontSize: 18,
    fontWeight: '600',
    color: '#1e293b',
    padding: 0,
  },
  descriptionInput: {
    fontSize: 15,
    color: '#1e293b',
    minHeight: 80,
    textAlignVertical: 'top',
    padding: 0,
    lineHeight: 22,
  },
  input: {
    borderWidth: 1.5,
    borderColor: '#e2e8f0',
    borderRadius: 10,
    padding: 12,
    fontSize: 15,
    color: '#1e293b',
    backgroundColor: '#f8fafc',
  },
  priorityRow: {
    flexDirection: 'row',
    gap: 8,
  },
  priorityOption: {
    flex: 1,
    paddingVertical: 10,
    borderRadius: 10,
    borderWidth: 1.5,
    borderColor: '#e2e8f0',
    alignItems: 'center',
  },
  priorityText: {
    fontSize: 13,
    fontWeight: '600',
    color: '#64748b',
  },
  addButton: {
    color: '#6366f1',
    fontWeight: '700',
    fontSize: 14,
  },
  attachmentItem: {
    flexDirection: 'row',
    alignItems: 'center',
    padding: 10,
    backgroundColor: '#f8fafc',
    borderRadius: 10,
    marginBottom: 6,
  },
  attachmentIcon: {
    fontSize: 16,
    marginRight: 8,
  },
  attachmentName: {
    flex: 1,
    fontSize: 14,
    color: '#1e293b',
  },
  emptyText: {
    fontSize: 13,
    color: '#94a3b8',
    fontStyle: 'italic',
  },
  linkItem: {
    flexDirection: 'row',
    alignItems: 'center',
    padding: 10,
    backgroundColor: '#eef2ff',
    borderRadius: 10,
    marginBottom: 6,
  },
  linkIcon: {
    fontSize: 14,
    marginRight: 8,
  },
  linkText: {
    flex: 1,
    fontSize: 14,
    color: '#6366f1',
    fontWeight: '500',
  },
  commentItem: {
    backgroundColor: '#f8fafc',
    borderRadius: 12,
    padding: 12,
    marginBottom: 8,
  },
  commentHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 6,
  },
  commentAvatar: {
    width: 28,
    height: 28,
    borderRadius: 14,
    backgroundColor: '#6366f1',
    justifyContent: 'center',
    alignItems: 'center',
    marginRight: 8,
  },
  commentAvatarText: {
    color: '#ffffff',
    fontSize: 12,
    fontWeight: '700',
  },
  commentMeta: {
    flex: 1,
  },
  commentAuthor: {
    fontSize: 13,
    fontWeight: '600',
    color: '#1e293b',
  },
  commentDate: {
    fontSize: 11,
    color: '#94a3b8',
  },
  commentText: {
    fontSize: 14,
    color: '#334155',
    lineHeight: 20,
    marginLeft: 36,
  },
  commentInputRow: {
    flexDirection: 'row',
    gap: 8,
    marginTop: 8,
  },
  commentInput: {
    flex: 1,
    borderWidth: 1.5,
    borderColor: '#e2e8f0',
    borderRadius: 10,
    padding: 10,
    fontSize: 14,
    color: '#1e293b',
    backgroundColor: '#f8fafc',
    maxHeight: 80,
  },
  commentSendButton: {
    backgroundColor: '#6366f1',
    borderRadius: 10,
    paddingHorizontal: 16,
    justifyContent: 'center',
    alignItems: 'center',
  },
  commentSendText: {
    color: '#ffffff',
    fontWeight: '700',
    fontSize: 14,
  },
  deleteButton: {
    backgroundColor: '#fef2f2',
    borderWidth: 1.5,
    borderColor: '#fecaca',
    borderRadius: 14,
    padding: 16,
    alignItems: 'center',
    marginTop: 4,
  },
  deleteButtonText: {
    color: '#dc2626',
    fontSize: 16,
    fontWeight: '700',
  },
});

export default TaskDetailScreen;
