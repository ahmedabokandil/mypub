import React, { useState, useEffect, useCallback } from 'react';
import {
  View,
  Text,
  ScrollView,
  TouchableOpacity,
  StyleSheet,
  ActivityIndicator,
  Modal,
  TextInput,
  RefreshControl,
} from 'react-native';
import { getClient } from '../api/client';
import TaskCard from '../components/TaskCard';

const COLUMN_COLORS = {
  'To Do': '#6366f1',
  'In Progress': '#f59e0b',
  'Review': '#8b5cf6',
  'Done': '#22c55e',
};

const BoardScreen = ({ route, navigation }) => {
  const { boardId, boardName } = route.params;
  const [board, setBoard] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [modalVisible, setModalVisible] = useState(false);
  const [selectedColumn, setSelectedColumn] = useState(null);
  const [newTaskTitle, setNewTaskTitle] = useState('');
  const [newTaskPriority, setNewTaskPriority] = useState('medium');
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState('');

  const fetchBoard = useCallback(async () => {
    try {
      const client = getClient();
      const res = await client.get(`/api/boards/${boardId}`);
      setBoard(res.data.board || res.data);
    } catch (err) {
      console.error('Error fetching board:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, [boardId]);

  useEffect(() => {
    navigation.setOptions({ title: boardName || 'Board' });
    fetchBoard();
  }, [fetchBoard, navigation, boardName]);

  useEffect(() => {
    const unsubscribe = navigation.addListener('focus', () => {
      fetchBoard();
    });
    return unsubscribe;
  }, [navigation, fetchBoard]);

  const onRefresh = () => {
    setRefreshing(true);
    fetchBoard();
  };

  const handleCreateTask = async () => {
    if (!newTaskTitle.trim()) {
      setError('Task title is required');
      return;
    }
    setCreating(true);
    setError('');

    try {
      const client = getClient();
      await client.post(`/api/boards/${boardId}/tasks`, {
        title: newTaskTitle.trim(),
        priority: newTaskPriority,
        columnId: selectedColumn,
      });
      setNewTaskTitle('');
      setNewTaskPriority('medium');
      setModalVisible(false);
      fetchBoard();
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to create task');
    } finally {
      setCreating(false);
    }
  };

  const openAddTask = (columnId) => {
    setSelectedColumn(columnId);
    setModalVisible(true);
  };

  if (loading) {
    return (
      <View style={styles.loadingContainer}>
        <ActivityIndicator size="large" color="#6366f1" />
      </View>
    );
  }

  if (!board) {
    return (
      <View style={styles.loadingContainer}>
        <Text style={styles.errorTitle}>Board not found</Text>
      </View>
    );
  }

  const columns = board.columns || [];

  return (
    <View style={styles.container}>
      <View style={styles.header}>
        <TouchableOpacity onPress={() => navigation.goBack()} style={styles.backButton}>
          <Text style={styles.backText}>←</Text>
        </TouchableOpacity>
        <View style={styles.headerInfo}>
          <Text style={styles.headerTitle} numberOfLines={1}>
            {board.name}
          </Text>
          {board.members?.length > 0 ? (
            <Text style={styles.headerMembers}>
              {board.members.length} {board.members.length === 1 ? 'member' : 'members'}
            </Text>
          ) : null}
        </View>
      </View>

      <ScrollView
        horizontal
        showsHorizontalScrollIndicator={false}
        contentContainerStyle={styles.columnsContainer}
        refreshControl={
          <RefreshControl
            refreshing={refreshing}
            onRefresh={onRefresh}
            colors={['#6366f1']}
          />
        }
      >
        {columns.map((column, colIndex) => {
          const colColor =
            COLUMN_COLORS[column.name] ||
            Object.values(COLUMN_COLORS)[colIndex % Object.values(COLUMN_COLORS).length];
          const tasks = column.tasks || [];

          return (
            <View key={column._id || colIndex} style={styles.column}>
              <View style={styles.columnHeader}>
                <View style={[styles.columnDot, { backgroundColor: colColor }]} />
                <Text style={styles.columnName} numberOfLines={1}>
                  {column.name}
                </Text>
                <View style={styles.columnCount}>
                  <Text style={styles.columnCountText}>{tasks.length}</Text>
                </View>
              </View>

              <ScrollView
                style={styles.columnScroll}
                showsVerticalScrollIndicator={false}
                nestedScrollEnabled
              >
                {tasks.map((task) => (
                  <TaskCard
                    key={task._id}
                    task={task}
                    onPress={() =>
                      navigation.navigate('TaskDetail', {
                        taskId: task._id,
                        boardId,
                        boardName: board.name,
                      })
                    }
                  />
                ))}
                {tasks.length === 0 ? (
                  <View style={styles.emptyColumn}>
                    <Text style={styles.emptyColumnText}>No tasks</Text>
                  </View>
                ) : null}
              </ScrollView>

              <TouchableOpacity
                style={styles.addTaskButton}
                onPress={() => openAddTask(column._id)}
              >
                <Text style={styles.addTaskText}>+ Add Task</Text>
              </TouchableOpacity>
            </View>
          );
        })}

        {columns.length === 0 ? (
          <View style={styles.emptyBoard}>
            <Text style={styles.emptyIcon}>📋</Text>
            <Text style={styles.emptyTitle}>No Columns</Text>
            <Text style={styles.emptyText}>
              This board has no columns yet
            </Text>
          </View>
        ) : null}
      </ScrollView>

      <TouchableOpacity
        style={styles.fab}
        onPress={() => {
          if (columns.length > 0) {
            openAddTask(columns[0]._id);
          }
        }}
        activeOpacity={0.8}
      >
        <Text style={styles.fabText}>+</Text>
      </TouchableOpacity>

      <Modal
        visible={modalVisible}
        transparent
        animationType="slide"
        onRequestClose={() => setModalVisible(false)}
      >
        <View style={styles.modalOverlay}>
          <View style={styles.modalContent}>
            <Text style={styles.modalTitle}>Add New Task</Text>

            {error ? (
              <View style={styles.errorContainer}>
                <Text style={styles.errorTextMsg}>{error}</Text>
              </View>
            ) : null}

            <View style={styles.inputContainer}>
              <Text style={styles.label}>Title</Text>
              <TextInput
                style={styles.input}
                value={newTaskTitle}
                onChangeText={setNewTaskTitle}
                placeholder="Task title"
                placeholderTextColor="#94a3b8"
              />
            </View>

            <View style={styles.inputContainer}>
              <Text style={styles.label}>Priority</Text>
              <View style={styles.priorityRow}>
                {['low', 'medium', 'high', 'urgent'].map((p) => (
                  <TouchableOpacity
                    key={p}
                    style={[
                      styles.priorityOption,
                      newTaskPriority === p && styles.prioritySelected,
                    ]}
                    onPress={() => setNewTaskPriority(p)}
                  >
                    <Text
                      style={[
                        styles.priorityOptionText,
                        newTaskPriority === p && styles.prioritySelectedText,
                      ]}
                    >
                      {p.charAt(0).toUpperCase() + p.slice(1)}
                    </Text>
                  </TouchableOpacity>
                ))}
              </View>
            </View>

            <View style={styles.modalButtons}>
              <TouchableOpacity
                style={styles.cancelButton}
                onPress={() => {
                  setModalVisible(false);
                  setNewTaskTitle('');
                  setError('');
                }}
              >
                <Text style={styles.cancelButtonText}>Cancel</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={styles.createButton}
                onPress={handleCreateTask}
                disabled={creating}
              >
                {creating ? (
                  <ActivityIndicator color="#ffffff" size="small" />
                ) : (
                  <Text style={styles.createButtonText}>Create</Text>
                )}
              </TouchableOpacity>
            </View>
          </View>
        </View>
      </Modal>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#f1f5f9',
  },
  loadingContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: '#f8fafc',
  },
  header: {
    flexDirection: 'row',
    alignItems: 'center',
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
    marginRight: 12,
  },
  backText: {
    fontSize: 22,
    color: '#1e293b',
    fontWeight: '600',
  },
  headerInfo: {
    flex: 1,
  },
  headerTitle: {
    fontSize: 20,
    fontWeight: '700',
    color: '#1e293b',
  },
  headerMembers: {
    fontSize: 12,
    color: '#64748b',
    marginTop: 2,
  },
  columnsContainer: {
    paddingHorizontal: 12,
    paddingTop: 14,
    paddingBottom: 100,
  },
  column: {
    width: 280,
    marginHorizontal: 6,
    backgroundColor: '#f8fafc',
    borderRadius: 16,
    padding: 12,
    maxHeight: '100%',
  },
  columnHeader: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 12,
    paddingHorizontal: 4,
  },
  columnDot: {
    width: 10,
    height: 10,
    borderRadius: 5,
    marginRight: 8,
  },
  columnName: {
    fontSize: 15,
    fontWeight: '700',
    color: '#1e293b',
    flex: 1,
  },
  columnCount: {
    backgroundColor: '#e2e8f0',
    paddingHorizontal: 8,
    paddingVertical: 2,
    borderRadius: 10,
  },
  columnCountText: {
    fontSize: 12,
    fontWeight: '700',
    color: '#64748b',
  },
  columnScroll: {
    flex: 1,
    maxHeight: 500,
  },
  emptyColumn: {
    padding: 20,
    alignItems: 'center',
  },
  emptyColumnText: {
    color: '#94a3b8',
    fontSize: 13,
  },
  addTaskButton: {
    marginTop: 8,
    padding: 10,
    borderRadius: 10,
    borderWidth: 1.5,
    borderColor: '#e2e8f0',
    borderStyle: 'dashed',
    alignItems: 'center',
  },
  addTaskText: {
    color: '#64748b',
    fontWeight: '600',
    fontSize: 13,
  },
  emptyBoard: {
    width: 300,
    alignItems: 'center',
    paddingTop: 100,
  },
  emptyIcon: {
    fontSize: 48,
    marginBottom: 12,
  },
  emptyTitle: {
    fontSize: 18,
    fontWeight: '700',
    color: '#1e293b',
  },
  emptyText: {
    fontSize: 14,
    color: '#64748b',
    marginTop: 4,
  },
  errorTitle: {
    fontSize: 18,
    fontWeight: '600',
    color: '#64748b',
  },
  fab: {
    position: 'absolute',
    bottom: 24,
    right: 24,
    width: 58,
    height: 58,
    borderRadius: 29,
    backgroundColor: '#6366f1',
    justifyContent: 'center',
    alignItems: 'center',
    shadowColor: '#6366f1',
    shadowOffset: { width: 0, height: 6 },
    shadowOpacity: 0.35,
    shadowRadius: 10,
    elevation: 8,
  },
  fabText: {
    fontSize: 30,
    color: '#ffffff',
    fontWeight: '300',
    marginTop: -2,
  },
  modalOverlay: {
    flex: 1,
    backgroundColor: 'rgba(0,0,0,0.5)',
    justifyContent: 'flex-end',
  },
  modalContent: {
    backgroundColor: '#ffffff',
    borderTopLeftRadius: 24,
    borderTopRightRadius: 24,
    padding: 24,
    paddingBottom: 40,
  },
  modalTitle: {
    fontSize: 22,
    fontWeight: '700',
    color: '#1e293b',
    marginBottom: 20,
  },
  inputContainer: {
    marginBottom: 16,
  },
  label: {
    fontSize: 14,
    fontWeight: '600',
    color: '#374151',
    marginBottom: 8,
  },
  input: {
    borderWidth: 1.5,
    borderColor: '#e2e8f0',
    borderRadius: 12,
    padding: 14,
    fontSize: 16,
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
  prioritySelected: {
    borderColor: '#6366f1',
    backgroundColor: '#eef2ff',
  },
  priorityOptionText: {
    fontSize: 12,
    fontWeight: '600',
    color: '#64748b',
  },
  prioritySelectedText: {
    color: '#6366f1',
  },
  errorContainer: {
    backgroundColor: '#fef2f2',
    borderRadius: 10,
    padding: 12,
    marginBottom: 16,
  },
  errorTextMsg: {
    color: '#dc2626',
    fontSize: 13,
    fontWeight: '500',
  },
  modalButtons: {
    flexDirection: 'row',
    gap: 12,
    marginTop: 8,
  },
  cancelButton: {
    flex: 1,
    borderWidth: 1.5,
    borderColor: '#e2e8f0',
    borderRadius: 12,
    padding: 14,
    alignItems: 'center',
  },
  cancelButtonText: {
    color: '#64748b',
    fontSize: 16,
    fontWeight: '600',
  },
  createButton: {
    flex: 1,
    backgroundColor: '#6366f1',
    borderRadius: 12,
    padding: 14,
    alignItems: 'center',
  },
  createButtonText: {
    color: '#ffffff',
    fontSize: 16,
    fontWeight: '700',
  },
});

export default BoardScreen;
