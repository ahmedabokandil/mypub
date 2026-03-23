import React, { useState, useEffect, useCallback } from 'react';
import {
  View,
  Text,
  FlatList,
  TouchableOpacity,
  StyleSheet,
  ActivityIndicator,
  RefreshControl,
  Modal,
  TextInput,
  StatusBar,
} from 'react-native';
import { useAuth } from '../context/AuthContext';
import { getClient } from '../api/client';

const BOARD_COLORS = [
  '#6366f1', '#8b5cf6', '#ec4899', '#f43f5e',
  '#f97316', '#eab308', '#22c55e', '#14b8a6',
  '#06b6d4', '#3b82f6',
];

const DashboardScreen = ({ navigation }) => {
  const { user } = useAuth();
  const [boards, setBoards] = useState([]);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [modalVisible, setModalVisible] = useState(false);
  const [newBoardName, setNewBoardName] = useState('');
  const [newBoardDesc, setNewBoardDesc] = useState('');
  const [creating, setCreating] = useState(false);
  const [error, setError] = useState('');

  const fetchBoards = useCallback(async () => {
    try {
      const client = getClient();
      const res = await client.get('/api/boards');
      setBoards(res.data.boards || res.data || []);
    } catch (err) {
      console.error('Error fetching boards:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchBoards();
  }, [fetchBoards]);

  useEffect(() => {
    const unsubscribe = navigation.addListener('focus', () => {
      fetchBoards();
    });
    return unsubscribe;
  }, [navigation, fetchBoards]);

  const onRefresh = () => {
    setRefreshing(true);
    fetchBoards();
  };

  const handleCreateBoard = async () => {
    if (!newBoardName.trim()) {
      setError('Board name is required');
      return;
    }
    setCreating(true);
    setError('');

    try {
      const client = getClient();
      await client.post('/api/boards', {
        name: newBoardName.trim(),
        description: newBoardDesc.trim(),
      });
      setNewBoardName('');
      setNewBoardDesc('');
      setModalVisible(false);
      fetchBoards();
    } catch (err) {
      setError(err.response?.data?.message || 'Failed to create board');
    } finally {
      setCreating(false);
    }
  };

  const getColorForBoard = (index) => {
    return BOARD_COLORS[index % BOARD_COLORS.length];
  };

  const getTaskCount = (board) => {
    if (board.taskCount !== undefined) return board.taskCount;
    if (board.columns) {
      return board.columns.reduce(
        (acc, col) => acc + (col.tasks?.length || 0),
        0
      );
    }
    return 0;
  };

  const renderBoardCard = ({ item, index }) => {
    const color = item.color || getColorForBoard(index);
    const taskCount = getTaskCount(item);

    return (
      <TouchableOpacity
        style={styles.boardCard}
        onPress={() => navigation.navigate('Board', { boardId: item._id, boardName: item.name })}
        activeOpacity={0.7}
      >
        <View style={[styles.boardAccent, { backgroundColor: color }]} />
        <View style={styles.boardContent}>
          <Text style={styles.boardName} numberOfLines={1}>
            {item.name}
          </Text>
          {item.description ? (
            <Text style={styles.boardDesc} numberOfLines={2}>
              {item.description}
            </Text>
          ) : null}
          <View style={styles.boardMeta}>
            <View style={styles.taskCountBadge}>
              <Text style={styles.taskCountText}>
                {taskCount} {taskCount === 1 ? 'task' : 'tasks'}
              </Text>
            </View>
            {item.members?.length > 0 ? (
              <Text style={styles.memberCount}>
                {item.members.length} {item.members.length === 1 ? 'member' : 'members'}
              </Text>
            ) : null}
          </View>
        </View>
      </TouchableOpacity>
    );
  };

  if (loading) {
    return (
      <View style={styles.loadingContainer}>
        <ActivityIndicator size="large" color="#6366f1" />
      </View>
    );
  }

  return (
    <View style={styles.container}>
      <StatusBar barStyle="dark-content" backgroundColor="#f8fafc" />
      <View style={styles.header}>
        <View>
          <Text style={styles.greeting}>
            Hello, {user?.name?.split(' ')[0] || 'there'}!
          </Text>
          <Text style={styles.headerTitle}>My Boards</Text>
        </View>
        <View style={styles.avatarCircle}>
          <Text style={styles.avatarText}>
            {(user?.name || 'U').charAt(0).toUpperCase()}
          </Text>
        </View>
      </View>

      <FlatList
        data={boards}
        renderItem={renderBoardCard}
        keyExtractor={(item) => item._id}
        contentContainerStyle={styles.listContainer}
        refreshControl={
          <RefreshControl
            refreshing={refreshing}
            onRefresh={onRefresh}
            colors={['#6366f1']}
            tintColor="#6366f1"
          />
        }
        ListEmptyComponent={
          <View style={styles.emptyContainer}>
            <Text style={styles.emptyIcon}>📋</Text>
            <Text style={styles.emptyTitle}>No Boards Yet</Text>
            <Text style={styles.emptyText}>
              Create your first board to start organizing tasks
            </Text>
          </View>
        }
      />

      <TouchableOpacity
        style={styles.fab}
        onPress={() => setModalVisible(true)}
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
            <Text style={styles.modalTitle}>Create New Board</Text>

            {error ? (
              <View style={styles.errorContainer}>
                <Text style={styles.errorText}>{error}</Text>
              </View>
            ) : null}

            <View style={styles.inputContainer}>
              <Text style={styles.label}>Board Name</Text>
              <TextInput
                style={styles.input}
                value={newBoardName}
                onChangeText={setNewBoardName}
                placeholder="e.g., Project Alpha"
                placeholderTextColor="#94a3b8"
              />
            </View>

            <View style={styles.inputContainer}>
              <Text style={styles.label}>Description (optional)</Text>
              <TextInput
                style={[styles.input, styles.textArea]}
                value={newBoardDesc}
                onChangeText={setNewBoardDesc}
                placeholder="What's this board about?"
                placeholderTextColor="#94a3b8"
                multiline
                numberOfLines={3}
              />
            </View>

            <View style={styles.modalButtons}>
              <TouchableOpacity
                style={styles.cancelButton}
                onPress={() => {
                  setModalVisible(false);
                  setNewBoardName('');
                  setNewBoardDesc('');
                  setError('');
                }}
              >
                <Text style={styles.cancelButtonText}>Cancel</Text>
              </TouchableOpacity>
              <TouchableOpacity
                style={styles.createButton}
                onPress={handleCreateBoard}
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
    backgroundColor: '#f8fafc',
  },
  loadingContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
    backgroundColor: '#f8fafc',
  },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingHorizontal: 20,
    paddingTop: 56,
    paddingBottom: 16,
    backgroundColor: '#f8fafc',
  },
  greeting: {
    fontSize: 14,
    color: '#64748b',
    fontWeight: '500',
  },
  headerTitle: {
    fontSize: 28,
    fontWeight: '800',
    color: '#1e293b',
    marginTop: 2,
  },
  avatarCircle: {
    width: 44,
    height: 44,
    borderRadius: 22,
    backgroundColor: '#6366f1',
    justifyContent: 'center',
    alignItems: 'center',
  },
  avatarText: {
    color: '#ffffff',
    fontSize: 18,
    fontWeight: '700',
  },
  listContainer: {
    padding: 16,
    paddingBottom: 100,
  },
  boardCard: {
    backgroundColor: '#ffffff',
    borderRadius: 16,
    marginBottom: 14,
    flexDirection: 'row',
    overflow: 'hidden',
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.06,
    shadowRadius: 8,
    elevation: 3,
  },
  boardAccent: {
    width: 5,
  },
  boardContent: {
    flex: 1,
    padding: 16,
  },
  boardName: {
    fontSize: 17,
    fontWeight: '700',
    color: '#1e293b',
    marginBottom: 4,
  },
  boardDesc: {
    fontSize: 13,
    color: '#64748b',
    marginBottom: 10,
    lineHeight: 18,
  },
  boardMeta: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
  },
  taskCountBadge: {
    backgroundColor: '#eef2ff',
    paddingHorizontal: 10,
    paddingVertical: 4,
    borderRadius: 8,
  },
  taskCountText: {
    fontSize: 12,
    color: '#6366f1',
    fontWeight: '600',
  },
  memberCount: {
    fontSize: 12,
    color: '#94a3b8',
    fontWeight: '500',
  },
  emptyContainer: {
    alignItems: 'center',
    paddingTop: 80,
  },
  emptyIcon: {
    fontSize: 48,
    marginBottom: 16,
  },
  emptyTitle: {
    fontSize: 20,
    fontWeight: '700',
    color: '#1e293b',
    marginBottom: 8,
  },
  emptyText: {
    fontSize: 14,
    color: '#64748b',
    textAlign: 'center',
    maxWidth: 250,
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
  textArea: {
    minHeight: 80,
    textAlignVertical: 'top',
  },
  errorContainer: {
    backgroundColor: '#fef2f2',
    borderRadius: 10,
    padding: 12,
    marginBottom: 16,
  },
  errorText: {
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

export default DashboardScreen;
