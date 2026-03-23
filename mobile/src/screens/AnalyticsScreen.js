import React, { useState, useEffect, useCallback } from 'react';
import {
  View,
  Text,
  ScrollView,
  TouchableOpacity,
  StyleSheet,
  ActivityIndicator,
  RefreshControl,
  Modal,
  FlatList,
} from 'react-native';
import { isPast, isToday } from 'date-fns';
import { getClient } from '../api/client';

const PRIORITY_COLORS = {
  urgent: '#dc2626',
  high: '#ea580c',
  medium: '#ca8a04',
  low: '#16a34a',
};

const COLUMN_COLORS = {
  'To Do': '#6366f1',
  'In Progress': '#f59e0b',
  'Review': '#8b5cf6',
  'Done': '#22c55e',
};

const AnalyticsScreen = ({ navigation }) => {
  const [boards, setBoards] = useState([]);
  const [selectedBoard, setSelectedBoard] = useState(null);
  const [boardData, setBoardData] = useState(null);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [pickerVisible, setPickerVisible] = useState(false);

  const fetchBoards = useCallback(async () => {
    try {
      const client = getClient();
      const res = await client.get('/api/boards');
      const boardsList = res.data.boards || res.data || [];
      setBoards(boardsList);
      if (boardsList.length > 0 && !selectedBoard) {
        setSelectedBoard(boardsList[0]);
      }
    } catch (err) {
      console.error('Error fetching boards:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  const fetchBoardData = useCallback(async () => {
    if (!selectedBoard) return;
    try {
      const client = getClient();
      const res = await client.get(`/api/boards/${selectedBoard._id}`);
      setBoardData(res.data.board || res.data);
    } catch (err) {
      console.error('Error fetching board data:', err);
    } finally {
      setRefreshing(false);
    }
  }, [selectedBoard]);

  useEffect(() => {
    fetchBoards();
  }, [fetchBoards]);

  useEffect(() => {
    if (selectedBoard) {
      fetchBoardData();
    }
  }, [selectedBoard, fetchBoardData]);

  useEffect(() => {
    const unsubscribe = navigation.addListener('focus', () => {
      fetchBoards();
      if (selectedBoard) fetchBoardData();
    });
    return unsubscribe;
  }, [navigation, fetchBoards, fetchBoardData, selectedBoard]);

  const onRefresh = () => {
    setRefreshing(true);
    fetchBoardData();
  };

  // Compute stats from board data
  const computeStats = () => {
    if (!boardData || !boardData.columns) {
      return { total: 0, completed: 0, overdue: 0, inProgress: 0, byPriority: {}, byColumn: [] };
    }

    const columns = boardData.columns || [];
    let total = 0;
    let completed = 0;
    let overdue = 0;
    let inProgress = 0;
    const byPriority = { urgent: 0, high: 0, medium: 0, low: 0 };
    const byColumn = [];

    columns.forEach((col) => {
      const tasks = col.tasks || [];
      const colCount = tasks.length;
      total += colCount;
      byColumn.push({ name: col.name, count: colCount });

      tasks.forEach((task) => {
        const p = task.priority || 'medium';
        if (byPriority[p] !== undefined) byPriority[p]++;

        const colNameLower = col.name?.toLowerCase() || '';
        if (colNameLower.includes('done') || colNameLower.includes('complete')) {
          completed++;
        } else if (colNameLower.includes('progress') || colNameLower.includes('doing')) {
          inProgress++;
        }

        if (task.dueDate) {
          const due = new Date(task.dueDate);
          if (isPast(due) && !isToday(due) && !colNameLower.includes('done') && !colNameLower.includes('complete')) {
            overdue++;
          }
        }
      });
    });

    return { total, completed, overdue, inProgress, byPriority, byColumn };
  };

  const stats = computeStats();
  const maxPriority = Math.max(...Object.values(stats.byPriority), 1);
  const maxColumn = Math.max(...stats.byColumn.map((c) => c.count), 1);

  if (loading) {
    return (
      <View style={styles.loadingContainer}>
        <ActivityIndicator size="large" color="#6366f1" />
      </View>
    );
  }

  return (
    <View style={styles.container}>
      {/* Header */}
      <View style={styles.header}>
        <Text style={styles.headerTitle}>Analytics</Text>
      </View>

      <ScrollView
        contentContainerStyle={styles.scrollContent}
        refreshControl={
          <RefreshControl refreshing={refreshing} onRefresh={onRefresh} colors={['#6366f1']} tintColor="#6366f1" />
        }
      >
        {/* Board Selector */}
        <TouchableOpacity style={styles.selectorButton} onPress={() => setPickerVisible(true)} activeOpacity={0.7}>
          <View style={styles.selectorContent}>
            <Text style={styles.selectorLabel}>Board</Text>
            <Text style={styles.selectorValue} numberOfLines={1}>
              {selectedBoard?.name || 'Select a board'}
            </Text>
          </View>
          <Text style={styles.selectorArrow}>v</Text>
        </TouchableOpacity>

        {/* Stats Cards */}
        <View style={styles.statsGrid}>
          <View style={[styles.statCard, { borderLeftColor: '#6366f1' }]}>
            <Text style={styles.statValue}>{stats.total}</Text>
            <Text style={styles.statLabel}>Total Tasks</Text>
          </View>
          <View style={[styles.statCard, { borderLeftColor: '#22c55e' }]}>
            <Text style={[styles.statValue, { color: '#22c55e' }]}>{stats.completed}</Text>
            <Text style={styles.statLabel}>Completed</Text>
          </View>
          <View style={[styles.statCard, { borderLeftColor: '#dc2626' }]}>
            <Text style={[styles.statValue, { color: '#dc2626' }]}>{stats.overdue}</Text>
            <Text style={styles.statLabel}>Overdue</Text>
          </View>
          <View style={[styles.statCard, { borderLeftColor: '#f59e0b' }]}>
            <Text style={[styles.statValue, { color: '#f59e0b' }]}>{stats.inProgress}</Text>
            <Text style={styles.statLabel}>In Progress</Text>
          </View>
        </View>

        {/* Tasks by Priority */}
        <View style={styles.chartCard}>
          <Text style={styles.chartTitle}>Tasks by Priority</Text>
          {Object.entries(stats.byPriority).map(([priority, count]) => (
            <View key={priority} style={styles.barRow}>
              <Text style={styles.barLabel}>
                {priority.charAt(0).toUpperCase() + priority.slice(1)}
              </Text>
              <View style={styles.barTrack}>
                <View
                  style={[
                    styles.barFill,
                    {
                      width: `${(count / maxPriority) * 100}%`,
                      backgroundColor: PRIORITY_COLORS[priority] || '#94a3b8',
                    },
                  ]}
                />
              </View>
              <Text style={styles.barValue}>{count}</Text>
            </View>
          ))}
        </View>

        {/* Tasks by Column */}
        <View style={styles.chartCard}>
          <Text style={styles.chartTitle}>Tasks by Column</Text>
          {stats.byColumn.map((col, idx) => {
            const colColor =
              COLUMN_COLORS[col.name] ||
              Object.values(COLUMN_COLORS)[idx % Object.values(COLUMN_COLORS).length];
            return (
              <View key={col.name} style={styles.barRow}>
                <Text style={styles.barLabel} numberOfLines={1}>
                  {col.name}
                </Text>
                <View style={styles.barTrack}>
                  <View
                    style={[
                      styles.barFill,
                      {
                        width: `${(col.count / maxColumn) * 100}%`,
                        backgroundColor: colColor,
                      },
                    ]}
                  />
                </View>
                <Text style={styles.barValue}>{col.count}</Text>
              </View>
            );
          })}
          {stats.byColumn.length === 0 && (
            <Text style={styles.emptyChartText}>No columns found</Text>
          )}
        </View>

        {/* Completion Rate */}
        {stats.total > 0 && (
          <View style={styles.chartCard}>
            <Text style={styles.chartTitle}>Completion Rate</Text>
            <View style={styles.completionRow}>
              <View style={styles.completionTrack}>
                <View
                  style={[
                    styles.completionFill,
                    { width: `${(stats.completed / stats.total) * 100}%` },
                  ]}
                />
              </View>
              <Text style={styles.completionText}>
                {Math.round((stats.completed / stats.total) * 100)}%
              </Text>
            </View>
            <Text style={styles.completionSubtext}>
              {stats.completed} of {stats.total} tasks completed
            </Text>
          </View>
        )}

        <View style={{ height: 100 }} />
      </ScrollView>

      {/* Board Picker Modal */}
      <Modal visible={pickerVisible} transparent animationType="slide" onRequestClose={() => setPickerVisible(false)}>
        <View style={styles.modalOverlay}>
          <View style={styles.modalContent}>
            <Text style={styles.modalTitle}>Select Board</Text>
            <FlatList
              data={boards}
              keyExtractor={(item) => item._id}
              renderItem={({ item }) => (
                <TouchableOpacity
                  style={[
                    styles.modalItem,
                    selectedBoard?._id === item._id && styles.modalItemActive,
                  ]}
                  onPress={() => {
                    setSelectedBoard(item);
                    setPickerVisible(false);
                  }}
                >
                  <Text
                    style={[
                      styles.modalItemText,
                      selectedBoard?._id === item._id && styles.modalItemTextActive,
                    ]}
                  >
                    {item.name}
                  </Text>
                  {selectedBoard?._id === item._id && (
                    <Text style={styles.checkMark}>OK</Text>
                  )}
                </TouchableOpacity>
              )}
              ListEmptyComponent={
                <Text style={styles.emptyChartText}>No boards available</Text>
              }
            />
            <TouchableOpacity style={styles.modalCloseButton} onPress={() => setPickerVisible(false)}>
              <Text style={styles.modalCloseText}>Close</Text>
            </TouchableOpacity>
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
    paddingHorizontal: 20,
    paddingTop: 56,
    paddingBottom: 8,
    backgroundColor: '#f8fafc',
  },
  headerTitle: {
    fontSize: 28,
    fontWeight: '800',
    color: '#1e293b',
  },
  scrollContent: {
    padding: 16,
  },
  selectorButton: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#ffffff',
    borderRadius: 14,
    padding: 16,
    marginBottom: 16,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.06,
    shadowRadius: 8,
    elevation: 3,
  },
  selectorContent: {
    flex: 1,
  },
  selectorLabel: {
    fontSize: 12,
    fontWeight: '600',
    color: '#94a3b8',
    textTransform: 'uppercase',
    letterSpacing: 0.5,
    marginBottom: 2,
  },
  selectorValue: {
    fontSize: 17,
    fontWeight: '700',
    color: '#1e293b',
  },
  selectorArrow: {
    fontSize: 16,
    fontWeight: '700',
    color: '#94a3b8',
  },
  statsGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    gap: 10,
    marginBottom: 16,
  },
  statCard: {
    width: '48%',
    backgroundColor: '#ffffff',
    borderRadius: 14,
    padding: 18,
    borderLeftWidth: 4,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.06,
    shadowRadius: 8,
    elevation: 3,
  },
  statValue: {
    fontSize: 28,
    fontWeight: '800',
    color: '#6366f1',
    marginBottom: 4,
  },
  statLabel: {
    fontSize: 13,
    fontWeight: '600',
    color: '#64748b',
  },
  chartCard: {
    backgroundColor: '#ffffff',
    borderRadius: 14,
    padding: 18,
    marginBottom: 14,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.06,
    shadowRadius: 8,
    elevation: 3,
  },
  chartTitle: {
    fontSize: 16,
    fontWeight: '700',
    color: '#1e293b',
    marginBottom: 16,
  },
  barRow: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 12,
  },
  barLabel: {
    width: 70,
    fontSize: 13,
    fontWeight: '600',
    color: '#64748b',
  },
  barTrack: {
    flex: 1,
    height: 24,
    backgroundColor: '#f1f5f9',
    borderRadius: 12,
    overflow: 'hidden',
    marginHorizontal: 10,
  },
  barFill: {
    height: '100%',
    borderRadius: 12,
    minWidth: 4,
  },
  barValue: {
    width: 30,
    fontSize: 14,
    fontWeight: '700',
    color: '#1e293b',
    textAlign: 'right',
  },
  emptyChartText: {
    fontSize: 14,
    color: '#94a3b8',
    fontStyle: 'italic',
    textAlign: 'center',
    paddingVertical: 12,
  },
  completionRow: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 8,
  },
  completionTrack: {
    flex: 1,
    height: 28,
    backgroundColor: '#f1f5f9',
    borderRadius: 14,
    overflow: 'hidden',
    marginRight: 12,
  },
  completionFill: {
    height: '100%',
    borderRadius: 14,
    backgroundColor: '#22c55e',
    minWidth: 4,
  },
  completionText: {
    fontSize: 20,
    fontWeight: '800',
    color: '#22c55e',
    width: 50,
    textAlign: 'right',
  },
  completionSubtext: {
    fontSize: 13,
    color: '#64748b',
    fontWeight: '500',
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
    maxHeight: '60%',
  },
  modalTitle: {
    fontSize: 22,
    fontWeight: '700',
    color: '#1e293b',
    marginBottom: 16,
  },
  modalItem: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    padding: 16,
    borderRadius: 12,
    marginBottom: 6,
    backgroundColor: '#f8fafc',
  },
  modalItemActive: {
    backgroundColor: '#eef2ff',
    borderWidth: 1.5,
    borderColor: '#6366f1',
  },
  modalItemText: {
    fontSize: 16,
    fontWeight: '600',
    color: '#1e293b',
  },
  modalItemTextActive: {
    color: '#6366f1',
  },
  checkMark: {
    fontSize: 14,
    fontWeight: '800',
    color: '#6366f1',
  },
  modalCloseButton: {
    marginTop: 12,
    padding: 14,
    borderRadius: 12,
    backgroundColor: '#f1f5f9',
    alignItems: 'center',
  },
  modalCloseText: {
    fontSize: 16,
    fontWeight: '600',
    color: '#64748b',
  },
});

export default AnalyticsScreen;
