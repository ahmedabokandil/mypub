import React, { useState, useEffect, useRef, useCallback } from 'react';
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  FlatList,
  StyleSheet,
  ActivityIndicator,
  StatusBar,
} from 'react-native';
import { format, isPast, isToday } from 'date-fns';
import { getClient } from '../api/client';

const PRIORITY_FILTERS = [
  { key: 'all', label: 'All' },
  { key: 'high', label: 'High' },
  { key: 'medium', label: 'Medium' },
  { key: 'low', label: 'Low' },
  { key: 'urgent', label: 'Urgent' },
];

const PRIORITY_COLORS = {
  urgent: { bg: '#fef2f2', text: '#dc2626' },
  high: { bg: '#fff7ed', text: '#ea580c' },
  medium: { bg: '#fefce8', text: '#ca8a04' },
  low: { bg: '#f0fdf4', text: '#16a34a' },
};

const DATE_FILTERS = [
  { key: 'all', label: 'Any Date' },
  { key: 'overdue', label: 'Overdue' },
  { key: 'today', label: 'Today' },
  { key: 'week', label: 'This Week' },
];

const SearchScreen = ({ navigation }) => {
  const [query, setQuery] = useState('');
  const [allTasks, setAllTasks] = useState([]);
  const [results, setResults] = useState([]);
  const [loading, setLoading] = useState(true);
  const [priorityFilter, setPriorityFilter] = useState('all');
  const [dateFilter, setDateFilter] = useState('all');
  const debounceRef = useRef(null);
  const inputRef = useRef(null);

  const fetchAllTasks = useCallback(async () => {
    try {
      const client = getClient();
      const res = await client.get('/api/boards');
      const boards = res.data.boards || res.data || [];
      const tasks = [];

      for (const board of boards) {
        try {
          const boardRes = await client.get(`/api/boards/${board._id}`);
          const boardData = boardRes.data.board || boardRes.data;
          const columns = boardData.columns || [];
          columns.forEach((col) => {
            (col.tasks || []).forEach((task) => {
              tasks.push({
                ...task,
                boardId: board._id,
                boardName: board.name,
                columnName: col.name,
              });
            });
          });
        } catch (e) {
          // skip
        }
      }

      setAllTasks(tasks);
      setResults(tasks);
    } catch (err) {
      console.error('Error fetching tasks for search:', err);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAllTasks();
  }, [fetchAllTasks]);

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current);
    debounceRef.current = setTimeout(() => {
      filterTasks();
    }, 300);
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current);
    };
  }, [query, priorityFilter, dateFilter, allTasks]);

  const filterTasks = () => {
    let filtered = [...allTasks];

    // Text search
    if (query.trim()) {
      const q = query.toLowerCase();
      filtered = filtered.filter(
        (t) =>
          t.title?.toLowerCase().includes(q) ||
          t.description?.toLowerCase().includes(q) ||
          t.boardName?.toLowerCase().includes(q)
      );
    }

    // Priority filter
    if (priorityFilter !== 'all') {
      filtered = filtered.filter((t) => t.priority === priorityFilter);
    }

    // Date filter
    if (dateFilter !== 'all') {
      const now = new Date();
      filtered = filtered.filter((t) => {
        if (!t.dueDate) return false;
        const due = new Date(t.dueDate);
        switch (dateFilter) {
          case 'overdue':
            return isPast(due) && !isToday(due);
          case 'today':
            return isToday(due);
          case 'week': {
            const weekFromNow = new Date(now.getTime() + 7 * 24 * 60 * 60 * 1000);
            return due >= now && due <= weekFromNow;
          }
          default:
            return true;
        }
      });
    }

    setResults(filtered);
  };

  const renderTaskCard = ({ item }) => {
    const priority = PRIORITY_COLORS[item.priority] || PRIORITY_COLORS.medium;
    const dueDate = item.dueDate ? new Date(item.dueDate) : null;
    const isOverdue = dueDate && isPast(dueDate) && !isToday(dueDate);

    return (
      <TouchableOpacity
        style={styles.taskCard}
        onPress={() =>
          navigation.navigate('TaskDetail', {
            taskId: item._id,
            boardId: item.boardId,
            boardName: item.boardName,
          })
        }
        activeOpacity={0.7}
      >
        <View style={styles.taskCardContent}>
          <View style={styles.taskCardHeader}>
            <Text style={styles.taskTitle} numberOfLines={1}>
              {item.title}
            </Text>
            <View style={[styles.priorityBadge, { backgroundColor: priority.bg }]}>
              <Text style={[styles.priorityText, { color: priority.text }]}>
                {(item.priority || 'medium').charAt(0).toUpperCase() + (item.priority || 'medium').slice(1)}
              </Text>
            </View>
          </View>

          {item.description ? (
            <Text style={styles.taskDesc} numberOfLines={2}>
              {item.description}
            </Text>
          ) : null}

          <View style={styles.taskMeta}>
            <View style={styles.boardBadge}>
              <Text style={styles.boardBadgeText}>{item.boardName}</Text>
            </View>
            <Text style={styles.columnText}>{item.columnName}</Text>
            {dueDate && (
              <Text style={[styles.dateText, isOverdue && styles.overdueText]}>
                {format(dueDate, 'MMM d')}
              </Text>
            )}
          </View>
        </View>
      </TouchableOpacity>
    );
  };

  return (
    <View style={styles.container}>
      <StatusBar barStyle="dark-content" backgroundColor="#f8fafc" />

      {/* Header */}
      <View style={styles.header}>
        <Text style={styles.headerTitle}>Search</Text>
      </View>

      {/* Search Input */}
      <View style={styles.searchContainer}>
        <View style={styles.searchInputWrap}>
          <Text style={styles.searchIcon}>S</Text>
          <TextInput
            ref={inputRef}
            style={styles.searchInput}
            value={query}
            onChangeText={setQuery}
            placeholder="Search tasks, boards..."
            placeholderTextColor="#94a3b8"
            autoCapitalize="none"
            returnKeyType="search"
          />
          {query.length > 0 && (
            <TouchableOpacity onPress={() => setQuery('')} style={styles.clearButton}>
              <Text style={styles.clearText}>X</Text>
            </TouchableOpacity>
          )}
        </View>
      </View>

      {/* Priority Filter Chips */}
      <View style={styles.filterSection}>
        <FlatList
          horizontal
          data={PRIORITY_FILTERS}
          keyExtractor={(item) => item.key}
          showsHorizontalScrollIndicator={false}
          contentContainerStyle={styles.filterChips}
          renderItem={({ item }) => (
            <TouchableOpacity
              style={[
                styles.chip,
                priorityFilter === item.key && styles.chipActive,
              ]}
              onPress={() => setPriorityFilter(item.key)}
            >
              <Text
                style={[
                  styles.chipText,
                  priorityFilter === item.key && styles.chipTextActive,
                ]}
              >
                {item.label}
              </Text>
            </TouchableOpacity>
          )}
        />
      </View>

      {/* Date Filter Chips */}
      <View style={styles.filterSection}>
        <FlatList
          horizontal
          data={DATE_FILTERS}
          keyExtractor={(item) => item.key}
          showsHorizontalScrollIndicator={false}
          contentContainerStyle={styles.filterChips}
          renderItem={({ item }) => (
            <TouchableOpacity
              style={[
                styles.chip,
                dateFilter === item.key && styles.chipActive,
              ]}
              onPress={() => setDateFilter(item.key)}
            >
              <Text
                style={[
                  styles.chipText,
                  dateFilter === item.key && styles.chipTextActive,
                ]}
              >
                {item.label}
              </Text>
            </TouchableOpacity>
          )}
        />
      </View>

      {/* Results */}
      {loading ? (
        <View style={styles.centerContainer}>
          <ActivityIndicator size="large" color="#6366f1" />
        </View>
      ) : (
        <FlatList
          data={results}
          renderItem={renderTaskCard}
          keyExtractor={(item) => item._id}
          contentContainerStyle={styles.resultsList}
          ListEmptyComponent={
            <View style={styles.emptyContainer}>
              <Text style={styles.emptyIcon}>Q</Text>
              <Text style={styles.emptyTitle}>
                {query.trim() || priorityFilter !== 'all' || dateFilter !== 'all'
                  ? 'No results found'
                  : 'No tasks yet'}
              </Text>
              <Text style={styles.emptyText}>
                {query.trim()
                  ? 'Try adjusting your search or filters'
                  : 'Tasks from your boards will appear here'}
              </Text>
            </View>
          }
          ListHeaderComponent={
            results.length > 0 ? (
              <Text style={styles.resultCount}>
                {results.length} {results.length === 1 ? 'result' : 'results'}
              </Text>
            ) : null
          }
        />
      )}
    </View>
  );
};

const styles = StyleSheet.create({
  container: {
    flex: 1,
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
  searchContainer: {
    paddingHorizontal: 16,
    paddingVertical: 8,
  },
  searchInputWrap: {
    flexDirection: 'row',
    alignItems: 'center',
    backgroundColor: '#ffffff',
    borderRadius: 14,
    borderWidth: 1.5,
    borderColor: '#e2e8f0',
    paddingHorizontal: 14,
  },
  searchIcon: {
    fontSize: 16,
    fontWeight: '700',
    color: '#94a3b8',
    marginRight: 10,
  },
  searchInput: {
    flex: 1,
    paddingVertical: 14,
    fontSize: 16,
    color: '#1e293b',
  },
  clearButton: {
    width: 28,
    height: 28,
    borderRadius: 14,
    backgroundColor: '#f1f5f9',
    justifyContent: 'center',
    alignItems: 'center',
  },
  clearText: {
    fontSize: 12,
    fontWeight: '700',
    color: '#64748b',
  },
  filterSection: {
    marginBottom: 4,
  },
  filterChips: {
    paddingHorizontal: 16,
    gap: 8,
  },
  chip: {
    paddingHorizontal: 16,
    paddingVertical: 8,
    borderRadius: 20,
    backgroundColor: '#ffffff',
    borderWidth: 1.5,
    borderColor: '#e2e8f0',
  },
  chipActive: {
    backgroundColor: '#6366f1',
    borderColor: '#6366f1',
  },
  chipText: {
    fontSize: 13,
    fontWeight: '600',
    color: '#64748b',
  },
  chipTextActive: {
    color: '#ffffff',
  },
  centerContainer: {
    flex: 1,
    justifyContent: 'center',
    alignItems: 'center',
  },
  resultsList: {
    paddingHorizontal: 16,
    paddingTop: 8,
    paddingBottom: 100,
  },
  resultCount: {
    fontSize: 13,
    fontWeight: '600',
    color: '#64748b',
    marginBottom: 10,
  },
  taskCard: {
    backgroundColor: '#ffffff',
    borderRadius: 14,
    marginBottom: 10,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.06,
    shadowRadius: 8,
    elevation: 3,
  },
  taskCardContent: {
    padding: 16,
  },
  taskCardHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: 6,
  },
  taskTitle: {
    fontSize: 16,
    fontWeight: '600',
    color: '#1e293b',
    flex: 1,
    marginRight: 8,
  },
  priorityBadge: {
    paddingHorizontal: 8,
    paddingVertical: 3,
    borderRadius: 6,
  },
  priorityText: {
    fontSize: 11,
    fontWeight: '700',
    textTransform: 'uppercase',
  },
  taskDesc: {
    fontSize: 13,
    color: '#64748b',
    marginBottom: 8,
    lineHeight: 18,
  },
  taskMeta: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 8,
  },
  boardBadge: {
    backgroundColor: '#eef2ff',
    paddingHorizontal: 8,
    paddingVertical: 3,
    borderRadius: 6,
  },
  boardBadgeText: {
    fontSize: 11,
    fontWeight: '600',
    color: '#6366f1',
  },
  columnText: {
    fontSize: 12,
    color: '#94a3b8',
    fontWeight: '500',
  },
  dateText: {
    fontSize: 12,
    color: '#64748b',
    fontWeight: '500',
  },
  overdueText: {
    color: '#dc2626',
  },
  emptyContainer: {
    alignItems: 'center',
    paddingTop: 60,
  },
  emptyIcon: {
    fontSize: 40,
    fontWeight: '800',
    color: '#cbd5e1',
    marginBottom: 16,
    width: 64,
    height: 64,
    lineHeight: 64,
    textAlign: 'center',
    borderRadius: 32,
    backgroundColor: '#f1f5f9',
  },
  emptyTitle: {
    fontSize: 18,
    fontWeight: '700',
    color: '#1e293b',
    marginBottom: 6,
  },
  emptyText: {
    fontSize: 14,
    color: '#64748b',
    textAlign: 'center',
    maxWidth: 260,
  },
});

export default SearchScreen;
