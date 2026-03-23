import React, { useState, useEffect, useCallback } from 'react';
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  FlatList,
  ActivityIndicator,
  RefreshControl,
} from 'react-native';
import { format, startOfMonth, endOfMonth, eachDayOfInterval, getDay, addMonths, subMonths, isSameDay } from 'date-fns';
import { getClient } from '../api/client';

const PRIORITY_COLORS = {
  urgent: '#dc2626',
  high: '#ea580c',
  medium: '#ca8a04',
  low: '#16a34a',
};

const WEEKDAYS = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat'];

const CalendarScreen = ({ navigation }) => {
  const [currentMonth, setCurrentMonth] = useState(new Date());
  const [tasks, setTasks] = useState([]);
  const [selectedDate, setSelectedDate] = useState(new Date());
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);

  const fetchAllTasks = useCallback(async () => {
    try {
      const client = getClient();
      const res = await client.get('/api/boards');
      const boards = res.data.boards || res.data || [];
      const allTasks = [];

      for (const board of boards) {
        try {
          const boardRes = await client.get(`/api/boards/${board._id}`);
          const boardData = boardRes.data.board || boardRes.data;
          const columns = boardData.columns || [];
          columns.forEach((col) => {
            (col.tasks || []).forEach((task) => {
              allTasks.push({
                ...task,
                boardId: board._id,
                boardName: board.name,
                columnName: col.name,
              });
            });
          });
        } catch (e) {
          // skip boards that fail
        }
      }

      setTasks(allTasks);
    } catch (err) {
      console.error('Error fetching tasks for calendar:', err);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => {
    fetchAllTasks();
  }, [fetchAllTasks]);

  useEffect(() => {
    const unsubscribe = navigation.addListener('focus', () => {
      fetchAllTasks();
    });
    return unsubscribe;
  }, [navigation, fetchAllTasks]);

  const onRefresh = () => {
    setRefreshing(true);
    fetchAllTasks();
  };

  const monthStart = startOfMonth(currentMonth);
  const monthEnd = endOfMonth(currentMonth);
  const daysInMonth = eachDayOfInterval({ start: monthStart, end: monthEnd });
  const startDayOfWeek = getDay(monthStart);

  const getTasksForDate = (date) => {
    return tasks.filter((task) => {
      if (!task.dueDate) return false;
      return isSameDay(new Date(task.dueDate), date);
    });
  };

  const selectedTasks = getTasksForDate(selectedDate);

  const getPriorityDotsForDate = (date) => {
    const dateTasks = getTasksForDate(date);
    const priorities = [...new Set(dateTasks.map((t) => t.priority))];
    return priorities.slice(0, 3);
  };

  const goToPrevMonth = () => setCurrentMonth(subMonths(currentMonth, 1));
  const goToNextMonth = () => setCurrentMonth(addMonths(currentMonth, 1));

  const isToday = (date) => isSameDay(date, new Date());
  const isSelected = (date) => isSameDay(date, selectedDate);

  const renderCalendarGrid = () => {
    const blanks = [];
    for (let i = 0; i < startDayOfWeek; i++) {
      blanks.push(<View key={`blank-${i}`} style={styles.dayCell} />);
    }

    const dayCells = daysInMonth.map((day) => {
      const dots = getPriorityDotsForDate(day);
      const dayTaskCount = getTasksForDate(day).length;

      return (
        <TouchableOpacity
          key={day.toISOString()}
          style={[
            styles.dayCell,
            isToday(day) && styles.todayCell,
            isSelected(day) && styles.selectedCell,
          ]}
          onPress={() => setSelectedDate(day)}
          activeOpacity={0.7}
        >
          <Text
            style={[
              styles.dayText,
              isToday(day) && styles.todayText,
              isSelected(day) && styles.selectedDayText,
            ]}
          >
            {format(day, 'd')}
          </Text>
          {dots.length > 0 && (
            <View style={styles.dotsRow}>
              {dots.map((priority, idx) => (
                <View
                  key={idx}
                  style={[
                    styles.priorityDot,
                    { backgroundColor: PRIORITY_COLORS[priority] || '#94a3b8' },
                  ]}
                />
              ))}
            </View>
          )}
        </TouchableOpacity>
      );
    });

    return [...blanks, ...dayCells];
  };

  const renderTaskItem = ({ item }) => {
    const priorityColor = PRIORITY_COLORS[item.priority] || '#94a3b8';

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
        <View style={[styles.taskAccent, { backgroundColor: priorityColor }]} />
        <View style={styles.taskContent}>
          <Text style={styles.taskTitle} numberOfLines={1}>
            {item.title}
          </Text>
          <View style={styles.taskMeta}>
            <Text style={styles.taskBoard}>{item.boardName}</Text>
            <Text style={styles.taskColumn}>{item.columnName}</Text>
          </View>
        </View>
        <View style={[styles.taskPriorityBadge, { backgroundColor: priorityColor + '18' }]}>
          <Text style={[styles.taskPriorityText, { color: priorityColor }]}>
            {(item.priority || 'medium').charAt(0).toUpperCase() + (item.priority || 'medium').slice(1)}
          </Text>
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
      {/* Header */}
      <View style={styles.header}>
        <Text style={styles.headerTitle}>Calendar</Text>
      </View>

      {/* Month Navigation */}
      <View style={styles.monthNav}>
        <TouchableOpacity onPress={goToPrevMonth} style={styles.navButton}>
          <Text style={styles.navButtonText}>{'<'}</Text>
        </TouchableOpacity>
        <Text style={styles.monthTitle}>{format(currentMonth, 'MMMM yyyy')}</Text>
        <TouchableOpacity onPress={goToNextMonth} style={styles.navButton}>
          <Text style={styles.navButtonText}>{'>'}</Text>
        </TouchableOpacity>
      </View>

      {/* Weekday headers */}
      <View style={styles.weekdayRow}>
        {WEEKDAYS.map((day) => (
          <View key={day} style={styles.weekdayCell}>
            <Text style={styles.weekdayText}>{day}</Text>
          </View>
        ))}
      </View>

      {/* Calendar Grid */}
      <View style={styles.calendarGrid}>{renderCalendarGrid()}</View>

      {/* Selected date tasks */}
      <View style={styles.selectedDateHeader}>
        <Text style={styles.selectedDateTitle}>
          {format(selectedDate, 'EEEE, MMM d')}
        </Text>
        <Text style={styles.selectedDateCount}>
          {selectedTasks.length} {selectedTasks.length === 1 ? 'task' : 'tasks'}
        </Text>
      </View>

      <FlatList
        data={selectedTasks}
        renderItem={renderTaskItem}
        keyExtractor={(item) => item._id}
        contentContainerStyle={styles.taskList}
        refreshControl={
          <RefreshControl refreshing={refreshing} onRefresh={onRefresh} colors={['#6366f1']} tintColor="#6366f1" />
        }
        ListEmptyComponent={
          <View style={styles.emptyContainer}>
            <Text style={styles.emptyText}>No tasks due on this date</Text>
          </View>
        }
      />
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
  monthNav: {
    flexDirection: 'row',
    alignItems: 'center',
    justifyContent: 'space-between',
    paddingHorizontal: 20,
    paddingVertical: 12,
  },
  navButton: {
    width: 40,
    height: 40,
    borderRadius: 12,
    backgroundColor: '#eef2ff',
    justifyContent: 'center',
    alignItems: 'center',
  },
  navButtonText: {
    fontSize: 20,
    fontWeight: '700',
    color: '#6366f1',
  },
  monthTitle: {
    fontSize: 18,
    fontWeight: '700',
    color: '#1e293b',
  },
  weekdayRow: {
    flexDirection: 'row',
    paddingHorizontal: 12,
    marginBottom: 4,
  },
  weekdayCell: {
    flex: 1,
    alignItems: 'center',
    paddingVertical: 6,
  },
  weekdayText: {
    fontSize: 12,
    fontWeight: '600',
    color: '#94a3b8',
    textTransform: 'uppercase',
  },
  calendarGrid: {
    flexDirection: 'row',
    flexWrap: 'wrap',
    paddingHorizontal: 12,
    marginBottom: 8,
  },
  dayCell: {
    width: '14.28%',
    aspectRatio: 1,
    justifyContent: 'center',
    alignItems: 'center',
    padding: 2,
  },
  todayCell: {
    backgroundColor: '#eef2ff',
    borderRadius: 12,
  },
  selectedCell: {
    backgroundColor: '#6366f1',
    borderRadius: 12,
  },
  dayText: {
    fontSize: 14,
    fontWeight: '600',
    color: '#334155',
  },
  todayText: {
    color: '#6366f1',
    fontWeight: '800',
  },
  selectedDayText: {
    color: '#ffffff',
    fontWeight: '800',
  },
  dotsRow: {
    flexDirection: 'row',
    gap: 2,
    marginTop: 2,
  },
  priorityDot: {
    width: 5,
    height: 5,
    borderRadius: 2.5,
  },
  selectedDateHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingHorizontal: 20,
    paddingVertical: 10,
    borderTopWidth: 1,
    borderTopColor: '#e2e8f0',
  },
  selectedDateTitle: {
    fontSize: 16,
    fontWeight: '700',
    color: '#1e293b',
  },
  selectedDateCount: {
    fontSize: 13,
    fontWeight: '600',
    color: '#64748b',
  },
  taskList: {
    paddingHorizontal: 16,
    paddingBottom: 100,
  },
  taskCard: {
    backgroundColor: '#ffffff',
    borderRadius: 14,
    marginBottom: 10,
    flexDirection: 'row',
    alignItems: 'center',
    overflow: 'hidden',
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.06,
    shadowRadius: 8,
    elevation: 3,
  },
  taskAccent: {
    width: 4,
    alignSelf: 'stretch',
  },
  taskContent: {
    flex: 1,
    padding: 14,
  },
  taskTitle: {
    fontSize: 15,
    fontWeight: '600',
    color: '#1e293b',
    marginBottom: 4,
  },
  taskMeta: {
    flexDirection: 'row',
    gap: 8,
  },
  taskBoard: {
    fontSize: 12,
    color: '#6366f1',
    fontWeight: '600',
  },
  taskColumn: {
    fontSize: 12,
    color: '#94a3b8',
    fontWeight: '500',
  },
  taskPriorityBadge: {
    paddingHorizontal: 10,
    paddingVertical: 4,
    borderRadius: 8,
    marginRight: 14,
  },
  taskPriorityText: {
    fontSize: 11,
    fontWeight: '700',
  },
  emptyContainer: {
    alignItems: 'center',
    paddingTop: 24,
  },
  emptyText: {
    fontSize: 14,
    color: '#94a3b8',
    fontStyle: 'italic',
  },
});

export default CalendarScreen;
