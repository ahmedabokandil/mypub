import React from 'react';
import { View, Text, TouchableOpacity, StyleSheet } from 'react-native';
import { format, isPast, isToday } from 'date-fns';

const PRIORITY_COLORS = {
  urgent: { bg: '#fef2f2', text: '#dc2626', label: 'Urgent' },
  high: { bg: '#fff7ed', text: '#ea580c', label: 'High' },
  medium: { bg: '#fefce8', text: '#ca8a04', label: 'Medium' },
  low: { bg: '#f0fdf4', text: '#16a34a', label: 'Low' },
};

const TaskCard = ({ task, onPress }) => {
  const priority = PRIORITY_COLORS[task.priority] || PRIORITY_COLORS.medium;
  const dueDate = task.dueDate ? new Date(task.dueDate) : null;
  const isOverdue = dueDate && isPast(dueDate) && !isToday(dueDate);

  return (
    <TouchableOpacity style={styles.card} onPress={onPress} activeOpacity={0.7}>
      <View style={styles.header}>
        <Text style={styles.title} numberOfLines={2}>
          {task.title}
        </Text>
        <View style={[styles.priorityBadge, { backgroundColor: priority.bg }]}>
          <Text style={[styles.priorityText, { color: priority.text }]}>
            {priority.label}
          </Text>
        </View>
      </View>

      {task.description ? (
        <Text style={styles.description} numberOfLines={2}>
          {task.description}
        </Text>
      ) : null}

      <View style={styles.footer}>
        {dueDate ? (
          <View style={styles.footerItem}>
            <Text style={styles.iconText}>📅</Text>
            <Text style={[styles.dateText, isOverdue && styles.overdueText]}>
              {format(dueDate, 'MMM d')}
            </Text>
          </View>
        ) : null}

        {task.attachments?.length > 0 ? (
          <View style={styles.footerItem}>
            <Text style={styles.iconText}>📎</Text>
            <Text style={styles.countText}>{task.attachments.length}</Text>
          </View>
        ) : null}

        {task.comments?.length > 0 || task.commentCount > 0 ? (
          <View style={styles.footerItem}>
            <Text style={styles.iconText}>💬</Text>
            <Text style={styles.countText}>
              {task.comments?.length || task.commentCount}
            </Text>
          </View>
        ) : null}

        {task.reminder ? (
          <View style={styles.footerItem}>
            <Text style={styles.iconText}>🔔</Text>
          </View>
        ) : null}
      </View>
    </TouchableOpacity>
  );
};

const styles = StyleSheet.create({
  card: {
    backgroundColor: '#ffffff',
    borderRadius: 12,
    padding: 14,
    marginBottom: 10,
    shadowColor: '#000',
    shadowOffset: { width: 0, height: 2 },
    shadowOpacity: 0.08,
    shadowRadius: 8,
    elevation: 3,
  },
  header: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'flex-start',
    marginBottom: 6,
  },
  title: {
    fontSize: 15,
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
  description: {
    fontSize: 13,
    color: '#64748b',
    marginBottom: 8,
    lineHeight: 18,
  },
  footer: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 12,
    marginTop: 4,
  },
  footerItem: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 4,
  },
  iconText: {
    fontSize: 12,
  },
  dateText: {
    fontSize: 12,
    color: '#64748b',
    fontWeight: '500',
  },
  overdueText: {
    color: '#dc2626',
  },
  countText: {
    fontSize: 12,
    color: '#64748b',
    fontWeight: '500',
  },
});

export default TaskCard;
