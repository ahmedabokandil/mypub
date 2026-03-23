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

  // Subtask progress
  const subtasks = task.subtasks || task.checklist || [];
  const subtaskTotal = subtasks.length;
  const subtaskCompleted = subtasks.filter((s) => s.completed).length;
  const subtaskProgress = subtaskTotal > 0 ? subtaskCompleted / subtaskTotal : 0;

  // Recurring indicator
  const isRecurring = !!(task.recurrence || task.recurringPattern);

  // Assignees
  const assignees = task.assignees || task.assignedTo || [];

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

      {/* Subtask Progress */}
      {subtaskTotal > 0 && (
        <View style={styles.subtaskSection}>
          <View style={styles.subtaskTrack}>
            <View
              style={[
                styles.subtaskFill,
                { width: `${subtaskProgress * 100}%` },
                subtaskProgress === 1 && styles.subtaskFillComplete,
              ]}
            />
          </View>
          <Text style={styles.subtaskText}>
            {subtaskCompleted}/{subtaskTotal}
          </Text>
        </View>
      )}

      <View style={styles.footer}>
        {dueDate ? (
          <View style={styles.footerItem}>
            <Text style={[styles.dateText, isOverdue && styles.overdueText]}>
              {format(dueDate, 'MMM d')}
            </Text>
          </View>
        ) : null}

        {isRecurring && (
          <View style={styles.footerItem}>
            <Text style={styles.recurringIcon}>R</Text>
          </View>
        )}

        {task.attachments?.length > 0 ? (
          <View style={styles.footerItem}>
            <Text style={styles.countText}>{task.attachments.length} files</Text>
          </View>
        ) : null}

        {task.comments?.length > 0 || task.commentCount > 0 ? (
          <View style={styles.footerItem}>
            <Text style={styles.countText}>
              {task.comments?.length || task.commentCount} comments
            </Text>
          </View>
        ) : null}

        {task.reminder ? (
          <View style={styles.footerItem}>
            <Text style={styles.reminderDot}>!</Text>
          </View>
        ) : null}

        {/* Assignee Avatars */}
        {assignees.length > 0 && (
          <View style={styles.assigneesContainer}>
            {assignees.slice(0, 3).map((assignee, idx) => {
              const name = assignee?.name || assignee?.email || 'U';
              return (
                <View
                  key={assignee?._id || idx}
                  style={[
                    styles.assigneeAvatar,
                    { marginLeft: idx > 0 ? -6 : 0, zIndex: 3 - idx },
                  ]}
                >
                  <Text style={styles.assigneeInitial}>
                    {name.charAt(0).toUpperCase()}
                  </Text>
                </View>
              );
            })}
            {assignees.length > 3 && (
              <View style={[styles.assigneeAvatar, styles.assigneeMore, { marginLeft: -6 }]}>
                <Text style={styles.assigneeMoreText}>+{assignees.length - 3}</Text>
              </View>
            )}
          </View>
        )}
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
  subtaskSection: {
    flexDirection: 'row',
    alignItems: 'center',
    marginBottom: 8,
    gap: 8,
  },
  subtaskTrack: {
    flex: 1,
    height: 6,
    backgroundColor: '#f1f5f9',
    borderRadius: 3,
    overflow: 'hidden',
  },
  subtaskFill: {
    height: '100%',
    backgroundColor: '#6366f1',
    borderRadius: 3,
    minWidth: 2,
  },
  subtaskFillComplete: {
    backgroundColor: '#22c55e',
  },
  subtaskText: {
    fontSize: 11,
    fontWeight: '700',
    color: '#64748b',
  },
  footer: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 10,
    marginTop: 4,
    flexWrap: 'wrap',
  },
  footerItem: {
    flexDirection: 'row',
    alignItems: 'center',
    gap: 4,
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
  recurringIcon: {
    fontSize: 11,
    fontWeight: '900',
    color: '#6366f1',
    backgroundColor: '#eef2ff',
    width: 20,
    height: 20,
    lineHeight: 20,
    textAlign: 'center',
    borderRadius: 10,
    overflow: 'hidden',
  },
  reminderDot: {
    fontSize: 12,
    fontWeight: '800',
    color: '#f59e0b',
  },
  assigneesContainer: {
    flexDirection: 'row',
    alignItems: 'center',
    marginLeft: 'auto',
  },
  assigneeAvatar: {
    width: 22,
    height: 22,
    borderRadius: 11,
    backgroundColor: '#6366f1',
    justifyContent: 'center',
    alignItems: 'center',
    borderWidth: 2,
    borderColor: '#ffffff',
  },
  assigneeInitial: {
    color: '#ffffff',
    fontSize: 9,
    fontWeight: '700',
  },
  assigneeMore: {
    backgroundColor: '#94a3b8',
  },
  assigneeMoreText: {
    color: '#ffffff',
    fontSize: 8,
    fontWeight: '700',
  },
});

export default TaskCard;
