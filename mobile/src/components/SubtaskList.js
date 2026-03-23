import React, { useState } from 'react';
import {
  View,
  Text,
  TextInput,
  TouchableOpacity,
  StyleSheet,
  Alert,
} from 'react-native';

const SubtaskList = ({ subtasks = [], onUpdate, boardId, taskId }) => {
  const [newItem, setNewItem] = useState('');

  const items = subtasks || [];
  const completedCount = items.filter((s) => s.completed).length;
  const totalCount = items.length;
  const progress = totalCount > 0 ? completedCount / totalCount : 0;

  const handleToggle = (index) => {
    const updated = items.map((item, i) =>
      i === index ? { ...item, completed: !item.completed } : item
    );
    if (onUpdate) onUpdate(updated);
  };

  const handleAdd = () => {
    if (!newItem.trim()) return;
    const updated = [...items, { title: newItem.trim(), completed: false }];
    setNewItem('');
    if (onUpdate) onUpdate(updated);
  };

  const handleDelete = (index) => {
    Alert.alert('Delete Item', 'Remove this checklist item?', [
      { text: 'Cancel', style: 'cancel' },
      {
        text: 'Delete',
        style: 'destructive',
        onPress: () => {
          const updated = items.filter((_, i) => i !== index);
          if (onUpdate) onUpdate(updated);
        },
      },
    ]);
  };

  return (
    <View style={styles.container}>
      {/* Progress Bar */}
      <View style={styles.progressSection}>
        <View style={styles.progressHeader}>
          <Text style={styles.progressLabel}>Checklist</Text>
          <Text style={styles.progressCount}>
            {completedCount}/{totalCount}
          </Text>
        </View>
        <View style={styles.progressTrack}>
          <View
            style={[
              styles.progressFill,
              { width: `${progress * 100}%` },
              progress === 1 && styles.progressComplete,
            ]}
          />
        </View>
      </View>

      {/* Items */}
      {items.map((item, index) => (
        <View key={index} style={styles.itemRow}>
          <TouchableOpacity
            style={[styles.checkbox, item.completed && styles.checkboxChecked]}
            onPress={() => handleToggle(index)}
            activeOpacity={0.6}
          >
            {item.completed && <Text style={styles.checkmark}>OK</Text>}
          </TouchableOpacity>
          <Text
            style={[styles.itemText, item.completed && styles.itemTextCompleted]}
            numberOfLines={2}
          >
            {item.title || item.text || item.name}
          </Text>
          <TouchableOpacity
            style={styles.deleteButton}
            onPress={() => handleDelete(index)}
            hitSlop={{ top: 8, bottom: 8, left: 8, right: 8 }}
          >
            <Text style={styles.deleteText}>X</Text>
          </TouchableOpacity>
        </View>
      ))}

      {/* Add Item */}
      <View style={styles.addRow}>
        <TextInput
          style={styles.addInput}
          value={newItem}
          onChangeText={setNewItem}
          placeholder="Add checklist item..."
          placeholderTextColor="#94a3b8"
          onSubmitEditing={handleAdd}
          returnKeyType="done"
        />
        <TouchableOpacity
          style={[styles.addButton, !newItem.trim() && styles.addButtonDisabled]}
          onPress={handleAdd}
          disabled={!newItem.trim()}
        >
          <Text style={styles.addButtonText}>+</Text>
        </TouchableOpacity>
      </View>
    </View>
  );
};

const styles = StyleSheet.create({
  container: {},
  progressSection: {
    marginBottom: 14,
  },
  progressHeader: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginBottom: 8,
  },
  progressLabel: {
    fontSize: 13,
    fontWeight: '700',
    color: '#64748b',
    textTransform: 'uppercase',
    letterSpacing: 0.5,
  },
  progressCount: {
    fontSize: 13,
    fontWeight: '700',
    color: '#6366f1',
  },
  progressTrack: {
    height: 8,
    backgroundColor: '#f1f5f9',
    borderRadius: 4,
    overflow: 'hidden',
  },
  progressFill: {
    height: '100%',
    backgroundColor: '#6366f1',
    borderRadius: 4,
    minWidth: 2,
  },
  progressComplete: {
    backgroundColor: '#22c55e',
  },
  itemRow: {
    flexDirection: 'row',
    alignItems: 'center',
    paddingVertical: 8,
    borderBottomWidth: 1,
    borderBottomColor: '#f1f5f9',
  },
  checkbox: {
    width: 24,
    height: 24,
    borderRadius: 6,
    borderWidth: 2,
    borderColor: '#d1d5db',
    justifyContent: 'center',
    alignItems: 'center',
    marginRight: 12,
  },
  checkboxChecked: {
    backgroundColor: '#6366f1',
    borderColor: '#6366f1',
  },
  checkmark: {
    fontSize: 9,
    fontWeight: '900',
    color: '#ffffff',
  },
  itemText: {
    flex: 1,
    fontSize: 14,
    color: '#1e293b',
    lineHeight: 20,
  },
  itemTextCompleted: {
    textDecorationLine: 'line-through',
    color: '#94a3b8',
  },
  deleteButton: {
    width: 28,
    height: 28,
    borderRadius: 8,
    backgroundColor: '#fef2f2',
    justifyContent: 'center',
    alignItems: 'center',
    marginLeft: 8,
  },
  deleteText: {
    fontSize: 11,
    fontWeight: '800',
    color: '#dc2626',
  },
  addRow: {
    flexDirection: 'row',
    gap: 8,
    marginTop: 10,
  },
  addInput: {
    flex: 1,
    borderWidth: 1.5,
    borderColor: '#e2e8f0',
    borderRadius: 10,
    padding: 10,
    fontSize: 14,
    color: '#1e293b',
    backgroundColor: '#f8fafc',
  },
  addButton: {
    width: 40,
    height: 40,
    borderRadius: 10,
    backgroundColor: '#6366f1',
    justifyContent: 'center',
    alignItems: 'center',
  },
  addButtonDisabled: {
    backgroundColor: '#c7d2fe',
  },
  addButtonText: {
    fontSize: 22,
    fontWeight: '600',
    color: '#ffffff',
    marginTop: -2,
  },
});

export default SubtaskList;
