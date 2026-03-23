import React, { useState, useEffect, useRef } from 'react';
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  FlatList,
} from 'react-native';
import { format } from 'date-fns';

const formatDuration = (seconds) => {
  const hrs = Math.floor(seconds / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  const secs = seconds % 60;
  const pad = (n) => String(n).padStart(2, '0');
  return `${pad(hrs)}:${pad(mins)}:${pad(secs)}`;
};

const formatDurationShort = (seconds) => {
  const hrs = Math.floor(seconds / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  if (hrs > 0) return `${hrs}h ${mins}m`;
  return `${mins}m`;
};

const TimeTracker = ({ timeEntries = [], onStart, onStop, isRunning = false, currentStartTime }) => {
  const [elapsed, setElapsed] = useState(0);
  const intervalRef = useRef(null);

  useEffect(() => {
    if (isRunning && currentStartTime) {
      const updateElapsed = () => {
        const start = new Date(currentStartTime).getTime();
        const now = Date.now();
        setElapsed(Math.floor((now - start) / 1000));
      };
      updateElapsed();
      intervalRef.current = setInterval(updateElapsed, 1000);
      return () => clearInterval(intervalRef.current);
    } else {
      setElapsed(0);
      if (intervalRef.current) clearInterval(intervalRef.current);
    }
  }, [isRunning, currentStartTime]);

  const totalSeconds = timeEntries.reduce((acc, entry) => {
    if (entry.duration) return acc + entry.duration;
    if (entry.startTime && entry.endTime) {
      const start = new Date(entry.startTime).getTime();
      const end = new Date(entry.endTime).getTime();
      return acc + Math.floor((end - start) / 1000);
    }
    return acc;
  }, 0);

  const handleToggle = () => {
    if (isRunning) {
      if (onStop) onStop();
    } else {
      if (onStart) onStart();
    }
  };

  const renderEntry = ({ item, index }) => {
    const duration = item.duration ||
      (item.startTime && item.endTime
        ? Math.floor((new Date(item.endTime).getTime() - new Date(item.startTime).getTime()) / 1000)
        : 0);
    const dateStr = item.startTime
      ? format(new Date(item.startTime), 'MMM d, yyyy')
      : item.date
        ? format(new Date(item.date), 'MMM d, yyyy')
        : `Entry ${index + 1}`;
    const timeStr = item.startTime
      ? format(new Date(item.startTime), 'HH:mm') + (item.endTime ? ' - ' + format(new Date(item.endTime), 'HH:mm') : '')
      : '';

    return (
      <View style={styles.entryRow}>
        <View style={styles.entryInfo}>
          <Text style={styles.entryDate}>{dateStr}</Text>
          {timeStr ? <Text style={styles.entryTime}>{timeStr}</Text> : null}
        </View>
        <Text style={styles.entryDuration}>{formatDurationShort(duration)}</Text>
      </View>
    );
  };

  return (
    <View style={styles.container}>
      {/* Timer Display */}
      <View style={styles.timerSection}>
        <Text style={[styles.timerDisplay, isRunning && styles.timerDisplayActive]}>
          {formatDuration(isRunning ? elapsed : 0)}
        </Text>

        {/* Start/Stop Button */}
        <TouchableOpacity
          style={[styles.toggleButton, isRunning ? styles.stopButton : styles.startButton]}
          onPress={handleToggle}
          activeOpacity={0.7}
        >
          <Text style={styles.toggleButtonText}>
            {isRunning ? 'Stop' : 'Start'}
          </Text>
        </TouchableOpacity>
      </View>

      {/* Total Time */}
      <View style={styles.totalRow}>
        <Text style={styles.totalLabel}>Total Tracked</Text>
        <Text style={styles.totalValue}>
          {formatDurationShort(totalSeconds + (isRunning ? elapsed : 0))}
        </Text>
      </View>

      {/* Time Entries */}
      {timeEntries.length > 0 && (
        <View style={styles.entriesSection}>
          <Text style={styles.entriesTitle}>Time Entries</Text>
          <FlatList
            data={timeEntries}
            renderItem={renderEntry}
            keyExtractor={(item, index) => item._id || String(index)}
            scrollEnabled={false}
          />
        </View>
      )}
    </View>
  );
};

const styles = StyleSheet.create({
  container: {},
  timerSection: {
    alignItems: 'center',
    paddingVertical: 12,
  },
  timerDisplay: {
    fontSize: 40,
    fontWeight: '300',
    color: '#94a3b8',
    fontVariant: ['tabular-nums'],
    marginBottom: 16,
  },
  timerDisplayActive: {
    color: '#6366f1',
    fontWeight: '400',
  },
  toggleButton: {
    width: 80,
    height: 80,
    borderRadius: 40,
    justifyContent: 'center',
    alignItems: 'center',
    shadowOffset: { width: 0, height: 4 },
    shadowOpacity: 0.25,
    shadowRadius: 8,
    elevation: 6,
  },
  startButton: {
    backgroundColor: '#22c55e',
    shadowColor: '#22c55e',
  },
  stopButton: {
    backgroundColor: '#dc2626',
    shadowColor: '#dc2626',
  },
  toggleButtonText: {
    color: '#ffffff',
    fontSize: 15,
    fontWeight: '800',
    textTransform: 'uppercase',
    letterSpacing: 1,
  },
  totalRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    marginTop: 16,
    paddingTop: 14,
    borderTopWidth: 1,
    borderTopColor: '#f1f5f9',
  },
  totalLabel: {
    fontSize: 14,
    fontWeight: '600',
    color: '#64748b',
  },
  totalValue: {
    fontSize: 18,
    fontWeight: '800',
    color: '#6366f1',
  },
  entriesSection: {
    marginTop: 14,
    paddingTop: 14,
    borderTopWidth: 1,
    borderTopColor: '#f1f5f9',
  },
  entriesTitle: {
    fontSize: 13,
    fontWeight: '700',
    color: '#64748b',
    textTransform: 'uppercase',
    letterSpacing: 0.5,
    marginBottom: 10,
  },
  entryRow: {
    flexDirection: 'row',
    justifyContent: 'space-between',
    alignItems: 'center',
    paddingVertical: 8,
    borderBottomWidth: 1,
    borderBottomColor: '#f8fafc',
  },
  entryInfo: {},
  entryDate: {
    fontSize: 14,
    fontWeight: '600',
    color: '#1e293b',
  },
  entryTime: {
    fontSize: 12,
    color: '#94a3b8',
    marginTop: 2,
  },
  entryDuration: {
    fontSize: 15,
    fontWeight: '700',
    color: '#334155',
  },
});

export default TimeTracker;
