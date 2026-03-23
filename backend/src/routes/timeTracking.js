const express = require('express');
const prisma = require('../db');
const auth = require('../middleware/auth');
const router = express.Router();

router.use(auth);

// POST /api/tasks/:taskId/time/start - start timer
router.post('/tasks/:taskId/time/start', async (req, res) => {
  try {
    const { taskId } = req.params;
    const { description } = req.body;

    const entry = await prisma.timeEntry.create({
      data: {
        taskId,
        userId: req.user.userId,
        startTime: new Date(),
        description: description || null,
      },
    });

    res.status(201).json({ entry });
  } catch (error) {
    console.error('Start timer error:', error);
    res.status(500).json({ error: 'Failed to start timer' });
  }
});

// PUT /api/time/:id/stop - stop timer
router.put('/time/:id/stop', async (req, res) => {
  try {
    const { id } = req.params;
    const entry = await prisma.timeEntry.findUnique({ where: { id } });
    if (!entry) return res.status(404).json({ error: 'Time entry not found' });
    if (entry.endTime) return res.status(400).json({ error: 'Timer already stopped' });

    const endTime = new Date();
    const duration = Math.round((endTime - new Date(entry.startTime)) / 1000);

    const updated = await prisma.timeEntry.update({
      where: { id },
      data: { endTime, duration },
    });

    res.json({ entry: updated });
  } catch (error) {
    console.error('Stop timer error:', error);
    res.status(500).json({ error: 'Failed to stop timer' });
  }
});

// GET /api/tasks/:taskId/time - list time entries for task
router.get('/tasks/:taskId/time', async (req, res) => {
  try {
    const { taskId } = req.params;

    const entries = await prisma.timeEntry.findMany({
      where: { taskId },
      include: {
        user: { select: { id: true, name: true, avatar: true } },
      },
      orderBy: { startTime: 'desc' },
    });

    const totalDuration = entries.reduce((sum, e) => sum + (e.duration || 0), 0);

    res.json({ entries, totalDuration });
  } catch (error) {
    console.error('List time entries error:', error);
    res.status(500).json({ error: 'Failed to list time entries' });
  }
});

// DELETE /api/time/:id - delete time entry
router.delete('/time/:id', async (req, res) => {
  try {
    const { id } = req.params;
    await prisma.timeEntry.delete({ where: { id } });
    res.json({ message: 'Time entry deleted' });
  } catch (error) {
    console.error('Delete time entry error:', error);
    res.status(500).json({ error: 'Failed to delete time entry' });
  }
});

// GET /api/boards/:boardId/time-report - time summary per task/user
router.get('/boards/:boardId/time-report', async (req, res) => {
  try {
    const { boardId } = req.params;

    const entries = await prisma.timeEntry.findMany({
      where: { task: { boardId } },
      include: {
        task: { select: { id: true, title: true } },
        user: { select: { id: true, name: true, avatar: true } },
      },
    });

    // Group by task
    const byTask = {};
    const byUser = {};

    for (const entry of entries) {
      const dur = entry.duration || 0;

      if (!byTask[entry.taskId]) {
        byTask[entry.taskId] = { task: entry.task, totalDuration: 0 };
      }
      byTask[entry.taskId].totalDuration += dur;

      if (!byUser[entry.userId]) {
        byUser[entry.userId] = { user: entry.user, totalDuration: 0 };
      }
      byUser[entry.userId].totalDuration += dur;
    }

    res.json({
      byTask: Object.values(byTask),
      byUser: Object.values(byUser),
      totalDuration: entries.reduce((sum, e) => sum + (e.duration || 0), 0),
    });
  } catch (error) {
    console.error('Time report error:', error);
    res.status(500).json({ error: 'Failed to generate time report' });
  }
});

module.exports = router;
