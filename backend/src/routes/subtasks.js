const express = require('express');
const prisma = require('../db');
const auth = require('../middleware/auth');
const router = express.Router();

router.use(auth);

// POST /api/tasks/:taskId/subtasks - create subtask
router.post('/tasks/:taskId/subtasks', async (req, res) => {
  try {
    const { taskId } = req.params;
    const { title, description, priority } = req.body;

    const parentTask = await prisma.task.findUnique({ where: { id: taskId } });
    if (!parentTask) return res.status(404).json({ error: 'Parent task not found' });

    const subtask = await prisma.task.create({
      data: {
        title,
        description: description || null,
        priority: priority || 'medium',
        parentId: taskId,
        columnId: parentTask.columnId,
        boardId: parentTask.boardId,
        userId: req.user.userId,
      },
      include: {
        user: { select: { id: true, name: true, email: true, avatar: true } },
      },
    });

    res.status(201).json({ subtask });
  } catch (error) {
    console.error('Create subtask error:', error);
    res.status(500).json({ error: 'Failed to create subtask' });
  }
});

// GET /api/tasks/:taskId/subtasks - list subtasks
router.get('/tasks/:taskId/subtasks', async (req, res) => {
  try {
    const { taskId } = req.params;

    const subtasks = await prisma.task.findMany({
      where: { parentId: taskId },
      include: {
        user: { select: { id: true, name: true, email: true, avatar: true } },
        column: true,
      },
      orderBy: { position: 'asc' },
    });

    res.json({ subtasks });
  } catch (error) {
    console.error('List subtasks error:', error);
    res.status(500).json({ error: 'Failed to list subtasks' });
  }
});

// POST /api/tasks/:taskId/checklist - add checklist item
router.post('/tasks/:taskId/checklist', async (req, res) => {
  try {
    const { taskId } = req.params;
    const { title } = req.body;

    const maxPos = await prisma.checklistItem.aggregate({
      where: { taskId },
      _max: { position: true },
    });

    const item = await prisma.checklistItem.create({
      data: {
        title,
        taskId,
        position: (maxPos._max.position ?? -1) + 1,
      },
    });

    res.status(201).json({ item });
  } catch (error) {
    console.error('Create checklist item error:', error);
    res.status(500).json({ error: 'Failed to create checklist item' });
  }
});

// PUT /api/checklist/:id - update checklist item
router.put('/checklist/:id', async (req, res) => {
  try {
    const { id } = req.params;
    const { title, completed } = req.body;

    const data = {};
    if (title !== undefined) data.title = title;
    if (completed !== undefined) data.completed = completed;

    const item = await prisma.checklistItem.update({
      where: { id },
      data,
    });

    res.json({ item });
  } catch (error) {
    console.error('Update checklist item error:', error);
    res.status(500).json({ error: 'Failed to update checklist item' });
  }
});

// DELETE /api/checklist/:id - delete checklist item
router.delete('/checklist/:id', async (req, res) => {
  try {
    const { id } = req.params;
    await prisma.checklistItem.delete({ where: { id } });
    res.json({ message: 'Checklist item deleted' });
  } catch (error) {
    console.error('Delete checklist item error:', error);
    res.status(500).json({ error: 'Failed to delete checklist item' });
  }
});

// PUT /api/checklist/:taskId/reorder - reorder checklist items
router.put('/checklist/:taskId/reorder', async (req, res) => {
  try {
    const { taskId } = req.params;
    const { items } = req.body; // [{ id, position }]

    const updates = items.map((item) =>
      prisma.checklistItem.update({
        where: { id: item.id },
        data: { position: item.position },
      })
    );

    await prisma.$transaction(updates);
    res.json({ message: 'Checklist reordered' });
  } catch (error) {
    console.error('Reorder checklist error:', error);
    res.status(500).json({ error: 'Failed to reorder checklist' });
  }
});

module.exports = router;
