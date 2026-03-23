const express = require('express');
const prisma = require('../db');
const auth = require('../middleware/auth');

const router = express.Router();

// All routes are protected
router.use(auth);

// GET /api/tasks?boardId= - list tasks for board
router.get('/', async (req, res) => {
  try {
    const { boardId } = req.query;

    if (!boardId) {
      return res.status(400).json({ error: 'boardId is required' });
    }

    const tasks = await prisma.task.findMany({
      where: { boardId },
      include: {
        user: { select: { id: true, name: true, email: true, avatar: true } },
        column: true,
        labels: { include: { label: true } },
        _count: { select: { comments: true, attachments: true } },
      },
      orderBy: { position: 'asc' },
    });

    res.json({ tasks });
  } catch (error) {
    console.error('List tasks error:', error);
    res.status(500).json({ error: 'Failed to list tasks' });
  }
});

// POST /api/tasks - create task
router.post('/', async (req, res) => {
  try {
    const { title, description, dueDate, priority, columnId, boardId, reminder } = req.body;

    if (!title || !columnId || !boardId) {
      return res.status(400).json({ error: 'Title, columnId, and boardId are required' });
    }

    // Get the highest position in the column
    const lastTask = await prisma.task.findFirst({
      where: { columnId },
      orderBy: { position: 'desc' },
    });
    const position = lastTask ? lastTask.position + 1 : 0;

    const task = await prisma.task.create({
      data: {
        title,
        description,
        dueDate: dueDate ? new Date(dueDate) : null,
        priority: priority || 'medium',
        position,
        reminder: reminder ? new Date(reminder) : null,
        columnId,
        boardId,
        userId: req.user.userId,
      },
      include: {
        user: { select: { id: true, name: true, email: true, avatar: true } },
        column: true,
        labels: { include: { label: true } },
        attachments: true,
        embeds: true,
        comments: {
          include: {
            user: { select: { id: true, name: true, email: true, avatar: true } },
          },
        },
      },
    });

    res.status(201).json({ task });
  } catch (error) {
    console.error('Create task error:', error);
    res.status(500).json({ error: 'Failed to create task' });
  }
});

// GET /api/tasks/:id - get task with details
router.get('/:id', async (req, res) => {
  try {
    const task = await prisma.task.findUnique({
      where: { id: req.params.id },
      include: {
        user: { select: { id: true, name: true, email: true, avatar: true } },
        column: true,
        board: true,
        labels: { include: { label: true } },
        attachments: { orderBy: { createdAt: 'desc' } },
        embeds: true,
        comments: {
          orderBy: { createdAt: 'asc' },
          include: {
            user: { select: { id: true, name: true, email: true, avatar: true } },
          },
        },
      },
    });

    if (!task) {
      return res.status(404).json({ error: 'Task not found' });
    }

    res.json({ task });
  } catch (error) {
    console.error('Get task error:', error);
    res.status(500).json({ error: 'Failed to get task' });
  }
});

// PUT /api/tasks/:id - update task
router.put('/:id', async (req, res) => {
  try {
    const { title, description, dueDate, priority, columnId, reminder } = req.body;

    const existing = await prisma.task.findUnique({ where: { id: req.params.id } });
    if (!existing) {
      return res.status(404).json({ error: 'Task not found' });
    }

    const data = {};
    if (title !== undefined) data.title = title;
    if (description !== undefined) data.description = description;
    if (dueDate !== undefined) data.dueDate = dueDate ? new Date(dueDate) : null;
    if (priority !== undefined) data.priority = priority;
    if (columnId !== undefined) data.columnId = columnId;
    if (reminder !== undefined) {
      data.reminder = reminder ? new Date(reminder) : null;
      data.reminderSent = false;
    }

    const task = await prisma.task.update({
      where: { id: req.params.id },
      data,
      include: {
        user: { select: { id: true, name: true, email: true, avatar: true } },
        column: true,
        labels: { include: { label: true } },
        attachments: true,
        embeds: true,
        comments: {
          orderBy: { createdAt: 'asc' },
          include: {
            user: { select: { id: true, name: true, email: true, avatar: true } },
          },
        },
      },
    });

    res.json({ task });
  } catch (error) {
    console.error('Update task error:', error);
    res.status(500).json({ error: 'Failed to update task' });
  }
});

// DELETE /api/tasks/:id - delete task
router.delete('/:id', async (req, res) => {
  try {
    const task = await prisma.task.findUnique({ where: { id: req.params.id } });
    if (!task) {
      return res.status(404).json({ error: 'Task not found' });
    }

    await prisma.task.delete({ where: { id: req.params.id } });

    res.json({ message: 'Task deleted' });
  } catch (error) {
    console.error('Delete task error:', error);
    res.status(500).json({ error: 'Failed to delete task' });
  }
});

// PUT /api/tasks/:id/move - move task to different column and position
router.put('/:id/move', async (req, res) => {
  try {
    const { columnId, position } = req.body;

    if (columnId === undefined || position === undefined) {
      return res.status(400).json({ error: 'columnId and position are required' });
    }

    const task = await prisma.task.findUnique({ where: { id: req.params.id } });
    if (!task) {
      return res.status(404).json({ error: 'Task not found' });
    }

    // Reorder tasks in the target column
    const tasksInTargetColumn = await prisma.task.findMany({
      where: {
        columnId,
        id: { not: req.params.id },
      },
      orderBy: { position: 'asc' },
    });

    // Update positions for tasks in the target column
    const updates = tasksInTargetColumn.map((t, index) => {
      const newPosition = index >= position ? index + 1 : index;
      return prisma.task.update({
        where: { id: t.id },
        data: { position: newPosition },
      });
    });

    // Move the task
    updates.push(
      prisma.task.update({
        where: { id: req.params.id },
        data: { columnId, position },
      })
    );

    await prisma.$transaction(updates);

    const updatedTask = await prisma.task.findUnique({
      where: { id: req.params.id },
      include: {
        user: { select: { id: true, name: true, email: true, avatar: true } },
        column: true,
        labels: { include: { label: true } },
      },
    });

    res.json({ task: updatedTask });
  } catch (error) {
    console.error('Move task error:', error);
    res.status(500).json({ error: 'Failed to move task' });
  }
});

// POST /api/tasks/:id/comments - add comment
router.post('/:id/comments', async (req, res) => {
  try {
    const { content } = req.body;

    if (!content) {
      return res.status(400).json({ error: 'Content is required' });
    }

    const task = await prisma.task.findUnique({
      where: { id: req.params.id },
      include: { board: true },
    });
    if (!task) {
      return res.status(404).json({ error: 'Task not found' });
    }

    const comment = await prisma.comment.create({
      data: {
        content,
        taskId: req.params.id,
        userId: req.user.userId,
      },
      include: {
        user: { select: { id: true, name: true, email: true, avatar: true } },
      },
    });

    // Notify task owner if commenter is different
    if (task.userId !== req.user.userId) {
      await prisma.notification.create({
        data: {
          title: 'New Comment',
          message: `New comment on "${task.title}"`,
          type: 'comment',
          userId: task.userId,
          taskId: task.id,
        },
      });
    }

    res.status(201).json({ comment });
  } catch (error) {
    console.error('Add comment error:', error);
    res.status(500).json({ error: 'Failed to add comment' });
  }
});

module.exports = router;
