const express = require('express');
const prisma = require('../db');
const auth = require('../middleware/auth');
const router = express.Router();

router.use(auth);

// POST /api/tasks/:taskId/dependencies - add dependency
router.post('/tasks/:taskId/dependencies', async (req, res) => {
  try {
    const { taskId } = req.params;
    const { blockingId, type } = req.body;

    if (!blockingId) {
      return res.status(400).json({ error: 'blockingId is required' });
    }

    const dependency = await prisma.taskDependency.create({
      data: {
        dependentId: taskId,
        blockingId,
        type: type || 'blocked_by',
      },
      include: {
        blocking: { select: { id: true, title: true } },
        dependent: { select: { id: true, title: true } },
      },
    });

    res.status(201).json({ dependency });
  } catch (error) {
    console.error('Create dependency error:', error);
    res.status(500).json({ error: 'Failed to create dependency' });
  }
});

// GET /api/tasks/:taskId/dependencies - list dependencies
router.get('/tasks/:taskId/dependencies', async (req, res) => {
  try {
    const { taskId } = req.params;

    const blocking = await prisma.taskDependency.findMany({
      where: { dependentId: taskId },
      include: {
        blocking: { select: { id: true, title: true, priority: true, column: { select: { name: true } } } },
      },
    });

    const blockedBy = await prisma.taskDependency.findMany({
      where: { blockingId: taskId },
      include: {
        dependent: { select: { id: true, title: true, priority: true, column: { select: { name: true } } } },
      },
    });

    res.json({ blocking, blockedBy });
  } catch (error) {
    console.error('List dependencies error:', error);
    res.status(500).json({ error: 'Failed to list dependencies' });
  }
});

// DELETE /api/dependencies/:id - remove dependency
router.delete('/dependencies/:id', async (req, res) => {
  try {
    const { id } = req.params;
    await prisma.taskDependency.delete({ where: { id } });
    res.json({ message: 'Dependency removed' });
  } catch (error) {
    console.error('Delete dependency error:', error);
    res.status(500).json({ error: 'Failed to delete dependency' });
  }
});

module.exports = router;
