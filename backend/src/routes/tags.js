const express = require('express');
const prisma = require('../db');
const auth = require('../middleware/auth');
const router = express.Router();

router.use(auth);

// GET /api/tags - list all tags
router.get('/tags', async (req, res) => {
  try {
    const tags = await prisma.tag.findMany({
      include: { _count: { select: { tasks: true } } },
      orderBy: { name: 'asc' },
    });
    res.json({ tags });
  } catch (error) {
    console.error('List tags error:', error);
    res.status(500).json({ error: 'Failed to list tags' });
  }
});

// POST /api/tags - create tag
router.post('/tags', async (req, res) => {
  try {
    const { name, color } = req.body;

    const tag = await prisma.tag.create({
      data: { name, color: color || '#6366f1' },
    });

    res.status(201).json({ tag });
  } catch (error) {
    console.error('Create tag error:', error);
    res.status(500).json({ error: 'Failed to create tag' });
  }
});

// POST /api/tasks/:taskId/tags - add tag to task
router.post('/tasks/:taskId/tags', async (req, res) => {
  try {
    const { taskId } = req.params;
    const { tagId } = req.body;

    const taskTag = await prisma.taskTag.create({
      data: { taskId, tagId },
      include: { tag: true },
    });

    res.status(201).json({ taskTag });
  } catch (error) {
    console.error('Add tag to task error:', error);
    res.status(500).json({ error: 'Failed to add tag to task' });
  }
});

// DELETE /api/tasks/:taskId/tags/:tagId - remove tag from task
router.delete('/tasks/:taskId/tags/:tagId', async (req, res) => {
  try {
    const { taskId, tagId } = req.params;

    await prisma.taskTag.deleteMany({
      where: { taskId, tagId },
    });

    res.json({ message: 'Tag removed from task' });
  } catch (error) {
    console.error('Remove tag from task error:', error);
    res.status(500).json({ error: 'Failed to remove tag from task' });
  }
});

module.exports = router;
