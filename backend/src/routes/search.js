const express = require('express');
const prisma = require('../db');
const auth = require('../middleware/auth');
const router = express.Router();

router.use(auth);

// GET /api/search - search tasks with filters
router.get('/', async (req, res) => {
  try {
    const { q, boardId, priority, label, assignee, dateFrom, dateTo, archived } = req.query;

    const where = { AND: [] };

    if (q) {
      where.AND.push({
        OR: [
          { title: { contains: q } },
          { description: { contains: q } },
        ],
      });
    }

    if (boardId) {
      where.AND.push({ boardId });
    }

    if (priority) {
      where.AND.push({ priority });
    }

    if (label) {
      where.AND.push({
        labels: { some: { label: { name: label } } },
      });
    }

    if (assignee) {
      where.AND.push({ userId: assignee });
    }

    if (dateFrom) {
      where.AND.push({ dueDate: { gte: new Date(dateFrom) } });
    }

    if (dateTo) {
      where.AND.push({ dueDate: { lte: new Date(dateTo) } });
    }

    if (archived !== undefined) {
      where.AND.push({ archived: archived === 'true' });
    } else {
      where.AND.push({ archived: false });
    }

    if (where.AND.length === 0) delete where.AND;

    const tasks = await prisma.task.findMany({
      where,
      include: {
        user: { select: { id: true, name: true, avatar: true } },
        column: { select: { id: true, name: true } },
        board: { select: { id: true, name: true } },
        labels: { include: { label: true } },
        tags: { include: { tag: true } },
      },
      orderBy: { updatedAt: 'desc' },
      take: 50,
    });

    res.json({ tasks });
  } catch (error) {
    console.error('Search error:', error);
    res.status(500).json({ error: 'Search failed' });
  }
});

module.exports = router;
