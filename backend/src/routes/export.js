const express = require('express');
const prisma = require('../db');
const auth = require('../middleware/auth');

const router = express.Router();

router.use(auth);

// GET /api/export/board/:boardId/csv - export board tasks as CSV
router.get('/board/:boardId/csv', async (req, res) => {
  try {
    const { boardId } = req.params;

    const tasks = await prisma.task.findMany({
      where: { boardId },
      include: {
        column: { select: { name: true } },
        user: { select: { name: true, email: true } },
        labels: { include: { label: true } },
        assignments: { include: { user: { select: { name: true } } } },
      },
      orderBy: { position: 'asc' },
    });

    const board = await prisma.board.findUnique({
      where: { id: boardId },
      select: { name: true },
    });

    // Build CSV
    const headers = ['Title', 'Description', 'Column', 'Priority', 'Due Date', 'Assignee', 'Labels', 'Created', 'Archived'];
    const rows = tasks.map((t) => [
      `"${(t.title || '').replace(/"/g, '""')}"`,
      `"${(t.description || '').replace(/"/g, '""')}"`,
      `"${t.column.name}"`,
      t.priority,
      t.dueDate ? new Date(t.dueDate).toISOString().split('T')[0] : '',
      `"${t.assignments.map((a) => a.user.name).join(', ')}"`,
      `"${t.labels.map((l) => l.label.name).join(', ')}"`,
      new Date(t.createdAt).toISOString().split('T')[0],
      t.archived ? 'Yes' : 'No',
    ]);

    const csv = [headers.join(','), ...rows.map((r) => r.join(','))].join('\n');

    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', `attachment; filename="${(board?.name || 'board').replace(/"/g, '')}-tasks.csv"`);
    res.send(csv);
  } catch (error) {
    console.error('Export CSV error:', error);
    res.status(500).json({ error: 'Failed to export CSV' });
  }
});

// GET /api/export/board/:boardId/json - export board tasks as JSON
router.get('/board/:boardId/json', async (req, res) => {
  try {
    const { boardId } = req.params;

    const board = await prisma.board.findUnique({
      where: { id: boardId },
      include: {
        columns: {
          orderBy: { position: 'asc' },
          include: {
            tasks: {
              include: {
                user: { select: { id: true, name: true, email: true } },
                labels: { include: { label: true } },
                assignments: { include: { user: { select: { id: true, name: true } } } },
                checklists: { orderBy: { position: 'asc' } },
                comments: {
                  include: { user: { select: { id: true, name: true } } },
                  orderBy: { createdAt: 'asc' },
                },
              },
              orderBy: { position: 'asc' },
            },
          },
        },
        members: {
          include: { user: { select: { id: true, name: true, email: true } } },
        },
      },
    });

    if (!board) return res.status(404).json({ error: 'Board not found' });

    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="${(board.name || 'board').replace(/"/g, '')}-export.json"`);
    res.json(board);
  } catch (error) {
    console.error('Export JSON error:', error);
    res.status(500).json({ error: 'Failed to export JSON' });
  }
});

module.exports = router;
