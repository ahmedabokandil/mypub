const express = require('express');
const prisma = require('../db');
const auth = require('../middleware/auth');

const router = express.Router();

router.use(auth);

// GET /api/analytics/board/:boardId - board analytics
router.get('/board/:boardId', async (req, res) => {
  try {
    const { boardId } = req.params;

    // Tasks by column
    const columns = await prisma.column.findMany({
      where: { boardId },
      include: { _count: { select: { tasks: true } } },
      orderBy: { position: 'asc' },
    });
    const tasksByColumn = columns.map((col) => ({
      column: col.name,
      count: col._count.tasks,
    }));

    // Tasks by priority
    const tasks = await prisma.task.findMany({
      where: { boardId, archived: false },
      select: { priority: true, createdAt: true, updatedAt: true, dueDate: true, column: { select: { name: true } } },
    });

    const byPriority = {};
    for (const t of tasks) {
      byPriority[t.priority] = (byPriority[t.priority] || 0) + 1;
    }

    // Overdue count
    const now = new Date();
    const overdueCount = tasks.filter(
      (t) => t.dueDate && new Date(t.dueDate) < now && t.column.name !== 'Done'
    ).length;

    // Completed over time (last 30 days)
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    const completedTasks = await prisma.task.findMany({
      where: {
        boardId,
        column: { name: { in: ['Done', 'Completed', 'Verified', 'Fixed'] } },
        updatedAt: { gte: thirtyDaysAgo },
      },
      select: { updatedAt: true },
    });

    const completedByDay = {};
    for (const t of completedTasks) {
      const day = t.updatedAt.toISOString().split('T')[0];
      completedByDay[day] = (completedByDay[day] || 0) + 1;
    }

    res.json({
      tasksByColumn,
      tasksByPriority: byPriority,
      overdueCount,
      completedOverTime: completedByDay,
    });
  } catch (error) {
    console.error('Board analytics error:', error);
    res.status(500).json({ error: 'Failed to get board analytics' });
  }
});

// GET /api/analytics/user - user productivity
router.get('/user', async (req, res) => {
  try {
    const userId = req.user.userId;
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    // Tasks completed per day for last 30 days
    const completedTasks = await prisma.task.findMany({
      where: {
        userId,
        column: { name: { in: ['Done', 'Completed', 'Verified', 'Fixed'] } },
        updatedAt: { gte: thirtyDaysAgo },
      },
      select: { updatedAt: true, createdAt: true },
    });

    const completedByDay = {};
    let totalCompletionTime = 0;
    let completedCount = 0;

    for (const t of completedTasks) {
      const day = t.updatedAt.toISOString().split('T')[0];
      completedByDay[day] = (completedByDay[day] || 0) + 1;

      const completionTime = t.updatedAt.getTime() - t.createdAt.getTime();
      totalCompletionTime += completionTime;
      completedCount++;
    }

    const avgCompletionTime = completedCount > 0
      ? Math.round(totalCompletionTime / completedCount / (1000 * 60 * 60))
      : 0;

    res.json({
      completedPerDay: completedByDay,
      avgCompletionTimeHours: avgCompletionTime,
      totalCompleted: completedCount,
    });
  } catch (error) {
    console.error('User analytics error:', error);
    res.status(500).json({ error: 'Failed to get user analytics' });
  }
});

// GET /api/analytics/burndown/:boardId - burndown chart data
router.get('/burndown/:boardId', async (req, res) => {
  try {
    const { boardId } = req.params;
    const thirtyDaysAgo = new Date();
    thirtyDaysAgo.setDate(thirtyDaysAgo.getDate() - 30);

    const tasks = await prisma.task.findMany({
      where: { boardId },
      select: {
        createdAt: true,
        updatedAt: true,
        column: { select: { name: true } },
      },
    });

    const totalTasks = tasks.length;
    const burndownData = {};

    // Build day-by-day data
    for (let d = new Date(thirtyDaysAgo); d <= new Date(); d.setDate(d.getDate() + 1)) {
      const day = d.toISOString().split('T')[0];
      const created = tasks.filter((t) => t.createdAt.toISOString().split('T')[0] <= day).length;
      const completed = tasks.filter(
        (t) =>
          ['Done', 'Completed', 'Verified', 'Fixed'].includes(t.column.name) &&
          t.updatedAt.toISOString().split('T')[0] <= day
      ).length;

      burndownData[day] = { total: created, completed, remaining: created - completed };
    }

    res.json({ totalTasks, burndownData });
  } catch (error) {
    console.error('Burndown error:', error);
    res.status(500).json({ error: 'Failed to get burndown data' });
  }
});

module.exports = router;
