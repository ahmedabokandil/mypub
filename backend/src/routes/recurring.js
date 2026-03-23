const express = require('express');
const prisma = require('../db');
const auth = require('../middleware/auth');
const router = express.Router();

router.use(auth);

// PUT /api/tasks/:taskId/recurring - set recurring pattern
router.put('/tasks/:taskId/recurring', async (req, res) => {
  try {
    const { taskId } = req.params;
    const { pattern, interval } = req.body;

    if (!pattern) {
      return res.status(400).json({ error: 'pattern is required (daily, weekly, monthly)' });
    }

    const now = new Date();
    const recurNextDate = calculateNextDate(now, pattern, interval || 1);

    const task = await prisma.task.update({
      where: { id: taskId },
      data: {
        isRecurring: true,
        recurPattern: pattern,
        recurInterval: interval || 1,
        recurNextDate,
      },
    });

    res.json({ task });
  } catch (error) {
    console.error('Set recurring error:', error);
    res.status(500).json({ error: 'Failed to set recurring pattern' });
  }
});

function calculateNextDate(from, pattern, interval) {
  const date = new Date(from);
  switch (pattern) {
    case 'daily':
      date.setDate(date.getDate() + interval);
      break;
    case 'weekly':
      date.setDate(date.getDate() + 7 * interval);
      break;
    case 'monthly':
      date.setMonth(date.getMonth() + interval);
      break;
    default:
      date.setDate(date.getDate() + interval);
  }
  return date;
}

module.exports = router;
module.exports.calculateNextDate = calculateNextDate;
