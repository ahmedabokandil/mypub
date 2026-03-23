const express = require('express');
const prisma = require('../db');
const auth = require('../middleware/auth');
const router = express.Router();

router.use(auth);

// GET /api/boards/:boardId/activity - list activity for board (paginated)
router.get('/boards/:boardId/activity', async (req, res) => {
  try {
    const { boardId } = req.params;
    const page = parseInt(req.query.page) || 1;
    const limit = parseInt(req.query.limit) || 20;
    const skip = (page - 1) * limit;

    const [activities, total] = await Promise.all([
      prisma.activityLog.findMany({
        where: { boardId },
        include: {
          user: { select: { id: true, name: true, avatar: true } },
        },
        orderBy: { createdAt: 'desc' },
        skip,
        take: limit,
      }),
      prisma.activityLog.count({ where: { boardId } }),
    ]);

    res.json({
      activities,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
      },
    });
  } catch (error) {
    console.error('List activity error:', error);
    res.status(500).json({ error: 'Failed to list activity' });
  }
});

// Helper function to log activity
async function logActivity(userId, action, entity, entityId, details, boardId) {
  try {
    await prisma.activityLog.create({
      data: {
        userId,
        action,
        entity,
        entityId,
        details: details || null,
        boardId: boardId || null,
      },
    });
  } catch (error) {
    console.error('Log activity error:', error.message);
  }
}

module.exports = router;
module.exports.logActivity = logActivity;
