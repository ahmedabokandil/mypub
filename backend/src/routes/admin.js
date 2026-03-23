const express = require('express');
const prisma = require('../db');
const auth = require('../middleware/auth');
const router = express.Router();

router.use(auth);

// Admin check middleware
function requireAdmin(req, res, next) {
  // We need to fetch the user to check role
  prisma.user
    .findUnique({ where: { id: req.user.userId } })
    .then((user) => {
      if (!user || user.role !== 'admin') {
        return res.status(403).json({ error: 'Admin access required' });
      }
      req.adminUser = user;
      next();
    })
    .catch((err) => {
      console.error('Admin check error:', err);
      res.status(500).json({ error: 'Failed to verify admin access' });
    });
}

router.use(requireAdmin);

// GET /api/admin/users - list all users
router.get('/users', async (req, res) => {
  try {
    const users = await prisma.user.findMany({
      select: {
        id: true,
        email: true,
        name: true,
        avatar: true,
        role: true,
        createdAt: true,
        _count: { select: { tasks: true, boards: true } },
      },
      orderBy: { createdAt: 'desc' },
    });

    res.json({ users });
  } catch (error) {
    console.error('List users error:', error);
    res.status(500).json({ error: 'Failed to list users' });
  }
});

// PUT /api/admin/users/:id/role - change user role
router.put('/users/:id/role', async (req, res) => {
  try {
    const { id } = req.params;
    const { role } = req.body;

    if (!['admin', 'user'].includes(role)) {
      return res.status(400).json({ error: 'Role must be admin or user' });
    }

    const user = await prisma.user.update({
      where: { id },
      data: { role },
      select: { id: true, email: true, name: true, role: true },
    });

    res.json({ user });
  } catch (error) {
    console.error('Change role error:', error);
    res.status(500).json({ error: 'Failed to change user role' });
  }
});

// DELETE /api/admin/users/:id - delete user
router.delete('/users/:id', async (req, res) => {
  try {
    const { id } = req.params;

    if (id === req.user.userId) {
      return res.status(400).json({ error: 'Cannot delete yourself' });
    }

    await prisma.user.delete({ where: { id } });
    res.json({ message: 'User deleted' });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

// GET /api/admin/stats - system stats
router.get('/stats', async (req, res) => {
  try {
    const today = new Date();
    today.setHours(0, 0, 0, 0);

    const [totalUsers, totalBoards, totalTasks, activeToday] = await Promise.all([
      prisma.user.count(),
      prisma.board.count(),
      prisma.task.count(),
      prisma.user.count({
        where: { updatedAt: { gte: today } },
      }),
    ]);

    res.json({
      stats: { totalUsers, totalBoards, totalTasks, activeToday },
    });
  } catch (error) {
    console.error('Stats error:', error);
    res.status(500).json({ error: 'Failed to get stats' });
  }
});

module.exports = router;
