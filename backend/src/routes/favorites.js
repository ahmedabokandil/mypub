const express = require('express');
const prisma = require('../db');
const auth = require('../middleware/auth');
const router = express.Router();

router.use(auth);

// GET /api/favorites - list user's favorite boards
router.get('/', async (req, res) => {
  try {
    const favorites = await prisma.favorite.findMany({
      where: { userId: req.user.userId },
      include: {
        board: {
          select: { id: true, name: true, color: true, description: true },
        },
      },
    });

    res.json({ favorites });
  } catch (error) {
    console.error('List favorites error:', error);
    res.status(500).json({ error: 'Failed to list favorites' });
  }
});

// POST /api/favorites - toggle favorite
router.post('/', async (req, res) => {
  try {
    const { boardId } = req.body;
    const userId = req.user.userId;

    const existing = await prisma.favorite.findUnique({
      where: { userId_boardId: { userId, boardId } },
    });

    if (existing) {
      await prisma.favorite.delete({ where: { id: existing.id } });
      return res.json({ favorited: false });
    }

    const favorite = await prisma.favorite.create({
      data: { userId, boardId },
      include: { board: { select: { id: true, name: true, color: true } } },
    });

    res.status(201).json({ favorited: true, favorite });
  } catch (error) {
    console.error('Toggle favorite error:', error);
    res.status(500).json({ error: 'Failed to toggle favorite' });
  }
});

// DELETE /api/favorites/:boardId - remove favorite
router.delete('/:boardId', async (req, res) => {
  try {
    const { boardId } = req.params;
    const userId = req.user.userId;

    await prisma.favorite.deleteMany({
      where: { userId, boardId },
    });

    res.json({ message: 'Favorite removed' });
  } catch (error) {
    console.error('Remove favorite error:', error);
    res.status(500).json({ error: 'Failed to remove favorite' });
  }
});

module.exports = router;
