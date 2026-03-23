const express = require('express');
const prisma = require('../db');
const auth = require('../middleware/auth');
const router = express.Router();

router.use(auth);

// GET /api/boards/:boardId/chat - list messages (paginated, last 100)
router.get('/boards/:boardId/chat', async (req, res) => {
  try {
    const { boardId } = req.params;
    const limit = parseInt(req.query.limit) || 100;
    const before = req.query.before; // cursor-based pagination

    const where = { boardId };
    if (before) {
      where.createdAt = { lt: new Date(before) };
    }

    const messages = await prisma.chatMessage.findMany({
      where,
      include: {
        user: { select: { id: true, name: true, avatar: true } },
      },
      orderBy: { createdAt: 'desc' },
      take: limit,
    });

    res.json({ messages: messages.reverse() });
  } catch (error) {
    console.error('List chat messages error:', error);
    res.status(500).json({ error: 'Failed to list chat messages' });
  }
});

// DELETE /api/chat/:id - delete message (own only)
router.delete('/chat/:id', async (req, res) => {
  try {
    const { id } = req.params;

    const message = await prisma.chatMessage.findUnique({ where: { id } });
    if (!message) return res.status(404).json({ error: 'Message not found' });
    if (message.userId !== req.user.userId) {
      return res.status(403).json({ error: 'Can only delete your own messages' });
    }

    await prisma.chatMessage.delete({ where: { id } });
    res.json({ message: 'Message deleted' });
  } catch (error) {
    console.error('Delete chat message error:', error);
    res.status(500).json({ error: 'Failed to delete message' });
  }
});

module.exports = router;
