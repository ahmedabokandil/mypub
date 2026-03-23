const express = require('express');
const prisma = require('../db');
const auth = require('../middleware/auth');

const router = express.Router();

// All routes are protected
router.use(auth);

// GET /api/boards - list user's boards (owned + member of)
router.get('/', async (req, res) => {
  try {
    const boards = await prisma.board.findMany({
      where: {
        OR: [
          { ownerId: req.user.userId },
          { members: { some: { userId: req.user.userId } } },
        ],
      },
      include: {
        owner: { select: { id: true, name: true, email: true, avatar: true } },
        members: {
          include: {
            user: { select: { id: true, name: true, email: true, avatar: true } },
          },
        },
        columns: { orderBy: { position: 'asc' } },
        _count: { select: { tasks: true } },
      },
      orderBy: { updatedAt: 'desc' },
    });

    res.json({ boards });
  } catch (error) {
    console.error('List boards error:', error);
    res.status(500).json({ error: 'Failed to list boards' });
  }
});

// POST /api/boards - create board with default columns
router.post('/', async (req, res) => {
  try {
    const { name, description, color } = req.body;

    if (!name) {
      return res.status(400).json({ error: 'Board name is required' });
    }

    const board = await prisma.board.create({
      data: {
        name,
        description,
        color: color || '#6366f1',
        ownerId: req.user.userId,
        columns: {
          create: [
            { name: 'To Do', position: 0, color: '#e2e8f0' },
            { name: 'In Progress', position: 1, color: '#fbbf24' },
            { name: 'Review', position: 2, color: '#60a5fa' },
            { name: 'Done', position: 3, color: '#34d399' },
          ],
        },
      },
      include: {
        owner: { select: { id: true, name: true, email: true, avatar: true } },
        columns: { orderBy: { position: 'asc' } },
        members: {
          include: {
            user: { select: { id: true, name: true, email: true, avatar: true } },
          },
        },
      },
    });

    res.status(201).json({ board });
  } catch (error) {
    console.error('Create board error:', error);
    res.status(500).json({ error: 'Failed to create board' });
  }
});

// GET /api/boards/:id - get board with columns and tasks
router.get('/:id', async (req, res) => {
  try {
    const board = await prisma.board.findUnique({
      where: { id: req.params.id },
      include: {
        owner: { select: { id: true, name: true, email: true, avatar: true } },
        members: {
          include: {
            user: { select: { id: true, name: true, email: true, avatar: true } },
          },
        },
        columns: {
          orderBy: { position: 'asc' },
          include: {
            tasks: {
              orderBy: { position: 'asc' },
              include: {
                user: { select: { id: true, name: true, email: true, avatar: true } },
                labels: { include: { label: true } },
                _count: { select: { comments: true, attachments: true } },
              },
            },
          },
        },
      },
    });

    if (!board) {
      return res.status(404).json({ error: 'Board not found' });
    }

    // Check access
    const isMember = board.members.some((m) => m.userId === req.user.userId);
    if (board.ownerId !== req.user.userId && !isMember) {
      return res.status(403).json({ error: 'Access denied' });
    }

    res.json({ board });
  } catch (error) {
    console.error('Get board error:', error);
    res.status(500).json({ error: 'Failed to get board' });
  }
});

// PUT /api/boards/:id - update board
router.put('/:id', async (req, res) => {
  try {
    const { name, description, color } = req.body;

    const board = await prisma.board.findUnique({ where: { id: req.params.id } });
    if (!board) {
      return res.status(404).json({ error: 'Board not found' });
    }

    if (board.ownerId !== req.user.userId) {
      return res.status(403).json({ error: 'Only the owner can update the board' });
    }

    const updated = await prisma.board.update({
      where: { id: req.params.id },
      data: {
        ...(name !== undefined && { name }),
        ...(description !== undefined && { description }),
        ...(color !== undefined && { color }),
      },
      include: {
        owner: { select: { id: true, name: true, email: true, avatar: true } },
        columns: { orderBy: { position: 'asc' } },
        members: {
          include: {
            user: { select: { id: true, name: true, email: true, avatar: true } },
          },
        },
      },
    });

    res.json({ board: updated });
  } catch (error) {
    console.error('Update board error:', error);
    res.status(500).json({ error: 'Failed to update board' });
  }
});

// DELETE /api/boards/:id - delete board (owner only)
router.delete('/:id', async (req, res) => {
  try {
    const board = await prisma.board.findUnique({ where: { id: req.params.id } });
    if (!board) {
      return res.status(404).json({ error: 'Board not found' });
    }

    if (board.ownerId !== req.user.userId) {
      return res.status(403).json({ error: 'Only the owner can delete the board' });
    }

    await prisma.board.delete({ where: { id: req.params.id } });

    res.json({ message: 'Board deleted' });
  } catch (error) {
    console.error('Delete board error:', error);
    res.status(500).json({ error: 'Failed to delete board' });
  }
});

// POST /api/boards/:id/members - add member by email
router.post('/:id/members', async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    const board = await prisma.board.findUnique({ where: { id: req.params.id } });
    if (!board) {
      return res.status(404).json({ error: 'Board not found' });
    }

    if (board.ownerId !== req.user.userId) {
      return res.status(403).json({ error: 'Only the owner can add members' });
    }

    const user = await prisma.user.findUnique({ where: { email } });
    if (!user) {
      return res.status(404).json({ error: 'User not found' });
    }

    if (user.id === board.ownerId) {
      return res.status(400).json({ error: 'Owner is already a member' });
    }

    const existingMember = await prisma.boardMember.findUnique({
      where: { boardId_userId: { boardId: board.id, userId: user.id } },
    });

    if (existingMember) {
      return res.status(400).json({ error: 'User is already a member' });
    }

    const member = await prisma.boardMember.create({
      data: { boardId: board.id, userId: user.id },
      include: {
        user: { select: { id: true, name: true, email: true, avatar: true } },
      },
    });

    // Create notification for the added user
    await prisma.notification.create({
      data: {
        title: 'Board Invitation',
        message: `You have been added to the board "${board.name}"`,
        type: 'board_invite',
        userId: user.id,
      },
    });

    res.status(201).json({ member });
  } catch (error) {
    console.error('Add member error:', error);
    res.status(500).json({ error: 'Failed to add member' });
  }
});

// DELETE /api/boards/:id/members/:userId - remove member
router.delete('/:id/members/:userId', async (req, res) => {
  try {
    const board = await prisma.board.findUnique({ where: { id: req.params.id } });
    if (!board) {
      return res.status(404).json({ error: 'Board not found' });
    }

    if (board.ownerId !== req.user.userId) {
      return res.status(403).json({ error: 'Only the owner can remove members' });
    }

    const member = await prisma.boardMember.findUnique({
      where: {
        boardId_userId: { boardId: req.params.id, userId: req.params.userId },
      },
    });

    if (!member) {
      return res.status(404).json({ error: 'Member not found' });
    }

    await prisma.boardMember.delete({ where: { id: member.id } });

    res.json({ message: 'Member removed' });
  } catch (error) {
    console.error('Remove member error:', error);
    res.status(500).json({ error: 'Failed to remove member' });
  }
});

module.exports = router;
