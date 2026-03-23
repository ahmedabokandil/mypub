const express = require('express');
const prisma = require('../db');
const auth = require('../middleware/auth');

const router = express.Router();

// All routes are protected
router.use(auth);

// GET /api/notifications - list user's notifications
router.get('/', async (req, res) => {
  try {
    const notifications = await prisma.notification.findMany({
      where: { userId: req.user.userId },
      orderBy: { createdAt: 'desc' },
      take: 50,
    });

    res.json({ notifications });
  } catch (error) {
    console.error('List notifications error:', error);
    res.status(500).json({ error: 'Failed to list notifications' });
  }
});

// PUT /api/notifications/read-all - mark all as read
router.put('/read-all', async (req, res) => {
  try {
    await prisma.notification.updateMany({
      where: { userId: req.user.userId, read: false },
      data: { read: true },
    });

    res.json({ message: 'All notifications marked as read' });
  } catch (error) {
    console.error('Mark all read error:', error);
    res.status(500).json({ error: 'Failed to mark all as read' });
  }
});

// PUT /api/notifications/:id/read - mark as read
router.put('/:id/read', async (req, res) => {
  try {
    const notification = await prisma.notification.findUnique({
      where: { id: req.params.id },
    });

    if (!notification) {
      return res.status(404).json({ error: 'Notification not found' });
    }

    if (notification.userId !== req.user.userId) {
      return res.status(403).json({ error: 'Access denied' });
    }

    const updated = await prisma.notification.update({
      where: { id: req.params.id },
      data: { read: true },
    });

    res.json({ notification: updated });
  } catch (error) {
    console.error('Mark read error:', error);
    res.status(500).json({ error: 'Failed to mark as read' });
  }
});

// POST /api/notifications/subscribe - save push subscription
router.post('/subscribe', async (req, res) => {
  try {
    const { endpoint, keys } = req.body;

    if (!endpoint || !keys || !keys.p256dh || !keys.auth) {
      return res.status(400).json({ error: 'Invalid push subscription' });
    }

    // Upsert subscription
    const subscription = await prisma.pushSubscription.upsert({
      where: {
        userId_endpoint: {
          userId: req.user.userId,
          endpoint,
        },
      },
      update: {
        p256dh: keys.p256dh,
        auth: keys.auth,
      },
      create: {
        userId: req.user.userId,
        endpoint,
        p256dh: keys.p256dh,
        auth: keys.auth,
      },
    });

    res.status(201).json({ subscription });
  } catch (error) {
    console.error('Subscribe error:', error);
    res.status(500).json({ error: 'Failed to save subscription' });
  }
});

module.exports = router;
