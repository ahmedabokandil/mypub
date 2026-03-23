const express = require('express');
const prisma = require('../db');
const auth = require('../middleware/auth');

const router = express.Router();

// All routes are protected
router.use(auth);

function detectEmbedType(url) {
  const youtubeRegex = /(?:youtube\.com\/(?:watch\?v=|embed\/|shorts\/)|youtu\.be\/)([a-zA-Z0-9_-]+)/;
  if (youtubeRegex.test(url)) {
    return 'youtube';
  }
  return 'link';
}

function extractYouTubeTitle(url) {
  const match = url.match(/(?:youtube\.com\/(?:watch\?v=|embed\/|shorts\/)|youtu\.be\/)([a-zA-Z0-9_-]+)/);
  if (match) {
    return `YouTube Video (${match[1]})`;
  }
  return null;
}

// POST /api/tasks/:taskId/embeds - add embed
router.post('/tasks/:taskId/embeds', async (req, res) => {
  try {
    const { url, title } = req.body;

    if (!url) {
      return res.status(400).json({ error: 'URL is required' });
    }

    const task = await prisma.task.findUnique({ where: { id: req.params.taskId } });
    if (!task) {
      return res.status(404).json({ error: 'Task not found' });
    }

    const type = detectEmbedType(url);
    const embedTitle = title || (type === 'youtube' ? extractYouTubeTitle(url) : url);

    const embed = await prisma.embed.create({
      data: {
        url,
        type,
        title: embedTitle,
        taskId: req.params.taskId,
      },
    });

    res.status(201).json({ embed });
  } catch (error) {
    console.error('Create embed error:', error);
    res.status(500).json({ error: 'Failed to create embed' });
  }
});

// DELETE /api/embeds/:id - delete embed
router.delete('/:id', async (req, res) => {
  try {
    const embed = await prisma.embed.findUnique({ where: { id: req.params.id } });

    if (!embed) {
      return res.status(404).json({ error: 'Embed not found' });
    }

    await prisma.embed.delete({ where: { id: req.params.id } });

    res.json({ message: 'Embed deleted' });
  } catch (error) {
    console.error('Delete embed error:', error);
    res.status(500).json({ error: 'Failed to delete embed' });
  }
});

module.exports = router;
