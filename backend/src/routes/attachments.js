const express = require('express');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { v4: uuidv4 } = require('uuid');
const prisma = require('../db');
const auth = require('../middleware/auth');

const router = express.Router();

// All routes are protected
router.use(auth);

// Configure multer storage
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const uploadDir = path.join(__dirname, '../../uploads');
    if (!fs.existsSync(uploadDir)) {
      fs.mkdirSync(uploadDir, { recursive: true });
    }
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueName = `${uuidv4()}${path.extname(file.originalname)}`;
    cb(null, uniqueName);
  },
});

const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit
});

// POST /api/tasks/:taskId/attachments - upload file
router.post('/tasks/:taskId/attachments', upload.single('file'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }

    const task = await prisma.task.findUnique({ where: { id: req.params.taskId } });
    if (!task) {
      // Clean up uploaded file
      fs.unlinkSync(req.file.path);
      return res.status(404).json({ error: 'Task not found' });
    }

    const attachment = await prisma.attachment.create({
      data: {
        filename: req.file.originalname,
        filepath: req.file.filename,
        mimetype: req.file.mimetype,
        size: req.file.size,
        taskId: req.params.taskId,
      },
    });

    res.status(201).json({ attachment });
  } catch (error) {
    console.error('Upload attachment error:', error);
    if (req.file) {
      try {
        fs.unlinkSync(req.file.path);
      } catch (e) {
        // ignore cleanup error
      }
    }
    res.status(500).json({ error: 'Failed to upload attachment' });
  }
});

// GET /api/attachments/:id/download - download file
router.get('/:id/download', async (req, res) => {
  try {
    const attachment = await prisma.attachment.findUnique({
      where: { id: req.params.id },
    });

    if (!attachment) {
      return res.status(404).json({ error: 'Attachment not found' });
    }

    const filepath = path.join(__dirname, '../../uploads', attachment.filepath);

    if (!fs.existsSync(filepath)) {
      return res.status(404).json({ error: 'File not found on disk' });
    }

    res.setHeader('Content-Disposition', `attachment; filename="${attachment.filename}"`);
    res.setHeader('Content-Type', attachment.mimetype);
    res.sendFile(filepath);
  } catch (error) {
    console.error('Download attachment error:', error);
    res.status(500).json({ error: 'Failed to download attachment' });
  }
});

// DELETE /api/attachments/:id - delete attachment
router.delete('/:id', async (req, res) => {
  try {
    const attachment = await prisma.attachment.findUnique({
      where: { id: req.params.id },
    });

    if (!attachment) {
      return res.status(404).json({ error: 'Attachment not found' });
    }

    // Delete file from disk
    const filepath = path.join(__dirname, '../../uploads', attachment.filepath);
    if (fs.existsSync(filepath)) {
      fs.unlinkSync(filepath);
    }

    await prisma.attachment.delete({ where: { id: req.params.id } });

    res.json({ message: 'Attachment deleted' });
  } catch (error) {
    console.error('Delete attachment error:', error);
    res.status(500).json({ error: 'Failed to delete attachment' });
  }
});

module.exports = router;
