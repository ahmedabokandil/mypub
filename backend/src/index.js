require('dotenv').config();

const express = require('express');
const http = require('http');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const path = require('path');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const jwt = require('jsonwebtoken');
const cron = require('node-cron');
const prisma = require('./db');
const { startReminderService } = require('./services/reminder');
const { initSocket } = require('./socket');
const { apiLimiter, authLimiter, uploadLimiter } = require('./middleware/rateLimit');
const { sendDigests } = require('./services/digest');
const { seedDefaultTemplates } = require('./routes/templates');

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';

// Initialize Socket.IO
initSocket(server);

// Middleware
app.use(cors());
app.use(helmet({ crossOriginResourcePolicy: { policy: 'cross-origin' } }));
app.use(morgan('dev'));
app.use(express.json());

// Static file serving for uploads
app.use('/uploads', express.static(path.join(__dirname, '../uploads')));

// Passport Google OAuth setup
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID || '',
      clientSecret: process.env.GOOGLE_CLIENT_SECRET || '',
      callbackURL: process.env.GOOGLE_CALLBACK_URL || '/api/auth/google/callback',
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails[0].value;
        const name = profile.displayName;
        const avatar = profile.photos[0]?.value || null;
        const googleId = profile.id;

        let user = await prisma.user.findUnique({ where: { googleId } });

        if (!user) {
          // Check if user exists with same email
          user = await prisma.user.findUnique({ where: { email } });

          if (user) {
            // Link Google account to existing user
            user = await prisma.user.update({
              where: { id: user.id },
              data: { googleId, avatar: avatar || user.avatar },
            });
          } else {
            // Create new user
            user = await prisma.user.create({
              data: { email, name, avatar, googleId },
            });
          }
        }

        done(null, user);
      } catch (error) {
        done(error, null);
      }
    }
  )
);

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await prisma.user.findUnique({ where: { id } });
    done(null, user);
  } catch (error) {
    done(error, null);
  }
});

app.use(passport.initialize());

// Rate limiters
app.use('/api/auth', authLimiter);
app.use('/api/attachments', uploadLimiter);
app.use('/api', apiLimiter);

// Health check (before auth routes)
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Routes
const authRoutes = require('./routes/auth');
const boardRoutes = require('./routes/boards');
const taskRoutes = require('./routes/tasks');
const attachmentRoutes = require('./routes/attachments');
const embedRoutes = require('./routes/embeds');
const notificationRoutes = require('./routes/notifications');
const subtaskRoutes = require('./routes/subtasks');
const timeTrackingRoutes = require('./routes/timeTracking');
const dependencyRoutes = require('./routes/dependencies');
const recurringRoutes = require('./routes/recurring');
const searchRoutes = require('./routes/search');
const tagRoutes = require('./routes/tags');
const favoriteRoutes = require('./routes/favorites');
const templateRoutes = require('./routes/templates');
const activityRoutes = require('./routes/activity');
const chatRoutes = require('./routes/chat');
const adminRoutes = require('./routes/admin');
const twoFactorRoutes = require('./routes/twoFactor');
const analyticsRoutes = require('./routes/analytics');
const exportRoutes = require('./routes/export');
const linkPreviewRoutes = require('./routes/linkPreview');

app.use('/api/auth', authRoutes);
app.use('/api/boards', boardRoutes);
app.use('/api/tasks', taskRoutes);
app.use('/api/attachments', attachmentRoutes);
app.use('/api', attachmentRoutes); // Also mount for /api/tasks/:taskId/attachments
app.use('/api/embeds', embedRoutes);
app.use('/api', embedRoutes); // Also mount for /api/tasks/:taskId/embeds
app.use('/api/notifications', notificationRoutes);
app.use('/api', subtaskRoutes); // /api/tasks/:taskId/subtasks, /api/checklist/:id
app.use('/api', timeTrackingRoutes); // /api/tasks/:taskId/time, /api/time/:id, /api/boards/:boardId/time-report
app.use('/api', dependencyRoutes); // /api/tasks/:taskId/dependencies, /api/dependencies/:id
app.use('/api', recurringRoutes); // /api/tasks/:taskId/recurring
app.use('/api/search', searchRoutes);
app.use('/api', tagRoutes); // /api/tags, /api/tasks/:taskId/tags
app.use('/api/favorites', favoriteRoutes);
app.use('/api/templates', templateRoutes);
app.use('/api', templateRoutes); // /api/boards/from-template/:templateId
app.use('/api', activityRoutes); // /api/boards/:boardId/activity
app.use('/api', chatRoutes); // /api/boards/:boardId/chat, /api/chat/:id
app.use('/api/admin', adminRoutes);
app.use('/api/auth', twoFactorRoutes);
app.use('/api/analytics', analyticsRoutes);
app.use('/api/export', exportRoutes);
app.use('/api/link-preview', linkPreviewRoutes);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
server.listen(PORT, async () => {
  console.log(`Server running on port ${PORT}`);

  // Start reminder service
  startReminderService();

  // Seed default board templates
  await seedDefaultTemplates();

  // Schedule daily digest at 8:00 AM
  cron.schedule('0 8 * * *', async () => {
    console.log('Running daily digest...');
    await sendDigests();
  });
});

module.exports = app;
