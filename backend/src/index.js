require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const morgan = require('morgan');
const path = require('path');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const jwt = require('jsonwebtoken');
const prisma = require('./db');
const { startReminderService } = require('./services/reminder');

const app = express();
const PORT = process.env.PORT || 3001;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:3000';

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

app.use('/api/auth', authRoutes);
app.use('/api/boards', boardRoutes);
app.use('/api/tasks', taskRoutes);
app.use('/api/attachments', attachmentRoutes);
app.use('/api', attachmentRoutes); // Also mount for /api/tasks/:taskId/attachments
app.use('/api/embeds', embedRoutes);
app.use('/api', embedRoutes); // Also mount for /api/tasks/:taskId/embeds
app.use('/api/notifications', notificationRoutes);

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);

  // Start reminder service
  startReminderService();
});

module.exports = app;
