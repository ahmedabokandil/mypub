# RemindFlow - Smart Task & Reminder Management

A full-stack task management application with Kanban boards, reminders, email notifications, file attachments, and embedded media support. Features a beautiful modern web interface and Android mobile app sharing the same backend.

## Features

- **Multi-user support** with email/password and Google OAuth authentication
- **Kanban boards** with drag-and-drop task management
- **Reminders & due dates** with email and push notifications
- **File attachments** upload and download
- **Embedded URLs & YouTube videos** in tasks
- **Real-time notifications** with browser push notifications
- **Comments** on tasks for team collaboration
- **Labels & priorities** for task organization
- **Mobile app** (Android) with configurable backend URL
- **Responsive web design** works on all screen sizes

## Tech Stack

| Component | Technology |
|-----------|------------|
| Backend | Node.js, Express, Prisma ORM, SQLite |
| Web Frontend | React, Vite, Tailwind CSS, Framer Motion |
| Mobile App | React Native (Expo), Android |
| Auth | JWT, Google OAuth 2.0, Passport.js |
| Email | Nodemailer with Gmail SMTP |
| Notifications | Web Push API, node-cron |

## Project Structure

```
├── backend/          # Express API server
│   ├── src/
│   │   ├── index.js          # Server entry point
│   │   ├── db.js             # Prisma client
│   │   ├── middleware/       # Auth middleware
│   │   ├── routes/           # API routes
│   │   └── services/         # Email, push, reminder services
│   ├── prisma/               # Database schema & migrations
│   └── uploads/              # File attachments storage
├── web/              # React web application
│   └── src/
│       ├── pages/            # Page components
│       ├── components/       # Reusable components
│       ├── context/          # Auth & notification context
│       └── api/              # Axios API client
└── mobile/           # React Native mobile app
    └── src/
        ├── screens/          # App screens
        ├── components/       # Reusable components
        ├── context/          # Auth context
        └── api/              # API client
```

## Getting Started

### Prerequisites

- Node.js 18+
- npm or yarn

### Backend Setup

```bash
cd backend
cp .env.example .env
# Edit .env with your configuration
npm install
npx prisma migrate dev
npm run dev
```

The API will run on http://localhost:3001

### Web Frontend Setup

```bash
cd web
npm install
npm run dev
```

The web app will run on http://localhost:5173

### Mobile App Setup

```bash
cd mobile
npm install
npx expo start
```

Scan the QR code with Expo Go app on your Android device. On first launch, enter your backend server URL (e.g., `http://your-server-ip:3001`).

## Google OAuth Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/apis/credentials)
2. Create a new OAuth 2.0 Client ID
3. Add authorized redirect URI: `http://localhost:3001/api/auth/google/callback`
4. Copy Client ID and Secret to `.env`

## Gmail Email Setup

1. Enable 2-Factor Authentication on your Google account
2. Generate an App Password at https://myaccount.google.com/apppasswords
3. Add your Gmail and App Password to `.env`

## API Endpoints

### Auth
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login
- `GET /api/auth/google` - Google OAuth
- `GET /api/auth/me` - Get current user

### Boards
- `GET /api/boards` - List boards
- `POST /api/boards` - Create board
- `GET /api/boards/:id` - Get board with columns/tasks
- `PUT /api/boards/:id` - Update board
- `DELETE /api/boards/:id` - Delete board
- `POST /api/boards/:id/members` - Add member

### Tasks
- `POST /api/tasks` - Create task
- `GET /api/tasks/:id` - Get task details
- `PUT /api/tasks/:id` - Update task
- `DELETE /api/tasks/:id` - Delete task
- `PUT /api/tasks/:id/move` - Move task between columns
- `POST /api/tasks/:id/comments` - Add comment

### Attachments & Embeds
- `POST /api/tasks/:taskId/attachments` - Upload file
- `GET /api/attachments/:id/download` - Download file
- `POST /api/tasks/:taskId/embeds` - Add URL/YouTube embed

### Notifications
- `GET /api/notifications` - List notifications
- `PUT /api/notifications/:id/read` - Mark as read
- `PUT /api/notifications/read-all` - Mark all as read
