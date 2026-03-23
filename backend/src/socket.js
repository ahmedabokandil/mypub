const { Server } = require('socket.io');
const jwt = require('jsonwebtoken');

let io;

function initSocket(server) {
  io = new Server(server, {
    cors: { origin: '*', methods: ['GET', 'POST'] }
  });

  // JWT auth middleware for socket
  io.use((socket, next) => {
    const token = socket.handshake.auth.token;
    if (!token) return next(new Error('Authentication required'));
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
      socket.userId = decoded.userId;
      next();
    } catch (err) {
      next(new Error('Invalid token'));
    }
  });

  io.on('connection', (socket) => {
    // Join user's personal room
    socket.join(`user:${socket.userId}`);

    // Join board rooms
    socket.on('join-board', (boardId) => {
      socket.join(`board:${boardId}`);
    });

    socket.on('leave-board', (boardId) => {
      socket.leave(`board:${boardId}`);
    });

    // Chat messages
    socket.on('chat-message', async (data) => {
      const prisma = require('./db');
      try {
        const msg = await prisma.chatMessage.create({
          data: { content: data.content, boardId: data.boardId, userId: socket.userId },
          include: { user: { select: { id: true, name: true, avatar: true } } }
        });
        io.to(`board:${data.boardId}`).emit('chat-message', msg);
      } catch (err) { console.error('Chat error:', err); }
    });

    socket.on('disconnect', () => {});
  });

  return io;
}

function getIO() { return io; }
function emitToBoard(boardId, event, data) { if (io) io.to(`board:${boardId}`).emit(event, data); }
function emitToUser(userId, event, data) { if (io) io.to(`user:${userId}`).emit(event, data); }

module.exports = { initSocket, getIO, emitToBoard, emitToUser };
