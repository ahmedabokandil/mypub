const prisma = require('../db');
const { sendEmail } = require('./email');

async function sendDigests() {
  try {
    const configs = await prisma.emailDigestConfig.findMany({
      where: { enabled: true },
    });

    for (const config of configs) {
      try {
        const user = await prisma.user.findUnique({ where: { id: config.userId } });
        if (!user) continue;

        const now = new Date();
        const todayStart = new Date(now);
        todayStart.setHours(0, 0, 0, 0);
        const todayEnd = new Date(now);
        todayEnd.setHours(23, 59, 59, 999);

        // Tasks due today
        const dueToday = await prisma.task.findMany({
          where: {
            userId: config.userId,
            dueDate: { gte: todayStart, lte: todayEnd },
            archived: false,
          },
          select: { id: true, title: true, priority: true, dueDate: true },
        });

        // Overdue tasks
        const overdue = await prisma.task.findMany({
          where: {
            userId: config.userId,
            dueDate: { lt: todayStart },
            archived: false,
            column: { name: { notIn: ['Done', 'Completed', 'Verified', 'Fixed'] } },
          },
          select: { id: true, title: true, priority: true, dueDate: true },
        });

        // Recent activity (last 24 hours)
        const yesterday = new Date(now);
        yesterday.setDate(yesterday.getDate() - 1);

        const recentActivity = await prisma.activityLog.findMany({
          where: {
            createdAt: { gte: yesterday },
            board: { members: { some: { userId: config.userId } } },
          },
          include: { user: { select: { name: true } } },
          orderBy: { createdAt: 'desc' },
          take: 20,
        });

        // Build email
        const dueTodayHtml = dueToday.length > 0
          ? `<h3>Due Today (${dueToday.length})</h3><ul>${dueToday.map((t) => `<li><strong>${t.title}</strong> - ${t.priority} priority</li>`).join('')}</ul>`
          : '<p>No tasks due today.</p>';

        const overdueHtml = overdue.length > 0
          ? `<h3>Overdue (${overdue.length})</h3><ul>${overdue.map((t) => `<li><strong>${t.title}</strong> - due ${new Date(t.dueDate).toLocaleDateString()}</li>`).join('')}</ul>`
          : '';

        const activityHtml = recentActivity.length > 0
          ? `<h3>Recent Activity</h3><ul>${recentActivity.map((a) => `<li>${a.user.name}: ${a.action} ${a.entity}</li>`).join('')}</ul>`
          : '';

        const html = `
          <h2>Your Daily Digest</h2>
          ${dueTodayHtml}
          ${overdueHtml}
          ${activityHtml}
          <p><small>You can manage your digest settings in your profile.</small></p>
        `;

        await sendEmail({
          to: user.email,
          subject: `Daily Digest - ${now.toLocaleDateString()}`,
          html,
        });

        // Update last sent
        await prisma.emailDigestConfig.update({
          where: { id: config.id },
          data: { lastSent: now },
        });

        console.log(`Digest sent to ${user.email}`);
      } catch (userError) {
        console.error(`Failed to send digest for user ${config.userId}:`, userError.message);
      }
    }
  } catch (error) {
    console.error('Digest service error:', error.message);
  }
}

module.exports = { sendDigests };
