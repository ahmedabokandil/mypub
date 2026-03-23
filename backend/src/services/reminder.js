const cron = require('node-cron');
const prisma = require('../db');
const { sendEmail } = require('./email');
const { sendPushNotification } = require('./push');

function startReminderService() {
  // Check for reminders every minute
  cron.schedule('* * * * *', async () => {
    try {
      const now = new Date();

      const tasks = await prisma.task.findMany({
        where: {
          reminder: { lte: now },
          reminderSent: false,
        },
        include: {
          user: true,
          board: true,
        },
      });

      for (const task of tasks) {
        try {
          // Create notification
          await prisma.notification.create({
            data: {
              title: 'Task Reminder',
              message: `Reminder: "${task.title}" is due${task.dueDate ? ' on ' + new Date(task.dueDate).toLocaleDateString() : ''}`,
              type: 'reminder',
              userId: task.userId,
              taskId: task.id,
            },
          });

          // Send email notification
          try {
            await sendEmail({
              to: task.user.email,
              subject: `Reminder: ${task.title}`,
              html: `
                <h2>Task Reminder</h2>
                <p>This is a reminder for your task: <strong>${task.title}</strong></p>
                ${task.description ? `<p>${task.description}</p>` : ''}
                ${task.dueDate ? `<p>Due date: ${new Date(task.dueDate).toLocaleDateString()}</p>` : ''}
                <p>Board: ${task.board.name}</p>
              `,
            });
          } catch (emailError) {
            console.error('Failed to send reminder email:', emailError.message);
          }

          // Send push notifications
          const subscriptions = await prisma.pushSubscription.findMany({
            where: { userId: task.userId },
          });

          for (const sub of subscriptions) {
            try {
              const result = await sendPushNotification(sub, {
                title: 'Task Reminder',
                body: `Reminder: "${task.title}"`,
                data: { taskId: task.id, boardId: task.boardId },
              });

              if (result.expired) {
                await prisma.pushSubscription.delete({ where: { id: sub.id } });
              }
            } catch (pushError) {
              console.error('Failed to send push notification:', pushError.message);
            }
          }

          // Mark reminder as sent
          await prisma.task.update({
            where: { id: task.id },
            data: { reminderSent: true },
          });

          console.log(`Reminder sent for task: ${task.title}`);
        } catch (taskError) {
          console.error(`Error processing reminder for task ${task.id}:`, taskError.message);
        }
      }
    } catch (error) {
      console.error('Reminder service error:', error.message);
    }

    // Process recurring tasks
    try {
      const now = new Date();
      const { calculateNextDate } = require('../routes/recurring');

      const recurringTasks = await prisma.task.findMany({
        where: {
          isRecurring: true,
          recurNextDate: { lte: now },
        },
      });

      for (const task of recurringTasks) {
        try {
          // Create a copy of the task in the same column
          await prisma.task.create({
            data: {
              title: task.title,
              description: task.description,
              priority: task.priority,
              dueDate: task.dueDate ? new Date(new Date(task.dueDate).getTime() + (task.recurNextDate.getTime() - new Date().getTime())) : null,
              columnId: task.columnId,
              boardId: task.boardId,
              userId: task.userId,
              position: task.position,
            },
          });

          // Update recurNextDate based on pattern
          const nextDate = calculateNextDate(now, task.recurPattern, task.recurInterval || 1);
          await prisma.task.update({
            where: { id: task.id },
            data: {
              recurNextDate: nextDate,
              reminderSent: false,
            },
          });

          console.log(`Recurring task created from: ${task.title}`);
        } catch (recurError) {
          console.error(`Error processing recurring task ${task.id}:`, recurError.message);
        }
      }
    } catch (error) {
      console.error('Recurring task service error:', error.message);
    }
  });

  console.log('Reminder service started');
}

module.exports = { startReminderService };
