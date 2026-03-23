const webpush = require('web-push');

const VAPID_PUBLIC_KEY = process.env.VAPID_PUBLIC_KEY || '';
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY || '';
const VAPID_EMAIL = process.env.VAPID_EMAIL || 'mailto:admin@example.com';

if (VAPID_PUBLIC_KEY && VAPID_PRIVATE_KEY) {
  webpush.setVapidDetails(VAPID_EMAIL, VAPID_PUBLIC_KEY, VAPID_PRIVATE_KEY);
}

async function sendPushNotification(subscription, payload) {
  try {
    await webpush.sendNotification(
      {
        endpoint: subscription.endpoint,
        keys: {
          p256dh: subscription.p256dh,
          auth: subscription.auth,
        },
      },
      JSON.stringify(payload)
    );
    console.log('Push notification sent to:', subscription.endpoint);
  } catch (error) {
    console.error('Failed to send push notification:', error.message);
    if (error.statusCode === 410) {
      return { expired: true, endpoint: subscription.endpoint };
    }
    throw error;
  }
  return { expired: false };
}

module.exports = { sendPushNotification };
