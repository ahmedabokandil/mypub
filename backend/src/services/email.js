const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.GMAIL_USER,
    pass: process.env.GMAIL_APP_PASSWORD,
  },
});

async function sendEmail({ to, subject, html }) {
  try {
    const info = await transporter.sendMail({
      from: process.env.GMAIL_USER,
      to,
      subject,
      html,
    });
    console.log('Email sent:', info.messageId);
    return info;
  } catch (error) {
    console.error('Failed to send email:', error.message);
    throw error;
  }
}

module.exports = { sendEmail };
