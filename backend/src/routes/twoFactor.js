const express = require('express');
const prisma = require('../db');
const auth = require('../middleware/auth');
const router = express.Router();

// POST /api/auth/2fa/setup - generate secret and QR code
router.post('/2fa/setup', auth, async (req, res) => {
  try {
    const { authenticator } = await import('otpauth');
    const QRCode = require('qrcode');

    const user = await prisma.user.findUnique({ where: { id: req.user.userId } });
    if (!user) return res.status(404).json({ error: 'User not found' });

    // Generate a random secret
    const secret = Array.from(crypto.getRandomValues(new Uint8Array(20)))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('')
      .slice(0, 32)
      .toUpperCase();

    // Create TOTP instance
    const totp = new authenticator.TOTP({
      issuer: 'MyPub',
      label: user.email,
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret: authenticator.Secret.fromHex(secret),
    });

    const otpauthUrl = totp.toString();

    // Store secret temporarily (not enabled yet)
    await prisma.user.update({
      where: { id: req.user.userId },
      data: { twoFactorSecret: secret },
    });

    // Generate QR code
    const qrCode = await QRCode.toDataURL(otpauthUrl);

    res.json({ secret, qrCode });
  } catch (error) {
    console.error('2FA setup error:', error);
    res.status(500).json({ error: 'Failed to setup 2FA' });
  }
});

// POST /api/auth/2fa/verify - verify token and enable 2FA
router.post('/2fa/verify', auth, async (req, res) => {
  try {
    const { authenticator } = await import('otpauth');
    const { token } = req.body;

    const user = await prisma.user.findUnique({ where: { id: req.user.userId } });
    if (!user || !user.twoFactorSecret) {
      return res.status(400).json({ error: '2FA not set up' });
    }

    const totp = new authenticator.TOTP({
      issuer: 'MyPub',
      label: user.email,
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret: authenticator.Secret.fromHex(user.twoFactorSecret),
    });

    const isValid = totp.validate({ token, window: 1 }) !== null;

    if (!isValid) {
      return res.status(400).json({ error: 'Invalid token' });
    }

    await prisma.user.update({
      where: { id: req.user.userId },
      data: { twoFactorEnabled: true },
    });

    res.json({ message: '2FA enabled successfully' });
  } catch (error) {
    console.error('2FA verify error:', error);
    res.status(500).json({ error: 'Failed to verify 2FA' });
  }
});

// POST /api/auth/2fa/validate - validate token during login
router.post('/2fa/validate', async (req, res) => {
  try {
    const { authenticator } = await import('otpauth');
    const { userId, token } = req.body;

    const user = await prisma.user.findUnique({ where: { id: userId } });
    if (!user || !user.twoFactorEnabled || !user.twoFactorSecret) {
      return res.status(400).json({ error: '2FA not enabled' });
    }

    const totp = new authenticator.TOTP({
      issuer: 'MyPub',
      label: user.email,
      algorithm: 'SHA1',
      digits: 6,
      period: 30,
      secret: authenticator.Secret.fromHex(user.twoFactorSecret),
    });

    const isValid = totp.validate({ token, window: 1 }) !== null;

    if (!isValid) {
      return res.status(401).json({ error: 'Invalid 2FA token' });
    }

    res.json({ valid: true });
  } catch (error) {
    console.error('2FA validate error:', error);
    res.status(500).json({ error: 'Failed to validate 2FA' });
  }
});

// DELETE /api/auth/2fa/disable - disable 2FA
router.delete('/2fa/disable', auth, async (req, res) => {
  try {
    await prisma.user.update({
      where: { id: req.user.userId },
      data: { twoFactorEnabled: false, twoFactorSecret: null },
    });

    res.json({ message: '2FA disabled' });
  } catch (error) {
    console.error('2FA disable error:', error);
    res.status(500).json({ error: 'Failed to disable 2FA' });
  }
});

module.exports = router;
