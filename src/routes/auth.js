import { Router } from 'express';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';
import { z } from 'zod';
import { UAParser } from 'ua-parser-js';
import User from '../models/User.js';
import LoginEvent from '../models/LoginEvent.js';
import { requireAuth } from '../middleware/auth.js';

const router = Router();

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 10, standardHeaders: true, legacyHeaders: false });

const SignupSchema = z.object({
  phone:    z.string().regex(/^[6-9]\d{9}$/, 'Invalid Indian mobile'),
  password: z.string().min(8).max(128),
  name:     z.string().trim().min(2).max(80).optional(),
  village:  z.string().trim().min(2).max(80).optional(),
});

const LoginSchema = z.object({
  phone:    z.string().regex(/^[6-9]\d{9}$/),
  password: z.string().min(1).max(128),
});

function captureContext(req) {
  const ua = req.headers['user-agent'] || '';
  const parsed = new UAParser(ua).getResult();
  return {
    ip:        req.ip || req.headers['x-forwarded-for']?.split(',')[0]?.trim() || '',
    userAgent: ua,
    browser:   [parsed.browser.name, parsed.browser.version].filter(Boolean).join(' '),
    os:        [parsed.os.name, parsed.os.version].filter(Boolean).join(' '),
    device:    parsed.device.type || 'desktop',
    language:  req.headers['accept-language'] || '',
    referrer:  req.headers['referer'] || req.headers['referrer'] || '',
  };
}

function sign(user) {
  return jwt.sign(
    { sub: user._id.toString(), phone: user.phone, role: user.role, tier: user.tier },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
  );
}

router.post('/signup', async (req, res, next) => {
  try {
    const parsed = SignupSchema.safeParse(req.body);
    if (!parsed.success) return res.status(400).json({ error: parsed.error.flatten() });
    const { phone, password, name = '', village = '' } = parsed.data;

    const exists = await User.findOne({ phone }).lean();
    if (exists) return res.status(409).json({ error: 'Phone already registered' });

    const passwordHash = await bcrypt.hash(password, 12);
    const user = await User.create({ phone, passwordHash, name, village });
    const token = sign(user);
    res.status(201).json({ token, user: { id: user._id, phone, name, village, tier: user.tier, role: user.role } });
  } catch (e) { next(e); }
});

router.post('/login', loginLimiter, async (req, res, next) => {
  const ctx = captureContext(req);
  const parsed = LoginSchema.safeParse(req.body);
  if (!parsed.success) {
    await LoginEvent.create({ phone: req.body?.phone || '', success: false, reason: 'invalid_input', ...ctx });
    return res.status(400).json({ error: parsed.error.flatten() });
  }
  const { phone, password } = parsed.data;
  try {
    const user = await User.findOne({ phone });
    if (!user) {
      await LoginEvent.create({ phone, success: false, reason: 'no_user', ...ctx });
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    const ok = await bcrypt.compare(password, user.passwordHash);
    if (!ok) {
      await LoginEvent.create({ userId: user._id, phone, success: false, reason: 'invalid_password', ...ctx });
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    await LoginEvent.create({ userId: user._id, phone, success: true, ...ctx });
    const token = sign(user);
    res.json({ token, user: { id: user._id, phone, name: user.name, village: user.village, tier: user.tier, role: user.role } });
  } catch (e) { next(e); }
});

router.get('/me', requireAuth, async (req, res, next) => {
  try {
    const user = await User.findById(req.user.sub).lean();
    if (!user) return res.status(404).json({ error: 'Not found' });
    const { passwordHash, ...safe } = user;
    res.json({ user: safe });
  } catch (e) { next(e); }
});

export default router;
