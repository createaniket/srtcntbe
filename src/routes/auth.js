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

/**
 * 🔒 Rate limiter
 */
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
});

/**
 * 🧾 VALIDATION
 */
const SignupSchema = z.object({
  username: z.string()
    .min(3)
    .max(20)
    .regex(/^[a-zA-Z0-9_]+$/, 'Only letters, numbers, underscore'),

  phone: z.string().regex(/^[6-9]\d{9}$/).optional(),

  password: z.string().min(8).max(128),

  name: z.string().trim().min(2).max(80).optional(),
  village: z.string().trim().min(2).max(80).optional(),
});

const LoginSchema = z.object({
  username: z.string().min(3),
  password: z.string().min(1).max(128),
});

/**
 * 📊 Capture context
 */
function captureContext(req) {
  const ua = req.headers['user-agent'] || '';
  const parsed = new UAParser(ua).getResult();

  return {
    ip:
      req.headers['x-forwarded-for']?.split(',')[0]?.trim() ||
      req.socket?.remoteAddress ||
      '',
    userAgent: ua,
    browser: [parsed.browser.name, parsed.browser.version].filter(Boolean).join(' '),
    os: [parsed.os.name, parsed.os.version].filter(Boolean).join(' '),
    device: parsed.device.type || 'desktop',
    language: req.headers['accept-language'] || '',
    referrer: req.headers['referer'] || '',
  };
}

/**
 * 🔐 JWT SIGN
 */
function sign(user) {
  return jwt.sign(
    {
      sub: user._id.toString(),
      username: user.username,
      phone: user.phone,
      role: user.role,
      tier: user.tier,
    },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN || '7d' }
  );
}

/**
 * 🟢 SIGNUP
 */
router.post('/signup', async (req, res, next) => {
  try {
    const parsed = SignupSchema.safeParse(req.body);

    if (!parsed.success) {
      return res.status(400).json({ error: parsed.error.flatten() });
    }

    let {
      username,
      phone,
      password,
      name = '',
      village = '',
    } = parsed.data;

    username = username.toLowerCase();

    const exists = await User.findOne({
      $or: [
        { username },
        ...(phone ? [{ phone }] : []),
      ],
    });

    if (exists) {
      return res.status(409).json({
        error: 'Username or phone already exists',
      });
    }

    const passwordHash = await bcrypt.hash(password, 12);

    const user = await User.create({
      username,
      phone,
      passwordHash,
      name,
      village,
    });

    const token = sign(user);

    res.status(201).json({
      token,
      user: {
        id: user._id,
        username,
        phone,
        name,
        village,
        tier: user.tier,
        role: user.role,
      },
    });

  } catch (e) {
    next(e);
  }
});

/**
 * 🔵 LOGIN (USERNAME BASED)
 */
router.post('/login', loginLimiter, async (req, res, next) => {
  const ctx = captureContext(req);

  const parsed = LoginSchema.safeParse(req.body);

  if (!parsed.success) {
    await LoginEvent.create({
      username: req.body?.username || '',
      success: false,
      reason: 'invalid_input',
      ...ctx,
    });

    return res.status(400).json({ error: parsed.error.flatten() });
  }

  let { username, password } = parsed.data;
  username = username.toLowerCase();

  try {
    const user = await User.findOne({ username });

    if (!user) {
      await LoginEvent.create({
        username,
        success: false,
        reason: 'no_user',
        ...ctx,
      });

      return res.status(401).json({ error: 'Invalid credentials' });
    }

    /**
     * 🔒 ACCOUNT LOCK CHECK
     */
    if (user.lockUntil && user.lockUntil > Date.now()) {
      return res.status(423).json({ error: 'Account temporarily locked' });
    }

    const ok = await bcrypt.compare(password, user.passwordHash);

    if (!ok) {
      user.failedLoginAttempts += 1;

      if (user.failedLoginAttempts >= 5) {
        user.lockUntil = Date.now() + 15 * 60 * 1000;
        user.failedLoginAttempts = 0;
      }

      await user.save();

      await LoginEvent.create({
        userId: user._id,
        username,
        success: false,
        reason: 'invalid_password',
        ...ctx,
      });

      return res.status(401).json({ error: 'Invalid credentials' });
    }

    /**
     * ✅ RESET ATTEMPTS
     */
    user.failedLoginAttempts = 0;
    user.lockUntil = null;
    await user.save();

    await LoginEvent.create({
      userId: user._id,
      username,
      success: true,
      ...ctx,
    });

    const token = sign(user);

    res.json({
      token,
      user: {
        id: user._id,
        username: user.username,
        phone: user.phone,
        name: user.name,
        village: user.village,
        tier: user.tier,
        role: user.role,
      },
    });

  } catch (e) {
    next(e);
  }
});

/**
 * 🟡 GET CURRENT USER
 */
router.get('/me', requireAuth, async (req, res, next) => {
  try {
    const user = await User.findById(req.user.sub).lean();

    if (!user) {
      return res.status(404).json({ error: 'Not found' });
    }

    const { passwordHash, ...safe } = user;

    res.json({ user: safe });

  } catch (e) {
    next(e);
  }
});

export default router;