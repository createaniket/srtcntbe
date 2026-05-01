import { Router } from 'express';
import LoginEvent from '../models/LoginEvent.js';
import { requireAuth } from '../middleware/auth.js';

const router = Router();

// Users see their own events; admins see everything.
router.get('/', requireAuth, async (req, res, next) => {
  try {
    const limit = Math.min(Number(req.query.limit) || 50, 200);
    const filter = req.user.role === 'admin' ? {} : { userId: req.user.sub };
    const events = await LoginEvent.find(filter).sort({ createdAt: -1 }).limit(limit).lean();
    res.json({ events });
  } catch (e) { next(e); }
});

export default router;
