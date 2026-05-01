import 'dotenv/config';
import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import mongoose from 'mongoose';
import authRouter from './routes/auth.js';
import eventsRouter from './routes/events.js';

const app = express();

if (process.env.TRUST_PROXY) app.set('trust proxy', Number(process.env.TRUST_PROXY));

app.use(helmet());
app.use(express.json({ limit: '32kb' }));

const allowed = (process.env.CORS_ORIGINS || '').split(',').map(s => s.trim()).filter(Boolean);
app.use(cors({
  origin: (origin, cb) => {
    if (!origin) return cb(null, true);            // curl / server-to-server
    if (allowed.includes(origin)) return cb(null, true);
    return cb(new Error(`CORS blocked: ${origin}`));
  },
  credentials: true,
}));

app.get('/healthz', (_req, res) => res.json({ ok: true, ts: Date.now() }));

app.use('/api/auth', authRouter);
app.use('/api/login-events', eventsRouter);

app.use((err, _req, res, _next) => {
  console.error('[error]', err.message);
  res.status(err.status || 500).json({ error: err.message || 'Internal error' });
});

const { MONGODB_URI, PORT = 4000 } = process.env;
if (!MONGODB_URI) { console.error('MONGODB_URI missing'); process.exit(1); }
if (!process.env.JWT_SECRET || process.env.JWT_SECRET.length < 32) {
  console.error('JWT_SECRET missing or too short (min 32 chars)'); process.exit(1);
}

mongoose.connect(MONGODB_URI).then(() => {
  console.log('[mongo] connected');
  app.listen(PORT, () => console.log(`[api] listening on :${PORT}`));
}).catch(err => { console.error('[mongo] connection failed', err); process.exit(1); });
