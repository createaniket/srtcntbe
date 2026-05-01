import mongoose from 'mongoose';

const UserSchema = new mongoose.Schema({
  // 🔑 Username (NEW - required & unique)
  username: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    minlength: 3,
    maxlength: 20,
  },

  // 📱 Phone (optional but unique if present)
  phone: {
    type: String,
    unique: true,
    sparse: true, // allows multiple null values
  },

  passwordHash: {
    type: String,
    required: true,
  },

  name: {
    type: String,
    default: '',
  },

  village: {
    type: String,
    default: '',
  },

  tier: {
    type: String,
    enum: ['bronze', 'silver', 'gold'],
    default: 'bronze',
  },

  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user',
  },

  aadhaarLast4: {
    type: String,
    default: '',
  },

  // 🔒 Security (NEW)
  failedLoginAttempts: {
    type: Number,
    default: 0,
  },

  lockUntil: {
    type: Date,
    default: null,
  },

  createdAt: {
    type: Date,
    default: Date.now,
  },
});

/**
 * ⚡ Indexes (IMPORTANT)
 */
UserSchema.index({ username: 1 }, { unique: true });
UserSchema.index({ phone: 1 }, { unique: true, sparse: true });

export default mongoose.model('User', UserSchema);