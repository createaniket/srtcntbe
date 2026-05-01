import mongoose from 'mongoose';

const UserSchema = new mongoose.Schema({
  phone:        { type: String, required: true, unique: true, index: true },
  passwordHash: { type: String, required: true },
  name:         { type: String, default: '' },
  village:      { type: String, default: '' },
  tier:         { type: String, enum: ['bronze', 'silver', 'gold'], default: 'bronze' },
  role:         { type: String, enum: ['user', 'admin'], default: 'user' },
  aadhaarLast4: { type: String, default: '' },
  createdAt:    { type: Date, default: Date.now },
});

export default mongoose.model('User', UserSchema);
