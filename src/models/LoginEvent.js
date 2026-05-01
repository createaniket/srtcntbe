import mongoose from 'mongoose';

const LoginEventSchema = new mongoose.Schema({
  userId:    { type: mongoose.Schema.Types.ObjectId, ref: 'User', index: true },
  phone:     { type: String, index: true },
  success:   { type: Boolean, required: true },
  reason:    { type: String, default: '' },           // e.g. 'invalid_password', 'no_user'
  ip:        { type: String, default: '' },
  userAgent: { type: String, default: '' },
  browser:   { type: String, default: '' },
  os:        { type: String, default: '' },
  device:    { type: String, default: '' },
  country:   { type: String, default: '' },           // fill via geo lookup if needed
  region:    { type: String, default: '' },
  city:      { type: String, default: '' },
  language:  { type: String, default: '' },
  referrer:  { type: String, default: '' },
  createdAt: { type: Date,   default: Date.now, index: true },
});

export default mongoose.model('LoginEvent', LoginEventSchema);
