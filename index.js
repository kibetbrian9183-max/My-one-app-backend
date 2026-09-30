import 'dotenv/config';
import crypto from 'node:crypto';
import express from 'express';
import cors from 'cors';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import rateLimit from 'express-rate-limit';

const { MONGODB_URI, JWT_SECRET, ADMIN_KEY, PORT = 4000, CLIENT_ORIGIN = 'http://localhost:5173' } = process.env;
if (!MONGODB_URI || !JWT_SECRET) {
  console.error('Set MONGODB_URI and JWT_SECRET in server/.env (see .env.example)');
  process.exit(1);
}

/* ---------- Models ---------- */
const User = mongoose.model('User', new mongoose.Schema({
  phone: { type: String, required: true, unique: true },   // normalised, e.g. 0712345678
  pinHash: { type: String, required: true },                // bcrypt hash, the PIN itself is never stored
  balance: { type: Number, default: 0, min: 0 },            // M-PESA balance (Ksh): edit this in MongoDB
  fuliza: { type: Number, default: 0, min: 0 },             // available Fuliza limit (Ksh): edit this in MongoDB
  failedAttempts: { type: Number, default: 0 },
  lockedUntil: Date,
}, { timestamps: true }));

const Txn = mongoose.model('Transaction', new mongoose.Schema({
  user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
  code: String,
  name: String,
  masked: String,
  amount: Number,                                           // negative = money out
  at: { type: Date, default: Date.now },
}));

/* ---------- Helpers ---------- */
const PHONE_RE = /^(?:\+?254|0)[17]\d{8}$/;
const FEE_TIERS = [ // keep in sync with the client: [highest amount in band, fee]
  [49, 0], [100, 0], [500, 7], [1000, 13], [1500, 23], [2500, 33], [3500, 53], [5000, 57],
  [7500, 78], [10000, 90], [15000, 100], [20000, 105], [35000, 108], [50000, 108], [250000, 108],
];
const feeFor = (n) => (FEE_TIERS.find(([max]) => n <= max) ?? [0, 0])[1];
const round = (n) => Math.round(n * 100) / 100;
const normalizePhone = (raw) => {
  const p = String(raw || '').replace(/\s/g, '');
  if (p.startsWith('+254')) return '0' + p.slice(4);
  if (p.startsWith('254')) return '0' + p.slice(3);
  return p;
};
const maskPhone = (p) => `${p.slice(0, 4)}***${p.slice(-3)}`;
const makeCode = () => Array.from(crypto.randomBytes(10), (b) => 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'[b % 36]).join('');
const publicUser = (u) => ({ phone: u.phone, balance: u.balance, fuliza: u.fuliza });

class HttpError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

const MAX_ATTEMPTS = 5, LOCK_MINUTES = 15;
async function checkPin(user, pin) {
  if (user.lockedUntil && user.lockedUntil > new Date()) {
    const mins = Math.ceil((user.lockedUntil - Date.now()) / 60000);
    throw new HttpError(423, `Too many wrong attempts. Try again in ${mins} min.`);
  }
  if (await bcrypt.compare(String(pin), user.pinHash)) {
    if (user.failedAttempts) { user.failedAttempts = 0; user.lockedUntil = undefined; await user.save(); }
    return;
  }
  user.failedAttempts += 1;
  if (user.failedAttempts >= MAX_ATTEMPTS) { user.lockedUntil = new Date(Date.now() + LOCK_MINUTES * 60000); user.failedAttempts = 0; }
  await user.save();
  const left = MAX_ATTEMPTS - user.failedAttempts;
  throw new HttpError(403, user.lockedUntil > new Date() ? `Too many wrong attempts. Locked for ${LOCK_MINUTES} min.` : `Wrong PIN. ${left} attempt${left === 1 ? '' : 's'} left.`);
}

const wrap = (fn) => (req, res, next) => fn(req, res).catch(next);
const auth = (req, _res, next) => {
  try {
    req.userId = jwt.verify((req.headers.authorization || '').replace('Bearer ', ''), JWT_SECRET).sub;
    next();
  } catch { next(new HttpError(401, 'Session expired. Please sign in again.')); }
};

/* ---------- App ---------- */
const app = express();
app.use(cors({ origin: CLIENT_ORIGIN }));
app.use(express.json({ limit: '10kb' }));

// Sign in. A phone number we have not seen yet is registered with the PIN entered.
app.post('/api/auth/login', rateLimit({ windowMs: 15 * 60000, limit: 30, standardHeaders: true, legacyHeaders: false }), wrap(async (req, res) => {
  const phone = normalizePhone(req.body.phone);
  const pin = String(req.body.pin ?? '');
  if (!PHONE_RE.test(phone) || !/^\d{4}$/.test(pin)) throw new HttpError(400, 'Enter a valid phone number and a 4-digit PIN.');
  let user = await User.findOne({ phone });
  let created = false;
  if (user) await checkPin(user, pin);
  else {
    try { user = await User.create({ phone, pinHash: await bcrypt.hash(pin, 10) }); created = true; }
    catch (e) { if (e.code === 11000) throw new HttpError(409, 'Please try again.'); throw e; }
  }
  const token = jwt.sign({ sub: String(user._id) }, JWT_SECRET, { expiresIn: '12h' });
  res.json({ token, created, user: publicUser(user) });
}));

app.get('/api/me', auth, wrap(async (req, res) => {
  const user = await User.findById(req.userId);
  if (!user) throw new HttpError(401, 'Session expired. Please sign in again.');
  res.json(publicUser(user));
}));

app.get('/api/transactions', auth, wrap(async (req, res) => {
  const rows = await Txn.find({ user: req.userId }).sort({ at: -1 }).limit(300).lean();
  res.json(rows.map((t) => ({ id: String(t._id), name: t.name, masked: t.masked, amount: t.amount, at: t.at })));
}));

// Send money: verifies the PIN, checks funds, deducts amount + fee and records the statement lines.
app.post('/api/transfer', auth, wrap(async (req, res) => {
  const { pin, method, phone: rawPhone } = req.body;
  const name = String(req.body.name ?? '').trim().slice(0, 40);
  const phone = normalizePhone(rawPhone);
  const amount = Number(req.body.amount);
  if (!name || !PHONE_RE.test(phone)) throw new HttpError(400, 'Recipient name or number is invalid.');
  if (!Number.isInteger(amount) || amount < 1 || amount > 250000) throw new HttpError(400, 'Amount must be between Ksh 1 and Ksh 250,000.');

  const user = await User.findById(req.userId);
  if (!user) throw new HttpError(401, 'Session expired. Please sign in again.');
  await checkPin(user, pin);

  const code = makeCode();
  const at = new Date();
  if (method !== 'mpesa') return res.json({ id: code, at, fee: 0, balance: user.balance, fuliza: user.fuliza });

  const fee = feeFor(amount);
  const total = amount + fee;
  if (user.balance + user.fuliza < total) {
    throw new HttpError(400, `Insufficient funds. You need Ksh ${total.toFixed(2)} including the Ksh ${fee.toFixed(2)} fee.`);
  }
  // Spend the M-PESA balance first, then draw the rest from the Fuliza limit.
  const fromWallet = Math.min(user.balance, total);
  const updated = await User.findOneAndUpdate(
    { _id: user._id, balance: user.balance, fuliza: user.fuliza }, // fails if it changed meanwhile
    { $set: { balance: round(user.balance - fromWallet), fuliza: round(user.fuliza - (total - fromWallet)) } },
    { new: true },
  );
  if (!updated) throw new HttpError(409, 'Your balance just changed. Please try again.');

  const masked = maskPhone(phone);
  await Txn.insertMany([
    { user: user._id, code, name, masked, amount: -amount, at },
    ...(fee > 0 ? [{ user: user._id, code: `${code}-FEE`, name: 'Transaction cost', masked: 'M-PESA', amount: -fee, at }] : []),
  ]);
  res.json({ id: code, at, fee, balance: updated.balance, fuliza: updated.fuliza });
}));

// Optional admin route to set balance / Fuliza limit (you can also edit the user document directly in MongoDB).
app.patch('/api/admin/users/:phone', wrap(async (req, res) => {
  const given = Buffer.from(String(req.headers['x-admin-key'] || ''));
  const real = Buffer.from(ADMIN_KEY || '');
  if (!ADMIN_KEY || given.length !== real.length || !crypto.timingSafeEqual(given, real)) throw new HttpError(404, 'Not found');
  const set = {};
  for (const key of ['balance', 'fuliza']) {
    if (req.body[key] === undefined) continue;
    const v = Number(req.body[key]);
    if (!Number.isFinite(v) || v < 0) throw new HttpError(400, `${key} must be a number, 0 or more.`);
    set[key] = round(v);
  }
  const user = await User.findOneAndUpdate({ phone: normalizePhone(req.params.phone) }, { $set: set }, { new: true });
  if (!user) throw new HttpError(404, 'No user with that phone number.');
  res.json(publicUser(user));
}));

app.use((err, _req, res, _next) => {
  if (!err.status) console.error(err);
  res.status(err.status || 500).json({ error: err.status ? err.message : 'Something went wrong on the server.' });
});

await mongoose.connect(MONGODB_URI);
app.listen(PORT, () => console.log(`API ready on http://localhost:${PORT}`));
