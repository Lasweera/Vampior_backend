require('dotenv').config();

const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const app = express();
const port = Number(process.env.PORT || 4000);
const jwtSecret = process.env.JWT_SECRET || 'local-only-secret-change-me';

app.use(cors());
app.use(express.json({ limit: '20kb' }));

// Demo-only in-memory user store. Replace with a database for persistent data.
const users = [];
const passwordResetTokens = new Map();

const normalizeEmail = (value) => String(value || '').trim().toLowerCase();
const normalizeMobile = (value) => String(value || '').replace(/[\s()+-]/g, '');
const publicUser = (user) => ({
  id: user.id,
  fullName: user.fullName,
  email: user.email,
  mobile: user.mobile,
});

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validMobile(mobile) {
  return /^\d{7,15}$/.test(normalizeMobile(mobile));
}

function validPassword(password) {
  return typeof password === 'string' &&
    password.length >= 8 &&
    /[A-Za-z]/.test(password) &&
    /\d/.test(password);
}

function findByIdentifier(identifier) {
  const value = String(identifier || '').trim();
  if (value.includes('@')) {
    const email = normalizeEmail(value);
    return users.find((user) => user.email === email);
  }
  const mobile = normalizeMobile(value);
  return users.find((user) => user.mobile === mobile);
}

app.get('/api/health', (_req, res) => {
  res.json({ success: true, message: 'Auth API is running.' });
});

app.post('/api/auth/register', async (req, res) => {
  const fullName = String(req.body.fullName || '').trim();
  const email = normalizeEmail(req.body.email);
  const mobile = normalizeMobile(req.body.mobile);
  const password = req.body.password;

  if (fullName.length < 2) return res.status(400).json({ message: 'Full name must contain at least 2 characters.' });
  if (!validEmail(email)) return res.status(400).json({ message: 'Enter a valid email address.' });
  if (!validMobile(mobile)) return res.status(400).json({ message: 'Enter a valid mobile number (7–15 digits).' });
  if (!validPassword(password)) return res.status(400).json({ message: 'Password must be at least 8 characters and contain a letter and a number.' });
  if (users.some((user) => user.email === email)) return res.status(409).json({ message: 'An account with this email already exists.' });
  if (users.some((user) => user.mobile === mobile)) return res.status(409).json({ message: 'An account with this mobile number already exists.' });

  try {
    const passwordHash = await bcrypt.hash(password, 10);
    const user = { id: crypto.randomUUID(), fullName, email, mobile, passwordHash };
    users.push(user);
    return res.status(201).json({ message: 'Account created successfully.', user: publicUser(user) });
  } catch (_error) {
    return res.status(500).json({ message: 'Could not create the account. Please try again.' });
  }
});

app.post('/api/auth/login', async (req, res) => {
  const identifier = String(req.body.identifier || '').trim();
  const password = req.body.password;
  if (!identifier || typeof password !== 'string' || !password) {
    return res.status(400).json({ message: 'Email/mobile number and password are required.' });
  }

  const user = findByIdentifier(identifier);
  if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ message: 'Invalid email/mobile number or password.' });
  }

  const token = jwt.sign({ sub: user.id }, jwtSecret, { expiresIn: '1h' });
  return res.json({ message: 'Login successful.', token, user: publicUser(user) });
});

app.post('/api/auth/forgot-password', (req, res) => {
  const identifier = String(req.body.identifier || '').trim();
  if (!identifier) return res.status(400).json({ message: 'Enter an email address or mobile number.' });

  const user = findByIdentifier(identifier);
  // For this local demo only, return a token so the reset flow can be tested without email/SMS.
  // Production systems should send a one-time link/code out-of-band and never return it in the API response.
  if (!user) {
    return res.status(404).json({ message: 'No account was found for those details.' });
  }

  const resetToken = crypto.randomBytes(24).toString('hex');
  passwordResetTokens.set(resetToken, {
    userId: user.id,
    expiresAt: Date.now() + 15 * 60 * 1000,
  });
  return res.json({
    message: 'Reset token generated for this local demo. Use it to set a new password.',
    resetToken,
  });
});

app.post('/api/auth/reset-password', async (req, res) => {
  const identifier = String(req.body.identifier || '').trim();
  const resetToken = String(req.body.resetToken || '').trim();
  const newPassword = req.body.newPassword;

  if (!identifier || !resetToken || typeof newPassword !== 'string') {
    return res.status(400).json({ message: 'Identifier, reset token, and new password are required.' });
  }
  if (!validPassword(newPassword)) {
    return res.status(400).json({ message: 'Password must be at least 8 characters and contain a letter and a number.' });
  }

  const tokenRecord = passwordResetTokens.get(resetToken);
  if (!tokenRecord || tokenRecord.expiresAt < Date.now()) {
    passwordResetTokens.delete(resetToken);
    return res.status(400).json({ message: 'Reset token is invalid or expired. Request a new token.' });
  }

  const user = findByIdentifier(identifier);
  if (!user || user.id !== tokenRecord.userId) {
    return res.status(400).json({ message: 'Reset token does not match this account.' });
  }

  try {
    user.passwordHash = await bcrypt.hash(newPassword, 10);
    passwordResetTokens.delete(resetToken);
    return res.json({ message: 'Password reset successfully.' });
  } catch (_error) {
    return res.status(500).json({ message: 'Could not reset the password. Please try again.' });
  }
});

app.use((err, _req, res, _next) => {
  if (err instanceof SyntaxError && 'body' in err) {
    return res.status(400).json({ message: 'Request body must be valid JSON.' });
  }
  return res.status(500).json({ message: 'Unexpected server error.' });
});

async function seedDemoUser() {
  const email = 'demo@example.com';
  if (users.some((user) => user.email === email)) return;
  users.push({
    id: crypto.randomUUID(),
    fullName: 'Demo User',
    email,
    mobile: '0771234567',
    passwordHash: await bcrypt.hash('Demo1234', 10),
  });
}

seedDemoUser().then(() => {
  app.listen(port, '0.0.0.0', () => {
    console.log(`Auth API listening on http://localhost:${port}`);
    console.log('Demo login: demo@example.com / Demo1234');
  });
});
