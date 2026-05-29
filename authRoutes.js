const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const db = require('./db');
const router = express.Router();

router.post('/signup', (req, res) => {
 const { username, email, password } = req.body;
 if (!username || !email || !password) return res.status(400).json({ error: 'All fields required' });
 if (password.length < 6) return res.status(400).json({ error: 'Password must be at least 6 characters' });
 if (username.length < 3) return res.status(400).json({ error: 'Username must be at least 3 characters' });
 try {
 const existing = db.prepare('SELECT id FROM users WHERE email = ? OR username = ?').get(email, username);
 if (existing) return res.status(409).json({ error: 'User already exists' });
 const hash = bcrypt.hashSync(password, 10);
 const result = db.prepare('INSERT INTO users (username, email, password) VALUES (?, ?, ?)').run(username, email, hash);
 const token = jwt.sign({ id: result.lastInsertRowid }, process.env.JWT_SECRET, { expiresIn: '7d' });
 res.status(201).json({ message: 'User created', token });
 } catch (err) { res.status(500).json({ error: err.message }); }
});

router.post('/login', (req, res) => {
 const { email, password } = req.body;
 if (!email || !password) return res.status(400).json({ error: 'Email and password required' });
 try {
 const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
 if (!user) return res.status(401).json({ error: 'Invalid credentials' });
 if (!bcrypt.compareSync(password, user.password)) return res.status(401).json({ error: 'Invalid credentials' });
 const token = jwt.sign({ id: user.id }, process.env.JWT_SECRET, { expiresIn: '7d' });
 res.json({ message: 'Login successful', token });
 } catch (err) { res.status(500).json({ error: err.message }); }
});

function authenticate(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth) return res.status(401).json({ error: 'No token' });
  try {
    const decoded = jwt.verify(auth.split(' ')[1], process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) { res.status(401).json({ error: 'Invalid token' }); }
}

router.get('/me', authenticate, (req, res) => {
  const user = db.prepare('SELECT id, username, email, created_at FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'Not found' });
  res.json({ user });
});

router.get('/profile', authenticate, (req, res) => {
  try {
    let profile = db.prepare('SELECT * FROM profiles WHERE user_id = ?').get(req.user.id);
    if (!profile) return res.json({ profile: { full_name: '', phone: '', addresses: [] } });
    profile.addresses = JSON.parse(profile.addresses || '[]');
    res.json({ profile });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

router.put('/profile', authenticate, (req, res) => {
  try {
    const { full_name, phone, addresses } = req.body;
    const existing = db.prepare('SELECT id FROM profiles WHERE user_id = ?').get(req.user.id);
    if (existing) {
      db.prepare('UPDATE profiles SET full_name = ?, phone = ?, addresses = ? WHERE user_id = ?')
        .run(full_name ?? '', phone ?? '', addresses ? JSON.stringify(addresses) : '[]', req.user.id);
    } else {
      db.prepare('INSERT INTO profiles (user_id, full_name, phone, addresses) VALUES (?, ?, ?, ?)')
        .run(req.user.id, full_name ?? '', phone ?? '', addresses ? JSON.stringify(addresses) : '[]');
    }
    res.json({ message: 'Profile updated' });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

module.exports = router;
