const express = require('express');
const bcrypt = require('bcryptjs');
const Database = require('better-sqlite3');
const crypto = require('crypto');
const path = require('path');

const app = express();
const db = new Database(path.join(__dirname, 'focusdomain.db'));
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '5mb' }));
app.use(express.static(__dirname));

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE NOT NULL,
  email TEXT,
  password_hash TEXT NOT NULL,
  profile_json TEXT,
  data_json TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  FOREIGN KEY(user_id) REFERENCES users(id)
);
`);

function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO sessions (token, user_id, created_at) VALUES (?, ?, ?)').run(token, userId, Date.now());
  return token;
}

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing auth token' });

  const session = db.prepare('SELECT user_id FROM sessions WHERE token = ?').get(token);
  if (!session) return res.status(401).json({ error: 'Invalid session' });
  req.userId = session.user_id;
  req.token = token;
  next();
}

app.post('/api/signup', async (req, res) => {
  const { username, password, email, profile, data } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }
  if (String(password).length < 8) {
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  }

  const normalized = String(username).trim().toLowerCase();
  const existing = db.prepare('SELECT id FROM users WHERE username = ?').get(normalized);
  if (existing) return res.status(409).json({ error: 'Username already taken' });

  const hash = await bcrypt.hash(password, 10);
  const now = Date.now();
  const result = db.prepare(`
    INSERT INTO users (username, email, password_hash, profile_json, data_json, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `).run(
    normalized,
    email || null,
    hash,
    JSON.stringify(profile || {}),
    JSON.stringify(data || {}),
    now,
    now
  );

  const token = createSession(result.lastInsertRowid);
  res.json({ username: normalized, token, data: data || {} });
});

app.post('/api/login', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  const normalized = String(username).trim().toLowerCase();
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(normalized);
  if (!user) return res.status(401).json({ error: 'Invalid username or password' });

  const valid = await bcrypt.compare(password, user.password_hash);
  if (!valid) return res.status(401).json({ error: 'Invalid username or password' });

  const token = createSession(user.id);
  res.json({
    username: user.username,
    token,
    data: JSON.parse(user.data_json || '{}'),
    profile: JSON.parse(user.profile_json || '{}')
  });
});

app.get('/api/me', authMiddleware, (req, res) => {
  const user = db.prepare('SELECT username, profile_json, data_json FROM users WHERE id = ?').get(req.userId);
  if (!user) return res.status(404).json({ error: 'User not found' });
  res.json({
    username: user.username,
    profile: JSON.parse(user.profile_json || '{}'),
    data: JSON.parse(user.data_json || '{}')
  });
});

app.post('/api/save', authMiddleware, (req, res) => {
  const { data } = req.body || {};
  if (!data || typeof data !== 'object') {
    return res.status(400).json({ error: 'Data object required' });
  }

  db.prepare('UPDATE users SET data_json = ?, updated_at = ? WHERE id = ?')
    .run(JSON.stringify(data), Date.now(), req.userId);

  res.json({ ok: true });
});

app.post('/api/logout', authMiddleware, (req, res) => {
  db.prepare('DELETE FROM sessions WHERE token = ?').run(req.token);
  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log(`FocusDomain backend running on http://localhost:${PORT}`);
});
