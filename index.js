const express = require('express');
const http = require('http');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const sqlite3 = require('sqlite3').verbose();
const { Server } = require('socket.io');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

const JWT_SECRET = process.env.JWT_SECRET || 'dev_secret_change_me';
const PORT = process.env.PORT || 3001;

// Initialize DB
const db = new sqlite3.Database('./data.sqlite');

db.serialize(() => {
  db.run('PRAGMA foreign_keys = ON');
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at INTEGER NOT NULL
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS friend_requests (
    id TEXT PRIMARY KEY,
    from_user_id TEXT NOT NULL,
    to_user_id TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    UNIQUE(from_user_id, to_user_id),
    FOREIGN KEY(from_user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(to_user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    from_user_id TEXT NOT NULL,
    to_user_id TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(from_user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY(to_user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);

  // Groups
  db.run(`CREATE TABLE IF NOT EXISTS groups (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    owner_user_id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(owner_user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS group_members (
    group_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    role TEXT NOT NULL,
    joined_at INTEGER NOT NULL,
    PRIMARY KEY(group_id, user_id),
    FOREIGN KEY(group_id) REFERENCES groups(id) ON DELETE CASCADE,
    FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS group_messages (
    id TEXT PRIMARY KEY,
    group_id TEXT NOT NULL,
    from_user_id TEXT NOT NULL,
    content TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY(group_id) REFERENCES groups(id) ON DELETE CASCADE,
    FOREIGN KEY(from_user_id) REFERENCES users(id) ON DELETE CASCADE
  )`);
});

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: '*',
  },
});

app.use(cors());
app.use(express.json());

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No token' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.user = payload;
    next();
  } catch (e) {
    return res.status(401).json({ error: 'Invalid token' });
  }
}

// Register
app.post('/api/register', async (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  const userId = uuidv4();
  const passwordHash = await bcrypt.hash(password, 10);
  const createdAt = Date.now();
  db.run(
    'INSERT INTO users (id, username, password_hash, created_at) VALUES (?,?,?,?)',
    [userId, username, passwordHash, createdAt],
    function (err) {
      if (err) {
        if (err.message.includes('UNIQUE')) return res.status(409).json({ error: 'Ник занят' });
        return res.status(500).json({ error: 'db error' });
      }
      const token = jwt.sign({ userId, username }, JWT_SECRET, { expiresIn: '7d' });
      res.json({ token, user: { id: userId, username } });
    }
  );
});

// Login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'username and password required' });
  db.get('SELECT * FROM users WHERE username = ?', [username], async (err, row) => {
    if (err) return res.status(500).json({ error: 'db error' });
    if (!row) return res.status(401).json({ error: 'invalid credentials' });
    const ok = await bcrypt.compare(password, row.password_hash);
    if (!ok) return res.status(401).json({ error: 'invalid credentials' });
    const token = jwt.sign({ userId: row.id, username: row.username }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ token, user: { id: row.id, username: row.username } });
  });
});

// Search users by username prefix
app.get('/api/users/search', authMiddleware, (req, res) => {
  const q = (req.query.q || '').toString();
  db.all('SELECT id, username FROM users WHERE username LIKE ? LIMIT 20', [q + '%'], (err, rows) => {
    if (err) return res.status(500).json({ error: 'db error' });
    res.json(rows);
  });
});

// Send friend request
app.post('/api/friends/request', authMiddleware, (req, res) => {
  const { toUserId } = req.body || {};
  if (!toUserId) return res.status(400).json({ error: 'toUserId required' });
  if (toUserId === req.user.userId) return res.status(400).json({ error: 'cannot friend yourself' });
  const id = uuidv4();
  const createdAt = Date.now();
  db.run(
    'INSERT INTO friend_requests (id, from_user_id, to_user_id, status, created_at) VALUES (?,?,?,?,?)',
    [id, req.user.userId, toUserId, 'pending', createdAt],
    function (err) {
      if (err) {
        if (err.message.includes('UNIQUE')) return res.status(409).json({ error: 'already requested' });
        return res.status(500).json({ error: 'db error' });
      }
      io.to(toUserId).emit('friend:request', { id, fromUserId: req.user.userId, createdAt });
      res.json({ id, status: 'pending' });
    }
  );
});

// Accept friend request
app.post('/api/friends/accept', authMiddleware, (req, res) => {
  const { fromUserId } = req.body || {};
  if (!fromUserId) return res.status(400).json({ error: 'fromUserId required' });
  db.run(
    "UPDATE friend_requests SET status = 'accepted' WHERE from_user_id = ? AND to_user_id = ?",
    [fromUserId, req.user.userId],
    function (err) {
      if (err) return res.status(500).json({ error: 'db error' });
      if (this.changes === 0) return res.status(404).json({ error: 'not found' });
      io.to(fromUserId).emit('friend:accepted', { userId: req.user.userId });
      res.json({ ok: true });
    }
  );
});

// List friends (accepted only)
app.get('/api/friends', authMiddleware, (req, res) => {
  const uid = req.user.userId;
  const sql = `
    SELECT u.id, u.username FROM users u
    WHERE u.id IN (
      SELECT CASE WHEN from_user_id = ? THEN to_user_id ELSE from_user_id END AS friend_id
      FROM friend_requests
      WHERE (from_user_id = ? OR to_user_id = ?) AND status = 'accepted'
    )
  `;
  db.all(sql, [uid, uid, uid], (err, rows) => {
    if (err) return res.status(500).json({ error: 'db error' });
    res.json(rows);
  });
});

// List pending incoming requests
app.get('/api/friends/requests', authMiddleware, (req, res) => {
  db.all(
    `SELECT fr.id, fr.from_user_id as fromUserId, u.username as fromUsername, fr.created_at as createdAt
     FROM friend_requests fr JOIN users u ON fr.from_user_id = u.id
     WHERE fr.to_user_id = ? AND fr.status = 'pending'`,
    [req.user.userId],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'db error' });
      res.json(rows);
    }
  );
});

// Send message (only if friendship accepted between users)
app.post('/api/messages/send', authMiddleware, (req, res) => {
  const { toUserId, content } = req.body || {};
  if (!toUserId || !content) return res.status(400).json({ error: 'toUserId and content required' });
  const checkSql = `
    SELECT 1 FROM friend_requests
    WHERE ((from_user_id = ? AND to_user_id = ?) OR (from_user_id = ? AND to_user_id = ?))
      AND status = 'accepted'
    LIMIT 1
  `;
  db.get(checkSql, [req.user.userId, toUserId, toUserId, req.user.userId], (err, row) => {
    if (err) return res.status(500).json({ error: 'db error' });
    if (!row) return res.status(403).json({ error: 'not friends' });

    const id = uuidv4();
    const createdAt = Date.now();
    db.run(
      'INSERT INTO messages (id, from_user_id, to_user_id, content, created_at) VALUES (?,?,?,?,?)',
      [id, req.user.userId, toUserId, content, createdAt],
      function (err2) {
        if (err2) return res.status(500).json({ error: 'db error' });
        const payload = { id, fromUserId: req.user.userId, toUserId, content, createdAt };
        io.to(toUserId).emit('message:new', payload);
        io.to(req.user.userId).emit('message:new', payload);
        res.json(payload);
      }
    );
  });
});

// Get message history with a friend
app.get('/api/messages/history/:friendId', authMiddleware, (req, res) => {
  const friendId = req.params.friendId;
  const sql = `
    SELECT id, from_user_id as fromUserId, to_user_id as toUserId, content, created_at as createdAt
    FROM messages
    WHERE (from_user_id = ? AND to_user_id = ?) OR (from_user_id = ? AND to_user_id = ?)
    ORDER BY created_at ASC
    LIMIT 500
  `;
  db.all(sql, [req.user.userId, friendId, friendId, req.user.userId], (err, rows) => {
    if (err) return res.status(500).json({ error: 'db error' });
    res.json(rows);
  });
});

// Simple health
app.get('/api/health', (_req, res) => res.json({ ok: true }));

// Socket.IO auth by token
io.use((socket, next) => {
  const token = socket.handshake.auth?.token;
  if (!token) return next(new Error('no token'));
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    socket.user = payload;
    next();
  } catch (e) {
    next(new Error('bad token'));
  }
});

io.on('connection', (socket) => {
  const userId = socket.user.userId;
  socket.join(userId);
  socket.emit('connected', { userId });
});

// GROUPS: create
app.post('/api/groups/create', authMiddleware, (req, res) => {
  const { name, memberIds } = req.body || {};
  if (!name || !Array.isArray(memberIds)) return res.status(400).json({ error: 'name and memberIds required' });
  const id = uuidv4();
  const createdAt = Date.now();
  const allMembers = Array.from(new Set([req.user.userId, ...memberIds]));
  db.serialize(() => {
    db.run('INSERT INTO groups (id, name, owner_user_id, created_at) VALUES (?,?,?,?)', [id, name, req.user.userId, createdAt], function (err) {
      if (err) return res.status(500).json({ error: 'db error' });
      const stmt = db.prepare('INSERT OR IGNORE INTO group_members (group_id, user_id, role, joined_at) VALUES (?,?,?,?)');
      allMembers.forEach((uid) => {
        stmt.run(id, uid, uid === req.user.userId ? 'owner' : 'member', createdAt);
      });
      stmt.finalize((finErr) => {
        if (finErr) return res.status(500).json({ error: 'db error' });
        // notify members
        allMembers.forEach((uid) => io.to(uid).emit('group:created', { id, name }));
        res.json({ id, name });
      });
    });
  });
});

// GROUPS: list for current user
app.get('/api/groups', authMiddleware, (req, res) => {
  const sql = `SELECT g.id, g.name FROM groups g JOIN group_members gm ON g.id = gm.group_id WHERE gm.user_id = ? ORDER BY g.created_at DESC`;
  db.all(sql, [req.user.userId], (err, rows) => {
    if (err) return res.status(500).json({ error: 'db error' });
    res.json(rows);
  });
});

// GROUPS: history
app.get('/api/groups/history/:groupId', authMiddleware, (req, res) => {
  const gid = req.params.groupId;
  const check = 'SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ? LIMIT 1';
  db.get(check, [gid, req.user.userId], (err, row) => {
    if (err) return res.status(500).json({ error: 'db error' });
    if (!row) return res.status(403).json({ error: 'no access' });
    const sql = `SELECT id, group_id as groupId, from_user_id as fromUserId, content, created_at as createdAt FROM group_messages WHERE group_id = ? ORDER BY created_at ASC LIMIT 500`;
    db.all(sql, [gid], (err2, rows) => {
      if (err2) return res.status(500).json({ error: 'db error' });
      res.json(rows);
    });
  });
});

// GROUPS: send message
app.post('/api/groups/send', authMiddleware, (req, res) => {
  const { groupId, content } = req.body || {};
  if (!groupId || !content) return res.status(400).json({ error: 'groupId and content required' });
  const check = 'SELECT 1 FROM group_members WHERE group_id = ? AND user_id = ? LIMIT 1';
  db.get(check, [groupId, req.user.userId], (err, row) => {
    if (err) return res.status(500).json({ error: 'db error' });
    if (!row) return res.status(403).json({ error: 'no access' });
    const id = uuidv4();
    const createdAt = Date.now();
    db.run('INSERT INTO group_messages (id, group_id, from_user_id, content, created_at) VALUES (?,?,?,?,?)', [id, groupId, req.user.userId, content, createdAt], function (err2) {
      if (err2) return res.status(500).json({ error: 'db error' });
      const payload = { id, groupId, fromUserId: req.user.userId, content, createdAt };
      // emit to all group members via their personal rooms
      db.all('SELECT user_id FROM group_members WHERE group_id = ?', [groupId], (e3, members) => {
        if (!e3 && members) members.forEach(m => io.to(m.user_id).emit('group:message', payload));
        res.json(payload);
      });
    });
  });
});

server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});


