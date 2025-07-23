const express = require('express');
const mqtt = require('mqtt');
const sqlite3 = require('sqlite3').verbose();
const path = require('path');
const cors = require('cors');
const http = require('http');
const { Server } = require('socket.io');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST'],
    allowedHeaders: ['Authorization'],
  },
});

const PORT = 3000;

// MQTT Setup
const mqttClient = mqtt.connect('mqtt://127.0.0.1', {
  username: 'caxtiq',
  password: 'anthithhn1N_',
});

mqttClient.on('connect', () => {
  console.log('Connected to MQTT broker');
});

// SQLite Setup
const db = new sqlite3.Database(path.join(__dirname, 'codes.db'));

const initDB = () => {
  db.serialize(() => {
    db.run(`
      CREATE TABLE IF NOT EXISTS passwords (
        code TEXT PRIMARY KEY,
        type TEXT CHECK(type IN ('static', 'otp')) NOT NULL,
        expires_at INTEGER
      )
    `);

    db.run(`
      CREATE TABLE IF NOT EXISTS nfc_cards (
        id TEXT PRIMARY KEY,
        enrolled_at INTEGER
      )
    `);

    db.run(`
      CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        method TEXT,
        code TEXT,
        success INTEGER,
        time INTEGER
      )
    `);
  });
};
initDB();

// Middleware
app.use(express.json());
app.use(cors({ origin: '*' }));
app.use((req, res, next) => {
  if (req.headers['authorization'] !== 'xxxyyyzzz') {
    return res.status(403).json({ error: 'Unauthorized' });
  }
  next();
});

const logAttempt = (method, code, success) => {
  const time = Date.now();
  const log = { method, code, success, time };
  db.run(
    `INSERT INTO logs (method, code, success, time) VALUES (?, ?, ?, ?)`,
    [method, code, success ? 1 : 0, time],
    () => {
      io.emit('log-update');
      io.emit('new-log', log); // This is what the frontend expects
    }
  );
};


// Routes
app.post('/api/open', (req, res) => {
  mqttClient.publish('mytopic/open', 'open', (err) => {
    if (err) return res.status(500).json({ success: false, message: 'MQTT error' });
    res.json({ success: true, message: 'MQTT open sent' });
  });
});

app.post('/api/unlock', (req, res) => {
  const { code } = req.body;
  if (!code) return res.status(400).json({ error: 'Code or NFC ID required' });

  const now = Date.now();

  // Check if it's a 6-digit password
  if (/^\d{6}$/.test(code)) {
    db.get(`SELECT * FROM passwords WHERE code = ? AND expires_at > ?`, [code, now], (err, row) => {
      if (err) {
        logAttempt('password', code, false);
        return res.status(500).json({ error: 'Database error' });
      }
      if (!row) {
        logAttempt('password', code, false);
        return res.status(401).json({ error: 'Invalid or expired code' });
      }

      if (row.type === 'otp') {
        db.run(`DELETE FROM passwords WHERE code = ?`, [code]);
      }

      mqttClient.publish('mytopic/open', 'unlock');
      logAttempt('password', code, true);
      io.emit('password-update');
      res.json({ success: true, method: 'password', type: row.type });
    });
  } else {
    // Check if it's a valid NFC ID
    db.get(`SELECT * FROM nfc_cards WHERE id = ?`, [code], (err, row) => {
      if (err) {
        logAttempt('nfc', code, false);
        return res.status(500).json({ error: 'Database error' });
      }
      if (!row) {
        logAttempt('nfc', code, false);
        return res.status(401).json({ error: 'NFC card not recognized' });
      }

      mqttClient.publish('mytopic/open', 'unlock');
      logAttempt('nfc', code, true);
      res.json({ success: true, method: 'nfc', id: code });
    });
  }
});

app.post('/api/create-code', (req, res) => {
  const { code, ttlSeconds = 300, type = 'otp' } = req.body;
  if (!code || !/^\d{6}$/.test(code)) return res.status(400).json({ error: 'Invalid 6-digit code' });
  if (!['otp', 'static'].includes(type)) return res.status(400).json({ error: 'Invalid type (otp/static)' });

  const expiresAt = Date.now() + ttlSeconds * 1000;
  db.run(`INSERT OR REPLACE INTO passwords (code, type, expires_at) VALUES (?, ?, ?)`, [code, type, expiresAt], (err) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    io.emit('password-update');
    res.json({ success: true, code, type, expiresAt });
  });
});

app.post('/api/delete-code', (req, res) => {
  const { code } = req.body;
  if (!code || !/^\d{6}$/.test(code)) return res.status(400).json({ error: 'Invalid code format' });

  db.run(`DELETE FROM passwords WHERE code = ?`, [code], function (err) {
    if (err) return res.status(500).json({ error: 'Failed to delete code' });
    if (this.changes === 0) return res.status(404).json({ error: 'Code not found' });
    io.emit('password-update');
    res.json({ success: true, message: 'Code deleted' });
  });
});

app.post('/api/enroll', (req, res) => {
  const id = req.body?.id;
  if (!id) {
    mqttClient.publish('mytopic/activate', 'enroll');
    return res.json({ success: true, message: 'Tap card on ESP32 to enroll' });
  }

  const enrolledAt = Date.now();
  db.run(`INSERT OR REPLACE INTO nfc_cards (id, enrolled_at) VALUES (?, ?)`, [id, enrolledAt], (err) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    io.emit('nfc-update');
    res.json({ success: true, id, enrolledAt });
  });
});

app.post('/api/disenroll', (req, res) => {
  const { id } = req.body;
  if (!id || typeof id !== 'string') return res.status(400).json({ error: 'Invalid NFC card ID' });

  db.run(`DELETE FROM nfc_cards WHERE id = ?`, [id], function (err) {
    if (err) return res.status(500).json({ error: 'Database error' });
    if (this.changes === 0) return res.status(404).json({ error: 'NFC card not found' });
    mqttClient.publish('mytopic/deactivate', id);
    io.emit('nfc-update');
    res.json({ success: true, message: 'NFC card revoked' });
  });
});

app.get('/api/active-passwords', (req, res) => {
  const now = Date.now();
  db.all(`SELECT code, type, expires_at FROM passwords WHERE expires_at > ?`, [now], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows);
  });
});

app.get('/api/active-nfc-cards', (req, res) => {
  db.all(`SELECT id, enrolled_at FROM nfc_cards`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });
    res.json(rows);
  });
});

app.get('/api/logs', (req, res) => {
  const { page = 1, limit = 50 } = req.query;
  const offset = (Number(page) - 1) * Number(limit);

  db.all(
    `SELECT method, code, success, time FROM logs ORDER BY time DESC LIMIT ? OFFSET ?`,
    [limit, offset],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Database error' });
      res.json(rows);
    }
  );
});

server.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});
