const express = require('express');
const crypto = require('crypto');
const db = require('./db');
const router = express.Router();

// Endpoint untuk mengirim pesan
router.post('/send', (req, res) => {
  const { username, message } = req.body;

  if (!username || !message) {
    return res.status(400).json({ error: 'Username and message are required' });
  }

  const aesKey = crypto.randomBytes(32);
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', aesKey, iv);
  let encryptedMessage = cipher.update(message, 'utf8', 'hex');
  encryptedMessage += cipher.final('hex');

  const sql = 'INSERT INTO messages (username, message, aes_key, iv) VALUES (?, ?, ?, ?)';
  db.query(sql, [username, encryptedMessage, aesKey.toString('hex'), iv.toString('hex')], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ status: 'Message sent and encrypted' });
  });
});

// Endpoint untuk mengambil semua pesan
router.get('/all-messages', (req, res) => {
  const sql = 'SELECT username, message, aes_key, iv FROM messages';
  db.query(sql, (err, results) => {
    if (err) return res.status(500).json({ error: err.message });

    try {
      const decryptedMessages = results.map(row => {
        const aesKey = Buffer.from(row.aes_key, 'hex');
        const iv = Buffer.from(row.iv, 'hex');

        try {
          const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);
          let decryptedMessage = decipher.update(row.message, 'hex', 'utf8');
          decryptedMessage += decipher.final('utf8');

          return { username: row.username, message: decryptedMessage };
        } catch (decryptionError) {
          return { username: row.username, message: '[Error decrypting message]' };
        }
      });

      res.json({ messages: decryptedMessages });
    } catch (error) {
      res.status(500).json({ error: 'Failed to process messages', details: error.message });
    }
  });
});

module.exports = router;

// Register Endpoint
router.post('/register', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
  const sql = 'INSERT INTO users (username, password) VALUES (?, ?)';

  db.query(sql, [username, hashedPassword], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ status: 'Registration successful' });
  });
});

// Login Endpoint
router.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
  const sql = 'SELECT * FROM users WHERE username = ? AND password = ?';

  db.query(sql, [username, hashedPassword], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });

    if (results.length > 0) {
      res.json({ status: 'Login successful' });
    } else {
      res.status(401).json({ error: 'Invalid credentials' });
    }
  });
});