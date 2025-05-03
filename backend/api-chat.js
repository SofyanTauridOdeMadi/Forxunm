const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const { verifyJWT, sanitizeString } = require('./api-auth');
const db = require('./db');

// AES encryption key and IV - should be stored securely in environment variables
const AES_KEY = Buffer.from(process.env.AES_KEY || '0123456789abcdef0123456789abcdef', 'utf8'); // 32 bytes
const AES_IV = Buffer.from(process.env.AES_IV || 'abcdef9876543210', 'utf8'); // 16 bytes

// Helper function for encryption
function encryptMessage(message) {
  const cipher = crypto.createCipheriv('aes-256-cbc', AES_KEY, AES_IV);
  let encrypted = cipher.update(message, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
}

// Helper function for decryption
function decryptMessage(encrypted) {
  const decipher = crypto.createDecipheriv('aes-256-cbc', AES_KEY, AES_IV);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// Endpoint untuk Mengirim Pesan
router.post('/send', verifyJWT, express.json(), (req, res) => {
  let { message } = req.body;

  message = sanitizeString(message);
  if (!message) {
    return res.status(400).json({ error: 'Message is required' });
  }

  const username = req.user?.username;
  if (!username) {
    return res.status(403).json({ error: 'Username not found in token' });
  }

  const encryptedMessage = encryptMessage(message);

  const sql = 'INSERT INTO messages (username, message) VALUES (?, ?)';
  db.query(sql, [username, encryptedMessage], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ status: 'Message sent and encrypted' });
  });
});

// Endpoint untuk Mengambil Semua Pesan
router.get('/all-messages', verifyJWT, (req, res) => {
  const sql = 'SELECT id, username, message, created_at FROM messages ORDER BY created_at ASC';
  db.query(sql, (err, results) => {
    if (err) {
      console.error('Database query failed:', err.message);
      return res.status(500).json({ error: err.message });
    }

    const decryptedMessages = results.map(row => {
      try {
        return {
          id: row.id,
          username: row.username,
          message: decryptMessage(row.message),
          created_at: row.created_at,
        };
      } catch (decryptionError) {
        console.error('Error decrypting message:', decryptionError.message);
        return { id: row.id, username: row.username, message: '[Error decrypting message]', created_at: row.created_at };
      }
    });

    res.json({ messages: decryptedMessages });
  });
});

module.exports = router;
