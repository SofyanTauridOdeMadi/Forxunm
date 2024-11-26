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