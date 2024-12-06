const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const db = require('./db');
const router = express.Router();

const JWT_SECRET = 'e5a02f9d2488cb7d09e019f15eeb9e4f14b9a0543b8cc5e9cdcc88b6e4e243c90e1b1e0a0f37922dfabbf365ab407623'; // Ganti dengan kunci rahasia Anda

// Middleware untuk memverifikasi JWT
function verifyJWT(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  console.log('Received Token:', token); // Log token yang diterima server

  if (!token) {
    console.error('No token provided.');
    return res.status(403).json({ error: 'No token provided' });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      console.error('Token verification failed:', err.message); // Log error verifikasi token
      if (err.name === 'TokenExpiredError') {
        return res.status(403).json({ error: 'Token has expired. Please log in again.' });
      }
      return res.status(403).json({ error: 'Failed to authenticate token' });
    }

    console.log('Token verified:', decoded); // Log hasil verifikasi token
    req.user = decoded; // Token valid, simpan data user
    next();
  });
}

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

// Endpoint Login
router.post('/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password are required' });
  }

  const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
  const sql = 'SELECT id FROM users WHERE username = ? AND password = ?';

  db.query(sql, [username, hashedPassword], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });

    if (results.length > 0) {
      const token = jwt.sign({ id: results[0].id, username }, JWT_SECRET, { expiresIn: '1h' });
      console.log('Generated Token:', token); // Debug token yang dihasilkan
      res.json({ status: 'Login successful', token });
    } else {
      res.status(401).json({ error: 'Invalid username or password' });
    }
  });
});

// Endpoint untuk Mengirim Pesan
router.post('/send', verifyJWT, (req, res) => {
  const { message } = req.body;

  if (!message) {
    return res.status(400).json({ error: 'Message is required' });
  }

  const username = req.user?.username; // Ambil username dari token
  if (!username) {
    return res.status(403).json({ error: 'Username not found in token' });
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

// Endpoint untuk Mengambil Semua Pesan
router.get('/all-messages', verifyJWT, (req, res) => {
  const sql = 'SELECT username, message, aes_key, iv, created_at FROM messages';
  db.query(sql, (err, results) => {
    if (err) {
      console.error('Database query failed:', err.message); // Log error
      return res.status(500).json({ error: err.message });
    }

    const decryptedMessages = results.map(row => {
      try {
        const aesKey = Buffer.from(row.aes_key, 'hex');
        const iv = Buffer.from(row.iv, 'hex');
        const decipher = crypto.createDecipheriv('aes-256-cbc', aesKey, iv);
        let decryptedMessage = decipher.update(row.message, 'hex', 'utf8');
        decryptedMessage += decipher.final('utf8');
        return {
          username: row.username,
          message: decryptedMessage,
          created_at: new Date(row.created_at).toISOString(), // Pastikan format ISO 8601
        };
      } catch (decryptionError) {
        console.error('Error decrypting message:', decryptionError.message); // Log error
        return { username: row.username, message: '[Error decrypting message]', created_at: row.created_at };
      }
    });

    res.json({ messages: decryptedMessages });
  });
});

// Reset Password Endpoint
router.post('/reset-password', (req, res) => {
  const { username, newPassword } = req.body;

  if (!username || !newPassword) {
    return res.status(400).json({ error: 'Username and new password are required' });
  }

  const hashedPassword = crypto.createHash('sha256').update(newPassword).digest('hex');
  const sql = 'UPDATE users SET password = ? WHERE username = ?';

  db.query(sql, [hashedPassword, username], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ status: 'Password updated successfully' });
  });
});

module.exports = router;