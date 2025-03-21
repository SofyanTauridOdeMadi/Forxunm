const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const db = require('./db');
const router = express.Router();
const multer = require('multer');
const path = require('path');

const JWT_SECRET = 'e5a02f9d2488cb7d09e019f15eeb9e4f14b9a0543b8cc5e9cdcc88b6e4e243c90e1b1e0a0f37922dfabbf365ab407623'; // Ganti dengan kunci rahasia Anda

// **GET**: Mendapatkan semua thread
router.get('/threads', (req, res) => {
  const query = 'SELECT * FROM threads WHERE is_deleted = 0';
  db.query(query, (err, results) => {
      if (err) {
          res.status(500).json({ error: err.message });
      } else {
          res.json(results); // Mengirimkan data thread dalam format JSON
      }
  });
});

// **POST**: Membuat thread baru
router.post('/threads', express.json(), (req, res) => {
  const { user_id, title, content } = req.body;
  const query = 'INSERT INTO threads (user_id, title, content) VALUES (?, ?, ?)';
  db.query(query, [user_id, title, content], (err, result) => {
      if (err) {
          res.status(500).json({ error: err.message });
      } else {
          res.status(201).json({ thread_id: result.insertId });
      }
  });
});

// **POST**: Memberikan upvote pada thread
router.post('/threads/:id/upvote', (req, res) => {
  const threadId = req.params.id;
  const query = 'UPDATE threads SET upvotes = upvotes + 1 WHERE thread_id = ?';
  db.query(query, [threadId], (err, result) => {
      if (err) {
          res.status(500).json({ error: err.message });
      } else {
          res.status(200).json({ message: 'Upvoted successfully!' });
      }
  });
});

// **GET**: Mendapatkan semua balasan untuk thread tertentu
router.get('/threads/:id/replies', (req, res) => {
  const threadId = req.params.id;
  const query = 'SELECT * FROM replies WHERE thread_id = ? AND is_deleted = 0';
  db.query(query, [threadId], (err, results) => {
      if (err) {
          res.status(500).json({ error: err.message });
      } else {
          res.json(results);
      }
  });
});

// **POST**: Membalas thread
router.post('/threads/:id/reply', express.json(), (req, res) => {
  const threadId = req.params.id;
  const { user_id, content } = req.body;
  const query = 'INSERT INTO replies (thread_id, user_id, content) VALUES (?, ?, ?)';
  db.query(query, [threadId, user_id, content], (err, result) => {
      if (err) {
          res.status(500).json({ error: err.message });
      } else {
          res.status(201).json({ reply_id: result.insertId });
      }
  });
});

// **DELETE**: Menghapus thread (soft delete)
router.delete('/threads/:id', (req, res) => {
  const threadId = req.params.id;
  const query = 'UPDATE threads SET is_deleted = 1 WHERE thread_id = ?';
  db.query(query, [threadId], (err, result) => {
      if (err) {
          res.status(500).json({ error: err.message });
      } else {
          res.status(200).json({ message: 'Thread deleted successfully!' });
      }
  });
});

// Endpoint untuk upload gambar profil
// Konfigurasi penyimpanan dan filter file
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, 'uploads/'); // Tentukan direktori untuk menyimpan gambar
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + file.originalname); // Membuat nama file unik berdasarkan timestamp
  }
});

// Filter file untuk hanya menerima gambar
const fileFilter = (req, file, cb) => {
  // Menentukan tipe MIME yang diizinkan (hanya gambar)
  if (file.mimetype.startsWith('image/')) {
    cb(null, true); // Izinkan file jika tipe MIME-nya adalah gambar
  } else {
    cb(new Error('File must be an image'), false); // Tolak file jika bukan gambar
  }
};

// Konfigurasi batas ukuran file maksimal (5MB)
const upload = multer({
  storage: storage,
  fileFilter: fileFilter,
  limits: { fileSize: 5 * 1024 * 1024 } // Maksimal 5MB
});

// Endpoint untuk upload gambar profil
router.post('/upload-profile-image', verifyJWT, upload.single('profile_image'), (req, res) => {
  // Jika file tidak ada atau ukuran file terlalu besar
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded or invalid file format' });
  }

  if (req.file.size > 5 * 1024 * 1024) { // Cek jika ukuran file lebih dari 5MB
    return res.status(400).json({ error: 'File size exceeds 5MB limit' });
  }

  const userId = req.user.id;
  const profileImageUrl = `${req.file.filename}`; // Path file yang di-upload
  
  // Update URL gambar profil di database
  const query = 'UPDATE users SET profile_picture_url = ? WHERE id = ?';
  db.query(query, [profileImageUrl, userId], (err, result) => {
    if (err) {
      console.error('Error saving profile image URL:', err.message);
      return res.status(500).json({ error: 'Failed to save profile image URL' });
    }
    res.json({ status: true, profile_image_url: profileImageUrl });
  });
});

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

// Mendapatkan profil pengguna
router.get('/user-profile', verifyJWT, (req, res) => {
  const userId = req.user.id;
  const query = 'SELECT username, email, bio, profile_picture_url, created_at FROM users WHERE id = ?';

  db.query(query, [userId], (err, results) => {
    if (err) {
      console.error('Error retrieving user profile:', err.message);
      return res.status(500).json({ error: 'Failed to load user profile' });
    }

    if (results.length > 0) {
      res.json({ status: true, user: results[0] });
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  });
});

// Memperbarui profil pengguna
// **POST**: Update profil pengguna (termasuk kata sandi)
router.post('/update-profile', express.json(), async (req, res) => {
  const { email, bio, newPassword, confirmPassword, csrfToken } = req.body;
  const token = req.headers['authorization']?.split(' ')[1]; // Ambil token dari header

  if (!token) {
      return res.status(401).json({ error: 'Unauthorized' });
  }

  try {
      // Verifikasi token JWT dan ambil informasi pengguna
      const decoded = jwt.verify(token, JWT_SECRET);
      const userId = decoded.id;

      // Jika newPassword atau confirmPassword tidak ada, skip update password
      let hashedPassword = null;
      if (newPassword && confirmPassword) {
          // Jika password baru dan konfirmasi cocok
          if (newPassword === confirmPassword) {
              // Hash password baru
              hashedPassword = crypto.createHash('sha256').update(newPassword).digest('hex');
          } else {
              return res.status(400).json({ error: 'Passwords do not match' });
          }
      }

      // Update data pengguna di database, perbarui password hanya jika ada
      const query = 'UPDATE users SET email = ?, bio = ?, password = COALESCE(?, password) WHERE id = ?';
      db.query(query, [email, bio, hashedPassword || null, userId], (err, result) => {
          if (err) {
              console.error('Database Error:', err.message);
              return res.status(500).json({ error: 'Failed to update profile' });
          }

          // Log hasil query untuk debugging
          console.log('Query Result:', result);

          // Jika tidak ada baris yang terpengaruh, maka data tidak diperbarui
          if (result.affectedRows === 0) {
              return res.status(404).json({ error: 'User not found' });
          }

          // Jika ada perubahan, kirimkan respon sukses
          res.status(200).json({ message: 'Profile updated successfully' });
      });
  } catch (error) {
      console.error('Error in update profile:', error);
      res.status(500).json({ error: 'Failed to update profile' });
  }
});

// Endpoint untuk upload gambar profil
router.post('/upload-profile-image', verifyJWT, upload.single('profile_image'), (req, res) => {
  if (!req.file) {
    return res.status(400).json({ error: 'No file uploaded' });
  }

  const userId = req.user.id;
  const profileImageUrl = `${req.file.filename}`; // Path file yang di-upload
  
  // Update URL gambar profil di database
  const query = 'UPDATE users SET profile_picture_url = ? WHERE id = ?';
  db.query(query, [profileImageUrl, userId], (err, result) => {
    if (err) {
      console.error('Error saving profile image URL:', err.message);
      return res.status(500).json({ error: 'Failed to save profile image URL' });
    }
    res.json({ status: true, profile_image_url: profileImageUrl });
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

module.exports = router;