const express = require('express');
const multer = require('multer');
const { verifyJWT } = require('./api-auth');
const db = require('./db');
const router = express.Router();

// Helper functions for validation and sanitization
function isValidNumber(value) {
  return !isNaN(value) && Number.isInteger(Number(value)) && Number(value) > 0;
}

function sanitizeString(str) {
  if (typeof str !== 'string') return '';
  return str.trim();
}

function isValidEmail(email) {
  const emailRegex = /^[\w\-\.]+@([\w\-]+\.)+[\w\-]{2,4}$/;
  return emailRegex.test(email);
}

// **GET**: Mendapatkan semua thread dengan username user
router.get('/threads', (req, res) => {
  const query = `
    SELECT t.*, u.username 
    FROM threads t 
    JOIN users u ON t.user_id = u.id 
    WHERE t.is_deleted = 0
  `;
  db.query(query, (err, results) => {
      if (err) {
          res.status(500).json({ error: err.message });
      } else {
          res.json(results);
      }
  });
});

// **POST**: Membuat thread baru (dilindungi dengan verifyJWT)
router.post('/threads', express.json(), verifyJWT, (req, res) => {
  let { user_id, title, content } = req.body;

  if (!isValidNumber(user_id) || user_id !== req.user.id) {
    return res.status(403).json({ error: 'Unauthorized user_id' });
  }
  user_id = Number(user_id);

  title = sanitizeString(title);
  content = sanitizeString(content);

  if (!title || !content) {
    return res.status(400).json({ error: 'Title and content are required' });
  }

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
router.post('/threads/:id/upvote', verifyJWT, (req, res) => {
  let threadId = req.params.id;

  if (!isValidNumber(threadId)) {
    return res.status(400).json({ error: 'Invalid thread ID' });
  }
  threadId = Number(threadId);

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
  let threadId = req.params.id;

  if (!isValidNumber(threadId)) {
    return res.status(400).json({ error: 'Invalid thread ID' });
  }
  threadId = Number(threadId);

  const query = 'SELECT * FROM replies WHERE thread_id = ? AND is_deleted = 0';
  db.query(query, [threadId], (err, results) => {
      if (err) {
          res.status(500).json({ error: err.message });
      } else {
          res.json(results);
      }
  });
});

// **POST**: Membalas thread (dilindungi dengan verifyJWT)
router.post('/threads/:id/reply', express.json(), verifyJWT, (req, res) => {
  let threadId = req.params.id;
  let { user_id, content } = req.body;

  if (!isValidNumber(threadId)) {
    return res.status(400).json({ error: 'Invalid thread ID' });
  }
  threadId = Number(threadId);

  if (!isValidNumber(user_id) || user_id !== req.user.id) {
    return res.status(403).json({ error: 'Unauthorized user_id' });
  }
  user_id = Number(user_id);

  content = sanitizeString(content);
  if (!content) {
    return res.status(400).json({ error: 'Content is required' });
  }

  const query = 'INSERT INTO replies (thread_id, user_id, content) VALUES (?, ?, ?)';
  db.query(query, [threadId, user_id, content], (err, result) => {
      if (err) {
          res.status(500).json({ error: err.message });
      } else {
          res.status(201).json({ reply_id: result.insertId });
      }
  });
});

// **DELETE**: Menghapus thread (soft delete, dilindungi dengan verifyJWT)
router.delete('/threads/:id', verifyJWT, (req, res) => {
  let threadId = req.params.id;
  const userId = req.user.id;

  if (!isValidNumber(threadId)) {
    return res.status(400).json({ error: 'Invalid thread ID' });
  }
  threadId = Number(threadId);

  // Check if the thread belongs to the user before deleting
  const checkQuery = 'SELECT user_id FROM threads WHERE thread_id = ? AND is_deleted = 0';
  db.query(checkQuery, [threadId], (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: 'Thread not found' });
    }
    if (results[0].user_id !== userId) {
      return res.status(403).json({ error: 'Unauthorized to delete this thread' });
    }

    const deleteQuery = 'UPDATE threads SET is_deleted = 1 WHERE thread_id = ?';
    db.query(deleteQuery, [threadId], (err2, result) => {
      if (err2) {
        return res.status(500).json({ error: err2.message });
      }
      res.status(200).json({ message: 'Thread deleted successfully!' });
    });
  });
});

// Konfigurasi penyimpanan dan filter file untuk upload gambar profil
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

// Mendapatkan profil pengguna
router.get('/user-profile', verifyJWT, (req, res) => {
  const userId = req.user.id;

  if (!isValidNumber(userId)) {
    return res.status(400).json({ error: 'Invalid user ID' });
  }

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
// **POST**: Update profil pengguna (verifikasi password lama, dilindungi dengan verifyJWT)
router.post('/update-profile', express.json(), verifyJWT, async (req, res) => {
  let { email, bio, confirmPassword, csrfToken } = req.body;
  const userId = req.user.id;

  // Validate email and bio
  email = sanitizeString(email);
  bio = sanitizeString(bio);
  if (!isValidEmail(email)) {
    return res.status(400).json({ error: 'Invalid email format' });
  }
  if (bio.length > 500) {
    return res.status(400).json({ error: 'Bio is too long' });
  }

  if (!confirmPassword) {
    return res.status(400).json({ error: 'Current password is required for confirmation' });
  }

  try {
      // Ambil password hash dari database untuk verifikasi
      const queryGetPassword = 'SELECT password FROM users WHERE id = ?';
      db.query(queryGetPassword, [userId], (err, results) => {
        if (err) {
          console.error('Database Error:', err.message);
          if (!res.headersSent) {
            return res.status(500).json({ error: 'Failed to verify password' });
          }
          return;
        }
        if (results.length === 0) {
          if (!res.headersSent) {
            return res.status(404).json({ error: 'User not found' });
          }
          return;
        }

        const storedHashedPassword = results[0].password;
        const inputHashedPassword = crypto.createHash('sha256').update(confirmPassword).digest('hex');

        if (storedHashedPassword !== inputHashedPassword) {
          if (!res.headersSent) {
            return res.status(400).json({ error: 'Incorrect current password' });
          }
          return;
        }

        // Jika password cocok, update email dan bio saja
        const queryUpdate = 'UPDATE users SET email = ?, bio = ? WHERE id = ?';
        db.query(queryUpdate, [email, bio, userId], (err2, result) => {
          if (err2) {
            console.error('Database Error:', err2.message);
            if (!res.headersSent) {
              return res.status(500).json({ error: 'Failed to update profile' });
            }
            return;
          }

          if (result.affectedRows === 0) {
            if (!res.headersSent) {
              return res.status(404).json({ error: 'User not found' });
            }
            return;
          }

          if (!res.headersSent) {
            res.status(200).json({ status: true, message: 'Profile updated successfully' });
          }
        });
      });
  } catch (error) {
      console.error('Error in update profile:', error);
      res.status(500).json({ error: 'Failed to update profile' });
  }
});

module.exports = router;
