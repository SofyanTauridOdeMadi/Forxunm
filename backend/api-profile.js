const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const { verifyJWT } = require('./api-auth');
const db = require('./db');
const fs = require('fs');
const path = require('path');
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

// Escape HTML special characters to prevent XSS
function escapeHtml(text) {
  if (typeof text !== 'string') return '';
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '<')
    .replace(/>/g, '>')
    .replace(/"/g, '"')
    .replace(/'/g, '&#039;');
}

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
  const profileImageUrl = req.file.filename; // Save only filename without /uploads prefix
  
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
      const user = results[0];
      // Check if profile_picture_url file exists
      if (user.profile_picture_url) {
        // Remove leading slash if present to avoid path.join treating it as absolute path
        const relativePath = user.profile_picture_url.startsWith('/') ? user.profile_picture_url.slice(1) : user.profile_picture_url;
        const filePath = path.join(__dirname, '..', 'uploads', relativePath);
        if (!fs.existsSync(filePath)) {
          // File does not exist, set default image URL
          user.profile_picture_url = '/talk.png';
        } else {
          // Prepend slash to filename for URL
          user.profile_picture_url = '/' + relativePath;
        }
      } else {
        // No profile_picture_url set, use default image
        user.profile_picture_url = '/talk.png';
      }
      res.json({ status: true, user });
    } else {
      res.status(404).json({ error: 'User not found' });
    }
  });
});

// Memperbarui profil pengguna
router.post('/update-profile', express.json(), verifyJWT, async (req, res) => {
  let { email, bio, confirmPassword } = req.body;
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
        return res.status(500).json({ error: 'Failed to verify password' });
      }
      if (results.length === 0) {
        return res.status(404).json({ error: 'User not found' });
      }

      const storedHashedPassword = results[0].password;
      const inputHashedPassword = crypto.createHash('sha256').update(confirmPassword).digest('hex');

      if (storedHashedPassword !== inputHashedPassword) {
        return res.status(400).json({ error: 'Incorrect current password' });
      }

      // Jika password cocok, update email dan bio saja
      const queryUpdate = 'UPDATE users SET email = ?, bio = ? WHERE id = ?';
      db.query(queryUpdate, [email, bio, userId], (err2, result) => {
        if (err2) {
          console.error('Database Error:', err2.message);
          return res.status(500).json({ error: 'Failed to update profile' });
        }

        if (result.affectedRows === 0) {
          return res.status(404).json({ error: 'User not found' });
        }

        res.status(200).json({ status: true, message: 'Profile updated successfully' });
      });
    });
  } catch (error) {
    console.error('Error in update profile:', error);
    res.status(500).json({ error: 'Failed to update profile' });
  }
});

module.exports = router;
