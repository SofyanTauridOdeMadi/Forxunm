const express = require('express');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const db = require('./db');
const router = express.Router();
const multer = require('multer');
const path = require('path');

const fetch = require('node-fetch').default;

// Helper function to verify Google reCAPTCHA v2 token
async function verifyRecaptcha(token) {
  if (!token) return false;
  const secretKey = process.env.RECAPTCHA_SECRET_KEY || '6Lf5KCArAAAAAPCLdMpZWQX-fyceeCH1XmA0TA2R';
  const verificationUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${token}`;

  try {
    const response = await fetch(verificationUrl, { method: 'POST' });
    const data = await response.json();
    return data.success === true;
  } catch (error) {
    console.error('Error verifying reCAPTCHA:', error);
    return false;
  }
}

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

function isValidUsername(username) {
  const usernameRegex = /^[a-zA-Z0-9_]{3,30}$/;
  return usernameRegex.test(username);
}

function isValidPassword(password) {
  return typeof password === 'string' && password.length >= 6;
}

const JWT_SECRET = process.env.JWT_SECRET || 'e5a02f9d2488cb7d09e019f15eeb9e4f14b9a0543b8cc5e9cdcc88b6e4e243c90e1b1e0a0f37922dfabbf365ab407623'; // Use env variable for secret

// Middleware to verify JWT and limit access
function verifyJWT(req, res, next) {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) {
    return res.status(403).json({ error: 'No token provided' });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      if (err.name === 'TokenExpiredError') {
        return res.status(403).json({ error: 'Token has expired. Please log in again.' });
      }
      return res.status(403).json({ error: 'Failed to authenticate token' });
    }
    req.user = decoded;
    next();
  });
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
// (Already defined above as verifyJWT)

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

// Endpoint untuk Mengirim Pesan
router.post('/send', verifyJWT, (req, res) => {
  let { message } = req.body;

  message = sanitizeString(message);
  if (!message) {
    return res.status(400).json({ error: 'Message is required' });
  }

  const username = req.user?.username;
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
      console.error('Database query failed:', err.message);
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
          created_at: new Date(row.created_at).toISOString(),
        };
      } catch (decryptionError) {
        console.error('Error decrypting message:', decryptionError.message);
        return { username: row.username, message: '[Error decrypting message]', created_at: row.created_at };
      }
    });

    res.json({ messages: decryptedMessages });
  });
});

// Register Endpoint with reCAPTCHA verification
router.post('/register', async (req, res) => {
  let { username, password, recaptchaResponse } = req.body;

  if (!recaptchaResponse) {
    return res.status(400).json({ error: 'reCAPTCHA token is missing' });
  }

  const recaptchaValid = await verifyRecaptcha(recaptchaResponse);
  if (!recaptchaValid) {
    return res.status(400).json({ error: 'Failed reCAPTCHA verification' });
  }

  username = sanitizeString(username);
  if (!isValidUsername(username)) {
    return res.status(400).json({ error: 'Invalid username' });
  }
  if (!isValidPassword(password)) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }

  const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
  const sql = 'INSERT INTO users (username, password) VALUES (?, ?)';

  db.query(sql, [username, hashedPassword], (err) => {
    if (err) return res.status(500).json({ error: err.message });
    res.json({ status: 'Registration successful' });
  });
});

// Helper function to verify Google reCAPTCHA Enterprise token
async function verifyRecaptchaEnterprise(token, projectID, recaptchaKey, recaptchaAction) {
  const projectPath = client.projectPath(projectID);

  const request = {
    assessment: {
      event: {
        token: token,
        siteKey: recaptchaKey,
      },
    },
    parent: projectPath,
  };

  try {
    const [response] = await client.createAssessment(request);

    if (!response.tokenProperties.valid) {
      console.log(`The CreateAssessment call failed because the token was: ${response.tokenProperties.invalidReason}`);
      return { success: false, reason: response.tokenProperties.invalidReason };
    }

    if (response.tokenProperties.action !== recaptchaAction) {
      console.log("The action attribute in your reCAPTCHA tag does not match the action you are expecting to score");
      return { success: false, reason: "action_mismatch" };
    }

    return { success: true, score: response.riskAnalysis.score, reasons: response.riskAnalysis.reasons };
  } catch (error) {
    console.error('Error verifying reCAPTCHA Enterprise:', error);
    return { success: false, reason: 'verification_error' };
  }
}

// Endpoint Login with Login Throttling and reCAPTCHA v2 verification
router.post('/login', async (req, res) => {
  let { username, password, recaptchaResponse } = req.body;

  if (!recaptchaResponse) {
    return res.status(400).json({ error: 'reCAPTCHA token is missing' });
  }

  const recaptchaValid = await verifyRecaptcha(recaptchaResponse);
  if (!recaptchaValid) {
    return res.status(400).json({ error: 'Failed reCAPTCHA verification' });
  }

  username = sanitizeString(username);
  if (!isValidUsername(username)) {
    return res.status(400).json({ error: 'Invalid username' });
  }
  if (!isValidPassword(password)) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }

  const now = new Date();
  const LOCKOUT_THRESHOLD = 5; // Max failed attempts before lockout
  const LOCKOUT_DURATION = 15 * 60 * 1000; // 15 minutes in milliseconds

  // First, get user info including failed_login_attempts and lockout_until
  const sqlGetUser = 'SELECT id, password, failed_login_attempts, lockout_until FROM users WHERE username = ?';
  db.query(sqlGetUser, [username], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });

    if (results.length === 0) {
      // User not found - to prevent username enumeration, respond with generic message
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const user = results[0];

    // Check if user is currently locked out
    if (user.lockout_until && new Date(user.lockout_until) > now) {
      const lockoutMinutes = Math.ceil((new Date(user.lockout_until) - now) / 60000);
      return res.status(403).json({ error: `Account locked due to too many failed login attempts. Try again in ${lockoutMinutes} minute(s).` });
    }

    const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');

    if (hashedPassword === user.password) {
      // Successful login: reset failed_login_attempts and lockout_until
      const resetSql = 'UPDATE users SET failed_login_attempts = 0, lockout_until = NULL WHERE id = ?';
      db.query(resetSql, [user.id], (resetErr) => {
        if (resetErr) {
          console.error('Error resetting login attempts:', resetErr.message);
          // Proceed with login anyway
        }
        const token = jwt.sign({ id: user.id, username }, JWT_SECRET, { expiresIn: '1h' });
        return res.json({ status: 'Login successful', token });
      });
    } else {
      // Failed login: increment failed_login_attempts
      let failedAttempts = user.failed_login_attempts + 1;
      let lockoutUntil = null;

      if (failedAttempts >= LOCKOUT_THRESHOLD) {
        lockoutUntil = new Date(now.getTime() + LOCKOUT_DURATION);
      }

      const updateSql = 'UPDATE users SET failed_login_attempts = ?, lockout_until = ? WHERE id = ?';
      db.query(updateSql, [failedAttempts, lockoutUntil, user.id], (updateErr) => {
        if (updateErr) {
          console.error('Error updating failed login attempts:', updateErr.message);
        }
        if (lockoutUntil) {
          return res.status(403).json({ error: `Account locked due to too many failed login attempts. Try again in 15 minutes.` });
        } else {
          return res.status(401).json({ error: 'Invalid username or password' });
        }
      });
    }
  });
});

module.exports = router;
