const express = require('express');
const router = express.Router();
const db = require('./db');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');
const speakeasy = require('speakeasy');
const fetch = (...args) => import('node-fetch').then(({default: fetch}) => fetch(...args));

const JWT_SECRET = process.env.JWT_SECRET || 'e5a02f9d2488cb7d09e019f15eeb9e4f14b9a0543b8cc5e9cdcc88b6e4e243c90e1b1e0a0f37922dfabbf365ab407623'; // Use env variable for secret

// Helper functions for validation and sanitization
function sanitizeString(str) {
  if (typeof str !== 'string') return '';
  return str.trim();
}

function isValidUsername(username) {
  const usernameRegex = /^[a-zA-Z0-9_]{3,30}$/;
  return usernameRegex.test(username);
}

function isValidPassword(password) {
  return typeof password === 'string' && password.length >= 6;
}

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

// Function to verify Google reCAPTCHA token
async function verifyRecaptcha(token) {
const secretKey = process.env.RECAPTCHA_SECRET_KEY || '6LcW8iwrAAAAAAN7m5we_bEMUp_7ApYjeOA1UnI4';

  if (!secretKey) {
    console.warn('Warning: RECAPTCHA_SECRET_KEY is not set.');
    return false;
  }

  const verificationUrl = `https://www.google.com/recaptcha/api/siteverify?secret=${secretKey}&response=${token}`;

  try {
    const response = await fetch(verificationUrl, { method: 'POST' });
    const data = await response.json();
    console.log('reCAPTCHA verification response:', data);
    return data.success === true;
  } catch (error) {
    console.error('Error verifying reCAPTCHA:', error);
    return false;
  }
}

/**
 * POST /login
 * Login with username, using password or TOTP
 */
router.post('/login', express.json(), async (req, res) => {
  const { userInput, password, totpCode, recaptchaResponse } = req.body;

  // If TOTP code is provided, bypass reCAPTCHA verification
  if (totpCode) {
    // Skip reCAPTCHA check
  } else {
    if (!recaptchaResponse) {
      return res.status(400).json({ error: 'reCAPTCHA token is missing' });
    }
    // Assume verifyRecaptcha is implemented elsewhere
    const recaptchaValid = await verifyRecaptcha(recaptchaResponse);
    if (!recaptchaValid) {
      return res.status(400).json({ error: 'Failed reCAPTCHA verification' });
    }
  }

  if (!userInput) {
    return res.status(400).json({ error: 'User input is required' });
  }

  if (!password && !totpCode) {
    return res.status(400).json({ error: 'Password or TOTP code is required' });
  }

  // Find user by username
  const sqlFindUser = 'SELECT id, username, password, totp_secret, failed_login_attempts, lockout_until FROM users WHERE username = ? LIMIT 1';
  db.query(sqlFindUser, [userInput, userInput], async (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length === 0) {
      return res.status(401).json({ error: 'Invalid username or password' });
    }

    const user = results[0];
    const now = new Date();
    const LOCKOUT_THRESHOLD = 5;
    const LOCKOUT_DURATION = 15 * 60 * 1000;

    // Check lockout
    if (user.lockout_until && new Date(user.lockout_until) > now) {
      const lockoutMinutes = Math.ceil((new Date(user.lockout_until) - now) / 60000);
      return res.status(403).json({ error: `Account locked due to too many failed login attempts. Try again in ${lockoutMinutes} minute(s).` });
    }

    if (password) {
      // Verify password
      const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
      if (hashedPassword === user.password) {
        // Reset failed attempts
        const resetSql = 'UPDATE users SET failed_login_attempts = 0, lockout_until = NULL WHERE id = ?';
        db.query(resetSql, [user.id], (resetErr) => {
          if (resetErr) console.error('Error resetting login attempts:', resetErr.message);
          const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
          return res.json({ status: 'Login successful', token });
        });
      } else {
        // Increment failed attempts
        let failedAttempts = user.failed_login_attempts + 1;
        let lockoutUntil = null;
        if (failedAttempts >= LOCKOUT_THRESHOLD) {
          lockoutUntil = new Date(now.getTime() + LOCKOUT_DURATION);
        }
        const updateSql = 'UPDATE users SET failed_login_attempts = ?, lockout_until = ? WHERE id = ?';
        db.query(updateSql, [failedAttempts, lockoutUntil, user.id], (updateErr) => {
          if (updateErr) console.error('Error updating failed login attempts:', updateErr.message);
          if (lockoutUntil) {
            return res.status(403).json({ error: `Account locked due to too many failed login attempts. Try again in 15 minutes.` });
          } else {
            return res.status(401).json({ error: 'Invalid username or password' });
          }
        });
      }
    } else if (totpCode) {
      // Verify TOTP
      if (!user.totp_secret) {
        return res.status(400).json({ error: 'TOTP not set up for user' });
      }
      console.log('TOTP verification attempt:', { totpCode, totpSecret: user.totp_secret });
      const verified = speakeasy.totp.verify({
        secret: user.totp_secret,
        encoding: 'base32',
        token: totpCode,
        window: 2,
      });
      if (!verified) {
        return res.status(401).json({ error: 'Invalid or expired TOTP code' });
      }
      // Successful login, reset failed attempts
      const resetSql = 'UPDATE users SET failed_login_attempts = 0, lockout_until = NULL WHERE id = ?';
      db.query(resetSql, [user.id], (resetErr) => {
        if (resetErr) console.error('Error resetting login attempts:', resetErr.message);
        const token = jwt.sign({ id: user.id, username: user.username }, JWT_SECRET, { expiresIn: '1h' });
        return res.json({ status: 'Login successful', token });
      });
    }
  });
});

/**
 * POST /register
 * Register with username, password, and TOTP setup
 */
router.post('/register', express.json(), async (req, res) => {
  const { username, password, recaptchaResponse } = req.body;

  if (!recaptchaResponse) {
    return res.status(400).json({ error: 'reCAPTCHA token is missing' });
  }
  const recaptchaValid = await verifyRecaptcha(recaptchaResponse);
  if (!recaptchaValid) {
    return res.status(400).json({ error: 'Failed reCAPTCHA verification' });
  }

  if (!username) {
    return res.status(400).json({ error: 'Username is required' });
  }

  if (!password) {
    return res.status(400).json({ error: 'Password is required' });
  }

  // Validate username
  if (!isValidUsername(username)) {
    return res.status(400).json({ error: 'Invalid username' });
  }

  // Validate password
  if (!isValidPassword(password)) {
    return res.status(400).json({ error: 'Password must be at least 6 characters' });
  }

  // Generate TOTP secret for user
  const secret = speakeasy.generateSecret({ length: 20 });
  const totpSecret = secret.base32;

  // Generate otpauth URL for QR code
  const issuer = 'ForXunm';
  const otpauthUrl = `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(username)}?secret=${totpSecret}&issuer=${encodeURIComponent(issuer)}&algorithm=SHA1&digits=6&period=30`;

  // Check if username already exists
  const sqlCheckUser = 'SELECT id FROM users WHERE username = ? LIMIT 1';
  db.query(sqlCheckUser, [username], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length > 0) {
      return res.status(400).json({ error: 'Username already registered' });
    }

    // Insert user with hashed password and TOTP secret
    const hashedPassword = crypto.createHash('sha256').update(password).digest('hex');
    const sqlInsert = 'INSERT INTO users (username, password, totp_secret) VALUES (?, ?, ?)';
    db.query(sqlInsert, [username, hashedPassword, totpSecret], (insertErr) => {
      if (insertErr) return res.status(500).json({ error: insertErr.message });
      res.json({ status: 'Registration successful', totpSecret, otpauthUrl });
    });
  });
});

module.exports = { router, verifyJWT, sanitizeString };
