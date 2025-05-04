const express = require('express');
const multer = require('multer');
const { verifyJWT, sanitizeString } = require('./api-auth');
const db = require('./db');
const router = express.Router();

// Helper function to validate if a value is a positive integer
function isValidNumber(value) {
  return !isNaN(value) && Number.isInteger(Number(value)) && Number(value) > 0;
}

// Utility function to escape HTML special characters in user input
function escapeHtml(text) {
  if (typeof text !== 'string') {
    return text;
  }
  return text
    .replace(/&/g, '&amp;')
    .replace(/</g, '<')
    .replace(/>/g, '>')
    .replace(/"/g, '"')
    .replace(/'/g, '&#039;');
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
      // Escape user-generated content before sending
      const escapedResults = results.map(row => ({
        ...row,
        title: escapeHtml(row.title),
        content: escapeHtml(row.content),
        username: escapeHtml(row.username),
      }));
      res.json(escapedResults);
    }
  });
});

// **POST**: Membuat thread baru (dilindungi dengan verifyJWT)
router.post('/threads', express.json(), verifyJWT, (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized: No user information' });
  }
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

// **GET**: Mendapatkan semua balasan untuk thread tertentu
router.get('/threads/:id/replies', (req, res) => {
  let threadId = req.params.id;

  if (!isValidNumber(threadId)) {
    return res.status(400).json({ error: 'Invalid thread ID' });
  }
  threadId = Number(threadId);

  const query = 'SELECT r.reply_id, r.content, r.created_at, u.username FROM replies r JOIN users u ON r.user_id = u.id WHERE r.thread_id = ? AND r.is_deleted = 0 ORDER BY r.created_at ASC';
  db.query(query, [threadId], (err, results) => {
    if (err) {
      res.status(500).json({ error: err.message });
    } else {
      // Escape user-generated content before sending
      const escapedResults = results.map(row => ({
        ...row,
        content: escapeHtml(row.content),
        username: escapeHtml(row.username),
      }));
      res.json(escapedResults);
    }
  });
});

// **POST**: Membalas thread (dilindungi dengan verifyJWT)
router.post('/threads/:id/reply', express.json(), verifyJWT, (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized: No user information' });
  }
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
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized: No user information' });
  }
  let threadId = req.params.id;
  const userId = req.user.id;

  console.log(`Delete thread request by userId: ${userId} for threadId: ${threadId}`);

  if (!isValidNumber(threadId)) {
    return res.status(400).json({ error: 'Invalid thread ID' });
  }
  threadId = Number(threadId);

  // Check if the thread belongs to the user before deleting
  const checkQuery = 'SELECT user_id FROM threads WHERE thread_id = ? AND is_deleted = 0';
  db.query(checkQuery, [threadId], (err, results) => {
    if (err) {
      console.error('DB error checking thread ownership:', err.message);
      return res.status(500).json({ error: err.message });
    }
    if (results.length === 0) {
      console.log('Thread not found or already deleted');
      return res.status(404).json({ error: 'Thread not found' });
    }
    console.log(`Thread owner userId: ${results[0].user_id}`);

    if (results[0].user_id !== userId) {
      console.log('Unauthorized delete attempt: userId does not match thread owner');
      return res.status(403).json({ error: 'Unauthorized to delete this thread' });
    }

    const deleteQuery = 'UPDATE threads SET is_deleted = 1 WHERE thread_id = ?';
    db.query(deleteQuery, [threadId], (err2, result) => {
      if (err2) {
        console.error('DB error deleting thread:', err2.message);
        return res.status(500).json({ error: err2.message });
      }
      console.log('Thread deleted successfully');
      res.status(200).json({ message: 'Thread deleted successfully!' });
    });
  });
});

// **DELETE**: Menghapus balasan (soft delete, dilindungi dengan verifyJWT)
router.delete('/replies/:id', verifyJWT, (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: 'Unauthorized: No user information' });
  }
  let replyId = req.params.id;
  const userId = req.user.id;

  if (!isValidNumber(replyId)) {
    return res.status(400).json({ error: 'Invalid reply ID' });
  }
  replyId = Number(replyId);

  // Check if the reply belongs to the user before deleting
  const checkQuery = 'SELECT user_id FROM replies WHERE reply_id = ? AND is_deleted = 0';
  db.query(checkQuery, [replyId], (err, results) => {
    if (err) {
      return res.status(500).json({ error: err.message });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: 'Reply not found' });
    }
    if (results[0].user_id !== userId) {
      return res.status(403).json({ error: 'Unauthorized to delete this reply' });
    }

    const deleteQuery = 'UPDATE replies SET is_deleted = 1 WHERE reply_id = ?';
    db.query(deleteQuery, [replyId], (err2, result) => {
      if (err2) {
        return res.status(500).json({ error: err2.message });
      }
      res.status(200).json({ message: 'Reply deleted successfully!' });
    });
  });
});

module.exports = router;