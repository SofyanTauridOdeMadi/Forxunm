const express = require('express');
const cookieParser = require('cookie-parser');
const router = express.Router();

const { generateCsrfToken, validateCsrfToken, CSRF_TOKEN_COOKIE } = require('./csrf');
const authRouter = require('./api-auth').router;
const chatRouter = require('./api-chat');
const threadsRouter = require('./api-threads');
const profileRouter = require('./api-profile');

router.use(cookieParser());

// Generate CSRF token for all requests except auth routes
router.use((req, res, next) => {
  if (req.path.startsWith('/auth')) {
    return next();
  }
  generateCsrfToken(req, res, next);
});

// Validate CSRF token on state-changing requests except auth routes
router.use((req, res, next) => {
  if (req.path.startsWith('/auth')) {
    return next();
  }
  validateCsrfToken(req, res, next);
});

// New endpoint to get CSRF token
router.get('/csrf-token', (req, res) => {
  const token = req.cookies ? req.cookies[CSRF_TOKEN_COOKIE] : null;
  if (!token) {
    return res.status(404).json({ error: 'CSRF token not found' });
  }
  res.json({ csrfToken: token });
});

router.use('/auth', authRouter);
router.use('/chat', chatRouter);
router.use('/profile', profileRouter);
router.use('/', threadsRouter);

module.exports = router;
