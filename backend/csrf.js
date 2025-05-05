const crypto = require('crypto');

const CSRF_TOKEN_HEADER = 'x-csrf-token';
const CSRF_TOKEN_COOKIE = 'csrfToken';

// Middleware to generate CSRF token and set it in cookie
function generateCsrfToken(req, res, next) {
  let token = req.cookies ? req.cookies[CSRF_TOKEN_COOKIE] : null;
  if (!token) {
    token = crypto.randomBytes(24).toString('hex');
    const cookieOptions = {
      httpOnly: true,
      sameSite: 'strict',
    };
    if (process.env.NODE_ENV === 'production') {
      cookieOptions.secure = true;
    }
    res.cookie(CSRF_TOKEN_COOKIE, token, cookieOptions);
  }
  res.locals.csrfToken = token;
  next();
}

// Middleware to validate CSRF token on state-changing requests
function validateCsrfToken(req, res, next) {
  const method = req.method.toUpperCase();

  // Skip CSRF validation for login, register, and OTP related routes
  if (method === 'POST' && (
    req.path === '/api/auth/register' ||
    (req.path === '/api/auth/login' && req.body && req.body.totpCode)
  )) {
    return next();
  }

  // Validate Referer and Origin headers for CSRF protection
  const referer = req.headers['referer'] || '';
  const origin = req.headers['origin'] || '';
  const host = req.headers['host'] || '';

  // Allow if referer or origin matches host (same origin)
  if (referer && !referer.includes(host) && origin && !origin.includes(host)) {
    return res.status(403).json({ error: 'Invalid Referer or Origin header' });
  }

  if (['POST', 'PUT', 'DELETE', 'PATCH'].includes(method)) {
    const tokenFromHeader = req.headers[CSRF_TOKEN_HEADER];
    const tokenFromCookie = req.cookies ? req.cookies[CSRF_TOKEN_COOKIE] : null;
    if (!tokenFromHeader || !tokenFromCookie || tokenFromHeader !== tokenFromCookie) {
      return res.status(403).json({ error: 'Invalid or missing CSRF token' });
    }
  }
  next();
}

module.exports = {
  generateCsrfToken,
  validateCsrfToken,
  CSRF_TOKEN_HEADER,
  CSRF_TOKEN_COOKIE,
};
