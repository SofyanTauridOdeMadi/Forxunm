const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const https = require('https');
const fs = require('fs');
const apiRoutes = require('./backend/api');

const app = express();

// Apply rate limiting to all requests to mitigate brute force and DoS attacks
const limiter = rateLimit({
  windowMs: 1 * 30 * 1000, // 30 seconds seconds
  max: 50, // limit each IP to 50 requests per windowMs
  standardHeaders: true,
  legacyHeaders: false,
  handler: (req, res) => {
    res.redirect('/rate-limit.html');
  }
});

const skipRateLimit = (req) => {
  const bypassPaths = [
    '/rate-limit.html'
  ];
  return bypassPaths.includes(req.path);
};

app.use((req, res, next) => {
  if (skipRateLimit(req)) {
    return next();
  } else {
    return limiter(req, res, next);
  }
});

app.use(helmet({
      contentSecurityPolicy: {
        directives: {
          defaultSrc: ["'self'"],
          scriptSrc: [
            "'self'",
            "https://cdn.jsdelivr.net",
            "https://cdnjs.cloudflare.com",
            "https://code.jquery.com",
            "https://www.google.com/recaptcha/api.js",
            "https://www.google.com/recaptcha/",
            "https://www.gstatic.com",
            "'unsafe-inline'",
            "'unsafe-eval'"
          ],
          styleSrc: [
            "'self'",
            "https://cdn.jsdelivr.net",
            "https://cdnjs.cloudflare.com",
            "'unsafe-inline'"
          ],
          imgSrc: [
            "'self'",
            "data:",
            "https://*",
            "https://localhost:3443/assets/*"
          ],
          connectSrc: ["'self'", "https://www.google.com"],
          fontSrc: [
            "'self'",
            "https://cdn.jsdelivr.net",
            "https://cdnjs.cloudflare.com"
          ],
          frameSrc: [
            "https://www.google.com",
            "https://www.gstatic.com"
          ],
          objectSrc: ["'none'"],
          upgradeInsecureRequests: [],
        },
      },
}));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.use(express.static(path.join(__dirname, 'assets')));
app.use(express.static(path.join(__dirname, 'uploads')));

app.use('/api', apiRoutes);

// Redirect root to /home.html
app.get('/', (req, res) => {
    res.redirect('/home.html');
});

app.get('/home.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend', 'home.html'));
});

app.get('/profile.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend', 'profile.html'));
});

app.get('/auth/login.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend', 'auth', 'login.html'));
});

app.get('/auth/register.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend', 'auth', 'register.html'));
});

app.get('/auth/otp-login.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend', 'auth', 'otp-login.html'));
});

app.get('/auth/otp-register.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend', 'auth', 'otp-register.html'));
});

app.get('/chat.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend', 'chat.html'));
});

app.get('/rate-limit.html', (req, res) => {
  res.sendFile(path.join(__dirname, 'frontend', 'rate-limit.html'));
});

const PORT = process.env.PORT || 3000;
const HTTPS_PORT = process.env.HTTPS_PORT || 3443;
const NODE_ENV = process.env.NODE_ENV || 'development';

const sslOptions = {
  key: fs.readFileSync(path.join(__dirname, 'certs', 'key.pem')),
  cert: fs.readFileSync(path.join(__dirname, 'certs', 'cert.pem')),
};

https.createServer(sslOptions, app).listen(HTTPS_PORT, () => {
  console.log(`
  ▄▖    ▖▖       
  ▙▖▛▌▛▘▚▘▌▌▛▌▛▛▌
  ▌ ▙▌▌ ▌▌▙▌▌▌▌▌▌ By Sofyan Taurid Ode Madi
  
  HTTPS Server berjalan di https://localhost:${HTTPS_PORT} - Mode: ${NODE_ENV}
  `);
});
