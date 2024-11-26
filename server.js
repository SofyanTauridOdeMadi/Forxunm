const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const apiRoutes = require('./api');

const app = express();
app.use(bodyParser.json());

// Melayani file statis
app.use(express.static(path.join(__dirname)));

// Melayani file HTML utama
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

// Rute API
app.use('/api', apiRoutes);

// Jalankan server
app.listen(3001, () => {
  console.log('Server running on http://localhost:3001');
});