const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const apiRoutes = require('./api');

const app = express();

// Middleware untuk JSON parsing
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Menyajikan file statik dari root direktori
app.use(express.static(__dirname));

// Endpoint untuk API
app.use('/api', apiRoutes);

// Menangani permintaan ke auth.html
app.get('/auth.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'auth.html'));
});

// Menangani permintaan ke chat.html
app.get('/chat.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'chat.html'));
});

// Jalankan server
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server berjalan di http://localhost:${PORT}`);
});