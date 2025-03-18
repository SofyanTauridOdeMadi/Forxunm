const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const apiRoutes = require('./backend/api');

const app = express();

// Middleware untuk JSON parsing
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Menyajikan file statik dari root direktori
app.use(express.static(path.join(__dirname, 'assets')));  // Folder untuk gambar
app.use(express.static(path.join(__dirname, 'uploads'))); // Folder untuk Uploads

// Endpoint untuk API
app.use('/api', apiRoutes);

// Menampilkan halaman utama
app.get('/home.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend','home.html'));
});

// Menampilkan halaman utama
app.get('/profile.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend','profile.html'));
});

// Menangani permintaan ke auth.html
app.get('/auth.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend', 'auth.html'));
});

// Menangani permintaan ke chat.html
app.get('/chat.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'frontend', 'chat.html'));
});

// Jalankan server
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server berjalan di http://localhost:${PORT}`);
});