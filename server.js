const express = require('express');
const bodyParser = require('body-parser');
const path = require('path');
const apiRoutes = require('./core/api');

const app = express();

// Middleware untuk JSON parsing
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// Menyajikan file statik dari root direktori
app.use(express.static(path.join(__dirname, 'assets')));  // Folder untuk gambar dan file statik lainnya
app.use(express.static(path.join(__dirname, 'css')));     // Folder untuk CSS

// Endpoint untuk API
app.use('/api', apiRoutes);

// Rute untuk root (/) - Menampilkan halaman utama
app.get('/home.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'html','home.html'));
});

// Menangani permintaan ke auth.html
app.get('/auth.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'html', 'auth.html'));
});

// Menangani permintaan ke chat.html
app.get('/chat.html', (req, res) => {
    res.sendFile(path.join(__dirname, 'html', 'chat.html'));
});

// Jalankan server
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`Server berjalan di http://localhost:${PORT}`);
});