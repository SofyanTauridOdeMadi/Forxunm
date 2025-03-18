const mysql = require('mysql2');

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'secure_web'
});

console.time('DB Connection');
db.connect((err) => {
    console.timeEnd('DB Connection');
    if (err) throw err;
    console.log('Koneksi Database Berhasil');
});