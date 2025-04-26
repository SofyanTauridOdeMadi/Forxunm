const mysql = require('mysql2');

const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'secure_web'
});

db.connect((err) => {
    if (err) throw err;
    console.log('   -------------------------------//-------------------------------');
});

module.exports = db;