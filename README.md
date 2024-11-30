# 🔒 **Forxunm** - Forum Web Sederhana dengan Keamanan Hybrid Kriptografi

**Forxunm** adalah sebuah web forum sederhana namun dengan tingkat keamanan tinggi. Aplikasi ini menggunakan kombinasi teknik kriptografi hybrid: **AES**, **SHA-256**, dan **RSA** untuk melindungi data pengguna dan memastikan privasi tetap terjaga.

---

## 🚀 **Fitur Utama**
### 🔐 **Keamanan Tingkat Lanjut**
- **AES (Advanced Encryption Standard)** untuk mengenkripsi data pengguna.  
- **SHA-256** untuk memastikan integritas data.  
- **RSA (Rivest–Shamir–Adleman)** untuk komunikasi yang aman dan berbasis kunci publik.

### 💬 **Fitur Forum**
- Posting thread dan balasan antar pengguna.  
- Sistem komentar real-time.  
- Mendukung format teks kaya (bold, italic, dll.).

### 🔏 **Autentikasi & Akses**
- Sistem registrasi dan login dengan keamanan tinggi.  
- Pemulihan akun melalui email terverifikasi.  
- Validasi CAPTCHA untuk mencegah bot.

### 📊 **Manajemen Data**
- Log aktivitas pengguna untuk memantau interaksi di forum.  
- Penyimpanan data terenkripsi untuk mencegah kebocoran informasi.

---

## 💻 **Teknologi yang Digunakan**
- **Frontend**: HTML, CSS, dan JavaScript  
- **Backend**: Node.js dengan Express.js  
- **Database**: MongoDB  
- **Keamanan**: AES, SHA-256, RSA  
- **Pengelolaan Dependensi**: NPM

---

## 📂 **Struktur Proyek**
/.gitignore           # File untuk mengecualikan file tertentu dari repository
/README.md            # Dokumentasi proyek
/api.js               # Logika API untuk komunikasi antara frontend dan backend
/db.js                # Konfigurasi database
/index.html           # Halaman utama forum
/package.json         # Konfigurasi dependensi proyek
/script.js            # Logika frontend untuk interaksi pengguna
/server.js            # Server utama untuk menjalankan aplikasi
/style.css            # Gaya visual untuk halaman web

---

## 🌟 **Cara Menggunakan**
1. **Instalasi**  
   - Pastikan Anda sudah menginstal Node.js dan MongoDB.  
   - Clone repository ini:  
     ```bash
     git clone https://github.com/username/forxunm.git
     ```
   - Masuk ke direktori proyek dan instal dependensi:  
     ```bash
     cd forxunm
     npm install
     ```

2. **Jalankan Server**  
   - Mulai server Node.js:  
     ```bash
     node server.js
     ```
   - Akses aplikasi melalui browser di `http://localhost:3000`.

3. **Fitur Forum**  
   - Registrasi akun baru atau login menggunakan akun yang telah terdaftar.  
   - Mulai membuat thread, membalas, dan berdiskusi dengan pengguna lain.

---

## 🛠️ **To-Do List**
### **Fase Pengembangan**
- [x] Implementasi sistem keamanan hybrid (AES, SHA-256, RSA)  
- [x] Membuat API untuk autentikasi dan komunikasi forum  
- [x] Menambahkan fitur posting dan komentar  
- [ ] Menyempurnakan desain UI/UX  
- [ ] Penambahan fitur pengelolaan admin  

### **Fase Testing**
- [ ] Pengujian integritas data menggunakan SHA-256  
- [ ] Pengujian kecepatan enkripsi dan dekripsi dengan AES  
- [ ] Pengujian akses publik dan privat menggunakan RSA  

---

## 🎯 **Visi**
Kami ingin menghadirkan forum online sederhana namun dengan keamanan data yang optimal. Dengan **Forxunm**, kami berharap pengguna dapat berdiskusi dengan nyaman tanpa khawatir tentang privasi dan keamanan data mereka.

---

💡 **Kontribusi**  
Kami menyambut kontribusi Anda! Silakan fork repository ini, kirim pull request, atau diskusikan ide Anda dengan tim kami.
