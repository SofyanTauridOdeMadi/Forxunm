# 🛡️ Keamanan Aplikasi Web: Panduan Serangan dan Mitigasi

Semangat Ujian Akhir Semester !!!

---

## 💥 Serangan XSS (Cross-Site Scripting)

Serangan XSS (Cross-Site Scripting)
XSS (Cross-Site Scripting) adalah jenis serangan yang memungkinkan penyerang untuk menyuntikkan
skrip berbahaya ke dalam situs web yang dapat dieksekusi oleh pengguna lain.
Ini terjadi ketika aplikasi web memperbolehkan pengguna untuk memasukkan data yang diproses dan
disajikan kembali ke pengguna tanpa terlebih dahulu memvalidasi atau menyaring input tersebut.

Jenis serangan XSS:
 1. Stored XSS (Persistent): Skrip berbahaya disimpan di server dan kemudian dieksekusi di sisi klien setiap kali halaman dimuat oleh pengguna yang terpengaruh. (Yang dilalukan di laporan)
 2. Reflected XSS (Non-Persistent): Skrip berbahaya tidak disimpan di server, tetapi dikirim dalam permintaan HTTP dan langsung diproses oleh aplikasi web, kemudian dieksekusi oleh klien.
 3. DOM-based XSS: Skrip berbahaya mengubah struktur DOM di browser dengan memanfaatkan perubahan pada objek JavaScript yang dimuat.

⸻

Mitigasi dari Serangan XSS
 1. Validasi dan Sanitasi Input:
 Memastikan untuk memvalidasi input pengguna dengan ketat (misalnya, hanya izinkan karakter tertentu dalam formulir).
 Mengunakan sanitasi input untuk menghapus tag HTML atau JavaScript yang berbahaya.
 
 2. Encoding dan Escaping Output:
 Selalu encode output sebelum menampilkannya kembali di halaman web. Ini memastikan bahwa skrip tidak dieksekusi, tetapi hanya ditampilkan sebagai teks.
 Gunakan encoding HTML untuk mencegah elemen HTML dieksekusi sebagai skrip.

 3. Menonaktifkan Eksekusi JavaScript dalam Input Pengguna: 
 Hindari mengeksekusi JavaScript dalam data input pengguna, terutama di area yang menampilkan pesan atau elemen HTML dinamis.
  
## 🛡️ Serangan CSRF (Cross-Site Request Forgery)

CSRF (Cross-Site Request Forgery) adalah jenis serangan di mana penyerang memanfaatkan kepercayaan
yang dimiliki oleh pengguna terhadap situs web tertentu untuk melakukan aksi yang tidak sah tanpa
sepengetahuan pengguna. CSRF mengeksploitasi sesi yang telah ada, di mana penyerang mengirimkan permintaan
palsu ke server atas nama pengguna yang sudah login, biasanya dengan cara menipu pengguna untuk melakukan
klik atau mengunjungi halaman yang memicu permintaan berbahaya.

⸻

Bagaimana Cara Kerja Serangan CSRF?
 1. Pengguna login ke aplikasi: Pengguna login ke aplikasi web dan mendapatkan sesi aktif, misalnya dengan menggunakan cookie sesi.
 2. Penyerang membuat halaman berbahaya: Penyerang membuat halaman web atau email yang mengandung permintaan berbahaya yang akan dikirimkan ke aplikasi yang ditargetkan. Misalnya, permintaan untuk mengubah email atau mengirimkan uang.
 3. Pengguna mengunjungi halaman berbahaya: Pengguna mengunjungi halaman web atau membuka email yang dikirim oleh penyerang, tanpa menyadari adanya ancaman.
 4. Permintaan CSRF dikirim: Karena pengguna sudah login dan memiliki sesi aktif (misalnya, cookie), aplikasi web yang ditargetkan tidak membedakan antara permintaan yang sah dan permintaan yang berasal dari penyerang. Permintaan dari halaman berbahaya ini akan dikirimkan ke server aplikasi web atas nama pengguna.
 5. Permintaan dijalankan di server: Server menerima permintaan tersebut, memverifikasi sesi pengguna (karena ada cookie yang valid), dan mengeksekusi perintah yang tidak sah, seperti mengganti pengaturan pengguna, mentransfer uang, atau melakukan tindakan merugikan lainnya.

⸻

Mitigasi dari Serangan CSRF
Untuk melindungi web dari serangan CSRF, Kami menerapkan beberapa teknik pencegahan yaitu:
 1. Token CSRF:
 Penggunaan Token Unik: Setiap permintaan sensitif (seperti POST, PUT, DELETE) menyertakan token CSRF yang unik dan tidak dapat ditebak. Token ini biasanya dikirim bersama dengan permintaan dan divalidasi oleh server.
 Token dalam Formulir: Menambahkan token CSRF pada setiap formulir HTML untuk memastikan bahwa permintaan berasal dari pengguna yang sah.
 Token dalam Header: Menambahkan token CSRF dalam header permintaan HTTP.
 
 2. SameSite Cookies:
 Mengatur atribut SameSite pada cookies menjadi Strict untuk membatasi pengiriman cookie dari situs yang berbeda.
 Dengan ini, aplikasi kami akan lebih aman dari CSRF karena cookie hanya akan dikirim jika permintaan berasal dari situs yang sama.
 
 3. Validasi Referer dan Origin Header:
 Kami bisa memeriksa header Referer atau Origin untuk memastikan bahwa permintaan berasal dari sumber yang sah.
 Ini akan mencegah permintaan yang berasal dari situs yang tidak tepercaya.
 
 4.Validasi Tambahan:
 Menambahkan kata sandi dalam melakukan perubahan formulir.

## 📂 Serangan File Upload Vulnerability          

File Upload Vulnerability adalah jenis kerentanannya yang terjadi ketika aplikasi web memungkinkan pengguna
untuk mengunggah file tanpa melakukan validasi yang memadai terhadap tipe atau konten file tersebut.
Ini dapat membuka celah bagi penyerang untuk mengunggah file berbahaya, seperti skrip berbahaya (misalnya PHP, JavaScript, atau HTML yang dapat dieksekusi)
yang bisa dieksekusi di server atau di browser pengguna. Serangan file upload dapat digunakan untuk menjalankan kode berbahaya di server, mengakses data sensitif,
atau bahkan mengambil alih server atau aplikasi web yang rentan.

⸻

Jenis-Jenis Serangan File Upload
 1. Upload Skrip Berbahaya:
 Penyerang mengunggah file skrip (misalnya, PHP, ASP, atau JSP) yang dapat dieksekusi di server.
 Setelah file diunggah, penyerang dapat mengakses file tersebut melalui URL dan menjalankan skrip untuk merusak sistem, mencuri data, atau menjalankan perintah yang tidak sah.
 2. Web Shell:
 Penyerang dapat mengunggah web shell, yaitu skrip atau file yang memungkinkan mereka mengakses server dan menjalankan perintah shell di server tersebut. Web shell ini sering digunakan untuk mengambil alih server atau melakukan serangan lebih lanjut.
 3. Cross-Site Scripting (XSS) Melalui File:
 File yang diunggah oleh pengguna (seperti gambar atau dokumen) dapat disusupi dengan skrip berbahaya yang dieksekusi saat file dilihat oleh pengguna lain. Misalnya, file gambar yang berisi skrip JavaScript yang berbahaya.
 4. Upload File dengan Ekstensi Berbahaya:
Penyerang mengunggah file dengan ekstensi yang terlihat sah (misalnya .jpg, .png), namun isinya adalah file skrip atau executable yang dapat dipicu oleh aplikasi yang tidak memvalidasi file tersebut.

⸻

Contoh Serangan File Upload
Misalnya, sebuah aplikasi web memungkinkan pengguna untuk mengunggah file gambar. Namun, aplikasi tidak memvalidasi jenis file dengan benar, dan penyerang mengunggah file PHP berbahaya dengan ekstensi .jpg atau .png. Jika server tidak memeriksa jenis file dengan benar, file tersebut akan diproses dan disimpan di direktori unggahan.
Kemudian, penyerang dapat mengakses file tersebut melalui URL seperti: http://www.example.com/uploads/evilfile.jpg Jika server memungkinkan eksekusi file PHP, skrip PHP tersebut dapat dieksekusi dan penyerang dapat menjalankan perintah berbahaya, mengakses data sensitif, atau bahkan mendapatkan akses penuh ke server.

⸻

Mitigasi dari Serangan File Upload Vulnerability
Untuk melindungi web dari serangan File Upload Vulnerability, Kami menerapkan beberapa teknik pencegahan yaitu:
 1. Validasi Tipe File dengan Cermat:
 Pemeriksaan Ekstensi: Pastikan hanya file dengan ekstensi yang sah dan diizinkan yang dapat diunggah, seperti .jpg, .png, atau .pdf.
 Pemeriksaan MIME Type: Selain pemeriksaan ekstensi, periksa MIME type file untuk memastikan bahwa file yang diunggah adalah tipe file yang sah. Misalnya, untuk gambar, pastikan file memiliki MIME type image/jpeg atau image/png.
 Validasi Konten File: Pastikan konten file sesuai dengan jenisnya (misalnya, file gambar benar-benar gambar, file PDF benar-benar berformat PDF) dengan menggunakan pustaka validasi file seperti ImageMagick (untuk gambar) atau PDF.js (untuk PDF).
 
 2. Hindari Mengeksekusi File yang Diupload:
 Jangan biarkan file yang diunggah dieksekusi di server. Simpan file unggahan di folder yang tidak dapat dieksekusi (misalnya, di luar webroot).
 Gunakan Randomized Filenames: Hindari menggunakan nama asli file yang diunggah untuk mencegah penyerang mengetahui file yang mereka unggah.
 
 3. Batasi Ukuran File:
 Batasi ukuran file yang diunggah untuk mencegah file besar yang tidak diinginkan diunggah, yang dapat membebani server atau digunakan untuk menutupi file berbahaya.

## 🧩 Serangan SQL Injection

SQL Injection adalah jenis serangan keamanan di mana penyerang menyisipkan atau "menyuntikkan" kode SQL berbahaya ke dalam input 
web yang kemudian dieksekusi oleh database. Tujuannya adalah untuk mengakses, memanipulasi, atau merusak data yang seharusnya tidak boleh diakses,
seperti mencuri data sensitif, mengubah data, atau bahkan menghapus data.

Mitigasi SQL Injection dilakukan dengan beberapa cara utama diantarannya:
 1. Penggunaan Parameterized Queries (Prepared Statements):
 Semua query SQL yang menerima input pengguna menggunakan placeholder (?) dan nilai input disisipkan sebagai parameter terpisah.
 Contohnya di backend/api-auth.js, backend/api-chat.js, dan backend/api-profile.js. Ini memastikan input pengguna diperlakukan sebagai data, 
 bukan kode SQL, sehingga mencegah eksekusi kode berbahaya.

 2.Validasi dan Sanitasi Input:
 Sebelum digunakan dalam query, input pengguna divalidasi dan disanitasi, misalnya validasi username dengan regex, validasi email, dan sanitasi string 
 seperti const forbiddenPatterns = [/--/, /\bOR\b/i, /\bAND\b/i, /\bUNION\b/i, /;/, /'/, /"/];
 untuk menghilangkan karakter yang tidak diinginkan. Ini membantu memastikan data yang masuk sesuai format yang diharapkan dan mengurangi risiko input berbahaya.
 
 3. Penggunaan Hashing untuk Password:
 Password pengguna di-hash sebelum disimpan atau dibandingkan, sehingga meskipun data bocor, password asli tidak langsung terekspos.
 Ini adalah praktik keamanan penting meskipun tidak langsung mencegah SQL Injection.

## 🔓 Brute Force Attack

Brute force adalah jenis serangan di mana penyerang mencoba berbagai kombinasi username dan password secara berulang-ulang
untuk mendapatkan akses tidak sah ke sistem. Serangan ini mengandalkan percobaan dan kesalahan (trial and error)
untuk menebak kredensial yang benar.

Mitigasi terhadap serangan brute force dilakukan dengan beberapa cara:
 1. Penggunaan OTP (One-Time Password) / 2FA (Two-Factor Authentication):
 Pada proses login, terdapat mekanisme OTP yang menambah lapisan keamanan sehingga meskipun password berhasil ditebak,
 penyerang tetap memerlukan kode OTP yang biasanya dikirim ke perangkat pengguna.
 
 2. Lockout Akun Sementara:
 Setelah 5 kali percobaan login gagal berturut-turut (LOCKOUT_THRESHOLD = 5),
 akun akan dikunci selama 15 menit (LOCKOUT_DURATION = 15 menit). Selama periode ini,
 pengguna tidak dapat melakukan login dan akan menerima pesan bahwa akunnya terkunci sementara.
 
 3. Penggunaan reCAPTCHA:
 Di frontend, terdapat integrasi Google reCAPTCHA yang membantu membedakan antara pengguna manusia dan bot,
 sehingga menghambat serangan brute force otomatis.
 
 4. Hashing Password:
 Password disimpan dalam bentuk hash, sehingga meskipun data bocor, password asli tidak langsung diketahui.
 
 5. Rate limiting:
 Menggunakan middleware express-rate-limit. Konfigurasi rate limiting ini membatasi setiap IP hanya dapat melakukan maksimal 50 request
 dalam jangka waktu 30 detik. Jika batas ini terlampaui, server akan menolak request dengan pesan "Too many requests from this IP, please try again later."