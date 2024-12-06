document.addEventListener('DOMContentLoaded', () => {
  const token = localStorage.getItem('token'); // Ambil token dari localStorage
  console.log('Token Loaded:', token); // Log token untuk memastikan token diambil

  if (!token) {
    alert('Token not found. Please log in again.');
    window.location.href = 'auth.html';
    return;
  }

  // Coba memuat pesan
  fetch('/api/all-messages', {
    headers: {
      'Authorization': `Bearer ${token}`, // Kirim token
    },
  })
    .then(response => {
      console.log('Response Status:', response.status); // Debug status respons
      if (response.status === 403) {
        alert('Your session has expired. Please log in again.');
        localStorage.removeItem('token'); // Hapus token
        window.location.href = 'auth.html';
      }
      return response.json();
    })
    .then(data => {
      console.log('Messages Data:', data); // Log data pesan
    })
    .catch(err => {
      console.error('Error Loading Messages:', err.message); // Log error
    });
});