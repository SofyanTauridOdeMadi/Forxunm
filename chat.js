document.addEventListener('DOMContentLoaded', () => {
  const token = localStorage.getItem('token'); // Ambil token dari localStorage
  if (!token) {
    alert('Token not found. Please log in again.');
    window.location.href = 'auth.html';
    return;
  }

  const sendBtn = document.getElementById('sendBtn');
  const messageInput = document.getElementById('message');
  const messagesContainer = document.getElementById('messages');

  let replyTo = null; // Untuk menyimpan pesan yang sedang dibalas

  // Fungsi untuk memuat semua pesan
  async function loadMessages() {
    const response = await fetch('/api/all-messages', {
      headers: {
        'Authorization': `Bearer ${token}`, // Kirim token
      },
    });

    const result = await response.json();
    messagesContainer.innerHTML = ''; // Clear old messages

    if (result.messages) {
      result.messages.forEach((msg, index) => {
        const messageElement = document.createElement('div');
        messageElement.className = `message ${msg.username === 'me' ? 'me' : ''}`;

        // Format waktu
        const formattedDate = new Date(msg.created_at).toLocaleString();

        messageElement.innerHTML = `
          <strong>${msg.username}:</strong> ${msg.message}
          <div class="message-time">${new Date(msg.created_at).toLocaleString()}</div>
          ${msg.replyTo ? `<div class="reply-to">Replying to: ${msg.replyTo}</div>` : ''}
          <div class="reply-button" data-id="${index}">Reply</div>
        `;
        messagesContainer.appendChild(messageElement);
      });

      // Tambahkan event listener untuk tombol reply
      document.querySelectorAll('.reply-button').forEach(button => {
        button.addEventListener('click', (e) => {
          replyTo = e.target.dataset.id; // Simpan ID pesan yang dibalas
          messageInput.focus();
          messageInput.placeholder = 'Replying...';
        });
      });
    } else {
      alert(result.error || 'Failed to load messages');
    }
  }

  // Fungsi untuk mengirim pesan
  sendBtn.addEventListener('click', async () => {
    const message = messageInput.value.trim();
    if (!message) {
      alert('Message cannot be empty!');
      return;
    }

    const payload = replyTo ? { message, replyTo } : { message }; // Tambahkan ID reply jika ada

    const response = await fetch('/api/send', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`, // Kirim token
      },
      body: JSON.stringify(payload),
    });

    const result = await response.json();
    if (result.status) {
      messageInput.value = ''; // Clear input field
      replyTo = null; // Reset reply
      loadMessages(); // Reload messages
    } else {
      alert(result.error);
    }
  });

  // Muat pesan saat halaman dimuat
  loadMessages();
});