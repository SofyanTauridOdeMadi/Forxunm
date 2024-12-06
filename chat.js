document.addEventListener('DOMContentLoaded', () => {
    const currentUser = localStorage.getItem('currentUser');
    if (!currentUser) {
      alert('Please log in first!');
      window.location.href = 'auth.html';
    }
  
    document.getElementById('sendBtn').addEventListener('click', async () => {
      const message = document.getElementById('message').value.trim();
  
      if (!message) {
        alert('Message cannot be empty!');
        return;
      }
  
      const response = await fetch('/api/send', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: currentUser, message }),
      });
  
      const result = await response.json();
      alert(result.status);
      loadMessages();
    });
  
    async function loadMessages() {
      const response = await fetch('/api/all-messages');
      const result = await response.json();
  
      const messagesDiv = document.getElementById('allMessages');
      messagesDiv.innerHTML = '';
  
      result.messages.forEach(msg => {
        const messageElement = document.createElement('div');
        messageElement.classList.add('message');
        messageElement.innerHTML = `<span>${msg.username}:</span> ${msg.message}`;
        messagesDiv.appendChild(messageElement);
      });
    }
  
    loadMessages();
  });