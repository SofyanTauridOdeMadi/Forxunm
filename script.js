document.getElementById('sendBtn').addEventListener('click', async () => {
    const username = document.getElementById('username').value.trim();
    const message = document.getElementById('message').value.trim();
  
    if (!username || !message) {
      alert('Both username and message are required!');
      return;
    }
  
    const response = await fetch('/api/send', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, message }),
    });
  
    const result = await response.json();
    if (result.status) {
      alert(result.status);
      loadMessages();
    }
  });
  
  async function loadMessages() {
    const response = await fetch('/api/all-messages');
    const result = await response.json();
  
    const messagesDiv = document.getElementById('allMessages');
    messagesDiv.innerHTML = '';
  
    if (result.messages) {
      result.messages.forEach(msg => {
        const messageElement = document.createElement('div');
        messageElement.classList.add('message');
        messageElement.innerHTML = `<span>${msg.username}:</span> ${msg.message}`;
        messagesDiv.appendChild(messageElement);
      });
    } else {
      messagesDiv.textContent = 'No messages available.';
    }
  }
  
  window.onload = loadMessages;