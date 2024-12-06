let currentUser = '';

document.getElementById('registerBtn').addEventListener('click', async () => {
  const username = document.getElementById('registerUsername').value.trim();
  const password = document.getElementById('registerPassword').value.trim();

  if (!username || !password) {
    alert('Username and password are required for registration!');
    return;
  }

  const response = await fetch('/api/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });

  const result = await response.json();
  alert(result.status || result.error);
});

document.getElementById('loginBtn').addEventListener('click', async () => {
  const username = document.getElementById('loginUsername').value.trim();
  const password = document.getElementById('loginPassword').value.trim();

  if (!username || !password) {
    alert('Username and password are required for login!');
    return;
  }

  const response = await fetch('/api/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ username, password }),
  });

  const result = await response.json();
  if (result.status === 'Login successful') {
    currentUser = username;
    alert(result.status);
    document.getElementById('loginSection').style.display = 'none';
    document.getElementById('registerSection').style.display = 'none';
    document.getElementById('forumSection').style.display = 'block';
  } else {
    alert(result.error);
  }
});

document.getElementById('sendBtn').addEventListener('click', async () => {
  const message = document.getElementById('message').value.trim();

  if (!currentUser || !message) {
    alert('Message and login are required!');
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

window.onload = loadMessages;