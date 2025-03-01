document.getElementById('loginBtn').addEventListener('click', async () => {
    const username = document.getElementById('loginUsername').value.trim();
    const password = document.getElementById('loginPassword').value.trim();
  
    if (!username || !password) {
      alert('Username and password are required!');
      return;
    }
  
    const response = await fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password }),
    });
  
    const result = await response.json();
    if (result.status === 'Login successful') {
      localStorage.setItem('currentUser', username); // Simpan username
      window.location.href = 'chat.html'; // Arahkan ke halaman chat
    } else {
      alert(result.error);
    }
  });
  
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