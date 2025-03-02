// Fungsi untuk memuat semua thread
function loadThreads() {
    fetch('/api/threads')
        .then(response => response.json())
        .then(data => {
            displayThreads(data);
        })
        .catch(error => {
            console.error('Error fetching threads:', error);
        });
}

// Fungsi untuk menampilkan thread di halaman
function displayThreads(threads) {
    const threadsContainer = document.getElementById('threadList');
    threadsContainer.innerHTML = '';  // Mengosongkan daftar thread sebelumnya

    threads.forEach(thread => {
        const threadElement = document.createElement('div');
        threadElement.classList.add('card', 'shadow-lg', 'mb-4');
        threadElement.innerHTML = `
            <div class="card-body" data-thread-id="${thread.thread_id}">
                <h5 class="card-title">${thread.title}</h5>
                <p class="card-text text-muted">${thread.content}</p>
                <div class="d-flex justify-content-between align-items-center mt-3">
                    <span class="text-muted">Posted by User ${thread.user_id}</span>
                    <div class="btn-group">
                        <button class="btn btn-purple" onclick="upvoteThread('${thread.thread_id}')">Upvote (${thread.upvotes})</button>
                        <button class="btn btn-outline-secondary" onclick="openReplyModal('${thread.thread_id}')">Reply</button>
                        <button class="btn btn-danger" onclick="deleteThread('${thread.thread_id}')">Delete</button>
                    </div>
                </div>
            </div>
        `;
        threadsContainer.appendChild(threadElement);
    });
}

// Fungsi untuk membuat thread baru
function createThread() {
    const title = document.getElementById('newThreadTitle').value;
    const content = document.getElementById('newThreadContent').value;

    if (title && content) {
        fetch('/api/threads', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                user_id: 1, // Gantilah sesuai dengan ID pengguna yang aktif
                title: title,
                content: content
            })
        })
        .then(response => response.json())
        .then(data => {
            alert('Thread created successfully!');
            loadThreads(); // Reload threads
            $('#createThreadModal').modal('hide'); // Menutup modal setelah thread dibuat
        })
        .catch(error => {
            console.error('Error creating thread:', error);
        });
    } else {
        alert('Please fill in both title and content.');
    }
}

// Fungsi untuk memberikan upvote pada thread
function upvoteThread(threadId) {
    fetch(`/api/threads/${threadId}/upvote`, {
        method: 'POST'
    }).then(response => {
        if (response.ok) {
            alert('Upvote successful!');
            loadThreads();  // Reload threads
        } else {
            alert('Error upvoting thread!');
        }
    });
}

// Fungsi untuk membuka modal reply
function openReplyModal(threadId) {
    const threadElement = document.querySelector(`[data-thread-id="${threadId}"]`);
    document.getElementById('replyContent').setAttribute('data-thread-id', threadId);
    $('#replyModal').modal('show');
}

// Fungsi untuk mengirimkan balasan
function submitReply() {
    const threadId = document.getElementById('replyContent').getAttribute('data-thread-id');
    const replyContent = document.getElementById('replyContent').value;

    if (replyContent) {
        fetch(`/api/threads/${threadId}/reply`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                user_id: 1, // Gantilah dengan ID pengguna yang sesuai
                content: replyContent
            })
        })
        .then(response => response.json())
        .then(data => {
            alert('Reply submitted!');
            loadThreads();  // Reload threads
            $('#replyModal').modal('hide'); // Menutup modal setelah reply dikirim
        })
        .catch(error => {
            console.error('Error submitting reply:', error);
        });
    } else {
        alert('Please write a reply.');
    }
}

// Fungsi untuk menghapus thread
function deleteThread(threadId) {
    if (confirm('Are you sure you want to delete this thread?')) {
        fetch(`/api/threads/${threadId}`, {
            method: 'DELETE'
        })
        .then(response => {
            if (response.ok) {
                alert('Thread deleted successfully!');
                loadThreads();  // Reload threads
            } else {
                alert('Error deleting thread!');
            }
        })
        .catch(error => {
            console.error('Error deleting thread:', error);
        });
    }
}

document.addEventListener('DOMContentLoaded', function() {
    loadThreads();  // Memuat semua thread saat halaman dimuat
});