document.addEventListener('DOMContentLoaded', () => {
    const token = localStorage.getItem('token');
    if (!token) {
        alert('Token not found. Please log in again.');
        window.location.href = 'auth.html';
        return;
    }

    const usernameElement = document.getElementById('username');
    const accountCreatedElement = document.getElementById('accountCreated');
    const profileImageElement = document.getElementById('profileImage');
    const emailElement = document.getElementById('email');
    const bioElement = document.getElementById('bio');

    async function loadUserProfile() {
        try {
            const response = await fetch('/api/user-profile', {
                headers: {
                    'Authorization': `Bearer ${token}`,
                },
            });

            const result = await response.json();

            if (result.status && result.user) {
                usernameElement.textContent = result.user.username;
                accountCreatedElement.textContent = new Date(result.user.created_at).toLocaleDateString();
                emailElement.value = result.user.email;
                bioElement.value = result.user.bio || '';

                if (result.user.profile_picture_url) {
                    profileImageElement.src = result.user.profile_picture_url;
                }

            } else {
                alert(result.error || 'Failed to load user profile');
            }
        } catch (error) {
            console.error('Error loading user profile:', error);
            alert('Failed to load user profile');
        }
    }

    // Fungsi untuk memperbarui profil pengguna
    async function updateProfile() {
        const bio = bioElement.value.trim();
        const newPassword = document.getElementById('newPassword').value.trim();
        const confirmPassword = document.getElementById('confirmPassword').value.trim();

        if (newPassword && newPassword !== confirmPassword) {
            alert('Passwords do not match!');
            return;
        }

        const payload = {
            bio,
            newPassword: newPassword || undefined,
        };

        try {
            const response = await fetch('/api/update-profile', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': `Bearer ${token}`,
                },
                body: JSON.stringify(payload),
            });

            const result = await response.json();
            if (result.status) {
                alert('Profile updated successfully!');
                loadUserProfile(); // Muat ulang profil
            } else {
                alert(result.error || 'Failed to update profile');
            }
        } catch (error) {
            console.error('Error updating profile:', error);
            alert('Failed to update profile');
        }
    }

    const updateProfileForm = document.getElementById('updateProfileForm');
    updateProfileForm.addEventListener('submit', (event) => {
        event.preventDefault();
        updateProfile();
    });

    // Muat profil pengguna saat halaman dimuat
    loadUserProfile();

    function uploadImage() {
        const uploadModal = new bootstrap.Modal(document.getElementById('uploadModal'));
        uploadModal.show();
    }

    async function saveProfileImage() {
        const fileInput = document.getElementById('fileInput');
        const file = fileInput.files[0];

        if (!file) {
            alert('Please select a file.');
            return;
        }

        const formData = new FormData();
        formData.append('profile_image', file);

        try {
            const response = await fetch('/api/upload-profile-image', {
                method: 'POST',
                headers: {
                    'Authorization': `Bearer ${token}`,
                },
                body: formData,
            });

            const result = await response.json();

            if (result.status) {
                alert('Profile image updated successfully!');
                document.getElementById('profileImage').src = result.profile_image_url;
                const uploadModal = new bootstrap.Modal(document.getElementById('uploadModal'));
                uploadModal.hide();
            } else {
                alert(result.error || 'Failed to upload profile image');
            }
        } catch (error) {
            console.error('Error uploading profile image:', error);
            alert('Failed to upload profile image');
        }
    }
});
