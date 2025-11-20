// extension/signup-complete.js

// Wait for the page to load
document.addEventListener('DOMContentLoaded', () => {
    const signInBtn = document.getElementById('signInBtn');
    const backBtn = document.getElementById('backBtn');

    // Function to handle navigation
    function goToPopup() {
        // Relative path is safest and simplest
        window.location.href = 'popup.html';
    }

    // Click Handler
    if (signInBtn) {
        signInBtn.addEventListener('click', goToPopup);
    }

    // Back button handler
    if (backBtn) {
        backBtn.addEventListener('click', () => {
            window.location.href = 'mnemonic-verify.html';
        });
    }

    // Auto-redirect timer (3 seconds)
    setTimeout(goToPopup, 3000);
});