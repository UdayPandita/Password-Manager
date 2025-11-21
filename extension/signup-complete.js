
document.addEventListener('DOMContentLoaded', () => {
    const signInBtn = document.getElementById('signInBtn');
    const backBtn = document.getElementById('backBtn');

   
    function goToPopup() {
        
        window.location.href = 'popup.html';
    }


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
