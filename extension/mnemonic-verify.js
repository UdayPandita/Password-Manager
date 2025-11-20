// ======================================================
// 🔐 LPH Password Manager - Mnemonic Verification Logic
// ======================================================

const form = document.getElementById('verifyForm');
const input = document.getElementById('mnemonicInput');
const msg = document.getElementById('msg');

form.addEventListener('submit', async (e) => {
  e.preventDefault();

  const mnemonic = input.value.trim().toLowerCase().replace(/\s+/g, ' ');
  const btn = form.querySelector('button[type="submit"]');

  if (!mnemonic) {
    showMessage('Please enter your recovery phrase.', 'error');
    return;
  }

  const words = mnemonic.split(' ');
  if (words.length !== 12) {
    showMessage('Please enter exactly 12 words.', 'error');
    return;
  }

  btn.disabled = true;
  btn.textContent = 'Verifying...';

  try {
    // Send to background script for verification
    const resp = await chrome.runtime.sendMessage({
      type: 'PM_VERIFY_MNEMONIC',
      mnemonic
    });

    if (resp.ok) {
      showMessage('✅ Verification successful! Your account is ready.', 'success');
      setTimeout(() => {
        window.location.href = chrome.runtime.getURL('signup-complete.html');
      }, 1500);
    } else {
      throw new Error(resp.error || 'Verification failed. Please check your words.');
    }
  } catch (err) {
    showMessage(err.message || 'Verification error. Please try again.', 'error');
    btn.disabled = false;
    btn.textContent = 'Verify and Complete Signup';
  }
});

function showMessage(text, type) {
  msg.textContent = text;
  msg.className = `message ${type}`;
  msg.style.display = 'block';
}

// Back button handler
document.getElementById('backBtn').addEventListener('click', () => {
  window.location.href = chrome.runtime.getURL('mnemonic-display.html');
});
