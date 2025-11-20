// ======================================================
// 🔐 LPH Password Manager - Content Script
// Detects login forms, saves credentials, and autofills.
// ======================================================

// ---------- Find Login Form ----------
function findLoginForm() {
  const passwordField = document.querySelector('input[type="password"]');
  if (!passwordField) return null;

  const form = passwordField.closest('form');
  if (!form) return null;

  // Try to detect username/email field
  const usernameField = form.querySelector(
    'input[type="email"], input[name*="user" i], input[name*="login" i], input[name*="email" i], input[type="text"]'
  );

  return { form, usernameField, passwordField };
}

// ---------- Toast Message ----------
function showToast(message, duration = 2500) {
  const toastId = 'lph-toast-notification';
  let toast = document.getElementById(toastId);

  if (!toast) {
    toast = document.createElement('div');
    toast.id = toastId;
    toast.style.cssText = `
      position: fixed;
      bottom: 20px;
      right: 20px;
      background: rgba(30, 30, 30, 0.95);
      color: #fff;
      padding: 12px 20px;
      border-radius: 8px;
      font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      font-size: 14px;
      z-index: 2147483647;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
      opacity: 0;
      transition: opacity 0.3s ease-in-out;
    `;
    document.body.appendChild(toast);
  }

  toast.textContent = message;
  toast.style.opacity = '1';

  // Fade out
  setTimeout(() => {
    toast.style.opacity = '0';
  }, duration);
}

// ---------- Save Credentials ----------
async function promptSave(username, password) {
  try {
    const response = await chrome.runtime.sendMessage({
      type: 'PM_SAVE_CREDENTIALS',
      url: window.location.href,
      username,
      password,
    });

    if (response?.ok) {
      showToast('✓ Password saved to LPH');
    } else {
      throw new Error(response?.error || 'Failed to save');
    }
  } catch (error) {
    console.error('LPH save error:', error);
    showToast('⚠️ Failed to save password');
  }
}

// ---------- Setup Form Submit Listener ----------
function setupFormListener() {
  const loginForm = findLoginForm();
  if (!loginForm) return;

  const { form, usernameField, passwordField } = loginForm;

  // Avoid attaching multiple listeners
  if (form.dataset.lphBound) return;
  form.dataset.lphBound = true;

  form.addEventListener(
    'submit',
    async () => {
      const username = usernameField ? usernameField.value.trim() : '';
      const password = passwordField.value;

      if (!username || !password) return;

      try {
        const status = await chrome.runtime.sendMessage({ type: 'PM_STATUS' });
        if (status?.unlocked) {
          await promptSave(username, password);
        } else {
          showToast('🔒 LPH is locked — unlock to save passwords');
        }
      } catch (err) {
        console.error('LPH status check failed:', err);
      }
    },
    { capture: true }
  );
}

// ---------- Autofill Handler ----------
async function autofill(username, password) {
  const loginForm = findLoginForm();
  if (!loginForm) {
    showToast('⚠️ No login form found on this page');
    return false;
  }

  const { usernameField, passwordField } = loginForm;

  if (usernameField && username) {
    usernameField.value = username;
    usernameField.dispatchEvent(new Event('input', { bubbles: true }));
    usernameField.dispatchEvent(new Event('change', { bubbles: true }));
  }

  if (passwordField && password) {
    passwordField.value = password;
    passwordField.dispatchEvent(new Event('input', { bubbles: true }));
    passwordField.dispatchEvent(new Event('change', { bubbles: true }));
  }

  showToast('✓ Credentials filled');
  return true;
}

// ---------- Message Listener (Autofill from Popup) ----------
chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.type === 'PM_AUTOFILL') {
    autofill(message.username, message.password).then((success) => {
      sendResponse({ ok: success });
    });
    return true; // Keep message channel open for async response
  }
});

// ---------- Initialize ----------
function init() {
  setupFormListener();

  // Re-scan periodically in case form loads later (SPA support)
  const observer = new MutationObserver(() => {
    if (!document.getElementById('lph-toast-notification')) setupFormListener();
  });
  observer.observe(document.body, { childList: true, subtree: true });
}

init();
