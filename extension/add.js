
const form = document.getElementById('addForm');
const cancelBtn = document.getElementById('cancelBtn');
const websiteInput = document.getElementById('website');
const websiteError = document.getElementById('websiteError');

// URL/Domain validation function
function isValidUrlOrDomain(input) {
  const trimmed = input.trim();
  if (!trimmed) return false;

  // Try to parse as URL (with or without protocol)
  let url = trimmed;
  if (!/^https?:\/\//i.test(url)) {
    url = 'https://' + url;
  }

  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname;

    // Check if hostname is valid
    // Must contain at least one dot (except localhost)
    if (hostname === 'localhost') return true;
    
    // Check for valid domain pattern
    const domainPattern = /^([a-z0-9]([a-z0-9-]*[a-z0-9])?\.)+[a-z]{2,}$/i;
    if (!domainPattern.test(hostname)) return false;

    // Additional checks
    if (hostname.length > 253) return false; // Max domain length
    const labels = hostname.split('.');
    for (const label of labels) {
      if (label.length > 63) return false; // Max label length
    }

    return true;
  } catch (e) {
    return false;
  }
}

// Real-time validation on input
websiteInput.addEventListener('input', () => {
  const value = websiteInput.value.trim();
  if (value && !isValidUrlOrDomain(value)) {
    websiteInput.classList.add('invalid');
    websiteError.classList.add('show');
  } else {
    websiteInput.classList.remove('invalid');
    websiteError.classList.remove('show');
  }
});

// Validation on blur
websiteInput.addEventListener('blur', () => {
  const value = websiteInput.value.trim();
  if (value && !isValidUrlOrDomain(value)) {
    websiteInput.classList.add('invalid');
    websiteError.classList.add('show');
  }
});

form.addEventListener('submit', async (e) => {
  e.preventDefault();

  const website = document.getElementById('website').value.trim();
  const username = document.getElementById('username').value.trim();
  const password = document.getElementById('password').value;
  const btn = form.querySelector('button[type="submit"]');

  if (!website || !username || !password) {
    alert('Please fill in all fields');
    return;
  }

  // Validate URL/domain
  if (!isValidUrlOrDomain(website)) {
    websiteInput.classList.add('invalid');
    websiteError.classList.add('show');
    websiteInput.focus();
    alert('Please enter a valid URL or domain name (e.g., example.com or https://example.com)');
    return;
  }

  let url = website;
  if (!/^https?:\/\//i.test(url)) {
    url = 'https://' + url;
  }

  btn.disabled = true;
  btn.textContent = 'Saving...';

  try {
    const response = await chrome.runtime.sendMessage({
      type: 'PM_SAVE_CREDENTIALS',
      url,
      username,
      password,
    });

    if (response.ok) {
      btn.textContent = '✓ Saved!';
      setTimeout(() => {
        window.location.href = chrome.runtime.getURL('popup.html');
      }, 1000);
    } else {
      throw new Error(response.error || 'Failed to save');
    }
  } catch (error) {
    console.error('Add password error:', error);
    alert('Error: ' + error.message);
    btn.disabled = false;
    btn.textContent = 'Save Password';
  }
});

cancelBtn.addEventListener('click', () => {
  window.location.href = chrome.runtime.getURL('popup.html');
});
