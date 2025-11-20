
const form = document.getElementById('addForm');
const cancelBtn = document.getElementById('cancelBtn');

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

  let url = website;
  if (!/^https?:\/\//i.test(url)) {
    url = 'https://' + url;
  }

  try {
    new URL(url);
  } catch (e) {
    alert('Invalid website URL');
    return;
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
