// ======================================================
// ⚙️ LPH Password Manager - Options / Settings Page
// ======================================================

// Elements
const userEmailEl = document.getElementById('userEmail');
const changePasswordBtn = document.getElementById('changePasswordBtn');
const changeMsg = document.getElementById('changePasswordMsg');
const wipeDataBtn = document.getElementById('wipeDataBtn');
const wipeMsg = document.getElementById('wipeMsg');

// Utility: show success/error messages
function showMessage(el, text, type = 'success') {
  el.textContent = text;
  el.className = `message ${type}`;
  el.style.display = 'block';
  setTimeout(() => {
    el.style.display = 'none';
  }, 4000);
}

// ---------------------------
// Load User Info
// ---------------------------
(async () => {
  try {
    const resp = await chrome.runtime.sendMessage({ type: 'PM_GET_USER' });
    if (resp?.ok && resp.user?.email) {
      userEmailEl.textContent = `Signed in as: ${resp.user.email}`;
    } else {
      userEmailEl.textContent = 'Not signed in';
    }
  } catch (error) {
    console.error('Failed to load user info:', error);
    userEmailEl.textContent = 'Error loading user info';
  }
})();

// ---------------------------
// Change Master Password
// ---------------------------
changePasswordBtn.addEventListener('click', async () => {
  const currentPassword = document.getElementById('currentPassword').value.trim();
  const newPassword = document.getElementById('newPassword').value.trim();
  const confirmPassword = document.getElementById('confirmPassword').value.trim();

  changeMsg.style.display = 'none';

  if (!currentPassword || !newPassword || !confirmPassword) {
    showMessage(changeMsg, 'Please fill in all fields', 'error');
    return;
  }

  if (newPassword.length < 8) {
    showMessage(changeMsg, 'New password must be at least 8 characters', 'error');
    return;
  }

  if (newPassword !== confirmPassword) {
    showMessage(changeMsg, 'Passwords do not match', 'error');
    return;
  }

  changePasswordBtn.disabled = true;
  changePasswordBtn.textContent = 'Updating...';

  try {
    const resp = await chrome.runtime.sendMessage({
      type: 'PM_CHANGE_PASSWORD',
      currentPassword,
      newPassword,
    });

    if (resp.ok) {
      showMessage(changeMsg, '✅ Password changed successfully. Please sign in again.', 'success');
      setTimeout(() => {
        // Navigate to auth page
        window.location.href = chrome.runtime.getURL('auth.html');
      }, 2000);
    } else {
      throw new Error(resp.error || 'Failed to change password');
    }
  } catch (error) {
    console.error('Password change failed:', error);
    showMessage(changeMsg, error.message, 'error');
  } finally {
    changePasswordBtn.disabled = false;
    changePasswordBtn.textContent = 'Change Password';
  }
});

// ---------------------------
// Wipe All Data (Danger Zone)
// ---------------------------
wipeDataBtn.addEventListener('click', async () => {
  const confirm1 = confirm('⚠️ WARNING: This will permanently delete ALL saved passwords and sign you out. Continue?');
  if (!confirm1) return;

  const confirm2 = confirm('Last chance! All your data will be permanently lost. Continue?');
  if (!confirm2) return;

  wipeDataBtn.disabled = true;
  wipeDataBtn.textContent = 'Clearing...';
  wipeMsg.style.display = 'none';

  try {
    const resp = await chrome.runtime.sendMessage({ type: 'PM_WIPE_DATA' });

    if (resp.ok) {
      showMessage(wipeMsg, '✅ All data cleared successfully. Redirecting...', 'success');
      setTimeout(() => {
        // Navigate to auth page
        window.location.href = chrome.runtime.getURL('auth.html');
      }, 2000);
    } else {
      throw new Error(resp.error || 'Failed to clear data');
    }
  } catch (error) {
    console.error('Data wipe failed:', error);
    showMessage(wipeMsg, error.message, 'error');
  } finally {
    wipeDataBtn.disabled = false;
    wipeDataBtn.textContent = 'Clear All Data';
  }
});

// ---------------------------
// Account Security - Check Breaches
// ---------------------------
const checkBreachesBtn = document.getElementById('checkBreachesBtn');
const breachMsg = document.getElementById('breachMsg');
const breachResults = document.getElementById('breachResults');
const breachList = document.getElementById('breachList');

// SHA-1 hash function for email
async function sha1Hash(text) {
  const encoder = new TextEncoder();
  const data = encoder.encode(text);
  const hashBuffer = await crypto.subtle.digest('SHA-1', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
  return hashHex.toUpperCase();
}

// Check if email has been pwned using Have I Been Pwned API
async function checkEmailBreach(email) {
  try {
    const hash = await sha1Hash(email.toLowerCase());
    const prefix = hash.substring(0, 5);
    const suffix = hash.substring(5);
    
    // Use k-anonymity model - only send first 5 chars of hash
    const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
      method: 'GET',
      headers: {
        'User-Agent': 'LPH-Password-Manager'
      }
    });
    
    if (!response.ok) {
      // If password API fails, try breach API
      const breachResponse = await fetch(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`, {
        method: 'GET',
        headers: {
          'User-Agent': 'LPH-Password-Manager'
        }
      });
      
      if (breachResponse.status === 404) {
        return { email, breached: false, count: 0, breaches: [] };
      }
      
      if (breachResponse.ok) {
        const breaches = await breachResponse.json();
        return { email, breached: true, count: breaches.length, breaches };
      }
      
      return { email, breached: false, count: 0, breaches: [], error: 'Unable to check' };
    }
    
    const text = await response.text();
    const hashes = text.split('\r\n');
    const found = hashes.some(line => line.startsWith(suffix));
    
    return { email, breached: found, count: found ? 1 : 0, breaches: [] };
  } catch (error) {
    console.error('Breach check error:', error);
    return { email, breached: false, count: 0, breaches: [], error: error.message };
  }
}

// Get all unique emails from saved credentials
async function getAllEmails() {
  try {
    const resp = await chrome.runtime.sendMessage({ type: 'PM_GET_ALL' });
    if (!resp.ok) {
      throw new Error(resp.error || 'Failed to load vault');
    }
    if (resp.data) {
      const emails = new Set();
      for (const [domain, creds] of Object.entries(resp.data)) {
        for (const cred of creds) {
          // Check if username looks like an email
          if (cred.username.includes('@')) {
            emails.add(cred.username.toLowerCase());
          }
        }
      }
      return Array.from(emails);
    }
    return [];
  } catch (error) {
    console.error('Failed to get emails:', error);
    throw error;
  }
}

checkBreachesBtn.addEventListener('click', async () => {
  breachMsg.style.display = 'none';
  breachResults.style.display = 'none';
  breachList.innerHTML = '';
  
  checkBreachesBtn.disabled = true;
  checkBreachesBtn.textContent = 'Checking...';
  
  try {
    const emails = await getAllEmails();
    
    if (emails.length === 0) {
      showMessage(breachMsg, 'No email accounts found to check', 'error');
      return;
    }
    
    showMessage(breachMsg, `Checking ${emails.length} account(s)...`, 'success');
    
    const results = [];
    for (const email of emails) {
      const result = await checkEmailBreach(email);
      results.push(result);
      // Add delay to respect API rate limits
      await new Promise(resolve => setTimeout(resolve, 1500));
    }
    
    // Display results
    breachList.innerHTML = '';
    let totalBreaches = 0;
    
    results.forEach(result => {
      const item = document.createElement('div');
      item.className = 'breach-item';
      
      if (result.error) {
        item.classList.add('warning');
        item.innerHTML = `
          <div class="breach-email">${result.email}</div>
          <div class="breach-count">⚠️ Unable to check: ${result.error}</div>
        `;
      } else if (result.breached) {
        item.classList.add('danger');
        totalBreaches++;
        const breachNames = result.breaches.length > 0 
          ? result.breaches.slice(0, 3).map(b => b.Name).join(', ') 
          : 'data breach detected';
        item.innerHTML = `
          <div class="breach-email">${result.email}</div>
          <div class="breach-count">🚨 Found in ${result.count} breach(es): ${breachNames}${result.breaches.length > 3 ? '...' : ''}</div>
        `;
      } else {
        item.classList.add('safe');
        item.innerHTML = `
          <div class="breach-email">${result.email}</div>
          <div class="breach-count">✅ Email doesn't exist in breach databases</div>
        `;
      }
      
      breachList.appendChild(item);
    });
    
    breachResults.style.display = 'block';
    
    if (totalBreaches > 0) {
      showMessage(breachMsg, `⚠️ ${totalBreaches} account(s) found in data breaches! Consider changing passwords.`, 'error');
    } else {
      showMessage(breachMsg, '✅ All accounts are safe!', 'success');
    }
    
  } catch (error) {
    console.error('Breach check failed:', error);
    showMessage(breachMsg, `Error: ${error.message}`, 'error');
  } finally {
    checkBreachesBtn.disabled = false;
    checkBreachesBtn.textContent = 'Check All Accounts for Breaches';
  }
});

// ---------------------------
// Scroll to Security Section if Hash is Present
// ---------------------------
window.addEventListener('DOMContentLoaded', () => {
  if (window.location.hash === '#security') {
    const securitySection = document.querySelector('.account-security-card');
    if (securitySection) {
      securitySection.scrollIntoView({ behavior: 'smooth', block: 'start' });
    }
  }
});

// ---------------------------
// Back Button
// ---------------------------
const backBtn = document.getElementById('backBtn');
if (backBtn) {
  backBtn.addEventListener('click', () => {
    window.location.href = chrome.runtime.getURL('popup.html');
  });
}
