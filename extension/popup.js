// LPH Password Manager - Popup Logic

let currentUrl = '';

// Helper to get the active tab (handling Electron popup quirks)
async function getActiveTab() {
  try {
    // First try standard query
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    
    // If we found a tab and it's NOT the extension popup itself, return it
    if (tab && tab.url && !tab.url.startsWith('chrome-extension://') && !tab.url.startsWith('devtools://')) {
      return tab;
    }

    // Fallback: Query all tabs and find the active one in the main window
    // In Electron, the "main window" tabs might be separate from the popup window
    const tabs = await chrome.tabs.query({});
    
    // Find a tab that looks like a real webpage
    const realTab = tabs.find(t => 
      t.active && 
      !t.url.startsWith('chrome-extension://') && 
      !t.url.startsWith('devtools://')
    );
    
    return realTab || tabs[0];
  } catch (error) {
    console.error('Error getting active tab:', error);
    return null;
  }
}

// Get current tab URL
async function getCurrentTabUrl() {
  try {
    const tab = await getActiveTab();
    return tab?.url || '';
  } catch (error) {
    console.error('Failed to get current tab URL:', error);
    return '';
  }
}

// Extract domain from URL
function getDomain(url) {
  try {
    if (!url) return '';
    return new URL(url).hostname;
  } catch {
    return '';
  }
}

// Get first letter for icon
function getInitial(domain) {
  if (!domain) return '?';
  const cleanDomain = domain.replace('www.', '');
  return cleanDomain.charAt(0).toUpperCase();
}

// Get favicon URL for a domain
function getFaviconUrl(domain) {
  if (!domain) return null;
  // Try Google's favicon service first
  return `https://www.google.com/s2/favicons?domain=${domain}&sz=64`;
}

// Check status
async function checkStatus() {
  try {
    const response = await chrome.runtime.sendMessage({ type: 'PM_STATUS' });
    return response;
  } catch (error) {
    console.error('Status check failed:', error);
    return { unlocked: false, user: null };
  }
}

// Unlock vault
async function unlock(password) {
  try {
    return await chrome.runtime.sendMessage({ type: 'PM_UNLOCK', password });
  } catch (error) {
    console.error('Unlock failed:', error);
    return { ok: false, error: error.message };
  }
}

// Lock vault
async function lock() {
  try {
    return await chrome.runtime.sendMessage({ type: 'PM_LOCK' });
  } catch (error) {
    console.error('Lock failed:', error);
    return { ok: false, error: error.message };
  }
}

// Get credentials for URL
async function getCredentials(url) {
  try {
    return await chrome.runtime.sendMessage({ type: 'PM_GET_CREDENTIALS', url });
  } catch (error) {
    console.error('Get credentials failed:', error);
    return { ok: false, credentials: [] };
  }
}

// Get all credentials
async function getAllCredentials() {
  try {
    return await chrome.runtime.sendMessage({ type: 'PM_GET_ALL' });
  } catch (error) {
    console.error('Get all credentials failed:', error);
    return { ok: false, data: {} };
  }
}

// Delete credential
async function deleteCredential(url, username) {
  try {
    return await chrome.runtime.sendMessage({ type: 'PM_DELETE_CREDENTIAL', url, username });
  } catch (error) {
    console.error('Delete credential failed:', error);
    return { ok: false, error: error.message };
  }
}

// Sign out
async function signOut() {
  try {
    await chrome.runtime.sendMessage({ type: 'PM_SIGNOUT' });
    // Open auth page in current window/tab
    window.location.href = chrome.runtime.getURL('auth.html');
  } catch (error) {
    console.error('Sign out failed:', error);
  }
}

// Autofill credentials
async function autofill(username, password) {
  try {
    const tab = await getActiveTab();
    if (!tab || !tab.id) {
      console.warn('No active tab found for autofill');
      return;
    }
    
    // Check if the tab is on a regular webpage (not chrome://, about:, etc.)
    if (!tab.url || tab.url.startsWith('chrome://') || tab.url.startsWith('about:') || tab.url.startsWith('chrome-extension://')) {
      console.warn('Cannot autofill on this page.');
      return;
    }
    
    try {
      await chrome.tabs.sendMessage(tab.id, {
        type: 'PM_AUTOFILL',
        username,
        password,
      });
      // Try to close popup window
      try {
        window.close();
      } catch (e) {
        // In Electron, window may not close - that's ok
      }
    } catch (msgError) {
      console.error('Message send error:', msgError);
      // alert('Failed to autofill. The page may not be fully loaded yet. Please try:\n1. Refresh the page\n2. Wait for it to fully load\n3. Try again');
    }
  } catch (error) {
    console.error('Autofill error:', error);
    // alert('Failed to autofill. Please refresh the page and try again.');
  }
}

// Copy to clipboard
async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (error) {
    console.error('Copy failed:', error);
    return false;
  }
}

// Update UI based on status
function updateUI(status) {
  const statusDot = document.getElementById('statusDot');
  const statusText = document.getElementById('statusText');
  const lockedView = document.getElementById('lockedView');
  const unlockedView = document.getElementById('unlockedView');
  const headerActions = document.getElementById('headerActions');

  if (status.unlocked) {
    statusDot.classList.add('unlocked');
    statusText.textContent = 'Unlocked';
    lockedView.style.display = 'none';
    unlockedView.style.display = 'block';
    headerActions.style.display = 'flex';
  } else {
    statusDot.classList.remove('unlocked');
    statusText.textContent = 'Locked';
    lockedView.style.display = 'block';
    unlockedView.style.display = 'none';
    headerActions.style.display = 'none';
  }
}

// Render credentials list
async function renderCredentials(searchQuery = '') {
  const listContainer = document.getElementById('credentialsList');

  let credentials = [];

  if (searchQuery) {
    // Search mode - show all matching passwords
    const allData = await getAllCredentials();
    if (allData.ok && allData.data) {
      for (const [domain, creds] of Object.entries(allData.data)) {
        for (const cred of creds) {
          if (
            domain.toLowerCase().includes(searchQuery) ||
            cred.username.toLowerCase().includes(searchQuery)
          ) {
            credentials.push({ domain, ...cred });
          }
        }
      }
    }
  } else {
    // Show ALL passwords by default
    const allData = await getAllCredentials();
    if (allData.ok && allData.data) {
      for (const [domain, creds] of Object.entries(allData.data)) {
        for (const cred of creds) {
          credentials.push({ domain, ...cred });
        }
      }
    }
  }

  if (credentials.length === 0) {
    listContainer.innerHTML = `
      <div class="empty-state">
        <div class="empty-state-icon">🔐</div>
        <div style="font-size: 14px; margin-bottom: 8px;">No passwords found</div>
        <div style="font-size: 12px; color: #999;">Save passwords as you log into websites</div>
      </div>
    `;
    return;
  }

  listContainer.innerHTML = '';

  for (const cred of credentials) {
    const card = document.createElement('div');
    card.className = 'cred-card';

    const initial = getInitial(cred.domain);
    const displayDomain = cred.domain || 'Unknown';
    const faviconUrl = getFaviconUrl(cred.domain);

    // Create header
    const header = document.createElement('div');
    header.className = 'cred-header';
    
    const iconDiv = document.createElement('div');
    iconDiv.className = 'cred-icon';
    if (faviconUrl) {
      const img = document.createElement('img');
      img.src = faviconUrl;
      img.alt = displayDomain;
      img.onerror = function() { this.style.display='none'; this.parentElement.textContent=initial; };
      iconDiv.appendChild(img);
    } else {
      iconDiv.textContent = initial;
    }
    
    const infoDiv = document.createElement('div');
    infoDiv.className = 'cred-info';
    
    const domainDiv = document.createElement('div');
    domainDiv.className = 'cred-domain';
    domainDiv.textContent = displayDomain;
    
    const usernameDiv = document.createElement('div');
    usernameDiv.className = 'cred-username';
    usernameDiv.textContent = cred.username;
    
    const passwordDiv = document.createElement('div');
    passwordDiv.className = 'cred-password';
    passwordDiv.style.fontFamily = 'monospace';
    passwordDiv.style.fontSize = '13px';
    passwordDiv.style.color = '#666';
    passwordDiv.style.marginTop = '4px';
    passwordDiv.style.display = 'none';
    passwordDiv.textContent = cred.password;
    
    infoDiv.appendChild(domainDiv);
    infoDiv.appendChild(usernameDiv);
    infoDiv.appendChild(passwordDiv);
    header.appendChild(iconDiv);
    header.appendChild(infoDiv);
    
    // Create actions
    const actions = document.createElement('div');
    actions.className = 'cred-actions';
    
    const toggleBtn = document.createElement('button');
    toggleBtn.className = 'toggle-btn';
    toggleBtn.textContent = 'Unhide';
    toggleBtn.dataset.visible = 'false';
    
    const copyBtn = document.createElement('button');
    copyBtn.className = 'copy-btn';
    copyBtn.textContent = 'Copy';
    copyBtn.dataset.password = cred.password;
    
    const deleteBtn = document.createElement('button');
    deleteBtn.className = 'delete-btn';
    deleteBtn.textContent = '×';
    deleteBtn.dataset.domain = cred.domain;
    deleteBtn.dataset.username = cred.username;
    
    actions.appendChild(toggleBtn);
    actions.appendChild(copyBtn);
    actions.appendChild(deleteBtn);
    
    card.appendChild(header);
    card.appendChild(actions);
    
    listContainer.appendChild(card);
  }

  // Add event listeners
  document.querySelectorAll('.toggle-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const card = btn.closest('.cred-card');
      const passwordDiv = card.querySelector('.cred-password');
      const isVisible = btn.dataset.visible === 'true';
      
      if (isVisible) {
        // Hide password
        passwordDiv.style.display = 'none';
        btn.textContent = 'Unhide';
        btn.dataset.visible = 'false';
      } else {
        // Show password
        passwordDiv.style.display = 'block';
        btn.textContent = 'Hide';
        btn.dataset.visible = 'true';
      }
    });
  });

  document.querySelectorAll('.copy-btn').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const success = await copyToClipboard(btn.dataset.password);
      if (success) {
        btn.textContent = '✓ Copied';
        setTimeout(() => (btn.textContent = 'Copy'), 1500);
      }
    });
  });

  document.querySelectorAll('.delete-btn').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const { domain, username } = btn.dataset;
      if (confirm(`Delete credentials for ${username}?`)) {
        const url = `https://${domain}`;
        await deleteCredential(url, username);
        await renderCredentials(searchQuery);
      }
    });
  });
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// Initialize
async function init() {
  currentUrl = await getCurrentTabUrl();
  const status = await checkStatus();

  if (!status.user) {
    // Navigate to auth page instead of creating new tab
    window.location.href = chrome.runtime.getURL('auth.html');
    return;
  }


  updateUI(status);
  if (status.unlocked) await renderCredentials();
}

// Event listeners
document.getElementById('unlockBtn')?.addEventListener('click', async () => {
  const password = document.getElementById('unlockInput').value;
  const btn = document.getElementById('unlockBtn');
  if (!password) return alert('Please enter your master password');
  btn.disabled = true;
  btn.textContent = 'Unlocking...';
  const resp = await unlock(password);
  if (resp.ok) {
    const status = await checkStatus();
    updateUI(status);
    await renderCredentials();
  } else alert(resp.error || 'Invalid password');
  btn.disabled = false;
  btn.textContent = 'Unlock Vault';
  document.getElementById('unlockInput').value = '';
});

document.getElementById('unlockInput')?.addEventListener('keydown', (e) => {
  if (e.key === 'Enter') document.getElementById('unlockBtn').click();
});

document.getElementById('lockBtn')?.addEventListener('click', async () => {
  await lock();
  updateUI(await checkStatus());
});

document.getElementById('signoutBtn')?.addEventListener('click', async () => {
  if (confirm('Sign out of LPH Password Manager?')) await signOut();
});

document.getElementById('searchInput')?.addEventListener('input', async (e) => {
  await renderCredentials(e.target.value.trim().toLowerCase());
});

document
  .getElementById('addPasswordBtn')
  ?.addEventListener('click', () => {
    // Navigate to add page in current window
    window.location.href = chrome.runtime.getURL('add.html');
  });

document.getElementById('shareBtn')?.addEventListener('click', () => {
  // Navigate to share page in current window
  window.location.href = chrome.runtime.getURL('share.html');
});

document.getElementById('securityCheckBtn')?.addEventListener('click', async () => {
  const btn = document.getElementById('securityCheckBtn');
  const originalText = btn.textContent;
  btn.disabled = true;
  btn.textContent = 'Checking...';
  
  try {
    // Get all emails from vault
    const resp = await chrome.runtime.sendMessage({ type: 'PM_GET_ALL' });
    if (!resp.ok) {
      alert('Error: ' + (resp.error || 'Failed to load vault'));
      return;
    }
    
    const emails = new Set();
    if (resp.data) {
      for (const [domain, creds] of Object.entries(resp.data)) {
        for (const cred of creds) {
          if (cred.username.includes('@')) {
            emails.add(cred.username.toLowerCase());
          }
        }
      }
    }
    
    if (emails.size === 0) {
      alert('No email accounts found to check');
      return;
    }
    
    const emailList = Array.from(emails);
    let message = `Checking ${emailList.length} account(s) for breaches...\n\n`;
    let breachCount = 0;
    
    for (const email of emailList) {
      try {
        // Simple check using Have I Been Pwned
        const encoder = new TextEncoder();
        const data = encoder.encode(email.toLowerCase());
        const hashBuffer = await crypto.subtle.digest('SHA-1', data);
        const hashArray = Array.from(new Uint8Array(hashBuffer));
        const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('').toUpperCase();
        const prefix = hashHex.substring(0, 5);
        
        const response = await fetch(`https://api.pwnedpasswords.com/range/${prefix}`, {
          headers: { 'User-Agent': 'LPH-Password-Manager' }
        });
        
        if (response.ok) {
          message += `✅ ${email}: Safe\n`;
        } else {
          // Try breach API
          const breachResponse = await fetch(`https://haveibeenpwned.com/api/v3/breachedaccount/${encodeURIComponent(email)}?truncateResponse=false`, {
            headers: { 'User-Agent': 'LPH-Password-Manager' }
          });
          
          if (breachResponse.status === 404) {
            message += `✅ ${email}: Email doesn't exist in breach databases\n`;
          } else if (breachResponse.ok) {
            const breaches = await breachResponse.json();
            breachCount++;
            message += `🚨 ${email}: Found in ${breaches.length} breach(es)\n`;
          } else {
            message += `⚠️ ${email}: Unable to check\n`;
          }
        }
        
        // Rate limit delay
        await new Promise(resolve => setTimeout(resolve, 1500));
      } catch (error) {
        message += `⚠️ ${email}: Error checking\n`;
      }
    }
    
    if (breachCount > 0) {
      message += `\n⚠️ ${breachCount} account(s) found in breaches! Consider changing passwords.`;
    } else {
      message += '\n✅ All accounts are safe!';
    }
    
    alert(message);
    
  } catch (error) {
    alert('Error: ' + error.message);
  } finally {
    btn.disabled = false;
    btn.textContent = originalText;
  }
});

document.getElementById('optionsLink')?.addEventListener('click', (e) => {
  e.preventDefault();
  // Navigate to options page in current window
  window.location.href = chrome.runtime.getURL('options.html');
});

document.getElementById('helpLink')?.addEventListener('click', (e) => {
  e.preventDefault();
  alert(`LPH Password Manager Help

• Save passwords automatically when you log in
• Use the popup to autofill saved passwords
• Keep your recovery phrase safe - it's the only way to recover your account
• Your data is encrypted end-to-end`);
});

// Initialize on load
init();
