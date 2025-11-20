// ======================================================
// 🔐 LPH Password Manager - View All Passwords Page
// ======================================================

// ---------- Fetch All Saved Credentials ----------
async function getAllCredentials() {
  try {
    return await chrome.runtime.sendMessage({ type: 'PM_GET_ALL' });
  } catch (error) {
    console.error('Failed to get all credentials:', error);
    return { ok: false, data: {} };
  }
}

// ---------- Delete a Credential ----------
async function deleteCredential(url, username) {
  try {
    return await chrome.runtime.sendMessage({
      type: 'PM_DELETE_CREDENTIAL',
      url,
      username,
    });
  } catch (error) {
    console.error('Failed to delete credential:', error);
    return { ok: false, error: error.message };
  }
}

// ---------- Copy to Clipboard ----------
async function copyToClipboard(text) {
  try {
    await navigator.clipboard.writeText(text);
    return true;
  } catch (error) {
    console.error('Copy failed:', error);
    return false;
  }
}

// ---------- Get Icon from Domain ----------
function getIcon(domain) {
  const d = domain.toLowerCase();
  if (d.includes('google')) return '🔎';
  if (d.includes('facebook')) return '📘';
  if (d.includes('amazon')) return '🅰️';
  if (d.includes('instagram')) return '📸';
  if (d.includes('netflix')) return '🎬';
  if (d.includes('discord')) return '💬';
  return domain[0]?.toUpperCase() || '🔐';
}

// ---------- Get Favicon URL ----------
function getFaviconUrl(domain) {
  if (!domain) return null;
  return `https://www.google.com/s2/favicons?domain=${domain}&sz=64`;
}

// ---------- Render All Credentials ----------
async function renderAll(query = '') {
  const grid = document.getElementById('grid');
  const emptyState = document.getElementById('emptyState');

  const response = await getAllCredentials();
  if (!response.ok || !response.data) {
    grid.innerHTML = '<p style="color:red;">Error loading passwords.</p>';
    return;
  }

  let data = Object.entries(response.data);

  // Filter based on search query
  if (query) {
    query = query.toLowerCase();
    data = data.filter(([domain, creds]) =>
      domain.toLowerCase().includes(query) ||
      creds.some((c) => c.username.toLowerCase().includes(query))
    );
  }

  if (data.length === 0) {
    grid.innerHTML = '';
    emptyState.style.display = 'block';
    return;
  }

  emptyState.style.display = 'none';
  grid.innerHTML = '';

  // Render each domain as a card
  for (const [domain, creds] of data) {
    const card = document.createElement('div');
    card.className = 'card';

    const faviconUrl = getFaviconUrl(domain);
    const fallbackIcon = getIcon(domain);

    const header = document.createElement('div');
    header.className = 'card-header';
    
    const iconDiv = document.createElement('div');
    iconDiv.className = 'card-icon';
    if (faviconUrl) {
      const img = document.createElement('img');
      img.src = faviconUrl;
      img.alt = domain;
      img.style.width = '100%';
      img.style.height = '100%';
      img.style.objectFit = 'cover';
      img.onerror = function() { this.style.display='none'; this.parentElement.textContent=fallbackIcon; };
      iconDiv.appendChild(img);
    } else {
      iconDiv.textContent = fallbackIcon;
    }
    
    const titleDiv = document.createElement('div');
    titleDiv.className = 'card-title';
    titleDiv.textContent = domain;
    
    header.appendChild(iconDiv);
    header.appendChild(titleDiv);
    card.appendChild(header);
    
    const body = document.createElement('div');
    body.className = 'card-body';
    
    creds.forEach((cred) => {
      const item = document.createElement('div');
      item.className = 'credential-item';
      
      const infoDiv = document.createElement('div');
      infoDiv.className = 'credential-info';
      
      const usernameDiv = document.createElement('div');
      usernameDiv.className = 'credential-username';
      usernameDiv.textContent = cred.username;
      
      const passwordDiv = document.createElement('div');
      passwordDiv.className = 'credential-password';
      passwordDiv.textContent = '••••••••';
      
      infoDiv.appendChild(usernameDiv);
      infoDiv.appendChild(passwordDiv);
      
      const actionsDiv = document.createElement('div');
      actionsDiv.className = 'credential-actions';
      
      const copyBtn = document.createElement('button');
      copyBtn.className = 'copy-btn';
      copyBtn.textContent = 'Copy';
      copyBtn.dataset.password = cred.password;
      
      const deleteBtn = document.createElement('button');
      deleteBtn.className = 'delete-btn';
      deleteBtn.textContent = '×';
      deleteBtn.dataset.domain = domain;
      deleteBtn.dataset.username = cred.username;
      
      actionsDiv.appendChild(copyBtn);
      actionsDiv.appendChild(deleteBtn);
      
      item.appendChild(infoDiv);
      item.appendChild(actionsDiv);
      body.appendChild(item);
    });
    
    card.appendChild(body);
    grid.appendChild(card);
  }

  // Add event listeners for copy buttons
  document.querySelectorAll('.copy-btn').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const success = await copyToClipboard(btn.dataset.password);
      if (success) {
        btn.textContent = '✓ Copied';
        setTimeout(() => (btn.textContent = 'Copy'), 1500);
      }
    });
  });

  // Add event listeners for delete buttons
  document.querySelectorAll('.delete-btn').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const { domain, username } = btn.dataset;
      if (confirm(`Delete credentials for ${username} on ${domain}?`)) {
        const url = `https://${domain}`;
        await deleteCredential(url, username);
        await renderAll(query);
      }
    });
  });

    grid.appendChild(card);
  }
}

// ---------- Escape HTML ----------
function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// ---------- Initialize ----------
async function init() {
  await renderAll();

  const searchInput = document.getElementById('searchInput');
  searchInput.addEventListener('input', async (e) => {
    const q = e.target.value.trim().toLowerCase();
    await renderAll(q);
  });
  
  // Add back button handler
  const backBtn = document.getElementById('backBtn');
  if (backBtn) {
    backBtn.addEventListener('click', () => {
      window.location.href = chrome.runtime.getURL('popup.html');
    });
  }
}

init();
