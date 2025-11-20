// ======================================================
// 🔐 LPH Password Manager - Share Passwords Page
// ======================================================

let currentPasswordVisible = null;

// Tab switching
document.querySelectorAll('.tab').forEach(tab => {
  tab.addEventListener('click', () => {
    const targetTab = tab.dataset.tab;

    // Update tab visuals
    document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
    tab.classList.add('active');

    // Show/hide tab content
    document.querySelectorAll('.tab-content').forEach(content => {
      content.classList.remove('active');
    });
    document.getElementById(`${targetTab}Tab`).classList.add('active');

    // Clear messages
    clearMessages();

    // Load data for the active tab
    if (targetTab === 'send') {
      loadPasswordsForSharing();
    } else if (targetTab === 'receive') {
      loadReceivedPasswords();
    }
  });
});

// Back button
document.getElementById('backBtn').addEventListener('click', () => {
  window.location.href = chrome.runtime.getURL('popup.html');
});

// Message helpers
function showMessage(tabId, text, type = 'error') {
  const msgEl = document.getElementById(`${tabId}Message`);
  if (!msgEl) return;
  msgEl.textContent = text;
  msgEl.className = `message ${type}`;
  msgEl.style.display = 'block';
}

function clearMessages() {
  document.querySelectorAll('.message').forEach(el => {
    el.style.display = 'none';
    el.textContent = '';
  });
}

// ===== SEND TAB =====

async function loadPasswordsForSharing() {
  try {
    const response = await chrome.runtime.sendMessage({ type: 'PM_GET_ALL' });
    
    if (!response.ok || !response.data) {
      showMessage('send', 'Failed to load passwords', 'error');
      return;
    }

    const select = document.getElementById('passwordSelect');
    select.innerHTML = '<option value="">-- Select a password --</option>';

    // Flatten all passwords from all domains
    for (const [domain, credentials] of Object.entries(response.data)) {
      for (const cred of credentials) {
        const option = document.createElement('option');
        option.value = JSON.stringify({ domain, username: cred.username, password: cred.password });
        option.textContent = `${domain} - ${cred.username}`;
        select.appendChild(option);
      }
    }

    if (select.options.length === 1) {
      showMessage('send', 'No passwords available to share. Save some passwords first.', 'error');
    }
  } catch (error) {
    console.error('Load passwords error:', error);
    showMessage('send', 'Failed to load passwords', 'error');
  }
}

document.getElementById('sendForm').addEventListener('submit', async (e) => {
  e.preventDefault();
  clearMessages();

  const recipientEmail = document.getElementById('recipientEmail').value.trim();
  const passwordData = document.getElementById('passwordSelect').value;
  const btn = document.getElementById('sendBtn');

  if (!recipientEmail || !passwordData) {
    showMessage('send', 'Please fill in all fields', 'error');
    return;
  }

  btn.disabled = true;
  btn.textContent = 'Sending...';

  try {
    const credential = JSON.parse(passwordData);
    
    const response = await chrome.runtime.sendMessage({
      type: 'PM_SHARE_PASSWORD',
      toEmail: recipientEmail,
      credential: credential
    });

    if (response.ok) {
      showMessage('send', '✅ Password shared successfully!', 'success');
      document.getElementById('sendForm').reset();
    } else {
      throw new Error(response.error || 'Failed to share password');
    }
  } catch (error) {
    console.error('Share password error:', error);
    showMessage('send', error.message, 'error');
  } finally {
    btn.disabled = false;
    btn.textContent = 'Send Password';
  }
});

// ===== RECEIVE TAB =====

async function loadReceivedPasswords() {
  const listContainer = document.getElementById('sharedList');
  
  try {
    const response = await chrome.runtime.sendMessage({ type: 'PM_GET_SHARED' });
    
    if (!response.ok || !response.shared) {
      listContainer.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon">❌</div>
          <div>Failed to load shared passwords</div>
        </div>
      `;
      return;
    }

    if (response.shared.length === 0) {
      listContainer.innerHTML = `
        <div class="empty-state">
          <div class="empty-state-icon">📭</div>
          <div>No shared passwords yet</div>
          <div style="font-size: 12px; margin-top: 8px; color: #999;">
            Passwords shared with you will appear here
          </div>
        </div>
      `;
      return;
    }

    listContainer.innerHTML = '';

    for (const item of response.shared) {
      const sharedItem = document.createElement('div');
      sharedItem.className = 'shared-item';
      sharedItem.dataset.id = item.id;
      // Store the encrypted data as-is (it's already a base64 string)
      sharedItem.dataset.encrypted = item.encryptedData;

      const date = new Date(item.created_at).toLocaleString();

      // Build DOM safely without innerHTML
      const header = document.createElement('div');
      header.className = 'shared-header';
      
      const fromDiv = document.createElement('div');
      fromDiv.className = 'shared-from';
      fromDiv.textContent = 'From: ' + item.from_email;
      
      const dateDiv = document.createElement('div');
      dateDiv.className = 'shared-date';
      dateDiv.textContent = date;
      
      header.appendChild(fromDiv);
      header.appendChild(dateDiv);
      
      const credDiv = document.createElement('div');
      credDiv.className = 'shared-credential';
      
      ['domain', 'username', 'password'].forEach(field => {
        const row = document.createElement('div');
        row.className = 'credential-row';
        
        const label = document.createElement('span');
        label.className = 'credential-label';
        label.textContent = field.charAt(0).toUpperCase() + field.slice(1) + ':';
        
        const value = document.createElement('span');
        value.className = 'credential-value';
        value.dataset.field = field;
        value.textContent = '••••••••';
        
        row.appendChild(label);
        row.appendChild(value);
        credDiv.appendChild(row);
      });
      
      const actionsDiv = document.createElement('div');
      actionsDiv.className = 'shared-actions';
      
      const decryptBtn = document.createElement('button');
      decryptBtn.className = 'btn btn-show btn-decrypt';
      decryptBtn.textContent = 'Decrypt & Show';
      
      const addBtn = document.createElement('button');
      addBtn.className = 'btn btn-add btn-add-to-vault';
      addBtn.textContent = 'Add to My Vault';
      addBtn.style.display = 'none';
      
      const deleteBtn = document.createElement('button');
      deleteBtn.className = 'btn btn-delete btn-delete-shared';
      deleteBtn.textContent = '🗑️ Delete';
      deleteBtn.style.background = '#dc3545';
      deleteBtn.style.color = 'white';
      
      actionsDiv.appendChild(decryptBtn);
      actionsDiv.appendChild(addBtn);
      actionsDiv.appendChild(deleteBtn);
      
      sharedItem.appendChild(header);
      sharedItem.appendChild(credDiv);
      sharedItem.appendChild(actionsDiv);
      
      listContainer.appendChild(sharedItem);
    }

    // Attach event listeners
    attachReceivedPasswordListeners();
  } catch (error) {
    console.error('Load received passwords error:', error);
    listContainer.innerHTML = `
      <div class="empty-state">
        <div class="empty-state-icon">❌</div>
        <div>Error loading shared passwords</div>
      </div>
    `;
  }
}

function attachReceivedPasswordListeners() {
  // Decrypt buttons
  document.querySelectorAll('.btn-decrypt').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      const sharedItem = e.target.closest('.shared-item');
      // encryptedData is already a base64 string
      const encryptedData = sharedItem.dataset.encrypted;
      
      btn.disabled = true;
      btn.textContent = 'Decrypting...';

      try {
        const response = await chrome.runtime.sendMessage({
          type: 'PM_DECRYPT_SHARED',
          encryptedData: encryptedData
        });

        if (response.ok && response.credential) {
          // Display decrypted data
          const cred = response.credential;
          sharedItem.querySelector('[data-field="domain"]').textContent = cred.domain;
          sharedItem.querySelector('[data-field="username"]').textContent = cred.username;
          sharedItem.querySelector('[data-field="password"]').textContent = cred.password;

          // Store decrypted data for adding to vault
          sharedItem.dataset.decrypted = JSON.stringify(cred);

          // Show "Add to Vault" button
          sharedItem.querySelector('.btn-add-to-vault').style.display = 'inline-block';
          btn.style.display = 'none';
        } else {
          throw new Error(response.error || 'Failed to decrypt');
        }
      } catch (error) {
        console.error('Decrypt error:', error);
        showMessage('receive', error.message, 'error');
        btn.disabled = true;
        btn.textContent = '❌ Failed';
      }
    });
  });

  // Add to vault buttons
  document.querySelectorAll('.btn-add-to-vault').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      const sharedItem = e.target.closest('.shared-item');
      const credential = JSON.parse(sharedItem.dataset.decrypted);
      
      btn.disabled = true;
      btn.textContent = 'Adding...';

      try {
        const url = `https://${credential.domain}`;
        const response = await chrome.runtime.sendMessage({
          type: 'PM_SAVE_CREDENTIALS',
          url: url,
          username: credential.username,
          password: credential.password
        });

        if (response.ok) {
          btn.textContent = '✓ Added';
          showMessage('receive', '✅ Password added to your vault!', 'success');
          
          // Optionally remove the shared item after adding
          setTimeout(() => {
            sharedItem.style.opacity = '0.5';
          }, 1000);
        } else {
          throw new Error(response.error || 'Failed to save');
        }
      } catch (error) {
        console.error('Add to vault error:', error);
        showMessage('receive', error.message, 'error');
        btn.disabled = false;
        btn.textContent = 'Add to My Vault';
      }
    });
  });

  // Delete buttons
  document.querySelectorAll('.btn-delete-shared').forEach(btn => {
    btn.addEventListener('click', async (e) => {
      const sharedItem = e.target.closest('.shared-item');
      const shareId = sharedItem.dataset.id;
      
      if (!confirm('Delete this shared password? This cannot be undone.')) {
        return;
      }
      
      btn.disabled = true;
      btn.textContent = 'Deleting...';

      try {
        const response = await chrome.runtime.sendMessage({
          type: 'PM_DELETE_SHARED',
          shareId: shareId
        });

        if (response.ok) {
          showMessage('receive', '✅ Shared password deleted!', 'success');
          // Remove from UI
          sharedItem.style.transition = 'opacity 0.3s';
          sharedItem.style.opacity = '0';
          setTimeout(() => {
            sharedItem.remove();
            // Check if list is empty
            const remaining = document.querySelectorAll('.shared-item').length;
            if (remaining === 0) {
              document.getElementById('sharedList').innerHTML = `
                <div class="empty-state">
                  <div class="empty-state-icon">📭</div>
                  <div>No shared passwords</div>
                  <div style="font-size: 12px; margin-top: 8px; color: #999;">
                    Passwords shared with you will appear here
                  </div>
                </div>
              `;
            }
          }, 300);
        } else {
          throw new Error(response.error || 'Failed to delete');
        }
      } catch (error) {
        console.error('Delete shared password error:', error);
        showMessage('receive', error.message, 'error');
        btn.disabled = false;
        btn.textContent = '🗑️ Delete';
      }
    });
  });
}

// Initialize
(async () => {
  await loadPasswordsForSharing();
})();
