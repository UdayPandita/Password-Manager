(async () => {
  const phraseGrid = document.getElementById('phraseGrid');
  const savedBtn = document.getElementById('savedBtn');
  const copyBtn = document.getElementById('copyBtn');

  try {
    const resp = await chrome.runtime.sendMessage({ type: 'PM_GET_MNEMONIC' });

    if (!resp.ok || !resp.mnemonic) {
      phraseGrid.innerHTML = `
        <div style="color:#c00;text-align:center;">
          ⚠️ Error: No recovery phrase found.<br>
          Please restart the signup process.
        </div>`;
      savedBtn.disabled = true;
      return;
    }

    const words = resp.mnemonic.trim().split(/\s+/);
    phraseGrid.innerHTML = '';

    words.forEach((word, index) => {
      const wordEl = document.createElement('div');
      wordEl.className = 'phrase-word';
      
      const span = document.createElement('span');
      span.textContent = index + 1;
      wordEl.appendChild(span);
      
      const textNode = document.createTextNode(word);
      wordEl.appendChild(textNode);
      
      phraseGrid.appendChild(wordEl);
    });

    copyBtn.style.display = 'block';

    setTimeout(() => {
      savedBtn.disabled = false;
    }, 3000);

    copyBtn.addEventListener('click', async () => {
      try {
        await navigator.clipboard.writeText(words.join(' '));
        copyBtn.textContent = '✅ Copied!';
        copyBtn.style.background = '#28a745';
        setTimeout(() => {
          copyBtn.textContent = '📋 Copy to Clipboard';
          copyBtn.style.background = '#6c757d';
        }, 2000);
      } catch {
        alert('Failed to copy. Please copy manually.');
      }
    });

  } catch (e) {
    phraseGrid.innerHTML = `
      <div style="color:#c00;text-align:center;">
        ❌ Error generating recovery phrase. Please try again.
      </div>`;
    savedBtn.disabled = true;
  }

  savedBtn.addEventListener('click', () => {
    window.location.href = chrome.runtime.getURL('mnemonic-verify.html');
  });

  // Back button handler
  const backBtn = document.getElementById('backBtn');
  backBtn.addEventListener('click', () => {
    if (confirm('Going back will restart the signup process. Are you sure?')) {
      window.location.href = chrome.runtime.getURL('auth.html');
    }
  });
})();
