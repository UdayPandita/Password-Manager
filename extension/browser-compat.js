// ======================================================
// Browser Compatibility Layer for Electron
// Handles differences between Chrome and Electron environments
// ======================================================

// Detect if we're running in Electron's extension context
const isElectron = typeof process !== 'undefined' && process.versions && !!process.versions.electron;

/**
 * Open a page (handles both Chrome tabs and Electron navigation)
 * @param {string} url - URL to open (can be chrome-extension:// URL or full path)
 */
async function openPage(url) {
  try {
    // If it's an extension URL, get the full URL
    const fullUrl = url.startsWith('chrome-extension://') ? url : chrome.runtime.getURL(url);
    
    if (isElectron) {
      // In Electron, we'll open in a new window or navigate the current page
      // For auth/settings pages, just navigate the current page
      if (url.includes('auth.html') || 
          url.includes('add.html') || 
          url.includes('view.html') || 
          url.includes('options.html') ||
          url.includes('mnemonic-display.html') ||
          url.includes('mnemonic-verify.html') ||
          url.includes('signup-complete.html') ||
          url.includes('recover.html')) {
        window.location.href = fullUrl;
      } else {
        // For other URLs, try to navigate the main browser view
        window.open(fullUrl, '_blank');
      }
    } else {
      // In Chrome, use tabs API
      await chrome.tabs.create({ url: fullUrl });
    }
  } catch (error) {
    console.error('Failed to open page:', error);
    // Fallback: just navigate
    window.location.href = url;
  }
}

/**
 * Close current window/popup
 */
function closeWindow() {
  try {
    if (isElectron) {
      // In Electron popup, try to close via window
      if (window.opener) {
        window.close();
      } else {
        // If no opener, navigate back to a safe page
        window.location.href = chrome.runtime.getURL('popup.html');
      }
    } else {
      // In Chrome, window.close() works for popups
      window.close();
    }
  } catch (error) {
    console.error('Failed to close window:', error);
  }
}

/**
 * Get active tab (works in both Chrome and Electron)
 */
async function getActiveTab() {
  try {
    if (typeof chrome !== 'undefined' && chrome.tabs) {
      const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
      return tab;
    }
    return null;
  } catch (error) {
    console.error('Failed to get active tab:', error);
    return null;
  }
}

/**
 * Send message to content script in active tab
 */
async function sendToContentScript(message) {
  try {
    const tab = await getActiveTab();
    if (tab && tab.id) {
      return await chrome.tabs.sendMessage(tab.id, message);
    }
    throw new Error('No active tab found');
  } catch (error) {
    console.error('Failed to send message to content script:', error);
    throw error;
  }
}

// Export for use in other scripts
if (typeof window !== 'undefined') {
  window.BrowserCompat = {
    isElectron,
    openPage,
    closeWindow,
    getActiveTab,
    sendToContentScript
  };
}
