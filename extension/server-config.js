// Server config for remote VM integration
export const API_CONFIG = {
  // When true, background.js will attempt to sync the encrypted vault
  // to a remote API. Now enabled for backend authentication and sync.
  useRemote: true,

  // Base URL of your VM API (see backend.md). Update this to your backend URL.
  // VM backend running on 192.168.2.242:3000
  // WARNING: Use HTTPS in production! HTTP is insecure for sensitive data.
  baseUrl: 'http://192.168.2.242:3000', // TODO: Change to HTTPS for production
};

// NOTE: Token management is handled at runtime and stored in chrome.storage.local
// under the key 'pm_remote_token'. To enable remote sync set `useRemote: true`
// here or toggle it at runtime and store a valid JWT token via messages.
