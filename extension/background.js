
import { API_CONFIG } from './server-config.js';

let session = {
  user: null,
  kVault: null,
  salt: null,
  unlocked: false
};

// Promise that resolves once the background has attempted to restore session
let restoreReady = null;
const STORAGE_KEYS = {
  USER_EMAIL: 'pm_user_email',
  ENCRYPTED_KVAULT: 'pm_encrypted_kvault',
  SALT: 'pm_salt',
  VAULT_DATA: 'pm_vault_data',
  VERIFIER: 'pm_verifier',
  TEMP_SIGNUP: 'pm_temp_signup',
  TEMP_MNEMONIC: 'pm_temp_mnemonic',
  REMOTE_TOKEN: 'pm_remote_token',
  ENCRYPTED_PRIVATE_KEY: 'pm_encrypted_private_key',
  PUBLIC_KEY: 'pm_public_key',
  SESSION_STATE: 'pm_session_state',
};

const BIP39_WORDLIST = [
  'abandon','ability','able','about','above','absent','absorb','abstract','absurd','abuse',
  'access','accident','account','accuse','achieve','acid','acoustic','acquire','across','act',
  'action','actor','actress','actual','adapt','add','addict','address','adjust','admit',
  'adult','advance','advice','aerobic','afford','afraid','again','age','agent','agree',
  'ahead','aim','air','airport','aisle','alarm','album','alcohol','alert','alien',
  'all','alley','allow','almost','alone','alpha','already','also','alter','always',
  'amateur','amazing','among','amount','amused','analyst','anchor','ancient','anger','angle',
  'angry','animal','ankle','announce','annual','another','answer','antenna','antique','anxiety',
  'any','apart','apology','appear','apple','approve','april','arch','arctic','area',
  'arena','argue','arm','armed','armor','army','around','arrange','arrest','arrive',
  'arrow','art','artefact','artist','artwork','ask','aspect','assault','asset','assist',
  'assume','asthma','athlete','atom','attack','attend','attitude','attract','auction','audit',
  'august','aunt','author','auto','autumn','average','avocado','avoid','awake','aware',
  'away','awesome','awful','awkward','axis','baby','bachelor','bacon','badge','bag',
  'balance','balcony','ball','bamboo','banana','banner','bar','barely','bargain','barrel',
  'base','basic','basket','battle','beach','bean','beauty','because','become','beef',
  'before','begin','behave','behind','believe','below','belt','bench','benefit','best',
  'betray','better','between','beyond','bicycle','bid','bike','bind','biology','bird',
  'birth','bitter','black','blade','blame','blanket','blast','bleak','bless','blind',
  'blood','blossom','blouse','blue','blur','blush','board','boat','body','boil',
  'bomb','bone','bonus','book','boost','border','boring','borrow','boss','bottom',
  'bounce','box','boy','bracket','brain','brand','brass','brave','bread','breeze',
  'brick','bridge','brief','bright','bring','brisk','broccoli','broken','bronze','broom',
  'brother','brown','brush','bubble','buddy','budget','buffalo','build','bulb','bulk',
  'bullet','bundle','bunker','burden','burger','burst','bus','business','busy','butter',
  'buyer','buzz','cabbage','cabin','cable','cactus','cage','cake','call','calm',
  'camera','camp','can','canal','cancel','candy','cannon','canoe','canvas','canyon',
  'capable','capital','captain','car','carbon','card','cargo','carpet','carry','cart',
  'case','cash','casino','castle','casual','cat','catalog','catch','category','cattle',
  'caught','cause','caution','cave','ceiling','celery','cement','census','century','cereal',
  'certain','chair','chalk','champion','change','chaos','chapter','charge','chase','chat',
  'cheap','check','cheese','chef','cherry','chest','chicken','chief','child','chimney',
  'choice','choose','chronic','chuckle','chunk','churn','cigar','cinnamon','circle','citizen',
  'city','civil','claim','clap','clarify','claw','clay','clean','clerk','clever',
  'click','client','cliff','climb','clinic','clip','clock','clog','close','cloth',
  'cloud','clown','club','clump','cluster','clutch','coach','coast','coconut','code',
  'coffee','coil','coin','collect','color','column','combine','come','comfort','comic',
  'common','company','concert','conduct','confirm','congress','connect','consider','control','convince',
  'cook','cool','copper','copy','coral','core','corn','correct','cost','cotton',
];

async function generateMnemonic() {
  const entropy = new Uint8Array(11);
  crypto.getRandomValues(entropy);
  
  const hashBuffer = await crypto.subtle.digest('SHA-256', entropy);
  const hashArray = new Uint8Array(hashBuffer);
  const checksum = hashArray[0]; 
  const indices = [...entropy, checksum];
  const words = indices.map(index => BIP39_WORDLIST[index]);
  
  return words.join(' ');
}

async function validateMnemonic(mnemonic) {
  const words = mnemonic.trim().split(/\s+/);
  if (words.length !== 12) return false;
  
  const indices = [];
  for (const word of words) {
    const index = BIP39_WORDLIST.indexOf(word);
    if (index === -1) return false; 
    indices.push(index);
  }
  
  const entropy = new Uint8Array(indices.slice(0, 11));
  const checksum = indices[11];
  
  const hashBuffer = await crypto.subtle.digest('SHA-256', entropy);
  const hashArray = new Uint8Array(hashBuffer);
  
  return hashArray[0] === checksum;
}

async function mnemonicToSeed(mnemonic, passphrase = '') {
  const enc = new TextEncoder();
  const mnemonicBytes = enc.encode(mnemonic.normalize('NFKD'));
  const salt = enc.encode('mnemonic' + passphrase.normalize('NFKD'));
  
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    mnemonicBytes,
    'PBKDF2',
    false,
    ['deriveBits']
  );
  
  const bits = await crypto.subtle.deriveBits(
    {
      name: 'PBKDF2',
      salt: salt,
      iterations: 2048,
      hash: 'SHA-512'
    },
    keyMaterial,
    512
  );
  
  return new Uint8Array(bits);
}

async function computeMnemonicFingerprint(seed) {
  const hashBuffer = await crypto.subtle.digest('SHA-256', seed);
  return bytesToBase64(new Uint8Array(hashBuffer));
}

async function deriveVaultKey(seed) {
  return await crypto.subtle.importKey(
    'raw',
    seed.slice(0, 32),
    { name: 'AES-GCM', length: 256 },
    true,
    ['encrypt', 'decrypt']
  );
}

async function deriveMasterPasswordKey(masterPassword, salt) {
  return deriveMasterPasswordKeyWithIterations(masterPassword, salt, 200000);
}

async function deriveMasterPasswordKeyWithIterations(masterPassword, salt, iterations = 200000) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    enc.encode(masterPassword),
    'PBKDF2',
    false,
    ['deriveKey']
  );
  
  return await crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt,
      iterations,
      hash: 'SHA-256'
    },
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function generateKeyPair() {
  return await crypto.subtle.generateKey(
    {
      name: 'RSA-OAEP',
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: 'SHA-256'
    },
    true,
    ['encrypt', 'decrypt']
  );
}

async function encryptData(data, key) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const enc = new TextEncoder();
  const encoded = enc.encode(JSON.stringify(data));
  
  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv },
    key,
    encoded
  );
  
  const combined = new Uint8Array(iv.length + ciphertext.byteLength);
  combined.set(iv, 0);
  combined.set(new Uint8Array(ciphertext), iv.length);
  
  return bytesToBase64(combined);
}

async function decryptData(base64Data, key) {
  const combined = base64ToBytes(base64Data);
  const iv = combined.slice(0, 12);
  const ciphertext = combined.slice(12);
  
  const decrypted = await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv },
    key,
    ciphertext
  );
  
  const dec = new TextDecoder();
  return JSON.parse(dec.decode(decrypted));
}

function bytesToBase64(bytes) {
  let binary = '';
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToBytes(base64) {
  if (!base64 || typeof base64 !== 'string') {
    throw new Error('Invalid base64 input: must be a non-empty string');
  }
  
  const cleaned = base64.trim();
  if (cleaned === '') {
    throw new Error('Invalid base64 input: empty string');
  }
  
  try {
    const binary = atob(cleaned);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  } catch (e) {
    console.error('base64ToBytes error:', e, 'Input:', base64?.substring(0, 50));
    throw new Error(`Failed to decode base64: ${e.message}`);
  }
}


async function saveSession() {
  const sessionData = {
    [STORAGE_KEYS.USER_EMAIL]: session.user?.email,
  };
  
  if (session.unlocked && session.kVault) {
    try {
      const kVaultData = await crypto.subtle.exportKey('raw', session.kVault);
      const saltBase64 = session.salt ? bytesToBase64(session.salt) : null;
      
      sessionData[STORAGE_KEYS.SESSION_STATE] = {
        unlocked: true,
        kVaultExport: bytesToBase64(new Uint8Array(kVaultData)),
        saltBase64: saltBase64
      };
    } catch (e) {
      console.error('Failed to export session state:', e);
    }
  } else {
    sessionData[STORAGE_KEYS.SESSION_STATE] = null;
  }
  
  await chrome.storage.local.set(sessionData);
}

async function restoreSession() {
  const stored = await chrome.storage.local.get([
    STORAGE_KEYS.USER_EMAIL,
    STORAGE_KEYS.SESSION_STATE,
  ]);
  
  if (stored[STORAGE_KEYS.USER_EMAIL]) {
    session.user = { email: stored[STORAGE_KEYS.USER_EMAIL] };
    
    // Don't restore unlocked state on browser restart - always start locked
    // but keep user signed in so they just need to unlock with password
    session.unlocked = false;
    session.kVault = null;
    session.salt = null;
    
    // Clear any persisted session state to avoid confusion
    await chrome.storage.local.set({
      [STORAGE_KEYS.SESSION_STATE]: null
    });
    
    return true;
  }
  
  return false;
}

async function clearSession() {
  await chrome.storage.local.remove([
    STORAGE_KEYS.USER_EMAIL,
    STORAGE_KEYS.REMOTE_TOKEN,
    STORAGE_KEYS.TEMP_SIGNUP,
    STORAGE_KEYS.TEMP_MNEMONIC,
    STORAGE_KEYS.SESSION_STATE,
  ]);
  
  session = {
    user: null,
    kVault: null,
    salt: null,
    unlocked: false
  };
}


async function initiateSignup(email, password) {
  try {
    const mnemonic = await generateMnemonic();
    
    const seed = await mnemonicToSeed(mnemonic);
    const kVault = await deriveVaultKey(seed);
    
    const mnemonicFingerprint = await computeMnemonicFingerprint(seed);
    
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const saltBase64 = bytesToBase64(salt);
    
    const kMP = await deriveMasterPasswordKey(password, salt);
    
    const kVaultData = await crypto.subtle.exportKey('raw', kVault);
    const encryptedKVault = await encryptData(
      { key: bytesToBase64(new Uint8Array(kVaultData)) },
      kMP
    );
    
    const verifier = await encryptData({ v: 'ok' }, kMP);
    
    const keyPair = await generateKeyPair();
    
    const publicKeyBuffer = await crypto.subtle.exportKey('spki', keyPair.publicKey);
    const publicKeyBase64 = bytesToBase64(new Uint8Array(publicKeyBuffer));
    
    const privateKeyBuffer = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
    const privateKeyBase64 = bytesToBase64(new Uint8Array(privateKeyBuffer));
    const encryptedPrivateKey = await encryptData({ key: privateKeyBase64 }, kVault);
    
    await chrome.storage.local.set({
      [STORAGE_KEYS.TEMP_SIGNUP]: {
        email,
        password,
        encryptedKVault,
        saltBase64,
        verifier,
        publicKeyBase64,
        encryptedPrivateKey,
        mnemonicFingerprint
      },
      [STORAGE_KEYS.TEMP_MNEMONIC]: mnemonic,
    });
    
    return { ok: true, mnemonic };
  } catch (error) {
    return { ok: false, error: error.message };
  }
}

async function completeSignup(mnemonic, password) {
  try {
    const stored = await chrome.storage.local.get([
      STORAGE_KEYS.TEMP_SIGNUP,
      STORAGE_KEYS.TEMP_MNEMONIC,
    ]);
    
    if (!stored[STORAGE_KEYS.TEMP_SIGNUP] || !stored[STORAGE_KEYS.TEMP_MNEMONIC]) {
      throw new Error('No signup in progress');
    }
    
    if (mnemonic.trim() !== stored[STORAGE_KEYS.TEMP_MNEMONIC]) {
      throw new Error('Mnemonic does not match');
    }
    
    const {
      email,
      password: storedPassword,
      encryptedKVault,
      saltBase64,
      verifier,
      publicKeyBase64,
      encryptedPrivateKey,
      mnemonicFingerprint
    } = stored[STORAGE_KEYS.TEMP_SIGNUP];
    
    const finalPassword = password || storedPassword;
    if (!finalPassword) {
      throw new Error('Password required for signup completion');
    }
    
    const seed = await mnemonicToSeed(mnemonic);
    const kVault = await deriveVaultKey(seed);
    const salt = base64ToBytes(saltBase64);
    
    if (!API_CONFIG?.baseUrl) {
      throw new Error('Backend API URL not configured in server-config.js');
    }

    try {
      const signupResp = await fetch(`${API_CONFIG.baseUrl.replace(/\/$/, '')}/api/auth/signup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          email,
          password: finalPassword,
          publicKey: publicKeyBase64,
          encryptedKVault: encryptedKVault,
          kvaultSalt: saltBase64,
          verifier: verifier,
          mnemonicFingerprint: mnemonicFingerprint,
          encryptedPrivateKey: encryptedPrivateKey
        })
      });

      if (!signupResp.ok) {
        const errorText = await signupResp.text();
        throw new Error(`Backend signup failed: ${signupResp.status} ${errorText}`);
      }

      const signupData = await signupResp.json();
      
      if (!signupData.ok || !signupData.token) {
        throw new Error(signupData.error || 'Backend signup failed');
      }

      await chrome.storage.local.set({
        [STORAGE_KEYS.USER_EMAIL]: email,
        [STORAGE_KEYS.ENCRYPTED_KVAULT]: encryptedKVault,
        [STORAGE_KEYS.SALT]: saltBase64,
        [STORAGE_KEYS.VERIFIER]: verifier,
        [STORAGE_KEYS.VAULT_DATA]: null,
        [STORAGE_KEYS.ENCRYPTED_PRIVATE_KEY]: encryptedPrivateKey,
        [STORAGE_KEYS.PUBLIC_KEY]: publicKeyBase64,
        [STORAGE_KEYS.REMOTE_TOKEN]: signupData.token
      });
      
      session.user = { email };
      session.kVault = kVault;
      session.salt = salt;
      session.unlocked = true;
      
      await saveSession();
    } catch (backendError) {
      console.error('Backend registration failed:', backendError);
      throw new Error(`Failed to register with backend: ${backendError.message}`);
    }
    
    await chrome.storage.local.remove([
      STORAGE_KEYS.TEMP_SIGNUP,
      STORAGE_KEYS.TEMP_MNEMONIC,
    ]);
    
    return { ok: true, user: session.user }
  } catch (error) {
    console.error('Complete signup error:', error);
    return { ok: false, error: error.message };
  }
}

async function signIn(email, password) {
  try {
    if (!API_CONFIG?.baseUrl) {
      return { ok: false, error: 'Backend API URL not configured in server-config.js' };
    }

    let token;
    try {
      const signinResp = await fetch(`${API_CONFIG.baseUrl.replace(/\/$/, '')}/api/auth/signin`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });

      if (!signinResp.ok) {
        const errorText = await signinResp.text();
        if (signinResp.status === 401) {
          return { ok: false, error: 'Invalid email or password' };
        }
        throw new Error(`Backend signin failed: ${signinResp.status} ${errorText}`);
      }

      const signinData = await signinResp.json();
      
      if (!signinData.ok || !signinData.token) {
        return { ok: false, error: signinData.error || 'Authentication failed' };
      }

      token = signinData.token;


      const existingLocal = await chrome.storage.local.get([
        STORAGE_KEYS.USER_EMAIL
      ]);
      
      const isDifferentUser = existingLocal[STORAGE_KEYS.USER_EMAIL] && 
                              existingLocal[STORAGE_KEYS.USER_EMAIL] !== email;
      
      if (isDifferentUser) {

        await chrome.storage.local.clear();
      }
      
      if (signinData.encryptedKVault && signinData.kvaultSalt && signinData.verifier) {
        const dataToStore = {
          [STORAGE_KEYS.USER_EMAIL]: email,
          [STORAGE_KEYS.ENCRYPTED_KVAULT]: signinData.encryptedKVault,
          [STORAGE_KEYS.SALT]: signinData.kvaultSalt,
          [STORAGE_KEYS.VERIFIER]: signinData.verifier,
          [STORAGE_KEYS.REMOTE_TOKEN]: token
        };
        
        if (signinData.encryptedPrivateKey) {
          dataToStore[STORAGE_KEYS.ENCRYPTED_PRIVATE_KEY] = signinData.encryptedPrivateKey;
        }
        
        if (signinData.publicKey) {
          dataToStore[STORAGE_KEYS.PUBLIC_KEY] = signinData.publicKey;
        }
        
        await chrome.storage.local.set(dataToStore);
      }
    } catch (backendError) {
      console.error('Backend signin failed:', backendError);
      return { ok: false, error: `Failed to authenticate: ${backendError.message}` };
    }

    const stored = await chrome.storage.local.get([
      STORAGE_KEYS.USER_EMAIL,
      STORAGE_KEYS.SALT,
      STORAGE_KEYS.ENCRYPTED_KVAULT,
      STORAGE_KEYS.VERIFIER
    ]);
    
    if (!stored[STORAGE_KEYS.USER_EMAIL] || stored[STORAGE_KEYS.USER_EMAIL] !== email) {
      return { ok: false, error: 'Local account data not found. Please use account recovery with your mnemonic.' };
    }
    
    if (!stored[STORAGE_KEYS.SALT]) {
      return { ok: false, error: 'Account data corrupted (missing salt)' };
    }
    
    const salt = base64ToBytes(stored[STORAGE_KEYS.SALT]);

    let kMP = await deriveMasterPasswordKeyWithIterations(password, salt, 200000);
    let verified = false;

    if (stored[STORAGE_KEYS.VERIFIER]) {
      try {
        const check = await decryptData(stored[STORAGE_KEYS.VERIFIER], kMP);
        if (check && check.v === 'ok') {
          verified = true;
        } else {
          throw new Error('Verifier mismatch');
        }
      } catch (e) {
        const legacyIters = [100000, 50000, 20000, 10000, 5000, 1000, 1];
        for (const it of legacyIters) {
          try {
            const kMPLegacy = await deriveMasterPasswordKeyWithIterations(password, salt, it);
            const checkLegacy = await decryptData(stored[STORAGE_KEYS.VERIFIER], kMPLegacy);
            if (checkLegacy && checkLegacy.v === 'ok') {
              if (!stored[STORAGE_KEYS.ENCRYPTED_KVAULT]) {
                kMP = kMPLegacy;
                verified = true;
                break;
              }
              try {
                const oldKVaultData = await decryptData(stored[STORAGE_KEYS.ENCRYPTED_KVAULT], kMPLegacy);
                const kVaultBytes = base64ToBytes(oldKVaultData.key);
                const importedKVault = await crypto.subtle.importKey(
                  'raw',
                  kVaultBytes,
                  { name: 'AES-GCM', length: 256 },
                  false,
                  ['encrypt', 'decrypt']
                );

                const newSalt = crypto.getRandomValues(new Uint8Array(16));
                const newSaltBase64 = bytesToBase64(newSalt);
                const newKMP = await deriveMasterPasswordKeyWithIterations(password, newSalt, 200000);
                const exportedKVault = await crypto.subtle.exportKey('raw', importedKVault);
                const encryptedKVault = await encryptData({ key: bytesToBase64(new Uint8Array(exportedKVault)) }, newKMP);
                const newVerifier = await encryptData({ v: 'ok' }, newKMP);
                await chrome.storage.local.set({
                  [STORAGE_KEYS.ENCRYPTED_KVAULT]: encryptedKVault,
                  [STORAGE_KEYS.SALT]: newSaltBase64,
                  [STORAGE_KEYS.VERIFIER]: newVerifier
                });

                kMP = newKMP;
                session.salt = newSalt;
                verified = true;
                break;
              } catch (migrateErr) {
              }
            }
          } catch (e2) {}
        }

        if (!verified) {
          return { ok: false, error: 'Invalid password' };
        }
      }
    } else {
      try {
        if (stored[STORAGE_KEYS.ENCRYPTED_KVAULT]) {
          await decryptData(stored[STORAGE_KEYS.ENCRYPTED_KVAULT], kMP);
          verified = true;
        } else {
          return { ok: false, error: 'Verifier missing and vault not present' };
        }
      } catch (e) {
        const legacyIters = [100000, 50000, 20000, 10000, 5000, 1000, 1];
        let migrated = false;
        for (const it of legacyIters) {
          try {
            const kMPLegacy = await deriveMasterPasswordKeyWithIterations(password, salt, it);
            const kVaultData = await decryptData(stored[STORAGE_KEYS.ENCRYPTED_KVAULT], kMPLegacy);
            const kVaultBytes = base64ToBytes(kVaultData.key);
            const importedKVault = await crypto.subtle.importKey('raw', kVaultBytes, { name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);

            const newSalt = crypto.getRandomValues(new Uint8Array(16));
            const newSaltBase64 = bytesToBase64(newSalt);
            const newKMP = await deriveMasterPasswordKeyWithIterations(password, newSalt, 200000);
            const exportedKVault = await crypto.subtle.exportKey('raw', importedKVault);
            const encryptedKVault = await encryptData({ key: bytesToBase64(new Uint8Array(exportedKVault)) }, newKMP);
            const newVerifier = await encryptData({ v: 'ok' }, newKMP);
            await chrome.storage.local.set({
              [STORAGE_KEYS.ENCRYPTED_KVAULT]: encryptedKVault,
              [STORAGE_KEYS.SALT]: newSaltBase64,
              [STORAGE_KEYS.VERIFIER]: newVerifier
            });
            kMP = newKMP;
            session.salt = newSalt;
            migrated = true;
            verified = true;
            break;
          } catch (e3) {
          }
        }
        if (!migrated) return { ok: false, error: 'Invalid password' };
      }
    }
    
    if (!stored[STORAGE_KEYS.ENCRYPTED_KVAULT]) {
      return { ok: false, error: 'Vault key not found. Please recover your account.' };
    }
    
    let kVault;
    try {
      const kVaultData = await decryptData(stored[STORAGE_KEYS.ENCRYPTED_KVAULT], kMP);
      const kVaultBytes = base64ToBytes(kVaultData.key);
      kVault = await crypto.subtle.importKey(
        'raw',
        kVaultBytes,
        { name: 'AES-GCM', length: 256 },
        true,
        ['encrypt', 'decrypt']
      );
    } catch (e) {
      return { ok: false, error: 'Failed to decrypt vault key. Invalid password.' };
    }
    
    session.user = { email: stored[STORAGE_KEYS.USER_EMAIL] };
    session.kVault = kVault;
    session.salt = salt;
    session.unlocked = true;
    
    await saveSession();
    
    try {
      if (API_CONFIG?.useRemote && token) {

        const remoteVaultData = await remoteGetVault(token);
        
        if (remoteVaultData) {
          await chrome.storage.local.set({
            [STORAGE_KEYS.VAULT_DATA]: remoteVaultData
          });

        } else {

        }
      }
    } catch (syncError) {
      console.warn('⚠️ Failed to sync from server (using local cache):', syncError);
    }
    
    return { ok: true, user: session.user };
  } catch (error) {
    return { ok: false, error: error.message };
  }
}

async function recoverAccount(email, mnemonic, newPassword) {
  try {
    if (!email || !email.includes('@')) {
      throw new Error('Valid email address is required');
    }

    const stored = await chrome.storage.local.get([STORAGE_KEYS.USER_EMAIL]);
    if (stored[STORAGE_KEYS.USER_EMAIL] && stored[STORAGE_KEYS.USER_EMAIL] !== email) {
      throw new Error(`Cannot recover - a different account (${stored[STORAGE_KEYS.USER_EMAIL]}) is stored locally. Please sign out first.`);
    }

    const mnemonicValid = await validateMnemonic(mnemonic);
    if (!mnemonicValid) {
       throw new Error('Invalid mnemonic phrase (checksum failed or invalid words)');
    }

    const seed = await mnemonicToSeed(mnemonic);
    const kVault = await deriveVaultKey(seed);
    
    const mnemonicFingerprint = await computeMnemonicFingerprint(seed);
    
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const saltBase64 = bytesToBase64(salt);
    
    const kMP = await deriveMasterPasswordKey(newPassword, salt);
    
    const kVaultData = await crypto.subtle.exportKey('raw', kVault);
    const encryptedKVault = await encryptData(
      { key: bytesToBase64(new Uint8Array(kVaultData)) },
      kMP
    );
    
    const verifier = await encryptData({ v: 'ok' }, kMP);
    
    // Retrieve existing RSA keys from the server (if they exist)
    let existingEncryptedPrivateKey = null;
    let existingPublicKey = null;
    
    if (API_CONFIG?.baseUrl) {
      try {
        const signinResp = await fetch(`${API_CONFIG.baseUrl.replace(/\/$/, '')}/api/auth/recover`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            email,
            newPassword,
            encryptedKVault,
            kvaultSalt: saltBase64,
            verifier,
            mnemonicFingerprint: mnemonicFingerprint
          })
        });

        if (!signinResp.ok) {
          if (signinResp.status === 404) {
            throw new Error('Account not found. Please check your email address.');
          }
          
          if (signinResp.status === 403) {
            throw new Error('This recovery phrase does not belong to this account. Please check your mnemonic.');
          }
          
          let errorMsg = 'Backend recovery failed';
          try {
            const errorData = await signinResp.json();
            errorMsg = errorData.error || errorData.message || errorMsg;
          } catch (e) {
            const errorText = await signinResp.text();
            errorMsg = errorText || errorMsg;
          }
          throw new Error(errorMsg);
        }
        
        const result = await signinResp.json();
        if (!result.ok) {
          throw new Error(result.message || 'Backend recovery failed');
        }
        
        // Store the existing keys returned from the server
        existingEncryptedPrivateKey = result.encryptedPrivateKey;
        existingPublicKey = result.publicKey;
        
        if (existingEncryptedPrivateKey && existingPublicKey) {
          console.log('✅ Account recovery: Existing RSA keys retrieved. Shared passwords will remain decryptable.');
        } else {
          console.warn('⚠️ No existing RSA keys found. This may be an old account. Generating new keys.');
        }
      } catch (backendError) {
        if (backendError instanceof Error) {
          throw backendError;
        }
        throw new Error('Cannot connect to server. Please check your connection.');
      }
    } else {
      throw new Error('Backend not configured. Account recovery requires server connection.');
    }
    
    // If no existing keys were found, generate new ones (for backwards compatibility)
    if (!existingEncryptedPrivateKey || !existingPublicKey) {
      console.warn('⚠️ Generating new RSA keys. Previously shared passwords will be undecryptable.');
      
      const keyPair = await generateKeyPair();
      
      const publicKeyBuffer = await crypto.subtle.exportKey('spki', keyPair.publicKey);
      existingPublicKey = bytesToBase64(new Uint8Array(publicKeyBuffer));
      
      const privateKeyBuffer = await crypto.subtle.exportKey('pkcs8', keyPair.privateKey);
      const privateKeyBase64 = bytesToBase64(new Uint8Array(privateKeyBuffer));
      existingEncryptedPrivateKey = await encryptData({ key: privateKeyBase64 }, kVault);
      
      // Update the server with new keys
      if (API_CONFIG?.baseUrl) {
        try {
          // We need to sign in first to get a token, then update the keys
          // For now, we'll store them locally and they'll be synced on next signin
        } catch (e) {
          console.warn('Failed to sync new keys to server:', e);
        }
      }
    }
    
    await chrome.storage.local.set({
      [STORAGE_KEYS.USER_EMAIL]: email,
      [STORAGE_KEYS.ENCRYPTED_KVAULT]: encryptedKVault,
      [STORAGE_KEYS.SALT]: saltBase64,
      [STORAGE_KEYS.VERIFIER]: verifier,
      [STORAGE_KEYS.ENCRYPTED_PRIVATE_KEY]: existingEncryptedPrivateKey,
      [STORAGE_KEYS.PUBLIC_KEY]: existingPublicKey
    });
    
    return { ok: true };
  } catch (error) {
    return { ok: false, error: error.message };
  }
}

async function signOut() {
  await clearSession();
  
  return { ok: true };
}


async function loadVault() {
  if (!session.unlocked) {
    const stored = await chrome.storage.local.get([STORAGE_KEYS.USER_EMAIL]);
    if (stored[STORAGE_KEYS.USER_EMAIL]) {
      await restoreSession();
    }
  }
  
  if (!session.unlocked || !session.kVault) {
    throw new Error('Vault is locked');
  }
  
  try {
    if (API_CONFIG?.useRemote) {
      const tokenObj = await chrome.storage.local.get(STORAGE_KEYS.REMOTE_TOKEN);
      const token = tokenObj[STORAGE_KEYS.REMOTE_TOKEN];
      if (token) {
        try {
          const remoteEncrypted = await remoteGetVault(token);
          if (remoteEncrypted && remoteEncrypted.trim() !== '' && remoteEncrypted !== '{}') {
            return await decryptData(remoteEncrypted, session.kVault);
          }
        } catch (e) {
          console.warn('Remote vault fetch failed, falling back to local storage:', e);
        }
      }
    }
  } catch (e) {
    console.error('Error while attempting remote vault fetch:', e);
  }

  const stored = await chrome.storage.local.get(STORAGE_KEYS.VAULT_DATA);
  if (!stored[STORAGE_KEYS.VAULT_DATA]) {
    return {};
  }
  
  const vaultData = stored[STORAGE_KEYS.VAULT_DATA];
  if (!vaultData || vaultData === '' || vaultData === '{}') {
    return {};
  }
  
  try {
    return await decryptData(vaultData, session.kVault);
  } catch (decryptError) {
    console.error('Failed to decrypt vault, returning empty vault:', decryptError);
    await chrome.storage.local.remove(STORAGE_KEYS.VAULT_DATA);
    return {};
  }
}

async function saveVault(data) {
  if (!session.unlocked) {
    const stored = await chrome.storage.local.get([STORAGE_KEYS.USER_EMAIL]);
    if (stored[STORAGE_KEYS.USER_EMAIL]) {
      await restoreSession();
    }
  }
  
  if (!session.unlocked || !session.kVault) {
    throw new Error('Vault is locked');
  }
  
  const encrypted = await encryptData(data, session.kVault);
  
  await chrome.storage.local.set({
    [STORAGE_KEYS.VAULT_DATA]: encrypted
  });

  try {
    if (API_CONFIG?.useRemote) {
      const tokenObj = await chrome.storage.local.get(STORAGE_KEYS.REMOTE_TOKEN);
      const token = tokenObj[STORAGE_KEYS.REMOTE_TOKEN];
      if (token) {
        await remoteSaveVault(encrypted, token);
      }
    }
  } catch (e) {
    console.error('Remote vault save failed:', e);
  }

  await saveSession();

  return { ok: true };
}


async function remoteSaveVault(encryptedBlob, token) {
  if (!API_CONFIG?.baseUrl) throw new Error('API baseUrl not configured');
  const url = `${API_CONFIG.baseUrl.replace(/\/$/, '')}/api/vault`;
  const res = await fetch(url, {
    method: 'PUT',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${token}`
    },
    body: JSON.stringify({ encryptedBlob })
  });

  if (!res.ok) {
    const txt = await res.text();
    throw new Error(`Remote save failed: ${res.status} ${txt}`);
  }
  return await res.json();
}

async function remoteGetVault(token) {
  if (!API_CONFIG?.baseUrl) throw new Error('API baseUrl not configured');
  const url = `${API_CONFIG.baseUrl.replace(/\/$/, '')}/api/vault`;
  const res = await fetch(url, {
    method: 'GET',
    headers: {
      'Authorization': `Bearer ${token}`
    }
  });

  if (!res.ok) {
    if (res.status === 404) return null;
    const txt = await res.text();
    throw new Error(`Remote get failed: ${res.status} ${txt}`);
  }
  const data = await res.json();
  const blob = data?.data?.encryptedBlob;
  
  if (!blob || blob === '' || blob === '{}' || blob === 'null') {
    return null;
  }
  
  return blob;
}


function domainFromUrl(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

async function saveCredential(url, username, password) {
  const domain = domainFromUrl(url);
  if (!domain) {
    throw new Error('Invalid URL');
  }
  
  const vault = await loadVault();
  
  if (!vault[domain]) {
    vault[domain] = [];
  }
  
  const existingIndex = vault[domain].findIndex(c => c.username === username);
  if (existingIndex >= 0) {
    vault[domain][existingIndex].password = password;
  } else {
    vault[domain].push({ username, password });
  }
  
  await saveVault(vault);
  return { ok: true };
}

async function getCredentials(url) {
  const domain = domainFromUrl(url);
  if (!domain) {
    return { ok: true, credentials: [] };
  }
  
  const vault = await loadVault();
  const credentials = vault[domain] || [];
  
  return { ok: true, credentials };
}

async function deleteCredential(url, username) {
  const domain = domainFromUrl(url);
  if (!domain) {
    throw new Error('Invalid URL');
  }
  
  const vault = await loadVault();
  
  if (vault[domain]) {
    vault[domain] = vault[domain].filter(c => c.username !== username);
    if (vault[domain].length === 0) {
      delete vault[domain];
    }
  }
  
  await saveVault(vault);
  return { ok: true };
}


async function sharePassword(toEmail, credential) {
  try {
    if (!session.unlocked) {
      const stored = await chrome.storage.local.get([STORAGE_KEYS.USER_EMAIL]);
      if (stored[STORAGE_KEYS.USER_EMAIL]) {
        await restoreSession();
      }
    }
    
    if (!session.unlocked) {
      throw new Error('Vault is locked');
    }

    const tokenObj = await chrome.storage.local.get(STORAGE_KEYS.REMOTE_TOKEN);
    const token = tokenObj[STORAGE_KEYS.REMOTE_TOKEN];
    
    if (!token) {
      throw new Error('Not authenticated');
    }

    if (!API_CONFIG?.baseUrl) {
      throw new Error('Backend API not configured');
    }

    const keyResp = await fetch(`${API_CONFIG.baseUrl.replace(/\/$/, '')}/api/user/${encodeURIComponent(toEmail)}/public-key`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    if (!keyResp.ok) {
      if (keyResp.status === 404) {
        throw new Error('Recipient not found');
      }
      throw new Error('Failed to get recipient public key');
    }

    const keyData = await keyResp.json();
    if (!keyData.ok || !keyData.publicKey) {
      throw new Error('Invalid public key response');
    }

    const publicKeyBytes = base64ToBytes(keyData.publicKey);
    const recipientPublicKey = await crypto.subtle.importKey(
      'spki',
      publicKeyBytes,
      {
        name: 'RSA-OAEP',
        hash: 'SHA-256'
      },
      false,
      ['encrypt']
    );

    const credentialJson = JSON.stringify(credential);
    const credentialBytes = new TextEncoder().encode(credentialJson);
    const encryptedCredential = await crypto.subtle.encrypt(
      { name: 'RSA-OAEP' },
      recipientPublicKey,
      credentialBytes
    );

    const encryptedBase64 = bytesToBase64(new Uint8Array(encryptedCredential));

    const shareResp = await fetch(`${API_CONFIG.baseUrl.replace(/\/$/, '')}/api/share`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${token}`
      },
      body: JSON.stringify({
        toEmail: toEmail,
        encryptedData: encryptedBase64
      })
    });

    if (!shareResp.ok) {
      const errorText = await shareResp.text();
      throw new Error(`Failed to share: ${shareResp.status} ${errorText}`);
    }

    const shareData = await shareResp.json();
    if (!shareData.ok) {
      throw new Error(shareData.error || 'Failed to share password');
    }

    return { ok: true };
  } catch (error) {
    return { ok: false, error: error.message };
  }
}

async function getSharedPasswords() {
  try {
    const tokenObj = await chrome.storage.local.get(STORAGE_KEYS.REMOTE_TOKEN);
    const token = tokenObj[STORAGE_KEYS.REMOTE_TOKEN];
    
    if (!token) {
      throw new Error('Not authenticated');
    }

    if (!API_CONFIG?.baseUrl) {
      throw new Error('Backend API not configured');
    }

    const resp = await fetch(`${API_CONFIG.baseUrl.replace(/\/$/, '')}/api/shared`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    if (!resp.ok) {
      throw new Error(`Failed to get shared passwords: ${resp.status}`);
    }

    const data = await resp.json();
    if (!data.ok) {
      throw new Error(data.error || 'Failed to get shared passwords');
    }

    return { ok: true, shared: data.shared || [] };
  } catch (error) {
    return { ok: false, error: error.message };
  }
}

async function deleteSharedPassword(shareId) {
  try {
    const tokenObj = await chrome.storage.local.get(STORAGE_KEYS.REMOTE_TOKEN);
    const token = tokenObj[STORAGE_KEYS.REMOTE_TOKEN];
    
    if (!token) {
      throw new Error('Not authenticated');
    }

    if (!API_CONFIG?.baseUrl) {
      throw new Error('Backend API not configured');
    }

    const resp = await fetch(`${API_CONFIG.baseUrl.replace(/\/$/, '')}/api/shared/${shareId}`, {
      method: 'DELETE',
      headers: {
        'Authorization': `Bearer ${token}`
      }
    });

    if (!resp.ok) {
      throw new Error(`Failed to delete shared password: ${resp.status}`);
    }

    const data = await resp.json();
    if (!data.ok) {
      throw new Error(data.error || 'Failed to delete shared password');
    }

    return { ok: true };
  } catch (error) {
    return { ok: false, error: error.message };
  }
}

async function decryptSharedPassword(encryptedData) {
  let stored;
  try {
    if (!session.unlocked) {
      const userStored = await chrome.storage.local.get([STORAGE_KEYS.USER_EMAIL]);
      if (userStored[STORAGE_KEYS.USER_EMAIL]) {
        await restoreSession();
      }
    }
    
    if (!session.unlocked || !session.kVault) {
      throw new Error('Vault is locked');
    }

    if (!encryptedData || typeof encryptedData !== 'string') {
      throw new Error('Invalid encrypted data format');
    }

    const cleanedData = encryptedData.trim();
    
    if (cleanedData.length === 0) {
      throw new Error('Empty encrypted data');
    }

    stored = await chrome.storage.local.get(STORAGE_KEYS.ENCRYPTED_PRIVATE_KEY);
    if (!stored[STORAGE_KEYS.ENCRYPTED_PRIVATE_KEY]) {
      throw new Error('Private key not found - account recovery may have failed to restore RSA keys');
    }

    const privateKeyData = await decryptData(stored[STORAGE_KEYS.ENCRYPTED_PRIVATE_KEY], session.kVault);
    const privateKeyBytes = base64ToBytes(privateKeyData.key);

    const privateKey = await crypto.subtle.importKey(
      'pkcs8',
      privateKeyBytes,
      {
        name: 'RSA-OAEP',
        hash: 'SHA-256'
      },
      false,
      ['decrypt']
    );

    const encryptedBytes = base64ToBytes(cleanedData);
    const decryptedBytes = await crypto.subtle.decrypt(
      { name: 'RSA-OAEP' },
      privateKey,
      encryptedBytes
    );

    const decryptedJson = new TextDecoder().decode(decryptedBytes);
    const credential = JSON.parse(decryptedJson);

    return { ok: true, credential };
  } catch (error) {
    console.error('Decrypt shared password:', error.message, {
      hasPrivateKey: !!stored?.[STORAGE_KEYS.ENCRYPTED_PRIVATE_KEY],
      vaultUnlocked: session.unlocked
    });
    
    if (error.message.includes('Private key not found')) {
      return { ok: false, error: 'RSA private key missing - shared passwords cannot be decrypted after account recovery', code: 'NO_PRIVATE_KEY' };
    }
    
    if (error.name === 'OperationError' || error.message.includes('decrypt')) {
      return { ok: false, error: 'Cannot decrypt - this password was shared before account recovery and uses old encryption keys', code: 'KEY_MISMATCH' };
    }
    
    if (error.message.includes('base64')) {
      return { ok: false, error: 'Corrupted encrypted data - invalid base64 encoding', code: 'CORRUPT_DATA' };
    }
    
    return { ok: false, error: error.message, code: 'UNKNOWN' };
  }
}


async function setActionIconIfAvailable() {
  try {
    const url = chrome.runtime.getURL('icons/logo.png');
    const res = await fetch(url);
    if (!res.ok) return;
    const blob = await res.blob();
    const bmp = await createImageBitmap(blob);
    const sizes = [16, 32, 48, 128];
    const imageData = {};
    for (const s of sizes) {
      imageData[s] = imageToImageData(bmp, s, s);
    }
    await chrome.action.setIcon({ imageData });
  } catch (e) {
  }
}

function imageToImageData(img, w, h) {
  const canvas = new OffscreenCanvas(w, h);
  const ctx = canvas.getContext('2d');
  ctx.clearRect(0, 0, w, h);
  const ratio = Math.max(w / img.width, h / img.height);
  const nw = Math.round(img.width * ratio);
  const nh = Math.round(img.height * ratio);
  const dx = Math.round((w - nw) / 2);
  const dy = Math.round((h - nh) / 2);
  ctx.drawImage(img, dx, dy, nw, nh);
  return ctx.getImageData(0, 0, w, h);
}

// Start background initialization and keep a promise so message handlers can wait
restoreReady = (async () => {
  await setActionIconIfAvailable();
  await restoreSession();
})();


chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  (async () => {
    // Ensure background initialization (restoreSession etc.) completed before handling messages
    try {
      await (restoreReady || Promise.resolve());
      switch (msg.type) {
        case 'PM_CHECK_EMAIL':
          try {
            if (!API_CONFIG?.baseUrl) {
              sendResponse({ ok: false, error: 'Backend API not configured' });
              break;
            }
            
            const checkResp = await fetch(`${API_CONFIG.baseUrl.replace(/\/$/, '')}/api/auth/check-email`, {
              method: 'POST',
              headers: { 'Content-Type': 'application/json' },
              body: JSON.stringify({ email: msg.email })
            });
            
            if (!checkResp.ok) {
              sendResponse({ ok: false, error: 'Failed to check email' });
              break;
            }
            
            const checkData = await checkResp.json();
            sendResponse({ ok: true, exists: checkData.exists });
          } catch (error) {
            console.error('Check email error:', error);
            sendResponse({ ok: false, error: error.message });
          }
          break;
          
        case 'PM_GENERATE_MNEMONIC':
          sendResponse(await initiateSignup(msg.email, msg.password));
          break;
          
        case 'PM_GET_MNEMONIC': {
          const stored = await chrome.storage.local.get(STORAGE_KEYS.TEMP_MNEMONIC);
          sendResponse({ ok: true, mnemonic: stored[STORAGE_KEYS.TEMP_MNEMONIC] || null });
          break;
        }
          
        case 'PM_VERIFY_MNEMONIC':
          sendResponse(await completeSignup(msg.mnemonic, msg.password));
          break;
          
        case 'PM_SIGNIN':
          sendResponse(await signIn(msg.email, msg.password));
          break;
          
        case 'PM_RECOVER_ACCOUNT':
          sendResponse(await recoverAccount(msg.email, msg.mnemonic, msg.newPassword));
          break;
          
        case 'PM_SIGNOUT':
          sendResponse(await signOut());
          break;
          
        case 'PM_LOCK':
          session.unlocked = false;
          session.kVault = null;
          session.salt = null;
          await chrome.storage.local.set({
            [STORAGE_KEYS.SESSION_STATE]: null
          });
          sendResponse({ ok: true });
          break;
          
        case 'PM_UNLOCK': {
          try {
            if (!session.user?.email) {
              sendResponse({ ok: false, error: 'No user session found' });
              break;
            }
            
            const stored = await chrome.storage.local.get([
              STORAGE_KEYS.SALT,
              STORAGE_KEYS.ENCRYPTED_KVAULT,
              STORAGE_KEYS.VERIFIER
            ]);
            
            if (!stored[STORAGE_KEYS.SALT] || !stored[STORAGE_KEYS.ENCRYPTED_KVAULT]) {
              sendResponse({ ok: false, error: 'Account data missing' });
              break;
            }
            
            const salt = base64ToBytes(stored[STORAGE_KEYS.SALT]);
            const kMP = await deriveMasterPasswordKey(msg.password, salt);
            
            if (stored[STORAGE_KEYS.VERIFIER]) {
              try {
                const check = await decryptData(stored[STORAGE_KEYS.VERIFIER], kMP);
                if (!check || check.v !== 'ok') {
                  sendResponse({ ok: false, error: 'Invalid password' });
                  break;
                }
              } catch (e) {
                sendResponse({ ok: false, error: 'Invalid password' });
                break;
              }
            }
            
            try {
              const kVaultData = await decryptData(stored[STORAGE_KEYS.ENCRYPTED_KVAULT], kMP);
              const kVaultBytes = base64ToBytes(kVaultData.key);
              const kVault = await crypto.subtle.importKey(
                'raw',
                kVaultBytes,
                { name: 'AES-GCM', length: 256 },
                true,
                ['encrypt', 'decrypt']
              );
              
              session.kVault = kVault;
              session.salt = salt;
              session.unlocked = true;
              
              await saveSession();
              
              sendResponse({ ok: true, user: session.user });
            } catch (e) {
              sendResponse({ ok: false, error: 'Failed to decrypt vault key' });
            }
          } catch (error) {
            console.error('Unlock error:', error);
            sendResponse({ ok: false, error: error.message });
          }
          break;
        }
          
        case 'PM_GET_USER':
          sendResponse({ ok: true, user: session.user });
          break;
          
        case 'PM_STATUS':
          sendResponse({
            unlocked: session.unlocked,
            user: session.user,
          });
          break;
          
        case 'PM_SAVE_CREDENTIALS':
          sendResponse(await saveCredential(msg.url, msg.username, msg.password));
          break;
          
        case 'PM_GET_CREDENTIALS':
          sendResponse(await getCredentials(msg.url));
          break;
          
        case 'PM_GET_ALL':
          try {
            const vault = await loadVault();
            sendResponse({ ok: true, data: vault });
          } catch (err) {
            sendResponse({ ok: false, error: err.message });
          }
          break;

        case 'PM_SET_REMOTE_TOKEN':
          try {
            if (!msg.token) throw new Error('No token provided');
            await chrome.storage.local.set({ [STORAGE_KEYS.REMOTE_TOKEN]: msg.token });
            sendResponse({ ok: true });
          } catch (err) {
            sendResponse({ ok: false, error: err.message });
          }
          break;

        case 'PM_CLEAR_REMOTE_TOKEN':
          try {
            await chrome.storage.local.remove([STORAGE_KEYS.REMOTE_TOKEN]);
            sendResponse({ ok: true });
          } catch (err) {
            sendResponse({ ok: false, error: err.message });
          }
          break;

        case 'PM_REMOTE_STATUS':
          try {
            const tokenObj = await chrome.storage.local.get(STORAGE_KEYS.REMOTE_TOKEN);
            const token = tokenObj[STORAGE_KEYS.REMOTE_TOKEN];
            sendResponse({ ok: true, useRemote: !!API_CONFIG?.useRemote, hasToken: !!token });
          } catch (err) {
            sendResponse({ ok: false, error: err.message });
          }
          break;

        case 'PM_REMOTE_SYNC':
          try {
            const tokenObj = await chrome.storage.local.get(STORAGE_KEYS.REMOTE_TOKEN);
            const token = tokenObj[STORAGE_KEYS.REMOTE_TOKEN];
            if (!API_CONFIG?.useRemote) throw new Error('Remote sync disabled in config');
            if (!token) throw new Error('No remote token configured');
            const local = await chrome.storage.local.get(STORAGE_KEYS.VAULT_DATA);
            const encrypted = local[STORAGE_KEYS.VAULT_DATA];
            if (!encrypted) throw new Error('No local vault to sync');
            const resp = await remoteSaveVault(encrypted, token);
            sendResponse({ ok: true, remote: resp });
          } catch (err) {
            sendResponse({ ok: false, error: err.message });
          }
          break;
          
        case 'PM_DELETE_CREDENTIAL':
          sendResponse(await deleteCredential(msg.url, msg.username));
          break;

        case 'PM_SHARE_PASSWORD':
          sendResponse(await sharePassword(msg.toEmail, msg.credential));
          break;

        case 'PM_GET_SHARED':
          sendResponse(await getSharedPasswords());
          break;

        case 'PM_DECRYPT_SHARED':
          sendResponse(await decryptSharedPassword(msg.encryptedData));
          break;

        case 'PM_DELETE_SHARED':
          sendResponse(await deleteSharedPassword(msg.shareId));
          break;

        case 'PM_CHANGE_PASSWORD': {
            try {
              const { currentPassword, newPassword } = msg;

              if (!session.user?.email) {
                sendResponse({ ok: false, error: 'No user signed in' });
                break;
              }

              const verify = await signIn(session.user.email, currentPassword);
              if (!verify.ok) {
                sendResponse({ ok: false, error: 'Incorrect current password' });
                break;
              }

              const salt = crypto.getRandomValues(new Uint8Array(16));
              const saltBase64 = bytesToBase64(salt);
              const kMP = await deriveMasterPasswordKey(newPassword, salt);
              const kVaultData = await crypto.subtle.exportKey('raw', session.kVault);
              const encryptedKVault = await encryptData(
                { key: bytesToBase64(new Uint8Array(kVaultData)) },
                kMP
              );
              
              const verifier = await encryptData({ v: 'ok' }, kMP);

              const existingKeys = await chrome.storage.local.get([
                STORAGE_KEYS.ENCRYPTED_PRIVATE_KEY,
                STORAGE_KEYS.PUBLIC_KEY
              ]);

              if (!existingKeys[STORAGE_KEYS.ENCRYPTED_PRIVATE_KEY]) {
                console.warn('No encrypted private key found during password change - shared passwords will not work');
              }

              await chrome.storage.local.set({
                [STORAGE_KEYS.ENCRYPTED_KVAULT]: encryptedKVault,
                [STORAGE_KEYS.SALT]: saltBase64,
                [STORAGE_KEYS.VERIFIER]: verifier,
              });

              if (API_CONFIG?.useRemote && API_CONFIG?.baseUrl) {
                const tokenObj = await chrome.storage.local.get(STORAGE_KEYS.REMOTE_TOKEN);
                const token = tokenObj[STORAGE_KEYS.REMOTE_TOKEN];
                
                if (token) {
                  try {
                    const changeResp = await fetch(`${API_CONFIG.baseUrl.replace(/\/$/, '')}/api/auth/change-password`, {
                      method: 'PUT',
                      headers: {
                        'Content-Type': 'application/json',
                        'Authorization': `Bearer ${token}`
                      },
                      body: JSON.stringify({
                        currentPassword,
                        newPassword,
                        encryptedKVault,
                        kvaultSalt: saltBase64,
                        verifier
                      })
                    });

                    if (!changeResp.ok) {
                      console.warn('Failed to sync password change to backend:', changeResp.status);
                    }
                  } catch (err) {
                    console.warn('Failed to sync password change to backend:', err.message);
                  }
                }
              }

              sendResponse({ ok: true });
            } catch (error) {
              console.error('PM_CHANGE_PASSWORD error:', error);
              sendResponse({ ok: false, error: error.message });
            }
            break;
        }

        case 'PM_WIPE_DATA':
          try {
            try {
              if (API_CONFIG?.baseUrl) {
                const tokenObj = await chrome.storage.local.get(STORAGE_KEYS.REMOTE_TOKEN);
                const token = tokenObj[STORAGE_KEYS.REMOTE_TOKEN];
                
                if (token) {
                  const deleteResp = await fetch(`${API_CONFIG.baseUrl.replace(/\/$/, '')}/api/auth/delete-account`, {
                    method: 'DELETE',
                    headers: {
                      'Authorization': `Bearer ${token}`
                    }
                  });

                  if (deleteResp.ok) {
  
                  } else {
                    console.warn('Failed to delete account from server:', await deleteResp.text());
                  }
                }
              }
            } catch (backendError) {
              console.warn('Backend account deletion failed (continuing with local wipe):', backendError);
            }

            await chrome.storage.local.clear();
            
            session = {
              user: null,
              kVault: null,
              salt: null,
              unlocked: false
            };
            
            sendResponse({ ok: true });
          } catch (error) {
            console.error('PM_WIPE_DATA error:', error);
            sendResponse({ ok: false, error: error.message });
          }
          break;

          
        default:
          sendResponse({ ok: false, error: 'Unknown message type' });
      }
    } catch (error) {
      console.error('Message handler error:', error);
      sendResponse({ ok: false, error: error.message });
    }
  })();
  return true;
});

