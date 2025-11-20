require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const { Pool } = require('pg');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

const pool = new Pool({
  host: process.env.DB_HOST,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
});

pool.query('SELECT NOW()', (err) => {
  if (err) {
    console.error('❌ Database connection failed:', err.message);
    process.exit(1);
  } else {
    console.log('✅ Database connected successfully');
  }
});


app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https:'],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"],
    },
  },
  crossOriginEmbedderPolicy: false,
}));

app.use(
  cors({
    origin: function(origin, callback) {
      if (!origin) return callback(null, true);
      
      if (origin.startsWith('chrome-extension://') || origin.startsWith('moz-extension://')) {
        return callback(null, true);
      }
      
      callback(new Error('Not allowed by CORS'));
    },
    credentials: true,
  })
);
app.use(express.json({ limit: '10mb' }));

const authLimiter = rateLimit({
  windowMs: 60 * 1000, 
  max: 30, 
  message: 'Too many authentication attempts, please try again later.',
  standardHeaders: true,
  legacyHeaders: false,
});

const apiLimiter = rateLimit({
  windowMs: 60 * 1000, 
  max: 200, 
  message: 'Too many requests, please slow down.',
  standardHeaders: true,
  legacyHeaders: false,
});

const shareLimiter = rateLimit({
  windowMs: 60 * 1000, 
  max: 30, 
  message: 'Too many sharing requests, please slow down.',
  standardHeaders: true,
  legacyHeaders: false,
});

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'Access token required' });

  jwt.verify(token, process.env.JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: 'Invalid or expired token' });
    req.user = user;
    next();
  });
};

app.post('/api/auth/signup', authLimiter, async (req, res) => {
  const client = await pool.connect();
  try {
    const { email, password, publicKey, encryptedKVault, kvaultSalt, verifier, mnemonicFingerprint, encryptedPrivateKey } = req.body;

    if (!email || !password || !publicKey) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    if (!mnemonicFingerprint) {
      return res.status(400).json({ error: 'Mnemonic fingerprint required for account recovery' });
    }

    await client.query('BEGIN');

    const existingUser = await client.query('SELECT id FROM users WHERE email = $1', [email]);
    if (existingUser.rows.length > 0) {
      await client.query('ROLLBACK');
      return res.status(400).json({ error: 'User already exists' });
    }

    const salt = await bcrypt.genSalt(12);
    const hashedPassword = await bcrypt.hash(password, salt);

    const userResult = await client.query(
      'INSERT INTO users (email, hashed_password, salt, public_key, encrypted_kvault, kvault_salt, verifier, mnemonic_fingerprint, encrypted_private_key) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id, email',
      [email, hashedPassword, salt, publicKey, encryptedKVault || null, kvaultSalt || null, verifier || null, mnemonicFingerprint, encryptedPrivateKey || null]
    );
    const user = userResult.rows[0];

    await client.query('INSERT INTO vault_data (user_id, encrypted_blob) VALUES ($1, $2)', [
      user.id,
      '{}',
    ]);

    await client.query('COMMIT');

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({ ok: true, user: { id: user.id, email: user.email }, token });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Signup error:', error.message);
    res.status(500).json({ error: 'Signup failed' });
  } finally {
    client.release();
  }
});

app.post('/api/auth/signin', authLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'Email and password required' });

    const userResult = await pool.query(
      'SELECT id, email, hashed_password, encrypted_kvault, kvault_salt, verifier, encrypted_private_key, public_key FROM users WHERE email = $1',
      [email]
    );
    if (userResult.rows.length === 0)
      return res.status(401).json({ error: 'Invalid credentials' });

    const user = userResult.rows[0];

    const isValid = await bcrypt.compare(password, user.hashed_password);
    if (!isValid) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      ok: true,
      user: { id: user.id, email: user.email },
      token,
      encryptedKVault: user.encrypted_kvault,
      kvaultSalt: user.kvault_salt,
      verifier: user.verifier,
      encryptedPrivateKey: user.encrypted_private_key,
      publicKey: user.public_key,
    });
  } catch (error) {
    console.error('Signin error:', error.message);
    res.status(500).json({ error: 'Signin failed' });
  }
});

app.delete('/api/auth/delete-account', authenticateToken, authLimiter, async (req, res) => {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    
    const result = await client.query('DELETE FROM users WHERE id = $1 RETURNING email', [
      req.user.userId,
    ]);

    if (result.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'User not found' });
    }

    await client.query('COMMIT');
    res.json({ ok: true, message: 'Account and all data permanently deleted' });
  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Delete account error:', error.message);
    res.status(500).json({ error: 'Failed to delete account' });
  } finally {
    client.release();
  }
});

app.post('/api/auth/check-email', authLimiter, async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    const userResult = await pool.query(
      'SELECT id FROM users WHERE email = $1',
      [email]
    );
    
    const exists = userResult.rows.length > 0;
    res.json({ ok: true, exists });
  } catch (error) {
    console.error('Check email error:', error.message);
    res.status(500).json({ error: 'Failed to check email' });
  }
});

app.post('/api/auth/recover', authLimiter, async (req, res) => {
  try {
    const { email, newPassword, encryptedKVault, kvaultSalt, verifier, mnemonicFingerprint } = req.body;
    
    if (!email || !newPassword || !encryptedKVault || !kvaultSalt || !verifier) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    if (!mnemonicFingerprint) {
      return res.status(400).json({ error: 'Mnemonic fingerprint required for verification' });
    }
    const userResult = await pool.query(
      'SELECT id, mnemonic_fingerprint, encrypted_private_key, public_key FROM users WHERE email = $1',
      [email]
    );
    
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'Account not found' });
    }

    const userId = userResult.rows[0].id;
    const storedFingerprint = userResult.rows[0].mnemonic_fingerprint;
    const existingEncryptedPrivateKey = userResult.rows[0].encrypted_private_key;
    const existingPublicKey = userResult.rows[0].public_key;

    if (!storedFingerprint) {
      return res.status(400).json({ error: 'Account was created without recovery support. Please contact support.' });
    }

    if (storedFingerprint !== mnemonicFingerprint) {
      return res.status(403).json({ error: 'Invalid recovery phrase - mnemonic does not match this account' });
    }

    const salt = await bcrypt.genSalt(12);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    // Update only password-related fields, preserve existing RSA keys
    await pool.query(
      'UPDATE users SET hashed_password = $1, salt = $2, encrypted_kvault = $3, kvault_salt = $4, verifier = $5 WHERE id = $6',
      [hashedPassword, salt, encryptedKVault, kvaultSalt, verifier, userId]
    );

    // Return the existing keys so the client can restore them
    res.json({ 
      ok: true, 
      message: 'Password reset successful',
      encryptedPrivateKey: existingEncryptedPrivateKey,
      publicKey: existingPublicKey
    });
  } catch (error) {
    console.error('Account recovery error:', error.message);
    res.status(500).json({ error: 'Account recovery failed' });
  }
});

app.put('/api/auth/change-password', authenticateToken, authLimiter, async (req, res) => {
  try {
    const { currentPassword, newPassword, encryptedKVault, kvaultSalt, verifier } = req.body;
    
    if (!currentPassword || !newPassword || !encryptedKVault || !kvaultSalt || !verifier) {
      return res.status(400).json({ error: 'Missing required fields' });
    }

    const userResult = await pool.query(
      'SELECT id, hashed_password FROM users WHERE id = $1',
      [req.user.userId]
    );
    
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = userResult.rows[0];
    const isValid = await bcrypt.compare(currentPassword, user.hashed_password);
    
    if (!isValid) {
      return res.status(401).json({ error: 'Incorrect current password' });
    }

    const salt = await bcrypt.genSalt(12);
    const hashedPassword = await bcrypt.hash(newPassword, salt);

    await pool.query(
      'UPDATE users SET hashed_password = $1, salt = $2, encrypted_kvault = $3, kvault_salt = $4, verifier = $5 WHERE id = $6',
      [hashedPassword, salt, encryptedKVault, kvaultSalt, verifier, req.user.userId]
    );

    res.json({ ok: true, message: 'Password changed successfully' });
  } catch (error) {
    console.error('Change password error:', error.message);
    res.status(500).json({ error: 'Failed to change password' });
  }
});

app.get('/api/vault', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const result = await pool.query('SELECT encrypted_blob FROM vault_data WHERE user_id = $1', [
      req.user.userId,
    ]);

    if (result.rows.length === 0) return res.json({ ok: true, data: { encryptedBlob: null } });

    const blobData = result.rows[0].encrypted_blob;
    const encryptedBlob = blobData?.encryptedBlob || blobData;

    res.json({ ok: true, data: { encryptedBlob } });
  } catch (error) {
    console.error('Get vault error:', error.message);
    res.status(500).json({ error: 'Failed to retrieve vault' });
  }
});

app.put('/api/vault', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { encryptedBlob } = req.body;
    if (!encryptedBlob) return res.status(400).json({ error: 'Encrypted blob required' });

    const blobData = typeof encryptedBlob === 'string' 
      ? { encryptedBlob: encryptedBlob }
      : encryptedBlob;

    await pool.query(
      'UPDATE vault_data SET encrypted_blob = $1, updated_at = CURRENT_TIMESTAMP WHERE user_id = $2',
      [blobData, req.user.userId]
    );

    res.json({ ok: true });
  } catch (error) {
    console.error('Update vault error:', error.message);
    res.status(500).json({ error: 'Failed to update vault' });
  }
});

app.get('/api/keys', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const result = await pool.query(
      'SELECT public_key FROM users WHERE id = $1',
      [req.user.userId]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ ok: true, publicKey: result.rows[0].public_key });
  } catch (error) {
    console.error('Get keys error:', error.message);
    res.status(500).json({ error: 'Failed to retrieve keys' });
  }
});

app.get('/api/user/:email/public-key', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { email } = req.params;
    const result = await pool.query(
      'SELECT public_key FROM users WHERE email = $1',
      [email]
    );
    if (result.rows.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ ok: true, publicKey: result.rows[0].public_key });
  } catch (error) {
    console.error('Get public key error:', error.message);
    res.status(500).json({ error: 'Failed to retrieve public key' });
  }
});

app.post('/api/share', authenticateToken, shareLimiter, async (req, res) => {
  try {
    const { toEmail, encryptedData } = req.body;
    if (!toEmail || !encryptedData)
      return res.status(400).json({ error: 'Missing required fields' });

    const recipientResult = await pool.query('SELECT id FROM users WHERE email = $1', [toEmail]);
    if (recipientResult.rows.length === 0)
      return res.status(404).json({ error: 'Recipient not found' });

    const toUserId = recipientResult.rows[0].id;
    const dupCheck = await pool.query(
      'SELECT id FROM shared_passwords WHERE from_user_id = $1 AND to_user_id = $2 AND encrypted_data = $3',
      [req.user.userId, toUserId, encryptedData]
    );

    if (dupCheck.rows.length > 0) {
      console.warn('Duplicate share detected — skipping insert for from_user_id=%s to_user_id=%s', req.user.userId, toUserId);
      return res.json({ ok: true });
    }

    await pool.query(
      'INSERT INTO shared_passwords (from_user_id, to_user_id, encrypted_data) VALUES ($1, $2, $3)',
      [req.user.userId, toUserId, encryptedData]
    );

    res.json({ ok: true });
  } catch (error) {
    console.error('Share password error:', error.message);
    res.status(500).json({ error: 'Failed to share password' });
  }
});

app.get('/api/shared', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT sp.id, sp.encrypted_data, sp.created_at, u.email AS from_email, u.public_key AS sender_public_key
       FROM shared_passwords sp
       JOIN users u ON sp.from_user_id = u.id
       WHERE sp.to_user_id = $1
       ORDER BY sp.created_at DESC`,
      [req.user.userId]
    );
    
    const shared = result.rows.map(row => ({
      id: row.id,
      encryptedData: row.encrypted_data,
      created_at: row.created_at,
      from_email: row.from_email,
      senderPublicKey: row.sender_public_key?.substring(0, 50) + '...'
    }));
    
    res.json({ ok: true, shared });
  } catch (error) {
    console.error('Get shared passwords error:', error.message);
    res.status(500).json({ error: 'Failed to retrieve shared passwords' });
  }
});

app.delete('/api/shared/:id', authenticateToken, apiLimiter, async (req, res) => {
  try {
    const { id } = req.params;
    
    const result = await pool.query(
      'DELETE FROM shared_passwords WHERE id = $1 AND to_user_id = $2 RETURNING id',
      [id, req.user.userId]
    );
    
    if (result.rows.length === 0) {
      return res.status(404).json({ error: 'Shared password not found or unauthorized' });
    }
    
    res.json({ ok: true, message: 'Shared password deleted' });
  } catch (error) {
    console.error('Delete shared password error:', error.message);
    res.status(500).json({ error: 'Failed to delete shared password' });
  }
});

app.get('/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 LPH API Server running on port ${PORT}`);
  console.log(`📍 Environment: ${process.env.NODE_ENV}`);
});

process.on('SIGTERM', () => {
  console.log('🛑 SIGTERM received: closing PostgreSQL connection...');
  pool.end();
  process.exit(0);
});