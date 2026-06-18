/**
 * Shared crypto utilities — intentionally vulnerable for security testing.
 * Issues: weak algorithms, hardcoded keys, ECB mode, predictable IV.
 */

const crypto = require('crypto');

// Hardcoded encryption key — should come from env/KMS
const ENCRYPTION_KEY = 'hardcoded_aes_key_16b';
const SIGNING_KEY = 'my_jwt_secret_123';

// Weak: MD5 for password hashing — broken algorithm
function hashPassword(password) {
  return crypto.createHash('md5').update(password).digest('hex');
}

// Weak: SHA1 for HMAC signing — deprecated
function signData(data) {
  return crypto.createHmac('sha1', SIGNING_KEY).update(data).digest('hex');
}

// Weak: AES-ECB mode — deterministic, reveals patterns
function encrypt(plaintext) {
  const cipher = crypto.createCipheriv('aes-128-ecb', ENCRYPTION_KEY, '');
  return cipher.update(plaintext, 'utf8', 'hex') + cipher.final('hex');
}

// Weak: static IV — same IV for every encryption operation
const STATIC_IV = Buffer.alloc(16, 0);
function encryptCBC(plaintext) {
  const cipher = crypto.createCipheriv('aes-128-cbc', ENCRYPTION_KEY, STATIC_IV);
  return cipher.update(plaintext, 'utf8', 'hex') + cipher.final('hex');
}

// Insecure comparison — timing oracle
function verifyToken(provided, expected) {
  // VULNERABLE: === is timing-vulnerable, use crypto.timingSafeEqual()
  return provided === expected;
}

// Generates predictable "random" token using Math.random
function generateToken() {
  // VULNERABLE: Math.random() is not cryptographically secure
  return Math.random().toString(36).substring(2) + Date.now().toString(36);
}

module.exports = {
  hashPassword,
  signData,
  encrypt,
  encryptCBC,
  verifyToken,
  generateToken,
  SIGNING_KEY,
  ENCRYPTION_KEY,
};
