/**
 * Client-side password-based encryption for password-protected cloud uploads.
 *
 * ─── Cryptographic design ────────────────────────────────────────────────
 * KDF    : Argon2id (hash-wasm WASM), 64 MiB / 3 iterations / 1 thread → 32-byte key
 * Cipher : AES-256-GCM (Web Crypto API — no manual crypto)
 * IV     : 12 bytes, crypto.getRandomValues(), unique per chunk (never reused)
 * AAD    : UTF-8("chunk-<0-based-index>") — binds tag to chunk position,
 *           preventing chunk reordering/splicing attacks
 * Format : [IV (12 B)] || [AES-GCM ciphertext + auth tag (16 B)]
 *
 * ─── What never leaves the browser ──────────────────────────────────────
 * • The user's password
 * • The derived AES key (non-extractable CryptoKey)
 *
 * ─── What is stored in share metadata ───────────────────────────────────
 * • salt (random, public, per-upload — required for decryption)
 * • algorithm, kdf, chunkSize, version (public parameters)
 *
 * ─── Overhead per encrypted chunk ───────────────────────────────────────
 * IV_BYTES (12) + GCM_TAG_BYTES (16) = 28 bytes per chunk
 */

/** Bytes prepended to each encrypted chunk as the AES-GCM nonce/IV. */
export const IV_BYTES = 12;

/** AES-GCM authentication tag length (appended by WebCrypto automatically). */
const GCM_TAG_BYTES = 16;

/** Per-chunk overhead added by encryption: IV + GCM auth tag. */
export const ENCRYPTION_OVERHEAD = IV_BYTES + GCM_TAG_BYTES; // 28 bytes

// ─── Argon2id parameters ─────────────────────────────────────────────────
// OWASP 2023 interactive minimum (stronger tier):
//   memory  = 64 MiB  (65536 KiB)
//   iterations = 3
//   parallelism = 1 (single-threaded browser)
const ARGON2_MEMORY_KIB = 65536;
const ARGON2_ITERATIONS = 3;
const ARGON2_PARALLELISM = 1;
const ARGON2_HASH_LENGTH = 32; // → 256-bit AES key

// ─── Helpers ─────────────────────────────────────────────────────────────

/**
 * Generate a cryptographically secure random salt.
 * Store this value in share metadata; it is required for decryption.
 *
 * @returns {Uint8Array} 16 random bytes
 */
export function generateSalt() {
  return crypto.getRandomValues(new Uint8Array(16));
}

/**
 * Encode a Uint8Array as base64url (RFC 4648 §5, no padding).
 * Used to transport the salt as a JSON-safe string.
 *
 * @param {Uint8Array} bytes
 * @returns {string}
 */
export function encodeBase64url(bytes) {
  let binary = '';
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}

/**
 * Decode a base64url string back to a Uint8Array.
 *
 * @param {string} str
 * @returns {Uint8Array}
 */
export function decodeBase64url(str) {
  const b64 = str.replace(/-/g, '+').replace(/_/g, '/');
  const padded = b64 + '='.repeat((4 - (b64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes;
}

// ─── Key Derivation ───────────────────────────────────────────────────────

/**
 * Derive a 256-bit AES-GCM CryptoKey from a password using Argon2id.
 *
 * The hash-wasm module is lazy-loaded so the WASM binary (~400 kB) is only
 * fetched when encryption is actually needed.
 *
 * This operation is intentionally slow (~0.5–2 s depending on device).
 * Call it from a non-blocking context and show a spinner while it runs.
 * The password is only held in memory for the duration of this call.
 *
 * @param {string}     password  User's password — NEVER stored or transmitted
 * @param {Uint8Array} salt      Per-upload random salt from generateSalt()
 * @returns {Promise<CryptoKey>} Non-extractable AES-256-GCM key
 */
export async function deriveKeyFromPassword(password, salt) {
  if (!password || typeof password !== 'string') {
    throw new Error('A password is required for encrypted uploads.');
  }

  // Lazy-load to avoid pulling the WASM binary into the initial bundle.
  const { argon2id } = await import('hash-wasm');

  // hash-wasm with outputType:'binary' returns a Uint8Array of raw key material.
  const keyMaterial = await argon2id({
    password,
    salt,
    parallelism: ARGON2_PARALLELISM,
    iterations:  ARGON2_ITERATIONS,
    memorySize:  ARGON2_MEMORY_KIB,
    hashLength:  ARGON2_HASH_LENGTH,
    outputType:  'binary',
  });

  // Import as a non-extractable key — raw bytes cannot be read back.
  return crypto.subtle.importKey(
    'raw',
    keyMaterial,
    { name: 'AES-GCM', length: 256 },
    false,               // non-extractable
    ['encrypt', 'decrypt']
  );
}

// ─── Chunk Encryption ─────────────────────────────────────────────────────

/**
 * Encrypt a plaintext chunk with AES-256-GCM.
 *
 * Output layout:
 *   [IV (12 B)] || [AES-GCM ciphertext (n B) + auth tag (16 B)]
 *
 * A fresh 12-byte random IV is generated for every call, guaranteeing nonce
 * uniqueness even when the same key is reused across many chunks.
 *
 * The chunk index is bound via AAD ("chunk-<index>"), which prevents an
 * attacker from reordering or substituting encrypted chunks.
 *
 * @param {CryptoKey}   key             Derived AES-256-GCM key
 * @param {ArrayBuffer} plaintextBuffer Raw chunk bytes
 * @param {number}      chunkIndex      0-based chunk index used as AAD
 * @returns {Promise<Uint8Array>} Encrypted blob (IV prepended) ready for upload
 */
export async function encryptChunkWithKey(key, plaintextBuffer, chunkIndex) {
  const iv  = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  const aad = new TextEncoder().encode(`chunk-${chunkIndex}`);

  const ciphertext = await crypto.subtle.encrypt(
    { name: 'AES-GCM', iv, additionalData: aad },
    key,
    plaintextBuffer
  );

  // Prepend the IV so the receiver can extract it without out-of-band metadata.
  const out = new Uint8Array(IV_BYTES + ciphertext.byteLength);
  out.set(iv, 0);
  out.set(new Uint8Array(ciphertext), IV_BYTES);
  return out;
}

// ─── Chunk Decryption ─────────────────────────────────────────────────────

/**
 * Decrypt an encrypted chunk produced by encryptChunkWithKey.
 *
 * Expects the same [IV (12 B)] || [ciphertext + tag] layout.
 *
 * Throws if any of the following conditions are detected:
 *   • Wrong password (key mismatch → GCM auth failure)
 *   • Tampered ciphertext or auth tag
 *   • Wrong chunk index (AAD mismatch → GCM auth failure)
 *
 * All three produce the same generic error message — no information is leaked
 * about which condition triggered the failure.
 *
 * @param {CryptoKey}  key             Derived AES-256-GCM key
 * @param {Uint8Array} encryptedBytes  IV-prepended encrypted chunk
 * @param {number}     chunkIndex      Must match the value used during encryption
 * @returns {Promise<ArrayBuffer>} Plaintext chunk
 */
export async function decryptChunkWithKey(key, encryptedBytes, chunkIndex) {
  if (encryptedBytes.length <= IV_BYTES + GCM_TAG_BYTES) {
    throw new Error('Encrypted chunk is too short — the file may be corrupted.');
  }

  const iv         = encryptedBytes.slice(0, IV_BYTES);
  const ciphertext = encryptedBytes.slice(IV_BYTES);
  const aad        = new TextEncoder().encode(`chunk-${chunkIndex}`);

  try {
    return await crypto.subtle.decrypt(
      { name: 'AES-GCM', iv, additionalData: aad },
      key,
      ciphertext
    );
  } catch {
    // Generic error: do NOT include password, key material, or raw data.
    throw new Error('Decryption failed — incorrect password or corrupted file.');
  }
}
