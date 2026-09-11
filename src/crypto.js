// Algorithm parameters come from the spec file that the marketing pages and
// guides also read, so the numbers we publish are the numbers we run. Change
// them there, not here.
import {
  E2E_CHUNK_CIPHER,
  E2E_KEY_EXCHANGE,
  E2E_SAFETY_CODE,
} from "./data/cryptoSpec.js";

export async function generateReceiverKeyPair() {
  return crypto.subtle.generateKey(
    {
      name: E2E_KEY_EXCHANGE.algorithm,
      modulusLength: E2E_KEY_EXCHANGE.modulusBits,
      publicExponent: new Uint8Array([1, 0, 1]),
      hash: E2E_KEY_EXCHANGE.hash
    },
    // extractable = false applies to the PRIVATE key only; public keys are
    // always exportable, so exportPublicKey still works. This makes "the
    // private key never leaves the browser" something the browser enforces
    // rather than something this code merely refrains from doing — injected
    // script on the page cannot read the key out either.
    E2E_KEY_EXCHANGE.privateKeyExtractable,
    ["encrypt", "decrypt"]
  );
}

export async function exportPublicKey(publicKey) {
  const spki = await crypto.subtle.exportKey("spki", publicKey);
  return arrayBufferToBase64(spki);
}

export async function importPublicKey(base64Key) {
  return crypto.subtle.importKey(
    "spki",
    base64ToArrayBuffer(base64Key),
    { name: "RSA-OAEP", hash: "SHA-256" },
    false,
    ["encrypt"]
  );
}

export async function generateAesKey() {
  return crypto.subtle.generateKey(
    { name: E2E_CHUNK_CIPHER.algorithm, length: E2E_CHUNK_CIPHER.keyBits },
    true,
    ["encrypt", "decrypt"]
  );
}

export async function encryptAesKeyWithPublicKey(aesKey, receiverPublicKeyBase64) {
  const receiverPublicKey = await importPublicKey(receiverPublicKeyBase64);
  const rawAesKey = await crypto.subtle.exportKey("raw", aesKey);
  const encrypted = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, receiverPublicKey, rawAesKey);
  return arrayBufferToBase64(encrypted);
}

export async function decryptAesKeyWithPrivateKey(encryptedAesKeyBase64, privateKey) {
  const rawKey = await crypto.subtle.decrypt(
    { name: "RSA-OAEP" },
    privateKey,
    base64ToArrayBuffer(encryptedAesKeyBase64)
  );

  return crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, ["decrypt"]);
}

// Raw binary variants — used by the direct WebRTC path, which sends the
// ciphertext as an ArrayBuffer over the data channel (no base64 / JSON).
export async function encryptChunkRaw(aesKey, chunkBuffer, sequence) {
  const iv = crypto.getRandomValues(new Uint8Array(E2E_CHUNK_CIPHER.ivBits / 8));
  const data = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
      additionalData: new TextEncoder().encode(String(sequence))
    },
    aesKey,
    chunkBuffer
  );

  return { iv, data };
}

export async function decryptChunkRaw(aesKey, iv, data, sequence) {
  return crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv,
      additionalData: new TextEncoder().encode(String(sequence))
    },
    aesKey,
    data
  );
}

// Base64 variants — used by the socket.io relay path, which carries chunks as JSON.
export async function encryptChunk(aesKey, chunkBuffer, sequence) {
  const { iv, data } = await encryptChunkRaw(aesKey, chunkBuffer, sequence);
  return {
    iv: arrayBufferToBase64(iv),
    data: arrayBufferToBase64(data)
  };
}

export async function decryptChunk(aesKey, encryptedChunk, sequence) {
  return decryptChunkRaw(
    aesKey,
    base64ToArrayBuffer(encryptedChunk.iv),
    base64ToArrayBuffer(encryptedChunk.data),
    sequence
  );
}

// Streaming SHA-256. Reading a whole 200 MB file into an ArrayBuffer before
// hashing costs a full copy in memory and a long main-thread digest before the
// first byte can move, so both helpers walk the blob's stream instead and hand
// hash-wasm one slice at a time. `onProgress` reports bytes consumed so callers
// can show that the hash pass is running.
export function sha256File(file, onProgress) {
  return sha256Stream(file, onProgress);
}

export function sha256Blob(blob, onProgress) {
  return sha256Stream(blob, onProgress);
}

async function sha256Stream(blob, onProgress) {
  if (typeof blob?.stream !== "function") return sha256Buffered(blob);

  let hasher;
  try {
    const { createSHA256 } = await import("hash-wasm");
    hasher = await createSHA256();
  } catch {
    // hash-wasm unavailable (blocked wasm, old browser) — fall back to WebCrypto.
    return sha256Buffered(blob);
  }

  hasher.init();
  const reader = blob.stream().getReader();
  let processed = 0;

  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      hasher.update(value);
      processed += value.byteLength;
      onProgress?.(processed, blob.size);
    }
  } finally {
    reader.releaseLock?.();
  }

  return hasher.digest("hex");
}

async function sha256Buffered(blob) {
  const buffer = await blob.arrayBuffer();
  const hash = await crypto.subtle.digest("SHA-256", buffer);
  return arrayBufferToHex(hash);
}

function arrayBufferToBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function base64ToArrayBuffer(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}

function arrayBufferToHex(buffer) {
  return [...new Uint8Array(buffer)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

// ── Safety code (key fingerprint) ───────────────────────────────────────────
// The one thing RSA-OAEP + AES-GCM cannot protect on its own: the sender is
// told the receiver's public key *by the server*, so a malicious server can
// hand over its own key, unwrap the AES key, read every chunk, and re-wrap it
// for the real receiver. Both sides would see a flawless transfer.
//
// So each side derives a short code from the key it is actually using — the
// receiver from its own public key, the sender from whatever key it was given
// — and the users compare them out of band. A substituted key produces a
// different code, and the server cannot make its key hash to the receiver's
// without a second-preimage attack on SHA-256.
//
// 48 bits, rendered two equivalent ways: 8 emoji (6 bits each) to compare at a
// glance when both screens are in the same room, and 12 hex characters to read
// aloud over a call. Comparing either one is the same check. 48 bits is well
// past what an attacker could grind out within a room's lifetime, since every
// attempt costs a full RSA-2048 keygen.
const SAFETY_EMOJI = [
  "🐶", "🐱", "🦊", "🐻", "🐼", "🐨", "🦁", "🐮",
  "🐷", "🐸", "🐵", "🐔", "🐧", "🦉", "🦄", "🐝",
  "🦋", "🐢", "🐙", "🦀", "🐳", "🐬", "🐟", "🌵",
  "🌲", "🍀", "🌺", "🌻", "🍎", "🍌", "🍇", "🍓",
  "🍒", "🥑", "🌽", "🥕", "🍕", "🍔", "🍟", "🍿",
  "🎂", "☕", "⚽", "🏀", "🎾", "🎸", "🎺", "🎨",
  "🚗", "🚕", "🚀", "✈️", "⛵", "🚲", "⏰", "💡",
  "🔑", "🔒", "🎁", "💎", "🔔", "⭐", "🌈", "🔥",
];

export async function deriveSafetyCode(publicKeyBase64) {
  if (!publicKeyBase64) return null;

  const digest = await crypto.subtle.digest(
    E2E_SAFETY_CODE.hash,
    base64ToArrayBuffer(publicKeyBase64),
  );
  const bytes = new Uint8Array(digest).slice(0, E2E_SAFETY_CODE.bits / 8);

  // Walk the 48 bits six at a time for the emoji; the hex is the same bytes.
  let bitBuffer = 0;
  let bitCount = 0;
  const emoji = [];
  for (const byte of bytes) {
    bitBuffer = (bitBuffer << 8) | byte;
    bitCount += 8;
    while (bitCount >= 6) {
      bitCount -= 6;
      emoji.push(SAFETY_EMOJI[(bitBuffer >> bitCount) & 0x3f]);
    }
  }

  const hex = [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
  return {
    emoji,
    // Grouped in fours for readability; derived from the digest length so the
    // grouping follows E2E_SAFETY_CODE.bits rather than assuming 48.
    hex: (hex.match(/.{1,4}/g) || []).join("-").toUpperCase(),
  };
}
