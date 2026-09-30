/**
 * The public surface of @getfileshare/crypto, and the entry point the
 * distributable bundle is built from.
 *
 * This file exists so there is exactly one answer to "what crypto does the
 * site run?". scripts/build-dist.mjs bundles it into a single self-contained
 * ESM file; the application loads that file at runtime rather than compiling
 * its own copy of these sources. That is what makes the published hash
 * meaningful: the bytes your browser fetches are the bytes this repository
 * builds, not a bundler's rendering of a copy that happened to match.
 *
 * Exports are listed by name rather than re-exported wholesale, because
 * crypto.js and cryptoClient.js deliberately export the same four names.
 */

/* The chunk cipher, worker-backed. cryptoClient mirrors crypto.js's
   signatures exactly and falls back to the main thread when a worker cannot
   be created, so these names must win over the direct implementations below —
   getting this precedence backwards would silently move per-chunk AES onto
   the main thread and freeze the UI on large files. */
export {
  encryptChunk,
  decryptChunk,
  encryptChunkRaw,
  decryptChunkRaw,
} from "./cryptoClient.js";

/* Key exchange, hashing and the safety code. These stay on the calling thread:
   they are WebCrypto calls on small inputs, where the cost of posting to a
   worker would exceed the work itself. */
export {
  generateReceiverKeyPair,
  exportPublicKey,
  importPublicKey,
  generateAesKey,
  encryptAesKeyWithPublicKey,
  decryptAesKeyWithPrivateKey,
  sha256File,
  sha256Blob,
  deriveSafetyCode,
} from "./crypto.js";

/* Password-based encryption for cloud uploads: Argon2id, then AES-256-GCM. */
export * from "./cryptoPassword.js";

/* The parameters every one of the above actually uses, and the copy the site
   states them in — exported so the application can never describe the crypto
   in terms that differ from the crypto it runs. */
export * from "./data/cryptoSpec.js";
