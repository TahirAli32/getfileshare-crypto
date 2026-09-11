/**
 * Single source of truth for every technical claim the app makes about its
 * cryptography.
 *
 * Two rules keep this honest:
 *
 *   1. `src/crypto.js` imports its algorithm parameters from here, so the
 *      numbers quoted on the marketing pages are the numbers the code actually
 *      runs. Changing the modulus size or the cipher changes the copy with it.
 *   2. No page, guide, or component may hand-write an algorithm name, key
 *      size, or protocol description. Import the label from here instead.
 *
 * The reason both rules exist: a public review of the site found the security
 * page and the E2E guide describing different protocols, and the security page
 * crediting end-to-end protection to WebRTC DTLS — which is transport
 * encryption for one hop, not end-to-end encryption at all. That kind of drift
 * is invisible in a build and corrosive to a product whose whole claim is that
 * you don't have to trust us.
 */

/* ── E2E transfer: the browser-to-browser path ── */

export const E2E_KEY_EXCHANGE = Object.freeze({
  algorithm: "RSA-OAEP",
  modulusBits: 2048,
  hash: "SHA-256",
  publicExponent: 65537,
  /* The private key is generated non-extractable, so the browser itself
     refuses to hand it out — not merely "our code doesn't ask for it". */
  privateKeyExtractable: false,
  label: "RSA-2048",
  fullLabel: "RSA-2048 (RSA-OAEP, SHA-256)",
});

export const E2E_CHUNK_CIPHER = Object.freeze({
  algorithm: "AES-GCM",
  keyBits: 256,
  ivBits: 96,
  /* The chunk's sequence number is bound in as additional authenticated data,
     so chunks cannot be reordered, duplicated, or moved between transfers. */
  authenticatesSequence: true,
  label: "AES-256-GCM",
  fullLabel: "AES-256-GCM (fresh 96-bit IV per chunk, sequence number authenticated)",
});

export const E2E_INTEGRITY = Object.freeze({
  fileHash: "SHA-256",
  label: "SHA-256 whole-file verification",
});

export const E2E_SAFETY_CODE = Object.freeze({
  hash: "SHA-256",
  bits: 48,
  emojiCount: 8,
  hexChars: 12,
  label: "Safety code",
});

export const E2E_TRANSPORT = Object.freeze({
  direct: {
    label: "WebRTC data channel",
    /* DTLS is what protects the connection. It is NOT what makes the transfer
       end-to-end — the AES-GCM layer above it is. Saying otherwise is the
       specific error this file exists to prevent. */
    transportSecurity: "DTLS",
    /* The correct stack for a data channel. SRTP secures audio/video media and
       has nothing to do with file transfer — citing it is simply wrong, and
       check-crypto-claims.mjs fails the build if it reappears. */
    stack: ["WebRTC data channel", "SCTP", "DTLS"],
    stackLabel: "WebRTC data channel → SCTP → DTLS",
    note: "Additional transport encryption on top of the AES-GCM layer, not a substitute for it.",
  },
  relay: {
    label: "Encrypted socket relay",
    note: "Used when a direct connection is impossible (strict firewalls, symmetric NAT, mobile CGNAT). Carries the same ciphertext; the server holds no key that opens it.",
  },
});

/* ── Password-protected cloud uploads: a different product ── */

export const CLOUD_PASSWORD = Object.freeze({
  kdf: "Argon2id",
  cipher: "AES-GCM",
  keyBits: 256,
  label: "AES-256-GCM",
  kdfLabel: "Argon2id",
  fullLabel: "AES-256-GCM with Argon2id key derivation",
});

/* ── Ready-made sentences, so no two pages phrase it differently ── */

/* The limits of the claim. A security page that states only the strong form
   ("we cannot read your files") overstates what any browser-delivered crypto
   can promise, because we serve the JavaScript that does the encrypting. State
   the architectural claim, then state the residual trust plainly. */
export const TRUST_MODEL = Object.freeze({
  architecturalClaim:
    "The system is designed so that our servers never hold a key that could decrypt your files. " +
    "On the direct path the file data never reaches us at all; on the relay path it passes through as ciphertext.",

  residualTrust:
    "That holds as long as the code running in your browser is the code we describe — and we are the ones who serve it. " +
    "This is the unavoidable limit of in-browser encryption: a compromised or malicious deployment could serve a build " +
    "that copies your file before encrypting it. No amount of AES or RSA changes that.",

  whatYouCanCheck:
    "Two things are checkable without trusting us: compare the safety code with the other device, which rules out a " +
    "substituted key; and watch the network traffic in your browser's developer tools, where the relay path shows " +
    "ciphertext and the direct path shows no file data reaching our servers at all.",

  buildEnforcement:
    "The algorithm names and key sizes on this page aren't hand-typed marketing copy — every page that states a crypto " +
    "claim imports it from the same source the encryption code itself uses, and an automated build check fails the " +
    "build if the two ever drift apart.",
});

export const CRYPTO_COPY = Object.freeze({
  e2eShort: `${E2E_CHUNK_CIPHER.label} per chunk, key wrapped with ${E2E_KEY_EXCHANGE.label}`,

  e2eProtocol:
    `The receiving browser generates a per-session ${E2E_KEY_EXCHANGE.fullLabel} key pair. ` +
    `The sender wraps a random ${E2E_CHUNK_CIPHER.keyBits}-bit AES key with that public key, then encrypts ` +
    `every chunk with ${E2E_CHUNK_CIPHER.label} before it leaves the device.`,

  e2eKeyCustody:
    "The private key is generated inside the receiving browser, is non-extractable, " +
    "and is destroyed when the tab closes. It is never transmitted.",

  e2eIntegrity:
    `Each chunk carries a GCM authentication tag with its sequence number authenticated alongside it, ` +
    `and a ${E2E_INTEGRITY.fileHash} hash of the whole file is verified on arrival.`,

  e2eTransport:
    `Files travel over a ${E2E_TRANSPORT.direct.label}, which adds ${E2E_TRANSPORT.direct.transportSecurity} ` +
    `transport encryption on top. ${E2E_TRANSPORT.direct.note}`,

  e2eRelay:
    `If a direct connection is impossible, chunks are relayed through our server — still as ciphertext ` +
    `we hold no key for. The relay is a bridge, not a reader.`,

  safetyCode:
    `Both devices display a fingerprint of the public key each is actually using, as ` +
    `${E2E_SAFETY_CODE.emojiCount} emoji and ${E2E_SAFETY_CODE.hexChars} hex characters. ` +
    `Comparing them rules out a substituted key — the one attack encryption alone cannot prevent.`,

  cloudPassword:
    `For password-protected cloud uploads, your passphrase becomes a ${CLOUD_PASSWORD.keyBits}-bit key ` +
    `in the browser via ${CLOUD_PASSWORD.kdf}. The password and key never leave your device.`,
});
