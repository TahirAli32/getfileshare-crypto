// src/data/cryptoSpec.js
var E2E_KEY_EXCHANGE = Object.freeze({
  algorithm: "RSA-OAEP",
  modulusBits: 2048,
  hash: "SHA-256",
  publicExponent: 65537,
  /* The private key is generated non-extractable, so the browser itself
     refuses to hand it out — not merely "our code doesn't ask for it". */
  privateKeyExtractable: false,
  label: "RSA-2048",
  fullLabel: "RSA-2048 (RSA-OAEP, SHA-256)"
});
var E2E_CHUNK_CIPHER = Object.freeze({
  algorithm: "AES-GCM",
  keyBits: 256,
  ivBits: 96,
  /* The chunk's sequence number is bound in as additional authenticated data,
     so chunks cannot be reordered, duplicated, or moved between transfers. */
  authenticatesSequence: true,
  label: "AES-256-GCM",
  fullLabel: "AES-256-GCM (fresh 96-bit IV per chunk, sequence number authenticated)"
});
var E2E_INTEGRITY = Object.freeze({
  fileHash: "SHA-256",
  label: "SHA-256 whole-file verification"
});
var E2E_SAFETY_CODE = Object.freeze({
  hash: "SHA-256",
  bits: 48,
  emojiCount: 8,
  hexChars: 12,
  label: "Safety code"
});
var E2E_TRANSPORT = Object.freeze({
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
    stackLabel: "WebRTC data channel \u2192 SCTP \u2192 DTLS",
    note: "Additional transport encryption on top of the AES-GCM layer, not a substitute for it."
  },
  relay: {
    label: "Encrypted socket relay",
    /* Two reasons, and the second one is easy to forget in copy: below
       NEXT_PUBLIC_WEBRTC_MIN_BYTES the app does not attempt a peer connection
       at all, because ICE negotiation would take longer than the transfer.
       Saying "only when a direct connection fails" is therefore wrong. */
    note: "Used when a direct connection is impossible (strict firewalls, symmetric NAT, mobile CGNAT), and for transfers small enough that negotiating a peer connection would take longer than sending the file. Carries the same ciphertext; the server holds no key that opens it."
  },
  /* A "direct" WebRTC connection is not always a straight line between the two
     devices: when NAT blocks a peer route, ICE falls back to routing the media
     through our own coturn server. The payload is still AES-GCM ciphertext
     inside DTLS, but "the bytes never reach our infrastructure" is not true of
     a TURN-relayed session, so no page may claim it without this caveat. */
  turn: {
    label: "TURN relay",
    note: "Some peer connections cannot find a direct route and are relayed by our TURN server instead. It forwards packets that are already encrypted twice over \u2014 your AES-GCM ciphertext inside the connection's own DTLS \u2014 and holds no key for either layer."
  }
});
var CLOUD_PASSWORD = Object.freeze({
  kdf: "Argon2id",
  cipher: "AES-GCM",
  keyBits: 256,
  label: "AES-256-GCM",
  kdfLabel: "Argon2id",
  fullLabel: "AES-256-GCM with Argon2id key derivation"
});
var TRUST_MODEL = Object.freeze({
  architecturalClaim: "The system is designed so that our servers never hold a key that could decrypt your files. On a direct peer connection the file data never reaches us at all. When one cannot be established \u2014 or the transfer is too small to be worth negotiating one \u2014 it passes through our relay, and a peer connection that cannot find a direct route is carried by our TURN server. In every one of those cases what we handle is ciphertext we hold no key for.",
  /* "Zero-knowledge" is a claim about file CONTENT and nothing else. Said
     without this qualifier it reads as "they know nothing about me", which is
     false on both modes — the name, size, type, timings and both IP addresses
     are ordinary readable records. Every page that uses the phrase must pair
     it with this sentence. */
  zeroKnowledgeScope: "Zero-knowledge describes the file's contents, not the transfer. The server still reads and stores the surrounding record \u2014 file size and type, the file name on cloud uploads, who uploaded it and when, and the IP address and browser of each side \u2014 and keeps it for the periods published in the privacy policy, not indefinitely.",
  /* Narrowed deliberately when the verifiable build shipped. The old wording
     said a malicious deployment could serve a build that copies your file and
     you would have no way to tell. The first half is still true of any web
     app; the second is not true here any more, and leaving it would have been
     underclaiming — which costs credibility exactly as overclaiming does. */
  residualTrust: "That holds as long as the code running in your browser is the code we describe. For the encryption itself you no longer have to take that on trust: it is served as a published build you can reproduce byte for byte and compare against what your browser loaded. What remains is the application around it, which is closed source \u2014 it is what hands your file and your password to that code, and nothing here proves it does not read them first.",
  whatYouCanCheck: "Three things are checkable without trusting us: rebuild the published encryption yourself and compare its hash with the file your browser loaded; compare the safety code with the other device, which rules out a substituted key; and watch the network traffic in your browser's developer tools, which also tells you which path a given transfer actually took \u2014 a relayed transfer shows ciphertext frames on the WebSocket, and a direct one shows no file data leaving for our servers at all.",
  /* Precise about what the check actually does. It is a lint: it fails the
     build when a page hardcodes an algorithm name instead of importing it.
     It does not compare the spec against the code, so it cannot catch a
     cipher being changed in crypto.js and the label left behind. */
  buildEnforcement: "The algorithm names and key sizes on this page aren't hand-typed marketing copy \u2014 the direct-transfer encryption code reads its parameters from the same file this page quotes, and an automated build check fails the build if any page states a crypto claim of its own instead of importing it from there."
});
var VERIFIABLE_BUILD = Object.freeze({
  version: "1.2.0",
  repository: "https://github.com/TahirAli32/getfileshare-crypto",
  digestAlgorithm: "SHA-256",
  headline: "Verifiable build",
  claim: "The encryption is not compiled into this site. Your browser fetches it as one published file, built from public source by a build anyone can repeat byte for byte \u2014 so you can check that the code encrypting your file is the code we published, rather than taking our word for it.",
  /* Written as something a reader can actually carry out in a few minutes.
     Instructions nobody can follow are decoration, not evidence. */
  steps: Object.freeze([
    "Open your browser's developer tools, reload, and find the crypto file it fetched. It is not minified \u2014 you can read it.",
    "Hash that file.",
    "Clone the public repository, run the build, and hash what it produces.",
    "The two digests match, or something is wrong and you should not trust this site."
  ]),
  reproducibility: "The build pins its compiler and its dependencies to exact versions, emits no timestamps and does not minify, so two builds of the same source produce identical bytes on any machine. Without that, a published hash would mean nothing \u2014 it could never be reproduced to contradict.",
  limit: "This proves the encryption is the published code. It does not prove the closed-source page around it hands your file and password to that code untouched \u2014 which is now the sharpest limit left, and the honest thing to say beside the claim."
});
var CRYPTO_COPY = Object.freeze({
  e2eShort: `${E2E_CHUNK_CIPHER.label} per chunk, key wrapped with ${E2E_KEY_EXCHANGE.label}`,
  e2eProtocol: `The receiving browser generates a per-session ${E2E_KEY_EXCHANGE.fullLabel} key pair. The sender wraps a random ${E2E_CHUNK_CIPHER.keyBits}-bit AES key with that public key, then encrypts every chunk with ${E2E_CHUNK_CIPHER.label} before it leaves the device.`,
  e2eKeyCustody: "The private key is generated inside the receiving browser, is non-extractable, and is destroyed when the tab closes. It is never transmitted.",
  e2eIntegrity: `Each chunk carries a GCM authentication tag with its sequence number authenticated alongside it, and a ${E2E_INTEGRITY.fileHash} hash of the whole file is verified on arrival.`,
  e2eTransport: `Larger transfers travel over a ${E2E_TRANSPORT.direct.label}, which adds ${E2E_TRANSPORT.direct.transportSecurity} transport encryption on top. ${E2E_TRANSPORT.direct.note}`,
  e2eRelay: `Chunks are relayed through our server when a direct connection is impossible, and for small transfers where negotiating one would take longer than sending the file \u2014 still as ciphertext we hold no key for. The relay is a bridge, not a reader.`,
  e2eTurn: `${E2E_TRANSPORT.turn.note}`,
  safetyCode: `Both devices display a fingerprint of the public key each is actually using, as ${E2E_SAFETY_CODE.emojiCount} emoji and ${E2E_SAFETY_CODE.hexChars} hex characters. Comparing them rules out a substituted key \u2014 the one attack encryption alone cannot prevent.`,
  cloudPassword: `For password-protected cloud uploads, your passphrase becomes a ${CLOUD_PASSWORD.keyBits}-bit key in the browser via ${CLOUD_PASSWORD.kdf}. The password and key never leave your device.`
});

// src/cryptoWorker.js
function aad(sequence) {
  return new TextEncoder().encode(String(sequence));
}
self.onmessage = async (event) => {
  const { id, op, aesKey, sequence, iv, data } = event.data;
  try {
    if (op === "encrypt") {
      const nonce = crypto.getRandomValues(
        new Uint8Array(E2E_CHUNK_CIPHER.ivBits / 8)
      );
      const result = await crypto.subtle.encrypt(
        {
          name: E2E_CHUNK_CIPHER.algorithm,
          iv: nonce,
          additionalData: aad(sequence)
        },
        aesKey,
        data
      );
      self.postMessage({ id, ok: true, iv: nonce, data: result }, [result]);
      return;
    }
    if (op === "decrypt") {
      const result = await crypto.subtle.decrypt(
        {
          name: E2E_CHUNK_CIPHER.algorithm,
          iv,
          additionalData: aad(sequence)
        },
        aesKey,
        data
      );
      self.postMessage({ id, ok: true, data: result }, [result]);
      return;
    }
    self.postMessage({ id, ok: false, error: `Unknown op: ${op}` });
  } catch (error) {
    self.postMessage({
      id,
      ok: false,
      error: error?.message || "Crypto operation failed"
    });
  }
};
