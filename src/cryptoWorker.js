/* AES-GCM chunk crypto, off the main thread.
   Encrypting a 200 MB file is thousands of subtle.crypto calls; on the main
   thread they compete with React re-renders and with the loop that pumps the
   data channel, which is where the throughput sawtooth and the UI jank both
   come from. The worker does nothing else, so neither can starve the other.

   CryptoKey survives structured clone, so the key is posted with each call
   rather than kept in worker state — no key lifecycle to get wrong, and no
   stale key after a transfer is torn down and restarted. */

import { E2E_CHUNK_CIPHER } from "./data/cryptoSpec.js";

function aad(sequence) {
  return new TextEncoder().encode(String(sequence));
}

self.onmessage = async (event) => {
  const { id, op, aesKey, sequence, iv, data } = event.data;

  try {
    if (op === "encrypt") {
      const nonce = crypto.getRandomValues(
        new Uint8Array(E2E_CHUNK_CIPHER.ivBits / 8),
      );
      const result = await crypto.subtle.encrypt(
        {
          name: E2E_CHUNK_CIPHER.algorithm,
          iv: nonce,
          additionalData: aad(sequence),
        },
        aesKey,
        data,
      );
      // The result buffer is created here and never touched again, so it can
      // be handed over rather than copied.
      self.postMessage({ id, ok: true, iv: nonce, data: result }, [result]);
      return;
    }

    if (op === "decrypt") {
      const result = await crypto.subtle.decrypt(
        {
          name: E2E_CHUNK_CIPHER.algorithm,
          iv,
          additionalData: aad(sequence),
        },
        aesKey,
        data,
      );
      self.postMessage({ id, ok: true, data: result }, [result]);
      return;
    }

    self.postMessage({ id, ok: false, error: `Unknown op: ${op}` });
  } catch (error) {
    // AES-GCM decrypt throws a bare OperationError on a bad tag; keep the
    // shape stable so the caller can surface something meaningful.
    self.postMessage({
      id,
      ok: false,
      error: error?.message || "Crypto operation failed",
    });
  }
};
