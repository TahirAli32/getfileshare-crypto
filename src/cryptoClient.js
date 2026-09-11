/* Main-thread front end for cryptoWorker.js.
   Exposes exactly the signatures the transfer code already used, so the call
   sites in useSocket.jsx did not have to change: swap the import, keep the
   awaits. If a worker cannot be created — SSR, a locked-down browser, a CSP
   that blocks blob/module workers — every call quietly runs the same
   operation on the main thread instead. Slower, never broken. */

import {
  encryptChunkRaw as encryptChunkRawInline,
  decryptChunkRaw as decryptChunkRawInline,
} from "./crypto.js";

let workerPromise = null;
let workerFailed = false;

const pending = new Map();
let nextId = 1;

function spawnWorker() {
  if (workerFailed) return null;
  if (typeof window === "undefined" || typeof Worker === "undefined") {
    workerFailed = true;
    return null;
  }

  try {
    const worker = new Worker(new URL("./cryptoWorker.js", import.meta.url), {
      type: "module",
    });

    worker.onmessage = (event) => {
      const { id, ok, error, iv, data } = event.data;
      const entry = pending.get(id);
      if (!entry) return;
      pending.delete(id);
      if (ok) entry.resolve({ iv, data });
      else entry.reject(new Error(error));
    };

    // A worker that dies takes its in-flight work with it. Fail those calls
    // rather than leaving their promises dangling, and send everything after
    // this point down the inline path.
    worker.onerror = () => {
      workerFailed = true;
      workerPromise = null;
      for (const entry of pending.values()) {
        entry.reject(new Error("Crypto worker failed"));
      }
      pending.clear();
    };

    return worker;
  } catch {
    workerFailed = true;
    return null;
  }
}

function getWorker() {
  if (workerFailed) return null;
  if (!workerPromise) workerPromise = spawnWorker();
  return workerPromise;
}

function call(worker, message, transfer) {
  return new Promise((resolve, reject) => {
    const id = nextId++;
    pending.set(id, { resolve, reject });
    try {
      worker.postMessage({ id, ...message }, transfer);
    } catch (error) {
      pending.delete(id);
      reject(error);
    }
  });
}

export async function encryptChunkRaw(aesKey, chunkBuffer, sequence) {
  const worker = getWorker();
  if (!worker) return encryptChunkRawInline(aesKey, chunkBuffer, sequence);

  try {
    // Deliberately NOT transferred. Handing the buffer over would save a copy,
    // but it also detaches it here — so if the worker then dies, the fallback
    // below would be handed an empty buffer and the transfer would fail
    // instead of degrading. One memcpy per chunk is worth that guarantee.
    return await call(worker, {
      op: "encrypt",
      aesKey,
      sequence,
      data: chunkBuffer,
    });
  } catch {
    return encryptChunkRawInline(aesKey, chunkBuffer, sequence);
  }
}

export async function decryptChunkRaw(aesKey, iv, data, sequence) {
  const worker = getWorker();
  if (!worker) return decryptChunkRawInline(aesKey, iv, data, sequence);

  // `data` is a view into the received frame, which still owns other views —
  // detaching it would break them, so this one is copied rather than
  // transferred. One memcpy per chunk, against a whole AES pass moved off the
  // main thread.
  const copy = data.slice(0);

  try {
    const result = await call(worker, {
      op: "decrypt",
      aesKey,
      sequence,
      iv,
      data: copy,
    });
    return result.data;
  } catch (error) {
    // A bad auth tag must stay an error — only a dead worker warrants a retry
    // on the main thread.
    if (workerFailed) return decryptChunkRawInline(aesKey, iv, data, sequence);
    throw error;
  }
}

/* Relay-path variants. Same crypto, base64 in and out, because that path
   carries chunks as JSON through socket.io. */
export async function encryptChunk(aesKey, chunkBuffer, sequence) {
  const { iv, data } = await encryptChunkRaw(aesKey, chunkBuffer, sequence);
  return { iv: toBase64(iv), data: toBase64(data) };
}

export async function decryptChunk(aesKey, encryptedChunk, sequence) {
  return decryptChunkRaw(
    aesKey,
    new Uint8Array(fromBase64(encryptedChunk.iv)),
    fromBase64(encryptedChunk.data),
    sequence,
  );
}

function toBase64(buffer) {
  const bytes = new Uint8Array(buffer);
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary);
}

function fromBase64(base64) {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
  return bytes.buffer;
}
