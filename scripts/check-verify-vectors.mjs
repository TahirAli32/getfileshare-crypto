/**
 * Fails if verify/vectors.json no longer matches src/cryptoPassword.js.
 *
 * The published vectors are the evidence behind "you can check this yourself".
 * If someone changes a KDF parameter and the vectors are not regenerated, the
 * published evidence quietly becomes false — worse than publishing nothing,
 * because a reader who runs check_vectors.py gets a failure and concludes the
 * implementation is broken.
 *
 * Only the KDF half is checked here, because it is the only deterministic
 * part: AES-GCM draws a fresh random IV per chunk, so ciphertext can never be
 * reproduced byte for byte. That is fine — a KDF parameter change is exactly
 * the drift this needs to catch, and check_vectors.py covers the cipher path
 * by decrypting.
 *
 * Run: node scripts/check-verify-vectors.mjs
 */

import { readFileSync } from "node:fs";
import { argon2id } from "hash-wasm";

const VECTORS = new URL("../verify/vectors.json", import.meta.url);

function decodeBase64url(value) {
  return new Uint8Array(Buffer.from(value.replace(/-/g, "+").replace(/_/g, "/"), "base64"));
}

let doc;
try {
  doc = JSON.parse(readFileSync(VECTORS, "utf8"));
} catch (error) {
  console.error(`\n  verify/vectors.json is missing or unreadable: ${error.message}`);
  console.error("  Run: node scripts/gen-verify-vectors.mjs\n");
  process.exit(1);
}

const failures = [];

for (const vector of doc.vectors || []) {
  const { kdf } = vector;
  const actual = await argon2id({
    password: vector.password,
    salt: decodeBase64url(vector.salt),
    parallelism: kdf.parallelism,
    iterations: kdf.iterations,
    memorySize: kdf.memoryKiB,
    hashLength: kdf.hashLength,
    outputType: "binary",
  });

  const actualHex = Buffer.from(actual).toString("hex");
  if (actualHex !== kdf.expectedKeyHex) {
    failures.push(
      `  ${vector.name}: published key no longer reproduces\n` +
        `    published ${kdf.expectedKeyHex}\n` +
        `    actual    ${actualHex}`,
    );
  }
}

if (failures.length) {
  console.error("\n  Published test vectors are stale:\n");
  console.error(failures.join("\n"));
  console.error("\n  Regenerate: node scripts/gen-verify-vectors.mjs\n");
  process.exit(1);
}

console.log(`Verify vectors OK (${(doc.vectors || []).length} checked against hash-wasm).`);
