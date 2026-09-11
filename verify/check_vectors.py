#!/usr/bin/env python3
"""
Check the published test vectors against an independent implementation.

    python check_vectors.py

Every vector in vectors.json was produced by the browser code itself
(src/cryptoPassword.js). This script re-derives each key with argon2-cffi and
decrypts each ciphertext with pyca/cryptography — two libraries with no
relationship to ours. If the numbers agree, the published cryptographic
parameters are the ones actually in use.

Note it verifies by DECRYPTING, not by re-encrypting. AES-GCM draws a fresh
random IV for every chunk, so re-encryption can never reproduce the same bytes.

Requires: pip install -r requirements.txt
"""

from __future__ import annotations

import base64
import hashlib
import json
import math
import sys
from pathlib import Path

try:
    from argon2.low_level import Type, hash_secret_raw
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    sys.exit("Missing dependencies. Run:  pip install -r requirements.txt")

OVERHEAD = 28  # 12-byte IV + 16-byte GCM tag


def b64url_decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def check(vector: dict) -> list[str]:
    """Returns a list of failure messages; empty means the vector passed."""
    failures: list[str] = []
    name = vector["name"]
    kdf, cipher = vector["kdf"], vector["cipher"]
    salt = b64url_decode(vector["salt"])

    key = hash_secret_raw(
        secret=vector["password"].encode("utf-8"),
        salt=salt,
        time_cost=kdf["iterations"],
        memory_cost=kdf["memoryKiB"],
        parallelism=kdf["parallelism"],
        hash_len=kdf["hashLength"],
        type=Type.ID,
    )

    if key.hex() == kdf["expectedKeyHex"]:
        print(f"  [ok]   {name}: Argon2id key matches")
    else:
        failures.append(f"{name}: KDF mismatch\n    expected {kdf['expectedKeyHex']}\n    got      {key.hex()}")

    blob = base64.b64decode(cipher["ciphertextBase64"])
    aes = AESGCM(key)
    size, chunk_size = cipher["plaintextSize"], cipher["chunkSize"]
    out = bytearray()

    try:
        for index in range(math.ceil(size / chunk_size)):
            plain_len = min(chunk_size, size - index * chunk_size)
            start = index * (chunk_size + OVERHEAD)
            block = blob[start : start + plain_len + OVERHEAD]
            out += aes.decrypt(block[:12], block[12:], f"chunk-{index}".encode("utf-8"))
    except Exception as error:
        failures.append(f"{name}: decryption failed — {error}")
        return failures

    digest = hashlib.sha256(out).hexdigest()
    if digest == cipher["expectedPlaintextSha256"]:
        print(f"  [ok]   {name}: decrypted {len(out):,} bytes, SHA-256 matches")
    else:
        failures.append(f"{name}: plaintext mismatch\n    expected {cipher['expectedPlaintextSha256']}\n    got      {digest}")

    # A wrong password must fail authentication, not return garbage.
    wrong = AESGCM(
        hash_secret_raw(
            secret=b"definitely not the password", salt=salt,
            time_cost=kdf["iterations"], memory_cost=kdf["memoryKiB"],
            parallelism=kdf["parallelism"], hash_len=kdf["hashLength"], type=Type.ID,
        )
    )
    first = blob[: min(chunk_size, size) + OVERHEAD]
    try:
        wrong.decrypt(first[:12], first[12:], b"chunk-0")
        failures.append(f"{name}: a wrong password decrypted the data")
    except Exception:
        print(f"  [ok]   {name}: wrong password rejected")

    # The AAD binds each chunk to its position, so a reordered chunk must fail.
    try:
        aes.decrypt(first[:12], first[12:], b"chunk-1")
        failures.append(f"{name}: chunk 0 authenticated as chunk 1 — AAD not enforced")
    except Exception:
        print(f"  [ok]   {name}: chunk reordering rejected")

    return failures


def main() -> None:
    path = Path(__file__).with_name("vectors.json")
    if not path.is_file():
        sys.exit("vectors.json not found beside this script.")

    doc = json.loads(path.read_text(encoding="utf-8"))
    vectors = doc["vectors"]
    print(f"Checking {len(vectors)} vectors against argon2-cffi + pyca/cryptography\n")

    failures: list[str] = []
    for vector in vectors:
        failures.extend(check(vector))
        print()

    if failures:
        print("FAILED:\n")
        for failure in failures:
            print(f"  {failure}")
        sys.exit(1)

    print("All vectors verified. The published parameters are the ones in use.")


if __name__ == "__main__":
    main()
