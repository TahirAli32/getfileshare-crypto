#!/usr/bin/env python3
"""
Decrypt a GetFileShare encrypted download, offline.

This script talks to nothing. Given the encrypted object and its metadata
sidecar, it recovers the original file using only your password — no network,
no API key, no GetFileShare code involved.

    python decrypt.py myfile.pdf.enc

It looks for myfile.pdf.enc.meta.json beside the .enc file, or pass --meta.

What a successful run demonstrates
----------------------------------
  * the object stored in our object storage is ciphertext, not your file;
  * that ciphertext really is AES-256-GCM with an Argon2id-derived key;
  * the key comes from your password and the public salt, and nothing else —
    no server-held key material is involved anywhere;
  * your data is recoverable without us.

What it does NOT demonstrate
----------------------------
  It says nothing about the browser code that produced the ciphertext. We
  serve that JavaScript, so this cannot rule out a compromised build that
  uploaded correct ciphertext and separately leaked your password. That is a
  different problem, addressed by published build hashes.

Requires: pip install -r requirements.txt
"""

from __future__ import annotations

import argparse
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

# Must match src/cryptoPassword.js. Changing any of these breaks decryption.
ARGON2_MEMORY_KIB = 65536      # 64 MiB
ARGON2_ITERATIONS = 3
ARGON2_PARALLELISM = 1
ARGON2_HASH_LENGTH = 32        # -> AES-256 key
IV_BYTES = 12
GCM_TAG_BYTES = 16
OVERHEAD = IV_BYTES + GCM_TAG_BYTES   # 28 bytes per chunk


def b64url_decode(value: str) -> bytes:
    """base64url with the padding the browser omits (RFC 4648 section 5)."""
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def derive_key(password: str, salt: bytes) -> bytes:
    """Argon2id, with exactly the parameters the browser used."""
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=ARGON2_ITERATIONS,
        memory_cost=ARGON2_MEMORY_KIB,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LENGTH,
        type=Type.ID,
    )


def decrypt_blob(blob: bytes, password: str, salt_b64: str, chunk_size: int, size: int) -> bytes:
    """
    Reassemble and decrypt.

    Chunks sit contiguously with no header. Chunk n holds
    min(chunk_size, size - n*chunk_size) plaintext bytes plus 28 bytes of
    overhead, and its GCM tag is bound to "chunk-<n>" as additional
    authenticated data — so a reordered or spliced chunk fails to authenticate
    rather than silently producing garbage.
    """
    aes = AESGCM(derive_key(password, b64url_decode(salt_b64)))
    total_chunks = math.ceil(size / chunk_size)
    out = bytearray()

    for index in range(total_chunks):
        plain_len = min(chunk_size, size - index * chunk_size)
        start = index * (chunk_size + OVERHEAD)
        block = blob[start : start + plain_len + OVERHEAD]

        if len(block) != plain_len + OVERHEAD:
            sys.exit(
                f"Chunk {index} is truncated: expected {plain_len + OVERHEAD} bytes, "
                f"found {len(block)}. The encrypted file looks incomplete."
            )

        try:
            out += aes.decrypt(
                block[:IV_BYTES], block[IV_BYTES:], f"chunk-{index}".encode("utf-8")
            )
        except Exception:
            if index == 0:
                sys.exit("Decryption failed. The password is almost certainly wrong.")
            sys.exit(
                f"Chunk {index} failed authentication. The password is correct for "
                f"earlier chunks, so the file is likely corrupted or truncated."
            )

        done = index + 1
        print(f"\r  decrypting {done}/{total_chunks} chunks", end="", file=sys.stderr)

    print("", file=sys.stderr)
    return bytes(out)


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Decrypt a GetFileShare encrypted download, entirely offline."
    )
    parser.add_argument("encrypted", type=Path, help="the .enc file you downloaded")
    parser.add_argument("--meta", type=Path, help="metadata JSON (default: <encrypted>.meta.json)")
    parser.add_argument("--out", type=Path, help="output path (default: the original filename)")
    parser.add_argument("--password", help="prompted for if omitted")
    args = parser.parse_args()

    meta_path = args.meta or Path(f"{args.encrypted}.meta.json")
    if not args.encrypted.is_file():
        sys.exit(f"Not found: {args.encrypted}")
    if not meta_path.is_file():
        sys.exit(f"Metadata not found: {meta_path}\nPass it explicitly with --meta.")

    meta = json.loads(meta_path.read_text(encoding="utf-8"))

    for field in ("salt", "chunkSize", "size"):
        if field not in meta:
            sys.exit(f"Metadata is missing '{field}'.")

    if meta.get("algorithm", "AES-256-GCM") != "AES-256-GCM" or meta.get("kdf", "argon2id") != "argon2id":
        sys.exit(
            f"This file uses {meta.get('kdf')} + {meta.get('algorithm')}, which this "
            f"version of the script does not implement."
        )

    password = args.password
    if not password:
        import getpass
        password = getpass.getpass("Password: ")

    blob = args.encrypted.read_bytes()
    expected = meta["size"] + math.ceil(meta["size"] / meta["chunkSize"]) * OVERHEAD
    if len(blob) != expected:
        print(
            f"Warning: expected {expected} encrypted bytes for a {meta['size']}-byte "
            f"file, found {len(blob)}. Continuing anyway.",
            file=sys.stderr,
        )

    plaintext = decrypt_blob(blob, password, meta["salt"], meta["chunkSize"], meta["size"])

    out_path = args.out or Path(meta.get("fileName") or "decrypted.bin")
    if out_path.exists() and not args.out:
        sys.exit(f"{out_path} already exists. Choose another name with --out.")
    out_path.write_bytes(plaintext)

    print(f"\nDecrypted {len(plaintext):,} bytes -> {out_path}")
    print(f"SHA-256: {hashlib.sha256(plaintext).hexdigest()}")
    if meta.get("sha256"):
        match = hashlib.sha256(plaintext).hexdigest() == meta["sha256"]
        print("Matches the hash recorded at upload." if match else "WARNING: hash mismatch!")


if __name__ == "__main__":
    main()
