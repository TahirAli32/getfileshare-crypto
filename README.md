# getfileshare-crypto

The client-side encryption used by [GetFileShare](https://getfileshare.cloud),
published so it can be read, reviewed, and independently verified.

The GetFileShare application itself is closed source. This repository is the
part that does not need to be: the code that encrypts your files, the exact
parameters it uses, and tools to check them without trusting us.

GetFileShare is new and **has not had an independent security audit.** This
repository exists so you do not have to take the encryption on faith.

---

## How this repository relates to the site

A published copy of crypto code is only worth something if it is the code
actually running. So the link is enforced, not promised:

- [`crypto-manifest.json`](crypto-manifest.json) records the SHA-256 of every
  file in `src/`.
- The GetFileShare application keeps a copy of that manifest and **refuses to
  build** if its own crypto files hash differently.
- A change to the site's encryption therefore has to land here first. This
  repository leads; the application follows.

What that guarantees, precisely: **the source code the site is built from
contains exactly this crypto.** It does not, on its own, prove the JavaScript
served to your browser was built from that source — see
[What this does not prove](#what-this-does-not-prove).

---

## What is here

```
src/
  cryptoPassword.js   password-protected cloud uploads: Argon2id + AES-256-GCM
  crypto.js           direct E2E transfers: RSA-OAEP key wrap + AES-256-GCM chunks
  cryptoClient.js     E2E helpers built on crypto.js
  cryptoWorker.js     E2E chunk encryption off the main thread
  data/cryptoSpec.js  single source of truth for every algorithm name and
                      parameter the site states publicly
verify/
  decrypt.py          decrypt a password-protected upload offline
  check_vectors.py    check the published test vectors independently
  vectors.json        test vectors generated from src/cryptoPassword.js
scripts/
  gen-verify-vectors.mjs    regenerate vectors.json from the real module
  check-verify-vectors.mjs  fail if vectors.json has drifted from the code
  build-manifest.mjs        write / check crypto-manifest.json
```

`src/data/cryptoSpec.js` is worth reading first. Its header explains why it
exists: every claim the site makes about its cryptography is imported from it,
and the site's build fails if any page hand-writes one instead.

---

## Verify it yourself

See [`verify/README.md`](verify/README.md). In short:

```bash
cd verify
pip install -r requirements.txt
python check_vectors.py
```

That re-derives every published key with `argon2-cffi` and decrypts every
published ciphertext with `pyca/cryptography` — libraries with no connection to
us. It also confirms that a wrong password is rejected and that a chunk moved
to the wrong position fails authentication.

---

## What this does not prove

Stated plainly, because a verification repository that overclaims is worse
than none.

**It does not prove the JavaScript your browser ran was built from this
source.** We serve that JavaScript. The manifest guarantees the site's *source*
contains this crypto; it cannot show that the *bundle* you received was
produced from it. A compromised deployment could serve different code.

**It does not prove the application passes your password to this code and
nothing else.** The password field and upload flow live in the closed-source
application. The crypto here being correct does not rule out code elsewhere
copying the password before encryption happens.

**Direct (E2E) transfers leave no artifact to inspect.** Nothing is stored, so
there is nothing to decrypt afterwards. The evidence available there is the
safety code shown on both devices, which rules out a substituted key, and your
browser's network tab.

Published build hashes are planned to narrow the first of these. They are not
shipped yet, and this section will change when they are.

---

## Versioning

Releases are tagged. The site records which release it ships in its copy of
`crypto-manifest.json`. Any change to a KDF parameter, cipher, IV size, AAD
format or chunk layout is a breaking change to decryption and gets a major
version.

## Reporting a problem

Security issues: https://getfileshare.cloud/contact — please do not open a
public issue for a vulnerability.
