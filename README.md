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

## Reproduce the build

The site does not compile its own copy of this source. It fetches a prebuilt
artifact, and that artifact is what you can check:

```bash
npm ci
npm run build:dist
sha256sum dist/1.1.0/index.mjs dist/1.1.0/cryptoWorker.js
```

Compare those digests with the `dist` section of
[`crypto-manifest.json`](crypto-manifest.json), and with what your browser
actually loaded:

```bash
curl -s https://getfileshare.cloud/crypto/1.1.0/index.mjs | sha256sum
curl -s https://getfileshare.cloud/crypto/1.1.0/cryptoWorker.js | sha256sum
```

Four digests, one value. If they agree, the encryption running in your browser
is built from the source in this repository — not a copy of it, and not a
description of it.

You can watch it happen: open DevTools → Network on the upload or transfer
page and you will see `index.mjs` fetched from `/crypto/1.1.0/`. It is not
minified, so you can read it.

**Why it reproduces.** esbuild and hash-wasm are pinned to exact versions, not
ranges; there is no minification, sourcemap, banner or timestamp; and
`.gitattributes` forces LF, so a Windows checkout and a Linux one feed the
bundler identical bytes. Two builds of the same commit produce the same bytes
on any machine — which is the only reason a published hash means anything.

---

## What this does not prove

Stated plainly, because a verification repository that overclaims is worse
than none.

**It does not prove the application hands your password to this code and
nothing else.** The password field and the upload flow live in the closed-source
application. The crypto here being correct and reproducible does not rule out
code elsewhere reading the password before encryption happens. This is now the
sharpest remaining limit, and the one the reproducible build does not touch.

**It does not prove the application chose to call this artifact.** You can see
that your browser fetched it, and that its bytes match. What you cannot see
from here is that nothing else ran instead. The network tab is the evidence
available: a second crypto implementation would have to come from somewhere,
and the page's Content Security Policy confines it to same-origin code.

**It does not prove the application passes your password to this code and
nothing else.** The password field and upload flow live in the closed-source
application. The crypto here being correct does not rule out code elsewhere
copying the password before encryption happens.

**Direct (E2E) transfers leave no artifact to inspect.** Nothing is stored, so
there is nothing to decrypt afterwards. The evidence available there is the
safety code shown on both devices, which rules out a substituted key, and your
browser's network tab.

The first of these used to read "we cannot show the bundle you received was
produced from this source". The reproducible build above closes that gap; what
remains above is what it does not close.

---

## Versioning

Releases are tagged. The site records which release it ships in its copy of
`crypto-manifest.json`. Any change to a KDF parameter, cipher, IV size, AAD
format or chunk layout is a breaking change to decryption and gets a major
version.

## Reporting a problem

Security issues: https://getfileshare.cloud/contact — please do not open a
public issue for a vulnerability.

## Licence

MIT — see [LICENSE](LICENSE). The point of publishing this is that you can read
it, run it and check it; the licence lets you reuse the decryptor too.
