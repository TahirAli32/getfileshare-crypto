/**
 * Builds the distributable bundle that the GetFileShare site actually loads,
 * and records its SHA-256 in crypto-manifest.json.
 *
 * Why this exists
 * ───────────────
 * crypto-manifest.json already hashes the *sources* here, and the application
 * refuses to build if its copy of them differs. That stops the published code
 * and the shipped code drifting — but it proves nothing to a visitor, because
 * the bytes their browser runs are the application's bundler's rendering of
 * those sources, mixed into chunks whose content depends on the whole app.
 * Nobody outside can reproduce those chunks, so their hashes are unverifiable.
 *
 * So the site loads this artifact instead of compiling its own copy. Then the
 * chain closes: fetch the file your browser loaded, hash it, compare it to the
 * hash published here, and rebuild it yourself from this repository to check
 * that hash was not simply asserted.
 *
 * What makes it reproducible
 * ──────────────────────────
 *   - esbuild is pinned to an exact version, not a range: bundler output is
 *     only stable for a fixed compiler.
 *   - hash-wasm is pinned exactly too, and bundled in, so the Argon2id
 *     implementation is covered by the same hash as everything else.
 *   - No minification. An artifact meant to be audited should be readable, and
 *     minifier output is the part of a toolchain most likely to shift between
 *     releases.
 *   - No sourcemap, no banner, no build timestamp — nothing that varies
 *     between two builds of identical inputs.
 *   - .gitattributes forces LF, so a Windows checkout and a Linux one feed the
 *     bundler identical bytes.
 *
 *   node scripts/build-dist.mjs           build and record
 *   node scripts/build-dist.mjs --check   fail if dist or the manifest is stale
 */

import { build } from "esbuild";
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
const OUT_DIR = join(ROOT, "dist", pkg.version);
const MANIFEST = join(ROOT, "crypto-manifest.json");

/* Two entry points, not one. cryptoClient.js starts the worker with
   `new URL("./cryptoWorker.js", import.meta.url)`, which esbuild leaves alone
   as ordinary runtime code — so the worker must land beside index.mjs under
   that exact name for the URL to resolve once served. Bundling the worker
   into index.mjs instead would leave that fetch pointing at nothing. */
const ENTRIES = [
  { in: join(ROOT, "src", "index.js"), out: "index.mjs" },
  { in: join(ROOT, "src", "cryptoWorker.js"), out: "cryptoWorker.js" },
];

/* Raw bytes, deliberately — unlike the source hashes, which normalise line
   endings because CRLF is checkout noise. This artifact is served over HTTP
   and hashed by whoever downloaded it, so the only honest digest is of exactly
   the bytes that travel. */
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");

const isCheck = process.argv.includes("--check");

async function buildAll() {
  rmSync(OUT_DIR, { recursive: true, force: true });
  mkdirSync(OUT_DIR, { recursive: true });

  for (const entry of ENTRIES) {
    await build({
      entryPoints: [entry.in],
      outfile: join(OUT_DIR, entry.out),
      bundle: true,
      format: "esm",
      target: "es2022",
      platform: "browser",
      minify: false,
      sourcemap: false,
      legalComments: "inline",
    });
  }

  return Object.fromEntries(
    ENTRIES.map((entry) => [
      `dist/${pkg.version}/${entry.out}`,
      sha256(readFileSync(join(OUT_DIR, entry.out))),
    ]).sort(([a], [b]) => a.localeCompare(b)),
  );
}

const dist = await buildAll();

const manifest = JSON.parse(readFileSync(MANIFEST, "utf8"));
const updated = { ...manifest, dist };
const serialised = `${JSON.stringify(updated, null, 2)}\n`;

if (isCheck) {
  if (readFileSync(MANIFEST, "utf8") !== serialised) {
    console.error(
      "dist is out of date, or was built from different sources.\n" +
        "Run: node scripts/build-dist.mjs",
    );
    process.exit(1);
  }
  console.log(`dist is current (${Object.keys(dist).length} files, v${pkg.version}).`);
} else {
  writeFileSync(MANIFEST, serialised);
  console.log(`wrote dist/${pkg.version} — ${Object.keys(dist).length} files`);
  for (const [path, hash] of Object.entries(dist)) {
    console.log(`  ${hash.slice(0, 16)}…  ${path}`);
  }
}
