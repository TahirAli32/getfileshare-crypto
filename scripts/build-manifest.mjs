/**
 * Writes crypto-manifest.json: the SHA-256 of every file in src/.
 *
 * The GetFileShare application is closed source; this repository is not. The
 * manifest is the bridge between them. The application keeps a copy of it and
 * refuses to build if its own crypto files hash differently — so the code this
 * repository publishes and the code the site ships cannot quietly diverge.
 *
 * Without it, this repository would be a description of the encryption, free
 * to drift from the real thing. With it, a change to the application's crypto
 * has to land here first.
 *
 *   node scripts/build-manifest.mjs           write the manifest
 *   node scripts/build-manifest.mjs --check   fail if it is out of date
 */

import { createHash } from "node:crypto";
import { readFileSync, readdirSync, statSync, writeFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const SRC = join(ROOT, "src");
const MANIFEST = join(ROOT, "crypto-manifest.json");
const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));

function walk(dir) {
  return readdirSync(dir).flatMap((entry) => {
    const full = join(dir, entry);
    return statSync(full).isDirectory() ? walk(full) : [full];
  });
}

/* Hash the canonical LF form, and normalise path separators, so a manifest
   built on Windows, one built on Linux, and a fresh clone all agree.

   Line endings ARE normalised, deliberately. CRLF vs LF is checkout noise,
   not a code change: it cannot alter JavaScript semantics (template literals
   normalise line terminators to LF per the spec, and ordinary strings cannot
   contain raw line breaks), and the site's bundler minifies the source anyway.
   Hashing raw bytes once let an editor's CRLF slip into the manifest, so a
   fresh clone — which .gitattributes forces to LF — failed to match it. The
   drift this exists to catch is code drift, which normalising cannot hide.

   MUST stay identical to hashCanonical() in the app's check-crypto-parity.mjs,
   or the two will disagree about every file. */
export function hashCanonical(bytes) {
  const canonical = Buffer.from(bytes.toString("utf8").replace(/\r\n?/g, "\n"), "utf8");
  return createHash("sha256").update(canonical).digest("hex");
}

const files = Object.fromEntries(
  walk(SRC)
    .filter((file) => file.endsWith(".js"))
    .map((file) => [relative(ROOT, file).split(sep).join("/"), hashCanonical(readFileSync(file))])
    .sort(([a], [b]) => a.localeCompare(b)),
);

const manifest = {
  $comment:
    "SHA-256 of each published crypto source file. The GetFileShare app ships " +
    "a copy of this and fails its build if its crypto differs.",
  package: pkg.name,
  version: pkg.version,
  files,
};

const serialised = `${JSON.stringify(manifest, null, 2)}\n`;

if (process.argv.includes("--check")) {
  let current = "";
  try {
    current = readFileSync(MANIFEST, "utf8");
  } catch {
    console.error("crypto-manifest.json is missing. Run: node scripts/build-manifest.mjs");
    process.exit(1);
  }
  if (current !== serialised) {
    console.error("crypto-manifest.json is out of date. Run: node scripts/build-manifest.mjs");
    process.exit(1);
  }
  console.log(`crypto-manifest.json is current (${Object.keys(files).length} files, v${pkg.version}).`);
} else {
  writeFileSync(MANIFEST, serialised);
  console.log(`wrote crypto-manifest.json — ${Object.keys(files).length} files, v${pkg.version}`);
  for (const [path, hash] of Object.entries(files)) console.log(`  ${hash.slice(0, 16)}…  ${path}`);
}
