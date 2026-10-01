/**
 * One command that checks the whole chain, so nobody has to assemble it by hand.
 *
 *   source at this commit → local build → published manifest → production
 *
 * This exists because the manual instructions went stale: the README was
 * written at 1.1.0, the release moved to 1.2.0, and the commands underneath
 * kept pointing at a path that no longer exists. A reader following them got a
 * 404 and had every reason to conclude the verification claim was hollow.
 *
 * Nothing here is typed twice. The version comes from package.json, the
 * expected digests come from crypto-manifest.json, and the production URLs are
 * built from the same version — so a release bump cannot leave this behind.
 *
 *   node scripts/verify-release.mjs                  full check, including production
 *   node scripts/verify-release.mjs --offline        skip the production fetch
 *   node scripts/verify-release.mjs --origin <url>   check a different deployment
 */

import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { readFileSync, existsSync } from "node:fs";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const pkg = JSON.parse(readFileSync(join(ROOT, "package.json"), "utf8"));
const manifest = JSON.parse(readFileSync(join(ROOT, "crypto-manifest.json"), "utf8"));

const argv = process.argv.slice(2);
const offline = argv.includes("--offline");
const origin =
  (argv.includes("--origin") ? argv[argv.indexOf("--origin") + 1] : null) ||
  "https://getfileshare.cloud";

const VERSION = pkg.version;
const sha256 = (bytes) => createHash("sha256").update(bytes).digest("hex");
const short = (h) => (h ? `${h.slice(0, 12)}…` : "—");

let commit = "unknown";
try {
  commit = execFileSync("git", ["rev-parse", "HEAD"], { cwd: ROOT, encoding: "utf8" }).trim();
} catch {
  /* A tarball download has no git metadata. Not fatal: the digests are the
     evidence, and the commit is only there to say which source produced them. */
}

console.log(`\nGetFileShare crypto release verification\n`);
console.log(`  Version   ${VERSION}`);
console.log(`  Commit    ${commit}`);
console.log(`  Origin    ${offline ? "(skipped — offline)" : origin}\n`);

/* Rebuild before comparing. Hashing a dist/ that happens to be lying around
   would check nothing: the point is that THIS source produces THOSE bytes. */
console.log("  Building from source…");
try {
  execFileSync(process.execPath, [join(ROOT, "scripts", "build-dist.mjs")], {
    cwd: ROOT,
    stdio: "pipe",
  });
} catch (error) {
  console.error(`\n  Build failed: ${error.message}\n`);
  process.exit(1);
}

const expected = manifest.dist || {};
if (!Object.keys(expected).length) {
  console.error("  crypto-manifest.json has no dist section — nothing to verify.\n");
  process.exit(1);
}

const rows = [];
let failed = false;

for (const [path, published] of Object.entries(expected)) {
  const name = path.replace(/^dist\/[^/]+\//, "");
  const local = join(ROOT, path);

  const localHash = existsSync(local) ? sha256(readFileSync(local)) : null;
  let prodHash = null;
  let prodNote = "";

  if (!offline) {
    const url = `${origin}/crypto/${VERSION}/${name}`;
    try {
      const res = await fetch(url);
      if (!res.ok) {
        prodNote = `HTTP ${res.status}`;
      } else {
        prodHash = sha256(Buffer.from(await res.arrayBuffer()));
      }
    } catch (error) {
      prodNote = error.message.slice(0, 40);
    }
  }

  const localOk = localHash === published;
  const prodOk = offline ? null : prodHash === published;
  if (!localOk || prodOk === false) failed = true;

  rows.push({ name, published, localHash, prodHash, prodNote, localOk, prodOk });
}

const pad = Math.max(...rows.map((r) => r.name.length));
console.log(`\n  ${"Artifact".padEnd(pad)}  ${"Published".padEnd(14)}  Local build   Production`);
console.log(`  ${"-".repeat(pad)}  ${"-".repeat(14)}  ------------  ----------`);
for (const r of rows) {
  const prod = offline ? "skipped" : r.prodOk ? "match" : r.prodNote || "MISMATCH";
  console.log(
    `  ${r.name.padEnd(pad)}  ${short(r.published).padEnd(14)}  ` +
      `${(r.localOk ? "match" : "MISMATCH").padEnd(12)}  ${prod}`,
  );
}

console.log("");
for (const r of rows) {
  if (!r.localOk) {
    console.log(`  ${r.name} — local build does not match the manifest`);
    console.log(`    published ${r.published}`);
    console.log(`    built     ${r.localHash || "(missing)"}`);
  }
  if (r.prodOk === false) {
    console.log(`  ${r.name} — production does not match the manifest`);
    console.log(`    published ${r.published}`);
    console.log(`    served    ${r.prodHash || `(not fetched: ${r.prodNote})`}`);
  }
}

if (failed) {
  console.log(
    `\n  RESULT: NOT VERIFIED\n\n` +
      `  A mismatch means the bytes running in a browser are not the bytes this\n` +
      `  source produces. That is exactly what this check exists to surface —\n` +
      `  please report it rather than assuming it is your environment.\n`,
  );
  process.exit(1);
}

console.log(
  `  RESULT: VERIFIED${offline ? " (local build only — production not checked)" : ""}\n`,
);
