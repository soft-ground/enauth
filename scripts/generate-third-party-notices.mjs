#!/usr/bin/env node
// Generates THIRD-PARTY-NOTICES.md: the license texts of every third-party Rust
// crate that is statically linked into the compiled WebAssembly module
// (core/clasp-wasm, target wasm32-unknown-unknown).
//
// Scope: normal (runtime) dependencies only. Build scripts, dev-dependencies and
// proc-macro crates run at compile time and are not shipped in the binary.
//
// Usage (from the repository root, with cargo on PATH and dependencies fetched):
//   node scripts/generate-third-party-notices.mjs
//
// Re-run whenever Cargo.lock changes. Exits non-zero if a shipped crate has no
// license file in its published package, so a gap is never silently ignored.

import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const TARGET = "wasm32-unknown-unknown";
const LICENSE_FILE = /^(licen[sc]e|copying|unlicense|notice)/i;
const OUTPUTS = [
  join(root, "THIRD-PARTY-NOTICES.md"),
  // wasm-pack copies files from the crate directory into the published package.
  join(root, "core", "clasp-wasm", "THIRD-PARTY-NOTICES.md"),
];

function cargo(args) {
  return execFileSync("cargo", args, {
    cwd: root,
    encoding: "utf8",
    maxBuffer: 256 * 1024 * 1024,
    stdio: ["ignore", "pipe", "pipe"],
  });
}

// 1. Which crates are linked into the WASM module?
const shipped = new Set();
for (const line of cargo([
  "tree", "-p", "clasp-wasm", "--target", TARGET,
  "-e", "normal,no-proc-macro", "--prefix", "none", "-f", "{p}",
]).split("\n")) {
  const m = line.trim().match(/^(\S+) v(\S+)/);
  if (m) shipped.add(`${m[1]}@${m[2]}`);
}

// 2. Metadata (license expression, repository, source directory) for each.
const metadata = JSON.parse(cargo(["metadata", "--format-version", "1", "--locked"]));
const crates = metadata.packages
  .filter((p) => p.source !== null) // skip workspace members (this project)
  .filter((p) => shipped.has(`${p.name}@${p.version}`))
  .sort((a, b) => a.name.localeCompare(b.name) || a.version.localeCompare(b.version));

// 3. Collect license texts, grouped by identical (normalized) content.
const normalize = (text) =>
  text.replace(/\r\n?/g, "\n").split("\n").map((l) => l.replace(/\s+$/, "")).join("\n").replace(/\n+$/, "") + "\n";

const groups = new Map(); // text -> crates[]
const missing = [];
for (const c of crates) {
  const dir = dirname(c.manifest_path);
  const files = readdirSync(dir)
    .filter((f) => LICENSE_FILE.test(f) && statSync(join(dir, f)).isFile())
    .sort();
  if (files.length === 0) {
    missing.push(`${c.name} ${c.version} (${c.license ?? "no license field"})`);
    continue;
  }
  for (const f of files) {
    const text = normalize(readFileSync(join(dir, f), "utf8"));
    if (!groups.has(text)) groups.set(text, []);
    if (!groups.get(text).includes(c)) groups.get(text).push(c);
  }
}

// 4. Render.
const out = [];
out.push(`# Third-party notices

enauth's own code is licensed under \`MIT OR Apache-2.0\` (see \`LICENSE-MIT\` and
\`LICENSE-APACHE\`). The compiled WebAssembly module (\`clasp-wasm\`) statically
links the third-party Rust crates listed below. Their licenses require that the
copyright notices and license texts be retained when the binary is redistributed;
they are reproduced here.

The Rust standard library (\`core\`, \`alloc\`, \`std\`, and the runtime crates it
bundles) is also linked. It is distributed by the Rust project under
\`MIT OR Apache-2.0\`; see the Rust project's COPYRIGHT file for the third-party
components it may contain. Those are not itemized here.

JavaScript packages in this repository declare their dependencies through their
package manager and are not bundled by this repository.

This file is generated. Do not edit it by hand. To regenerate it after a
\`Cargo.lock\` change: \`node scripts/generate-third-party-notices.mjs\`

## Crates

| Crate | Version | License | Repository |
|---|---|---|---|`);
for (const c of crates) {
  out.push(`| ${c.name} | ${c.version} | ${c.license ?? "n/a"} | ${c.repository ?? ""} |`);
}

const ordered = [...groups.entries()].sort(
  (a, b) => a[1][0].name.localeCompare(b[1][0].name) || a[0].localeCompare(b[0]),
);
out.push("", "## License texts", "");
ordered.forEach(([text, list], i) => {
  out.push(`### Text ${i + 1} of ${ordered.length}`, "");
  out.push("Applies to: " + list.map((c) => `${c.name} ${c.version}`).join(", "), "");
  out.push("~~~~text", text.replace(/\n$/, ""), "~~~~", "");
});

const rendered = out.join("\n").replace(/\n+$/, "\n");
for (const p of OUTPUTS) writeFileSync(p, rendered, "utf8");

console.log(`crates shipped in wasm: ${crates.length}`);
console.log(`distinct license texts: ${ordered.length}`);
console.log(`wrote: ${OUTPUTS.map((p) => p.replace(root, ".")).join(", ")}`);
if (missing.length) {
  console.error(`\nERROR: no license file found in the published package for:\n  ${missing.join("\n  ")}`);
  process.exit(1);
}
