/**
 * Bundle manifest: every file under the bundle root with its SHA-256 and
 * byte size, plus a root hash over the sorted file list. Written last.
 * The signature artifact (manifest.sigstore.json) is the only file exempt
 * from listing, because it is produced after the manifest and covers it.
 */
import { cpSync, existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join, relative } from "node:path";
import { canonicalSha256, sha256Hex } from "../schema/canonical.ts";

export const MANIFEST = "manifest.json";
export const SIGNATURE = "manifest.sigstore.json";

export type ManifestEntry = { path: string; sha256: string; bytes: number };
export type Manifest = {
  manifest_version: "0.1.0";
  created_at: string;
  files: ManifestEntry[];
  root_sha256: string;
};

export class BundleError extends Error {
  constructor(message: string, public readonly file?: string) {
    super(message);
    this.name = "BundleError";
  }
}

export function listFiles(root: string): string[] {
  const out: string[] = [];
  const walk = (dir: string) => {
    for (const name of readdirSync(dir).sort()) {
      const full = join(dir, name);
      if (statSync(full).isDirectory()) walk(full);
      else out.push(relative(root, full));
    }
  };
  walk(root);
  return out.sort();
}

export function hashFile(path: string): { sha256: string; bytes: number } {
  const buf = readFileSync(path);
  return { sha256: sha256Hex(buf), bytes: buf.length };
}

export function computeManifest(root: string, now: Date = new Date()): Manifest {
  const files = listFiles(root)
    .filter((p) => p !== MANIFEST && p !== SIGNATURE)
    .map((p) => ({ path: p, ...hashFile(join(root, p)) }));
  return { manifest_version: "0.1.0", created_at: now.toISOString(), files, root_sha256: canonicalSha256(files) };
}

/** Copy `from` into `out` (which must not exist or be empty), then write the manifest last. */
export function createBundle(from: string, out: string): Manifest {
  if (!existsSync(from)) throw new BundleError(`stage directory not found: ${from}`);
  if (existsSync(out) && readdirSync(out).length > 0) throw new BundleError(`refusing to write into non-empty directory: ${out}`);
  mkdirSync(out, { recursive: true });
  cpSync(from, out, { recursive: true });
  const manifest = computeManifest(out);
  writeFileSync(join(out, MANIFEST), JSON.stringify(manifest, null, 2) + "\n");
  return manifest;
}

export type ManifestCheck = { ok: true; files: number } | { ok: false; file: string; reason: string };

/** Compare the manifest against the directory: mismatch, missing, or extra files each name the file. */
export function checkManifest(root: string): ManifestCheck {
  const mpath = join(root, MANIFEST);
  if (!existsSync(mpath)) return { ok: false, file: MANIFEST, reason: "manifest.json missing" };
  let manifest: Manifest;
  try {
    manifest = JSON.parse(readFileSync(mpath, "utf8")) as Manifest;
  } catch {
    return { ok: false, file: MANIFEST, reason: "manifest.json is not valid JSON" };
  }
  const listed = new Map(manifest.files.map((f) => [f.path, f]));
  for (const f of manifest.files) {
    const full = join(root, f.path);
    if (!existsSync(full)) return { ok: false, file: f.path, reason: `listed in manifest but missing from bundle` };
    const h = hashFile(full);
    if (h.sha256 !== f.sha256) return { ok: false, file: f.path, reason: `sha256 mismatch: manifest ${f.sha256}, file ${h.sha256}` };
    if (h.bytes !== f.bytes) return { ok: false, file: f.path, reason: `size mismatch: manifest ${f.bytes}, file ${h.bytes}` };
  }
  for (const p of listFiles(root)) {
    if (p === MANIFEST || p === SIGNATURE) continue;
    if (!listed.has(p)) return { ok: false, file: p, reason: `present in bundle but not listed in manifest` };
  }
  const root_sha256 = canonicalSha256(manifest.files);
  if (root_sha256 !== manifest.root_sha256) return { ok: false, file: MANIFEST, reason: `root_sha256 mismatch: manifest ${manifest.root_sha256}, computed ${root_sha256}` };
  return { ok: true, files: manifest.files.length };
}
