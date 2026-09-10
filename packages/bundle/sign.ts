/**
 * Cosign 3.x over a blob. Two modes, never silently swapped:
 *   key      — local key pair, offline. Cosign 3 requires a signing config to
 *              sign without a transparency log; we create one with no services.
 *   keyless  — ambient OIDC (CI). Uses the default public Sigstore instance.
 * Every function throws on failure. Nothing here returns "signed" unless the
 * signature artifact exists on disk after cosign exited 0.
 */
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, statSync } from "node:fs";
import { join } from "node:path";

export class SignError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SignError";
  }
}

export function cosignBinary(): string {
  return process.env["COLOPHON_COSIGN_BIN"] ?? "cosign";
}

function run(args: string[], opts: { cwd?: string; env?: Record<string, string> } = {}): { status: number | null; stdout: string; stderr: string; error?: Error } {
  const r = spawnSync(cosignBinary(), args, { cwd: opts.cwd, env: { ...process.env, ...(opts.env ?? {}) }, encoding: "utf8", timeout: 120_000 });
  return { status: r.status, stdout: r.stdout ?? "", stderr: r.stderr ?? "", error: r.error };
}

function must(what: string, r: ReturnType<typeof run>): void {
  if (r.error) throw new SignError(`${what}: cosign (${cosignBinary()}) could not run: ${r.error.message}`);
  if (r.status !== 0) throw new SignError(`${what}: cosign exited ${r.status}: ${(r.stderr || r.stdout).trim().slice(0, 500)}`);
}

export function cosignVersion(): string {
  const r = run(["version"]);
  must("version", r);
  const m = /GitVersion:\s*(\S+)/.exec(r.stdout + r.stderr);
  return m?.[1] ?? "unknown";
}

/** Generate cosign.key / cosign.pub in `dir`. Password from `password` (may be empty). */
export function generateKeyPair(dir: string, password: string): { key: string; pub: string } {
  mkdirSync(dir, { recursive: true });
  const key = join(dir, "cosign.key");
  const pub = join(dir, "cosign.pub");
  if (existsSync(key) || existsSync(pub)) throw new SignError(`key pair already exists in ${dir}`);
  must("generate-key-pair", run(["generate-key-pair"], { cwd: dir, env: { COSIGN_PASSWORD: password } }));
  if (!existsSync(key) || !existsSync(pub)) throw new SignError(`generate-key-pair exited 0 but ${key} / ${pub} not found`);
  return { key, pub };
}

/** A signing config with no Fulcio, Rekor, TSA, or OIDC: what Cosign 3 needs to sign a blob offline with a key. */
export function offlineSigningConfig(dir: string): string {
  mkdirSync(dir, { recursive: true });
  const out = join(dir, "signing-config.offline.json");
  if (existsSync(out)) return out;
  must("signing-config create", run(["signing-config", "create", "--no-default-fulcio", "--no-default-oidc", "--no-default-rekor", "--no-default-tsa", "--out", out]));
  if (!existsSync(out)) throw new SignError(`signing-config create exited 0 but ${out} not found`);
  return out;
}

export type SignKeyOptions = { blob: string; key: string; password: string; out: string; signingConfig: string };

/** Sign `blob` with a key; writes the Cosign 3 bundle to `out`. Throws unless `out` exists afterwards. */
export function signBlobWithKey(o: SignKeyOptions): void {
  if (!existsSync(o.blob)) throw new SignError(`blob not found: ${o.blob}`);
  if (!existsSync(o.key)) throw new SignError(`key not found: ${o.key}`);
  must("sign-blob", run(["sign-blob", "--yes", "--key", o.key, "--bundle", o.out, "--signing-config", o.signingConfig, o.blob], { env: { COSIGN_PASSWORD: o.password } }));
  if (!existsSync(o.out) || statSync(o.out).size === 0) throw new SignError(`sign-blob exited 0 but no signature bundle at ${o.out}`);
}

/** Keyless (ambient OIDC, e.g. GitHub Actions). Network to the public Sigstore instance. */
export function signBlobKeyless(o: { blob: string; out: string }): void {
  if (!existsSync(o.blob)) throw new SignError(`blob not found: ${o.blob}`);
  must("sign-blob (keyless)", run(["sign-blob", "--yes", "--bundle", o.out, o.blob]));
  if (!existsSync(o.out) || statSync(o.out).size === 0) throw new SignError(`sign-blob exited 0 but no signature bundle at ${o.out}`);
}

export type VerifyOptions =
  | { blob: string; bundle: string; pubkey: string }
  | { blob: string; bundle: string; certIdentityRegexp: string; oidcIssuer: string };

/** Verify a Cosign 3 bundle over `blob`. Throws SignError on any failure. */
export function verifyBlob(o: VerifyOptions): void {
  if (!existsSync(o.blob)) throw new SignError(`blob not found: ${o.blob}`);
  if (!existsSync(o.bundle)) throw new SignError(`signature bundle not found: ${o.bundle}`);
  const args = ["verify-blob", "--bundle", o.bundle];
  if ("pubkey" in o) {
    if (!existsSync(o.pubkey)) throw new SignError(`public key not found: ${o.pubkey}`);
    // Key mode signs offline with no transparency-log entry; tell cosign not to demand one.
    args.push("--key", o.pubkey, "--insecure-ignore-tlog");
  } else {
    args.push("--certificate-identity-regexp", o.certIdentityRegexp, "--certificate-oidc-issuer", o.oidcIssuer);
  }
  args.push(o.blob);
  must("verify-blob", run(args));
}
