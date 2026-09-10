/**
 * RFC 8785 (JSON Canonicalization Scheme) for the value space Colophon uses:
 * objects, arrays, strings, finite numbers, booleans, null. Object keys are
 * sorted by UTF-16 code units; no insignificant whitespace; numbers use the
 * ES serialization JSON.stringify already produces. `undefined` members are
 * dropped (as JSON.stringify does).
 */
import { createHash } from "node:crypto";

export type Json = string | number | boolean | null | Json[] | { [k: string]: Json };

export function canonicalize(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("canonicalize: non-finite number");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return "[" + value.map((v) => canonicalize(v === undefined ? null : v)).join(",") + "]";
  }
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj)
      .filter((k) => obj[k] !== undefined)
      .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalize(obj[k])).join(",") + "}";
  }
  throw new Error(`canonicalize: unsupported type ${typeof value}`);
}

export function sha256Hex(data: string | Uint8Array): string {
  return createHash("sha256").update(data).digest("hex");
}

/** SHA-256 of the canonical form of a JSON value. */
export function canonicalSha256(value: unknown): string {
  return sha256Hex(canonicalize(value));
}

/** Canonical hash of an object with one field removed (used for self-referential hashes). */
export function hashWithout(value: Record<string, unknown>, field: string): string {
  const copy: Record<string, unknown> = { ...value };
  delete copy[field];
  return canonicalSha256(copy);
}
