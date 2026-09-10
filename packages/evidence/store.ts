/**
 * Content-addressed evidence. id = sha256 = SHA-256 of the RFC 8785 form of
 * the payload. The store refuses duplicates and payloads whose stated hash
 * does not match. The citation guard refuses to let a report cite an id the
 * store does not hold.
 */
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { canonicalSha256 } from "../schema/canonical.ts";

export type EvidenceItem = {
  id: string;
  source: string;
  kind: string;
  retrieved_at: string;
  sha256: string;
  payload: unknown;
};

export class EvidenceError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "EvidenceError";
  }
}

export class CitationError extends Error {
  constructor(public readonly missing: string[]) {
    super(`CitationError: report cites evidence not in the store: ${missing.join(", ")}`);
    this.name = "CitationError";
  }
}

export class EvidenceStore {
  private items = new Map<string, EvidenceItem>();

  /** Add a payload; returns the item. Duplicate ids are refused. */
  put(source: string, kind: string, payload: unknown, retrievedAt: Date = new Date()): EvidenceItem {
    const sha = canonicalSha256(payload);
    if (this.items.has(sha)) throw new EvidenceError(`duplicate evidence id ${sha} (${kind} from ${source})`);
    const item: EvidenceItem = { id: sha, source, kind, retrieved_at: retrievedAt.toISOString(), sha256: sha, payload };
    this.items.set(sha, item);
    return item;
  }

  /** Add a prebuilt item; refuses id/sha256 that do not match the payload. */
  add(item: EvidenceItem): EvidenceItem {
    const sha = canonicalSha256(item.payload);
    if (item.sha256 !== sha) throw new EvidenceError(`sha256 mismatch for ${item.id}: stated ${item.sha256}, computed ${sha}`);
    if (item.id !== sha) throw new EvidenceError(`id ${item.id} is not the payload hash ${sha}`);
    if (this.items.has(item.id)) throw new EvidenceError(`duplicate evidence id ${item.id}`);
    this.items.set(item.id, item);
    return item;
  }

  has(id: string): boolean {
    return this.items.has(id);
  }

  get(id: string): EvidenceItem | undefined {
    return this.items.get(id);
  }

  all(): EvidenceItem[] {
    return [...this.items.values()];
  }

  byKind(kind: string): EvidenceItem[] {
    return this.all().filter((i) => i.kind === kind);
  }

  /** Citation guard: throw if any id is not held. */
  assertCited(ids: Iterable<string>): void {
    const missing = [...new Set(ids)].filter((id) => !this.items.has(id));
    if (missing.length > 0) throw new CitationError(missing);
  }

  /** Write every item to <dir>/<id>.json. Returns relative paths. */
  writeTo(dir: string): string[] {
    mkdirSync(dir, { recursive: true });
    const written: string[] = [];
    for (const item of this.all()) {
      const file = join(dir, `${item.id}.json`);
      writeFileSync(file, evidenceFileBytes(item));
      written.push(file);
    }
    return written;
  }
}

/** The exact bytes `writeTo` puts on disk for an item; the report hashes these for rlinks. */
export function evidenceFileBytes(item: EvidenceItem): string {
  return JSON.stringify(item, null, 2) + "\n";
}
