import { readFileSync } from "node:fs";
import YAML from "yaml";
import { canonicalSha256, hashWithout } from "./canonical.ts";
import { formatErrors, validateDeclaration, validateRecord } from "./validate.ts";

export type Tool = {
  name: string;
  data_access: "none" | "read" | "write";
  data_classes: string[];
  destinations?: string[];
  requires_approval?: boolean;
};

/** Foreign PEP binding named on a Record. Optional; required fields apply only when present. */
export type PepBinding = {
  kind: string;
  enforcement_mode: "ENFORCE" | "LOG_ONLY";
  tool_schema_ref?: string;
  policy_set_id?: string;
  policy_set_version?: string;
  policy_set_hash?: string;
  policy_engine_id?: string;
  gateway_id?: string;
  /** Prefix the PEP records on tool names (AgentCore Gateway: `<Target>___`); COL-05 strips it before re-evaluation. */
  tool_name_prefix?: string;
  /** The policies the foreign PEP evaluated, each with the hash of its statement file. The packet stages every file under policy/ and bundle verify asserts each hash. */
  policies?: PepPolicy[];
};

export type PepPolicy = {
  /** The PEP's own policy id (AgentCore: policyId): what determiningPolicies cites, and therefore what Decision.rule_ids carries. */
  id: string;
  name?: string;
  kind: "cedar" | "dogwood-temporal";
  /** Repo-relative path to the statement file that is staged into the packet as policy/<id>.cedar. */
  path: string;
  /** SHA-256 of that file's bytes. */
  sha256: string;
  updated_at?: string;
};

export type Declaration = {
  id: string;
  name: string;
  owner: string;
  risk_tier: "low" | "medium" | "high" | "critical";
  autonomy_level: "L0" | "L1" | "L2" | "L3" | "L4" | "L5";
  tools: Tool[];
  data_classes: string[];
  sandbox: { write_paths: string[] };
  max_scopes: string[];
  kill_switch: { available: boolean; mechanism: string };
  review_due: string;
  control_mappings: { control_id: string; framework: string }[];
  identity?: { a2a_card_uri?: string };
  pep?: PepBinding;
  /** Labels a Colophon PEP applies when the caller states none; recorded on the Decision as context. */
  defaults?: { data_class?: string };
};

export type ColophonRecord = {
  record_type: "colophon-record";
  record_version: "0.1.0";
  declaration: Declaration;
  declaration_sha256: string;
  canonical_sha256: string;
  created_at: string;
};

export class SchemaError extends Error {
  constructor(public readonly what: string, public readonly detail: string) {
    super(`${what}: ${detail}`);
    this.name = "SchemaError";
  }
}

export function loadDeclaration(path: string): Declaration {
  const text = readFileSync(path, "utf8");
  const parsed: unknown = path.endsWith(".json") ? JSON.parse(text) : YAML.parse(text);
  const r = validateDeclaration(parsed);
  if (!r.ok) throw new SchemaError("declaration invalid", formatErrors(r));
  return parsed as Declaration;
}

export function buildRecord(declaration: Declaration, now: Date = new Date()): ColophonRecord {
  const r = validateDeclaration(declaration);
  if (!r.ok) throw new SchemaError("declaration invalid", formatErrors(r));
  const partial = {
    record_type: "colophon-record" as const,
    record_version: "0.1.0" as const,
    declaration,
    declaration_sha256: canonicalSha256(declaration),
    created_at: now.toISOString(),
  };
  const record: ColophonRecord = { ...partial, canonical_sha256: canonicalSha256(partial) };
  const v = validateRecord(record);
  if (!v.ok) throw new SchemaError("record invalid", formatErrors(v));
  return record;
}

export function loadRecord(path: string): ColophonRecord {
  const parsed: unknown = JSON.parse(readFileSync(path, "utf8"));
  const r = validateRecord(parsed);
  if (!r.ok) throw new SchemaError("record invalid", formatErrors(r));
  return parsed as ColophonRecord;
}

/** Recompute both hashes. Returns the first mismatch, or null when intact. */
export function verifyRecordHashes(record: ColophonRecord): string | null {
  const decl = canonicalSha256(record.declaration);
  if (decl !== record.declaration_sha256) return `declaration_sha256 mismatch: recorded ${record.declaration_sha256}, computed ${decl}`;
  const self = hashWithout(record as unknown as Record<string, unknown>, "canonical_sha256");
  if (self !== record.canonical_sha256) return `canonical_sha256 mismatch: recorded ${record.canonical_sha256}, computed ${self}`;
  return null;
}
