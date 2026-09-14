/**
 * Validate a document against the vendored GRC Eng Club finding.schema.json
 * (draft 2020-12), the same Ajv generation Colophon uses for its own schemas.
 */
import Ajv2020, { type ErrorObject, type ValidateFunction } from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { ValidationError, ValidationResult } from "../../schema/validate.ts";

export const FINDING_SCHEMA_ID = "https://github.com/GRCEngClub/claude-grc-engineering/schemas/finding.schema.json";
export const FINDING_SCHEMA_PATH = join(import.meta.dir, "finding.schema.json");
export const FINDING_SCHEMA_VERSION = "1.0.0";

let compiled: ValidateFunction | null = null;

function validator(): ValidateFunction {
  if (compiled) return compiled;
  const schema = JSON.parse(readFileSync(FINDING_SCHEMA_PATH, "utf8")) as Record<string, unknown>;
  // Club schema uses if/then to require message/severity on fail without
  // repeating those properties in the `then` subschema. Ajv strictRequired
  // treats that as an error; the schema is otherwise compiled in strict mode.
  const ajv = new Ajv2020({ allErrors: true, strict: true, strictRequired: false, allowUnionTypes: true });
  addFormats(ajv);
  compiled = ajv.compile(schema);
  return compiled;
}

function toErrors(errs: ErrorObject[] | null | undefined): ValidationError[] {
  return (errs ?? []).map((e) => {
    const missing = (e.params as { missingProperty?: string }).missingProperty;
    const path = missing ? `${e.instancePath}/${missing}` : e.instancePath || "/";
    return { path, message: e.message ?? "invalid" };
  });
}

export function validateFinding(value: unknown): ValidationResult {
  const v = validator();
  return v(value) ? { ok: true } : { ok: false, errors: toErrors(v.errors) };
}
