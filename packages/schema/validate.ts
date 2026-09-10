import Ajv2020, { type ErrorObject, type ValidateFunction } from "ajv/dist/2020.js";
import addFormats from "ajv-formats";
import { join } from "node:path";

export type ValidationError = { path: string; message: string };
export type ValidationResult = { ok: true } | { ok: false; errors: ValidationError[] };

const SCHEMA_DIR = import.meta.dir;

function load(name: string): Record<string, unknown> {
  return JSON.parse(require("node:fs").readFileSync(join(SCHEMA_DIR, name), "utf8"));
}

let ajv: Ajv2020 | null = null;
const compiled = new Map<string, ValidateFunction>();

function engine(): Ajv2020 {
  if (ajv) return ajv;
  ajv = new Ajv2020({ allErrors: true, strict: true, allowUnionTypes: true });
  addFormats(ajv);
  ajv.addSchema(load("declaration.schema.json"));
  ajv.addSchema(load("record.schema.json"));
  ajv.addSchema(load("decision.schema.json"));
  return ajv;
}

function validator(id: string): ValidateFunction {
  const cached = compiled.get(id);
  if (cached) return cached;
  const v = engine().getSchema(id);
  if (!v) throw new Error(`schema not registered: ${id}`);
  compiled.set(id, v);
  return v;
}

function toErrors(errs: ErrorObject[] | null | undefined): ValidationError[] {
  return (errs ?? []).map((e) => {
    const missing = (e.params as { missingProperty?: string }).missingProperty;
    const path = missing ? `${e.instancePath}/${missing}` : e.instancePath || "/";
    return { path, message: e.message ?? "invalid" };
  });
}

function run(id: string, value: unknown): ValidationResult {
  const v = validator(id);
  return v(value) ? { ok: true } : { ok: false, errors: toErrors(v.errors) };
}

export const validateDeclaration = (v: unknown) => run("https://colophon.dev/schema/declaration.schema.json", v);
export const validateRecord = (v: unknown) => run("https://colophon.dev/schema/record.schema.json", v);
export const validateDecision = (v: unknown) => run("https://colophon.dev/schema/decision.schema.json", v);

export function formatErrors(r: ValidationResult): string {
  if (r.ok) return "ok";
  return r.errors.map((e) => `${e.path}: ${e.message}`).join("; ");
}
