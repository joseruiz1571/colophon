/**
 * OSCAL 1.2.3 Assessment Results. One finding per control, one observation
 * per cited evidence item, back-matter resources with rlinks into the bundle
 * (path + SHA-256) so a verifier can walk finding → observation → resource →
 * file → hash. The citation guard runs before anything is serialized.
 */
import Ajv from "ajv";
import addFormats from "ajv-formats";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import type { ControlResult } from "../catalog/checks.ts";
import { evidenceFileBytes, type EvidenceStore } from "../evidence/store.ts";
import { sha256Hex } from "../schema/canonical.ts";

export const OSCAL_VERSION = "1.2.3";
export const COLOPHON_NS = "https://colophon.dev/ns/oscal";
const SCHEMA_PATH = join(import.meta.dir, "vendor", `oscal_assessment-results_schema-${OSCAL_VERSION}.json`);

/** Deterministic UUID (v5-shaped) from a name, so the same evidence yields the same uuid across runs. */
export function uuidFrom(name: string): string {
  const h = sha256Hex(name);
  const hex = h.slice(0, 12) + "5" + h.slice(13, 16) + "8" + h.slice(17, 20) + h.slice(20, 32);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-${hex.slice(12, 16)}-${hex.slice(16, 20)}-${hex.slice(20, 32)}`;
}

export type Prop = { name: string; value: string; ns?: string };
export type Rlink = { href: string; "media-type"?: string; hashes: { algorithm: "SHA-256"; value: string }[] };
export type Resource = { uuid: string; title: string; description?: string; props?: Prop[]; rlinks: Rlink[]; remarks?: string };

export type ReportInput = {
  title: string;
  description: string;
  source: string;
  sessionId: string;
  recordSha256?: string;
  results: ControlResult[];
  store: EvidenceStore;
  /** Bundle-relative directory that evidence files are written to. */
  evidenceDir: string;
  /** Extra resources (e.g. the catalog file) keyed by a stable name; href is bundle-relative. */
  extraResources: { key: string; title: string; href: string; sha256: string; mediaType: string; description: string }[];
  start: string;
  end: string;
};

export function buildAssessmentResults(input: ReportInput): Record<string, unknown> {
  // Citation guard: refuse before building anything.
  const cited = [...new Set(input.results.flatMap((r) => r.cited))].sort();
  input.store.assertCited(cited);

  const resources: Resource[] = [];
  const observations: Record<string, unknown>[] = [];
  const obsUuidByEvidence = new Map<string, string>();

  for (const id of cited) {
    const item = input.store.get(id)!;
    const fileHash = sha256Hex(evidenceFileBytes(item));
    const resUuid = uuidFrom(`resource:${id}`);
    resources.push({
      uuid: resUuid,
      title: `Evidence ${item.kind} ${id.slice(0, 12)}`,
      description: `${item.kind} from ${item.source}, retrieved ${item.retrieved_at}. Content-addressed: id is the SHA-256 of the canonical payload.`,
      props: [
        { name: "evidence-id", value: id, ns: COLOPHON_NS },
        { name: "kind", value: item.kind, ns: COLOPHON_NS },
        { name: "source", value: item.source, ns: COLOPHON_NS },
      ],
      rlinks: [{ href: `${input.evidenceDir}/${id}.json`, "media-type": "application/json", hashes: [{ algorithm: "SHA-256", value: fileHash }] }],
    });
    const obsUuid = uuidFrom(`observation:${id}`);
    obsUuidByEvidence.set(id, obsUuid);
    observations.push({
      uuid: obsUuid,
      title: `Examined ${item.kind}`,
      description: `Deterministic check over evidence ${id} (${item.kind}) collected from ${item.source}.`,
      methods: ["TEST"],
      types: ["control-objective"],
      props: [{ name: "evidence-id", value: id, ns: COLOPHON_NS }],
      "relevant-evidence": [{ href: `#${resUuid}`, description: `${input.evidenceDir}/${id}.json (SHA-256 ${fileHash})` }],
      collected: item.retrieved_at,
    });
  }

  for (const extra of input.extraResources) {
    resources.push({
      uuid: uuidFrom(`resource:${extra.key}`),
      title: extra.title,
      description: extra.description,
      rlinks: [{ href: extra.href, "media-type": extra.mediaType, hashes: [{ algorithm: "SHA-256", value: extra.sha256 }] }],
    });
  }

  const findings = input.results.map((r) => ({
    uuid: uuidFrom(`finding:${input.sessionId}:${r.control.id}`),
    title: `${r.control.id}: ${r.control.title} — ${r.state}`,
    description: r.rationale,
    props: [
      { name: "control-id", value: r.control.id, ns: COLOPHON_NS },
      { name: "check", value: r.control.check, ns: COLOPHON_NS },
      { name: "phase", value: r.control.phase, ns: COLOPHON_NS },
      { name: "falsifier", value: r.control.falsifier, ns: COLOPHON_NS },
      ...r.control.framework_refs.map((f) => ({ name: "framework-ref", value: `${f.framework}: ${f.ref}`, ns: COLOPHON_NS })),
    ],
    target: {
      type: "objective-id",
      "target-id": r.control.id.toLowerCase(),
      title: r.control.title,
      description: r.control.intent,
      status: { state: r.state },
    },
    "related-observations": r.cited.map((id) => ({ "observation-uuid": obsUuidByEvidence.get(id)! })),
  }));

  const catalogResource = input.extraResources.find((e) => e.key === "catalog");
  const importHref = catalogResource ? `#${uuidFrom("resource:catalog")}` : "#colophon-catalog";

  const resultProps: Prop[] = [
    { name: "source", value: input.source, ns: COLOPHON_NS },
    { name: "session-id", value: input.sessionId, ns: COLOPHON_NS },
    ...(input.recordSha256 ? [{ name: "record-sha256", value: input.recordSha256, ns: COLOPHON_NS }] : []),
  ];

  return {
    "assessment-results": {
      uuid: uuidFrom(`ar:${input.sessionId}:${input.source}`),
      metadata: {
        title: input.title,
        "last-modified": input.end,
        version: "0.1.0",
        "oscal-version": OSCAL_VERSION,
        props: [{ name: "generator", value: "colophon 0.1.0", ns: COLOPHON_NS }],
        remarks: "Custody is provable. Judgment is not. This document attests that the cited evidence exists, is unaltered, and was produced by the signer. It does not attest that the assessment is correct.",
      },
      "import-ap": {
        href: importHref,
        remarks: "Colophon has no separate assessment plan; the control catalog shipped in the bundle (catalog/controls.yaml) is the plan. Each control names its deterministic check and its falsifier.",
      },
      results: [
        {
          uuid: uuidFrom(`result:${input.sessionId}:${input.source}`),
          title: `Session ${input.sessionId} (${input.source})`,
          description: input.description,
          start: input.start,
          end: input.end,
          props: resultProps,
          "reviewed-controls": {
            description: "Colophon catalog controls evaluated in this phase.",
            "control-selections": [{ "include-controls": input.results.map((r) => ({ "control-id": r.control.id.toLowerCase() })) }],
          },
          observations,
          findings,
        },
      ],
      "back-matter": { resources },
    },
  };
}

type Validator = ((doc: unknown) => boolean) & { errors?: { instancePath: string; message?: string }[] | null };
let validator: Validator | null = null;

export function validateOscal(doc: unknown): { ok: true } | { ok: false; errors: string[] } {
  if (!validator) {
    const schema = JSON.parse(readFileSync(SCHEMA_PATH, "utf8"));
    const ajv = new Ajv({ strict: false, allErrors: true });
    addFormats(ajv);
    validator = ajv.compile(schema) as unknown as Validator;
  }
  const ok = validator!(doc);
  if (ok) return { ok: true };
  return { ok: false, errors: (validator!.errors ?? []).slice(0, 12).map((e) => `${e.instancePath || "/"}: ${e.message ?? "invalid"}`) };
}

export function oscalVersionOf(doc: unknown): string | null {
  const v = (doc as { "assessment-results"?: { metadata?: { "oscal-version"?: string } } })["assessment-results"]?.metadata?.["oscal-version"];
  return typeof v === "string" ? v : null;
}
