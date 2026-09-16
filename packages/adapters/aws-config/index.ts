/**
 * AWS configuration adapter — INTERFACE + FIXTURE READER ONLY.
 * No AWS SDK dependency, no live client, no credentials. The fixture files
 * are shaped like the API responses (CloudTrail LookupEvents, IAM
 * GetRolePolicy, S3 GetBucketEncryption) so a live provider could be written
 * against the same interface later; none ships here.
 *
 * Decisions: one per CloudTrail event. An errorCode (e.g. AccessDenied) is a
 * deny by the cloud's own PEP (IAM); success is allow. Config responses
 * become evidence items, not decisions.
 */
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { argsSha256, redactArgs, type DecisionDraft } from "../../normalize/decision.ts";

export const SOURCE = "aws-config";

export type LookupEventsOutput = {
  Events: { EventId: string; EventName: string; EventSource: string; EventTime: string; Username?: string; Resources?: { ResourceType: string; ResourceName: string }[]; CloudTrailEvent: string }[];
};
export type GetRolePolicyOutput = { RoleName: string; PolicyName: string; PolicyDocument: string };
export type GetBucketEncryptionOutput = { ServerSideEncryptionConfiguration: { Rules: unknown[] } };

export interface AwsConfigProvider {
  lookupEvents(): Promise<LookupEventsOutput>;
  getRolePolicy(roleName: string, policyName: string): Promise<GetRolePolicyOutput>;
  getBucketEncryption(bucket: string): Promise<GetBucketEncryptionOutput>;
}

export class FixtureAwsConfigProvider implements AwsConfigProvider {
  constructor(private readonly dir: string) {}
  private read<T>(name: string): T {
    return JSON.parse(readFileSync(join(this.dir, name), "utf8")) as T;
  }
  async lookupEvents(): Promise<LookupEventsOutput> {
    return this.read("lookup-events.json");
  }
  async getRolePolicy(): Promise<GetRolePolicyOutput> {
    return this.read("get-role-policy.json");
  }
  async getBucketEncryption(): Promise<GetBucketEncryptionOutput> {
    return this.read("get-bucket-encryption.json");
  }
}

type CloudTrailRecord = { userIdentity?: { arn?: string; type?: string }; errorCode?: string; errorMessage?: string; requestParameters?: Record<string, unknown> };

export async function normalizeAwsConfig(provider: AwsConfigProvider): Promise<{ sessionId: string; task: string; drafts: DecisionDraft[]; evidence: { kind: string; payload: unknown }[] }> {
  const events = await provider.lookupEvents();
  const drafts: DecisionDraft[] = events.Events.map((ev, i) => {
    const ct = JSON.parse(ev.CloudTrailEvent) as CloudTrailRecord;
    const params = ct.requestParameters ?? {};
    const denied = typeof ct.errorCode === "string" && ct.errorCode.length > 0;
    return {
      source: SOURCE,
      effect: denied ? "deny" : "allow",
      rule_ids: [denied ? `AWS-IAM-${ct.errorCode!.toUpperCase()}` : "AWS-IAM-ALLOWED"],
      // IAM's errorCode is the bound (the policy outcome); its message explains; the caller ARN is context.
      reasons: [
        ...(denied ? [{ field: "errorCode", value: ct.errorCode }, { field: "errorMessage", value: ct.errorMessage ?? ct.errorCode, role: "explanation" as const }] : [{ field: "eventName", value: ev.EventName }]),
        { field: "userIdentity.arn", value: ct.userIdentity?.arn ?? "unknown", role: "context" as const },
      ],
      tool: `${ev.EventSource}:${ev.EventName}`,
      args_sha256: argsSha256(params),
      args_redacted: redactArgs(params),
      session_id: ev.Username ?? "aws-unknown",
      call_index: i,
      ts: ev.EventTime,
    };
  });
  const roleEvents = events.Events.filter((e) => e.EventName === "GetRolePolicy");
  const bucketEvents = events.Events.filter((e) => e.EventName === "GetBucketEncryption");
  const evidence: { kind: string; payload: unknown }[] = [];
  for (const e of roleEvents) {
    const p = (JSON.parse(e.CloudTrailEvent) as CloudTrailRecord).requestParameters ?? {};
    evidence.push({ kind: "aws-role-policy", payload: await provider.getRolePolicy(String(p["roleName"] ?? ""), String(p["policyName"] ?? "")) });
  }
  for (const e of bucketEvents) {
    const p = (JSON.parse(e.CloudTrailEvent) as CloudTrailRecord).requestParameters ?? {};
    evidence.push({ kind: "aws-bucket-encryption", payload: { bucket: p["bucketName"], ...(await provider.getBucketEncryption(String(p["bucketName"] ?? ""))) } });
  }
  const sessionId = events.Events[0]?.Username ?? "aws-fixture";
  return { sessionId, task: `AWS CloudTrail replay for ${sessionId}: ${events.Events.length} events from fixture; IAM is the PEP.`, drafts, evidence };
}
