package colophon.gate_test

import rego.v1

import data.colophon.gate

record := {"record_type": "colophon-record", "declaration": {
	"name": "evidence-reader",
	"tools": [
		{"name": "repo.list", "data_access": "read", "data_classes": ["public", "internal"]},
		{"name": "repo.read_settings", "data_access": "read", "data_classes": ["internal"]},
		{"name": "fs.read", "data_access": "read", "data_classes": ["public", "internal"]},
		{"name": "fs.write", "data_access": "write", "data_classes": ["internal"]},
		{"name": "auth.request_scopes", "data_access": "none", "data_classes": []},
		{"name": "mail.send", "data_access": "none", "data_classes": [], "destinations": ["*@acme.example"]},
		{"name": "net.fetch", "data_access": "read", "data_classes": ["public"], "destinations": ["https://api.acme.example/*"]},
		{"name": "deploy.run", "data_access": "none", "data_classes": [], "requires_approval": true},
	],
	"data_classes": ["public", "internal"],
	"sandbox": {"write_paths": ["out/evidence-reader/"]},
	"max_scopes": ["repo:read"],
}}

ctx := {"session_id": "t", "call_index": 0}

d(name, arguments) := r if {
	r := gate.decision with input as {"record": record, "call": {"name": name, "arguments": arguments}, "context": ctx}
}

# ---- allow ----
test_allow_read_labeled if {
	r := d("repo.list", {"org": "acme", "data_class": "internal"})
	r.effect == "allow"
	r.rule_ids == ["COL-GATE-ALLOW"]
}

test_allow_write_in_sandbox if {
	r := d("fs.write", {"path": "out/evidence-reader/report.md", "data_class": "internal"})
	r.effect == "allow"
}

test_allow_scopes_within_max if {
	d("auth.request_scopes", {"scopes": ["repo:read"]}).effect == "allow"
}

test_allow_mail_in_domain if {
	d("mail.send", {"to": "team@acme.example", "subject": "x"}).effect == "allow"
}

test_allow_fetch_allowed_prefix if {
	d("net.fetch", {"url": "https://api.acme.example/repos", "data_class": "public"}).effect == "allow"
}

test_allow_reason_names_field if {
	r := d("repo.list", {"data_class": "public"})
	r.reasons[0].field == "tools[].name"
}

# ---- unknown tool ----
test_deny_unknown_tool if {
	r := d("shell.exec", {"cmd": "ls"})
	r.effect == "deny"
	"COL-GATE-UNKNOWN-TOOL" in r.rule_ids
	r.reasons[0].field == "tools[].name"
}

test_deny_no_record if {
	r := gate.decision with input as {"call": {"name": "repo.list", "arguments": {}}, "context": ctx}
	r.effect == "deny"
	"COL-GATE-NO-RECORD" in r.rule_ids
}

test_deny_empty_input_is_default_deny if {
	r := gate.decision with input as {}
	r.effect == "deny"
}

# ---- scope ----
test_deny_scope_expansion if {
	r := d("auth.request_scopes", {"scopes": ["repo:read", "admin:org"]})
	r.effect == "deny"
	"COL-GATE-SCOPE" in r.rule_ids
	some reason in r.reasons
	reason.field == "max_scopes"
	reason.value == "admin:org"
}

test_deny_scope_unstated if {
	r := d("auth.request_scopes", {})
	r.effect == "deny"
	"COL-GATE-SCOPE" in r.rule_ids
}

# ---- sandbox ----
test_deny_sandbox_escape_absolute if {
	r := d("fs.write", {"path": "/tmp/gh-token.json", "data_class": "internal"})
	r.effect == "deny"
	"COL-GATE-SANDBOX" in r.rule_ids
	r.reasons[0].field == "sandbox.write_paths"
	r.reasons[0].value == "/tmp/gh-token.json"
}

test_deny_sandbox_escape_traversal if {
	r := d("fs.write", {"path": "out/evidence-reader/../../etc/x", "data_class": "internal"})
	"COL-GATE-SANDBOX" in r.rule_ids
}

test_deny_sandbox_path_unstated if {
	r := d("fs.write", {"data_class": "internal"})
	"COL-GATE-SANDBOX" in r.rule_ids
}

test_sandbox_does_not_apply_to_read if {
	r := d("fs.read", {"path": "/etc/hosts", "data_class": "public"})
	r.effect == "allow"
}

# ---- data class ----
test_deny_dataclass_not_allowed if {
	r := d("fs.read", {"path": "secrets/deploy-token.txt", "data_class": "secret"})
	r.effect == "deny"
	"COL-GATE-DATACLASS" in r.rule_ids
	r.reasons[0].field == "tools[].data_classes"
	r.reasons[0].value == "secret"
}

test_deny_dataclass_unlabeled if {
	r := d("repo.read_settings", {"repo": "acme/web"})
	"COL-GATE-DATACLASS" in r.rule_ids
}

test_dataclass_not_required_for_none_access if {
	d("auth.request_scopes", {"scopes": ["repo:read"]}).effect == "allow"
}

# ---- destination ----
test_deny_destination_outside if {
	r := d("mail.send", {"to": "ops@evil.example"})
	r.effect == "deny"
	"COL-GATE-DESTINATION" in r.rule_ids
	r.reasons[0].field == "tools[].destinations"
	r.reasons[0].value == "ops@evil.example"
}

test_deny_destination_unstated if {
	r := d("mail.send", {"subject": "hi"})
	"COL-GATE-DESTINATION" in r.rule_ids
}

test_deny_fetch_outside_prefix if {
	r := d("net.fetch", {"url": "https://exfil.example/x", "data_class": "public"})
	"COL-GATE-DESTINATION" in r.rule_ids
}

# ---- escalate ----
test_escalate_requires_approval if {
	r := d("deploy.run", {"target": "staging"})
	r.effect == "escalate"
	r.rule_ids == ["COL-GATE-APPROVAL"]
}

# ---- combination: deny beats escalate, multiple ids sorted ----
test_deny_multiple_rule_ids_sorted if {
	r := d("fs.write", {"path": "/tmp/x", "data_class": "secret"})
	r.effect == "deny"
	r.rule_ids == ["COL-GATE-DATACLASS", "COL-GATE-SANDBOX"]
	count(r.reasons) == 2
}

test_every_verdict_has_rule_and_reason if {
	some name in ["repo.list", "shell.exec", "fs.write", "mail.send", "deploy.run"]
	r := d(name, {})
	count(r.rule_ids) > 0
	count(r.reasons) > 0
	count(r.reasons[0].field) > 0
}
