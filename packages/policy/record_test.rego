package colophon.record_test

import rego.v1

import data.colophon.record

good := {"record_type": "colophon-record", "record_version": "0.1.0", "declaration": {
	"risk_tier": "high",
	"review_due": "2099-01-01",
	"kill_switch": {"available": true, "mechanism": "revoke token"},
	"max_scopes": ["repo:read"],
	"data_classes": ["public", "internal"],
	"sandbox": {"write_paths": ["out/x/"]},
	"tools": [
		{"name": "auth.request_scopes", "data_access": "none", "data_classes": []},
		{"name": "fs.write", "data_access": "write", "data_classes": ["internal"]},
		{"name": "mail.send", "data_access": "none", "data_classes": [], "destinations": ["*@acme.example"]},
	],
}}

lint(r) := res if {
	res := record.result with input as r
}

test_good_record_passes if {
	res := lint(good)
	res.ok
	count(res.denies) == 0
}

test_stale_review_due if {
	res := lint(object.union(good, {"declaration": object.union(good.declaration, {"review_due": "2020-01-01"})}))
	not res.ok
	some d in res.denies
	d.rule_id == "COL-REC-STALE"
	d.field == "declaration.review_due"
}

test_bad_review_format if {
	res := lint(object.union(good, {"declaration": object.union(good.declaration, {"review_due": "soon"})}))
	some d in res.denies
	d.rule_id == "COL-REC-REVIEW-FORMAT"
}

test_high_without_killswitch if {
	res := lint(object.union(good, {"declaration": object.union(good.declaration, {"kill_switch": {"available": false, "mechanism": "none"}})}))
	some d in res.denies
	d.rule_id == "COL-REC-KILLSWITCH"
}

test_low_without_killswitch_ok if {
	res := lint(object.union(good, {"declaration": object.union(good.declaration, {"risk_tier": "low", "kill_switch": {"available": false, "mechanism": "none"}})}))
	res.ok
}

test_auth_tool_unbounded if {
	res := lint(object.union(good, {"declaration": object.union(good.declaration, {"max_scopes": []})}))
	some d in res.denies
	d.rule_id == "COL-REC-SCOPES-UNBOUNDED"
}

test_write_tool_empty_sandbox if {
	res := lint(object.union(good, {"declaration": object.union(good.declaration, {"sandbox": {"write_paths": []}})}))
	some d in res.denies
	d.rule_id == "COL-REC-SANDBOX-EMPTY"
}

test_tool_dataclass_not_subset if {
	res := lint(object.union(good, {"declaration": object.union(good.declaration, {"tools": [{"name": "fs.read", "data_access": "read", "data_classes": ["secret"]}]})}))
	some d in res.denies
	d.rule_id == "COL-REC-DATACLASS-SUBSET"
}

test_mail_tool_without_destinations if {
	res := lint(object.union(good, {"declaration": object.union(good.declaration, {"tools": [{"name": "mail.send", "data_access": "none", "data_classes": []}]})}))
	some d in res.denies
	d.rule_id == "COL-REC-DESTINATIONS-REQUIRED"
}

test_wrong_record_type if {
	res := lint(object.union(good, {"record_type": "card"}))
	some d in res.denies
	d.rule_id == "COL-REC-TYPE"
}
