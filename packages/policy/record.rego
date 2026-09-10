# Colophon Record lint. Runs AFTER JSON Schema validation and hash verification
# in TypeScript; those guarantee shape and integrity, this expresses governance
# obligations a schema cannot. Every deny carries a rule id and the field.
package colophon.record

import rego.v1

high_risk := {"high", "critical"}

decl := input.declaration

result := {"ok": count(deny) == 0, "denies": deny}

deny contains {"rule_id": "COL-REC-TYPE", "field": "record_type", "msg": "record_type must be colophon-record"} if {
	input.record_type != "colophon-record"
}

deny contains {"rule_id": "COL-REC-VERSION", "field": "record_version", "msg": "unsupported record_version"} if {
	input.record_version != "0.1.0"
}

deny contains {"rule_id": "COL-REC-REVIEW-FORMAT", "field": "declaration.review_due", "msg": "review_due missing or not YYYY-MM-DD"} if {
	review := object.get(decl, "review_due", "")
	not regex.match(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`, review)
}

deny contains {"rule_id": "COL-REC-STALE", "field": "declaration.review_due", "msg": sprintf("review_due %v is in the past", [decl.review_due])} if {
	regex.match(`^[0-9]{4}-[0-9]{2}-[0-9]{2}$`, decl.review_due)
	due := time.parse_ns("2006-01-02", decl.review_due)
	due < time.now_ns()
}

deny contains {"rule_id": "COL-REC-KILLSWITCH", "field": "declaration.kill_switch.available", "msg": sprintf("risk_tier %v requires an available kill switch", [decl.risk_tier])} if {
	decl.risk_tier in high_risk
	not decl.kill_switch.available == true
}

deny contains {"rule_id": "COL-REC-SCOPES-UNBOUNDED", "field": "declaration.max_scopes", "msg": sprintf("tool %v requests credential scopes but max_scopes is empty", [t.name])} if {
	some t in decl.tools
	startswith(t.name, "auth.")
	count(object.get(decl, "max_scopes", [])) == 0
}

deny contains {"rule_id": "COL-REC-SANDBOX-EMPTY", "field": "declaration.sandbox.write_paths", "msg": sprintf("tool %v writes but sandbox.write_paths is empty", [t.name])} if {
	some t in decl.tools
	t.data_access == "write"
	count(object.get(decl.sandbox, "write_paths", [])) == 0
}

deny contains {"rule_id": "COL-REC-DATACLASS-SUBSET", "field": "declaration.tools[].data_classes", "msg": sprintf("tool %v names data class %v not in declaration.data_classes", [t.name, dc])} if {
	some t in decl.tools
	some dc in t.data_classes
	not dc in decl.data_classes
}

deny contains {"rule_id": "COL-REC-DESTINATIONS-REQUIRED", "field": "declaration.tools[].destinations", "msg": sprintf("tool %v sends or fetches but declares no destinations", [t.name])} if {
	some t in decl.tools
	sending_tool(t.name)
	count(object.get(t, "destinations", [])) == 0
}

sending_tool(name) if startswith(name, "mail.")

sending_tool(name) if startswith(name, "net.")
