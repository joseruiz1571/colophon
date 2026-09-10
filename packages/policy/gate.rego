# Colophon gate policy. The ONLY place a verdict is decided.
#
# input := {
#   record:  the signed Record (TypeScript verified its hash and signature first),
#   call:    {name, arguments},
#   context: {session_id, call_index}
# }
# output := data.colophon.gate.decision = {effect, rule_ids, reasons}
#
# Fail closed: with no record, an unknown tool, or no rule reaching a verdict,
# the default is deny. Every deny names the Record field that bound it.
package colophon.gate

import rego.v1

default decision := {
	"effect": "deny",
	"rule_ids": ["COL-GATE-DEFAULT-DENY"],
	"reasons": [{"field": "record", "value": "no rule produced a verdict"}],
}

decl := input.record.declaration

call := input.call

tool := t if {
	some t in decl.tools
	t.name == call.name
}

tool_known if tool

args := object.get(call, "arguments", {})

# ---- verdict assembly -------------------------------------------------------

decision := {"effect": "deny", "rule_ids": ids, "reasons": reasons} if {
	count(denies) > 0
	ordered := sort([[d.rule_id, d.reason] | some d in denies])
	ids := [o[0] | some o in ordered]
	reasons := [o[1] | some o in ordered]
}

decision := {"effect": "escalate", "rule_ids": ["COL-GATE-APPROVAL"], "reasons": [{"field": "tools[].requires_approval", "value": call.name}]} if {
	count(denies) == 0
	tool_known
	tool.requires_approval == true
}

decision := {"effect": "allow", "rule_ids": ["COL-GATE-ALLOW"], "reasons": [{"field": "tools[].name", "value": call.name}]} if {
	count(denies) == 0
	tool_known
	not tool.requires_approval == true
}

# ---- deny rules --------------------------------------------------------------

denies contains {"rule_id": "COL-GATE-NO-RECORD", "reason": {"field": "record", "value": "missing"}} if {
	not input.record.declaration
}

denies contains {"rule_id": "COL-GATE-UNKNOWN-TOOL", "reason": {"field": "tools[].name", "value": call.name}} if {
	input.record.declaration
	not tool_known
}

# Credential scope expansion: any requested scope outside max_scopes, or no
# scopes stated at all (fail closed).
denies contains {"rule_id": "COL-GATE-SCOPE", "reason": {"field": "max_scopes", "value": s}} if {
	tool_known
	startswith(call.name, "auth.")
	some s in args.scopes
	not s in decl.max_scopes
}

denies contains {"rule_id": "COL-GATE-SCOPE", "reason": {"field": "max_scopes", "value": "scopes not stated"}} if {
	tool_known
	startswith(call.name, "auth.")
	not scopes_stated
}

# Sandbox: a write-access tool may only touch a path under sandbox.write_paths.
denies contains {"rule_id": "COL-GATE-SANDBOX", "reason": {"field": "sandbox.write_paths", "value": args.path}} if {
	tool_known
	tool.data_access == "write"
	is_string(args.path)
	not path_in_sandbox(args.path)
}

denies contains {"rule_id": "COL-GATE-SANDBOX", "reason": {"field": "sandbox.write_paths", "value": "path not stated"}} if {
	tool_known
	tool.data_access == "write"
	not path_stated
}

scopes_stated if is_array(args.scopes)

path_stated if is_string(args.path)

dataclass_stated if is_string(args.data_class)

path_in_sandbox(p) if {
	some prefix in decl.sandbox.write_paths
	startswith(p, prefix)
	not contains(p, "..")
}

# Data class: any tool that reads or writes must label the call, and the label
# must be one the tool is allowed to touch.
denies contains {"rule_id": "COL-GATE-DATACLASS", "reason": {"field": "tools[].data_classes", "value": args.data_class}} if {
	tool_known
	tool.data_access != "none"
	is_string(args.data_class)
	not args.data_class in tool.data_classes
}

denies contains {"rule_id": "COL-GATE-DATACLASS", "reason": {"field": "tools[].data_classes", "value": "data_class not stated"}} if {
	tool_known
	tool.data_access != "none"
	not dataclass_stated
}

# Destination: a tool that declares destinations may only send or fetch to one
# that matches; a call with no destination is refused.
denies contains {"rule_id": "COL-GATE-DESTINATION", "reason": {"field": "tools[].destinations", "value": dest}} if {
	tool_known
	count(object.get(tool, "destinations", [])) > 0
	dest := destination_of(args)
	not destination_allowed(dest)
}

denies contains {"rule_id": "COL-GATE-DESTINATION", "reason": {"field": "tools[].destinations", "value": "destination not stated"}} if {
	tool_known
	count(object.get(tool, "destinations", [])) > 0
	not destination_of(args)
}

has_to(a) if is_string(a.to)

destination_of(a) := a.to if has_to(a)

destination_of(a) := a.url if {
	not has_to(a)
	is_string(a.url)
}

destination_allowed(dest) if {
	some pattern in tool.destinations
	glob.match(pattern, [], dest)
}
