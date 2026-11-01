// Package projectprompt provides shared project-memory guidance without database dependencies.
package projectprompt

const factRhythmCore = "Record each verified new observation promptly with upsert_project_fact, updating the same fact_key for the same finding. Record each reproducible verified vulnerability with record_vulnerability, including POC and impact. Do not postpone recording until the session ends. If no project is bound, retain an evidence summary and state that project facts cannot be saved."
const factRhythmCoordinatorSuffix = " The coordinator must record specialist discoveries promptly and verify whether the specialist already saved them."
const factRhythmSubAgentSuffix = " If recording tools are unavailable, return structured pending entries (suggested fact_key, summary, body/POC and source evidence) for the coordinator to save immediately."

func FactRecordingIncrementalRhythmMarkdown(coordinator, subAgent bool) string {
	s := "- **Record evidence as work progresses:** " + factRhythmCore
	if coordinator {
		s += factRhythmCoordinatorSuffix
	}
	if subAgent {
		s += factRhythmSubAgentSuffix
	}
	return s
}
func factRecordingIncrementalRhythmBuiltin(coordinator, subAgent bool) string {
	return FactRecordingIncrementalRhythmMarkdown(coordinator, subAgent)
}
func factEdgeRecordingGuidance() string {
	return `### Structured fact relationships (links)
- For finding/chain/exploit/poc facts, supply links using from for the source fact; the edge points source → current fact_key.
- Findings should link from target/* with type=discovered_on. To associate an exploit with a finding, write from=exploit/*, type=exploits on that finding.
- Valid relationship types: discovered_on, depends_on, leads_to, enables, exploits, contains, part_of, supports.
- Omitting links preserves existing relationships. Supplying links replaces the current fact's incoming relationships. Human-readable dependency notes may coexist in body; links are the structured source of truth.`
}
func factRecordingGuidanceBlock() string {
	return `### Reproducible project facts
- summary is a concise index entry: what, where and how verified. A conclusion alone is insufficient.
- body holds complete reproducible context. The index omits it; retrieve it with get_project_fact(fact_key).
- Use target/, auth/, infra/ or business/ for environment observations; finding/, chain/, exploit/ or poc/ for findings and exploitation context. Include entry point, ordered steps, original request/response or command, observed evidence and related_vulnerability_id. Reuse stable keys for equivalent discoveries.
- note/context-* is reserved for system-generated, unverified continuation records; fact-writing tools must not overwrite it. Ordinary project facts are shared, while continuation records default to the current conversation. For explicit historical reference, use include_history=true with list_project_facts/search_project_facts/get_project_fact; source_conversation_id narrows lists/search. Verify source conversation, timestamp, current scope and evidence. Historical records do not authorize new work. Follow snapshot references to recover exact missing values; never guess.
- Record deliverable findings with record_vulnerability and the full reproducible context with project facts where appropriate. Deprecate false facts with deprecate_project_fact; mark false-positive vulnerability records false_positive. Do not confuse an obsolete fact with a confirmed negative test.`
}
func FactRecordingBlackboardSection(coordinatorDelegate bool) string {
	return "## Project facts and vulnerability records\n\n" +
		"A bound project injects a Project Blackboard Index of fact_key and summary. Read bodies with get_project_fact before relying on details.\n\n" +
		factRecordingIncrementalRhythmBuiltin(coordinatorDelegate, false) + "\n\n" +
		"Use upsert_project_fact for observations and reproducible context. Use list_vulnerabilities/get_vulnerability to check existing findings before record_vulnerability; include title, description, severity, type, target, POC, verified impact and remediation. On retest, use update_vulnerability_status(id,status,retest_notes); retain status when unverified. Supported severities: critical/high/medium/low/info. Preserve requests, responses, screenshots and command evidence. Search existing facts with list_project_facts/search_project_facts.\n\n" +
		factEdgeRecordingGuidance() + "\n\n" + factRecordingGuidanceBlock()
}
func FactRecordingSubAgentSection() string {
	return "## Record evidence\n\n" + ProjectResultRecordingGuidance() + "\n\n" + factRecordingIncrementalRhythmBuiltin(false, true) + "\n"
}
func FactRecordingBlackboardSectionMarkdown(coordinatorDelegate bool) string {
	return FactRecordingBlackboardSection(coordinatorDelegate)
}
func FactEdgeRecordingGuidance() string  { return factEdgeRecordingGuidance() }
func FactRecordingGuidanceBlock() string { return factRecordingGuidanceBlock() }
