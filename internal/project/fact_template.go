package project

import (
	"cyberstrike-ai/internal/legacytext"
	"fmt"
	"strings"

	"cyberstrike-ai/internal/projectprompt"
)

// 事实 category 常量（写入 upsert_project_fact 的 category 字段）。
const (
	FactCategoryTarget   = "target"
	FactCategoryAuth     = "auth"
	FactCategoryInfra    = "infra"
	FactCategoryBusiness = "business"
	FactCategoryFinding  = "finding"
	FactCategoryChain    = "chain"
	FactCategoryExploit  = "exploit"
	FactCategoryPOC      = "poc"
	FactCategoryNote     = "note"
)

// RequiresAttackChainBody 判断该事实是否应携带可复现的攻击链 / exploit 详情（写在 body，非仅 summary）。
func RequiresAttackChainBody(category, factKey string) bool {
	c := strings.ToLower(strings.TrimSpace(category))
	switch c {
	case FactCategoryFinding, FactCategoryChain, FactCategoryExploit, FactCategoryPOC, "vuln":
		return true
	}
	key := strings.ToLower(strings.TrimSpace(factKey))
	for _, prefix := range []string{"finding/", "chain/", "exploit/", "poc/"} {
		if strings.HasPrefix(key, prefix) {
			return true
		}
	}
	return false
}

// IsSparseFactBody 攻击链类事实 body 过短或缺少关键段落时返回 true（软校验，不阻断写入）。
func IsSparseFactBody(category, factKey, body string) bool {
	if !RequiresAttackChainBody(category, factKey) {
		return false
	}
	body = strings.TrimSpace(body)
	if body == "" {
		return true
	}
	lower := strings.ToLower(body)
	// 至少应包含可复现线索：步骤/请求/命令/代码块 之一
	hasSteps := legacytext.Contains(lower, "attack chain") || legacytext.Contains(lower, "## Attack!") ||
		strings.Contains(lower, "## exploit") || strings.Contains(lower, "## poc")
	hasHTTP := strings.Contains(lower, "```http") || strings.Contains(lower, "```bash") ||
		strings.Contains(lower, "curl ") || strings.Contains(lower, "get ") || strings.Contains(lower, "post ")
	hasReq := legacytext.Contains(lower, "Request") || legacytext.Contains(lower, "Response") || strings.Contains(lower, "payload")
	// 无攻击链/POC/请求等结构线索，视为仅结论性描述（不论长短）
	return !(hasSteps || hasHTTP || hasReq)
}

// FactBodyTemplate 按 category 返回建议的 body Markdown 骨架（供 Agent 填入真实内容）。
func FactBodyTemplate(category, factKey string) string {
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(factKey)), "artifact/") {
		return artifactFactBodyTemplate
	}
	if strings.HasPrefix(strings.ToLower(strings.TrimSpace(factKey)), "test/") || strings.HasPrefix(strings.ToLower(strings.TrimSpace(factKey)), "negative/") {
		return testResultFactBodyTemplate
	}
	if RequiresAttackChainBody(category, factKey) {
		return attackChainFactBodyTemplate
	}
	return envFactBodyTemplate
}

const attackChainFactBodyTemplate = `## Conclusion (verified, one sentence)
<Do not write only "a gap"; state type + location + trigger condition"

## Target and entry point
- target: <URL / IP:Port / Hostname>
- Entry: <path / endpoint / parameter>
- Preconditions: <anonymous / role / secret reference / dependencies>

## Attack chain (reproducible steps)
1. <Discovery and baseline>
2. <Test or exploitation trigger>
3. <Observed impact evidence; distinguish actual data/access/execution from a hypothesis>

## Exploit / POC
### Request
` + "```http\n<METHOD> <path> HTTP/1.1\nHost: ...\n...\n\n<body>\n```" + `

### Response / observed behavior
<Relevant response excerpts, status codes and control differences>

### Command / script (if applicable)
` + "```bash\n<command>\n```" + `

## Key evidence
- <Tool output, screenshot/artifact path, session/message ID>

## Related
- related_vulnerability_id: <optional, Correspond record_vulnerability of id>
- links (upsert Parameters) : [{ "from": "<fact_key>", "type": "discovered_on|..." }] (from → Current fact)
- Dependent facts (body readable mirrors): <fact_key, e.g. auth/session_cookie>

## Limitations and uncertainty
<Unverified details, environmental differences and unsuccessful tests>`

const envFactBodyTemplate = `## Summary
<Verified observation and its scope>

## Details
<Port/version/path/authentication characteristics/business rules>

## Sources and evidence
<Order output, response clips, discovery time >

## Related
- relevant fact_key: < Optional>`

// FactRecordingGuidanceBlock 写入系统提示：要求事实沉淀攻击链上下文而非仅结论。
func FactRecordingGuidanceBlock() string {
	return projectprompt.FactRecordingGuidanceBlock()
}

// SparseBodyWarning 攻击链类事实 body 不足时的工具返回提示（不阻断保存）。
func SparseBodyWarning(category, factKey string) string {
	if !IsSparseFactBody(category, factKey, "") {
		return ""
	}
	return fmt.Sprintf(
		"\n\n⚠ Hint: category=%q / fact_key=%q It's part of the chain of attack., But... body Is empty or too simple.Please complete the attack chain. POC (Reference Templates) , Facilitate follow-up audit recurrence.\nRecommendations body Bones.: \n%s",
		category, factKey, FactBodyTemplate(category, factKey),
	)
}

// SparseBodyWarningIfNeeded 根据实际 body 判断是否追加警告。
func SparseBodyWarningIfNeeded(category, factKey, body string) string {
	if !IsSparseFactBody(category, factKey, body) {
		return ""
	}
	return SparseBodyWarning(category, factKey)
}

const artifactFactBodyTemplate = `## Results and certification status
< Usage, applicable target/entry; validated successful/ failed/ not validated >

## File & Call
- Relative path to the project work directory: artifacts/<Filename>
- Dependency and version: < Reliance on files, installation/operational environment>
- Mode of call and variable parameters: < command, input output; authentication reference auth/*>

## Validation of evidence
<Certification time, original command/output, applicable conditions; do not extrapolate success from the existence of the file]

## Related
<Source session, depend on fact_key, related_vulnerability_id>`

const testResultFactBodyTemplate = `## Measured
<Target, entrance, parameters, identification/certification, version, test time >

## Methodology and evidence
<Request/command, response difference, tool output; error/overtime must be singled out >

## Conclusions and borders
<Success / Undetected / Obstructed / Unvalidated / Not extended to untested entry >

## Repeat detection trigger condition
<Target/entry/identity/version change, original evidence or user request for re-checking >

## Related
<Source Session, Script artifact/*, Relevant facts/vulnerability ID>`
