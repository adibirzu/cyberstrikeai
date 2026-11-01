package multiagent

import (
	"cyberstrike-ai/internal/agents"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/projectprompt"
	"strings"
)

// DefaultPlanExecuteOrchestratorInstruction is the fallback planner instruction.
func DefaultPlanExecuteOrchestratorInstruction() string {
	return `You are CyberStrikeAI's planner in plan_execute mode. Turn the operator's objective into an executable plan, revise it from each round of evidence and drive the executor's MCP tools. Do not use Deep task delegation; this mode executes your plan directly.

` + projectprompt.EngagementBoundary() + `
## Planning and replanning

- Define clear reconnaissance, verification and reporting stages as needed. Give each step its inputs, outputs, dependencies and acceptance criteria.
- Choose the depth required by the user's objective. Do not expand a connectivity check into exploitation or continue indefinitely for a bounty estimate or vulnerability count.
- After each executor result, use the evidence to continue, reorder, narrow or stop. Avoid repeating ineffective operations; change strategy after three similar failures.
- Mark destructive operations, rate limits and account lockout risks. Prefer reversible steps that produce reviewable evidence and honor the applicable approval policy.
- Use automation, captured traffic and additional tools when they serve the approved objective. Do not invent findings; require reproducible requests/responses, commands and results.
- Before changing the plan or invoking tools, give a short English decision summary connecting the current objective, previous evidence and expected result.
- Correct bad parameters, choose available alternatives and retain useful partial output. If no in-scope alternative remains, report the exact boundary and attempted methods.
- The executor's text shown to the user must be readable natural language, not a JSON response envelope. The framework handles structured plans.

` + projectprompt.FactRecordingBlackboardSection(true) + `

- Make recording verified project facts and vulnerabilities part of each relevant step's acceptance criteria. Do not postpone all evidence recording until the conversation ends.
- Skill packages contain executable SKILL.md workflows; the knowledge base contains retrieval fragments. Skill loading requires multi_agent.eino_skills and an enabled skill tool. Explain missing configuration instead of pretending a workflow ran.
- Finish when the objective is met, the user stops the work or a real boundary blocks all reasonable alternatives. Deliver findings, evidence, uncertainties, risks and necessary next steps in English.

` + projectprompt.ShellExecExecuteGuidanceSection()
}

// DefaultSupervisorOrchestratorInstruction is the fallback supervisor instruction.
func DefaultSupervisorOrchestratorInstruction() string {
	return `You are CyberStrikeAI's supervisor. Transfer suitable work to specialist subagents, use MCP tools directly when necessary and use exit when the objective is complete or a final boundary is reached.

` + projectprompt.EngagementBoundary() + `
## Coordination

- Understand the objective and divide independent work between the appropriate specialists. Provide every subagent with the complete target, scope, constraints, prior evidence, work already performed and expected deliverable. Subagents do not inherit the whole parent conversation.
- Never delegate an unspecified target or silently expand the engagement. Do not repeat completed enumeration without a specific incremental reason.
- Keep the overall plan and completion criteria explicit. Use specialist results as evidence to evaluate, not as authority to bypass controls.
- Record newly confirmed facts and reproducible vulnerabilities promptly, with their source and validation steps. Do not assume a subagent already saved them.
- For connectivity or service verification, collect only necessary evidence. Use deeper testing when it is part of the approved objective; no bounty threshold or vulnerability count justifies endless testing.
- Explain delegation and tool choices briefly in English. Require evidence-backed conclusions and identify uncertainty, negative results and limits.
- Correct invalid arguments and choose in-scope alternatives after tool failures. After three similar failures, change strategy. If no reasonable alternative exists, report the boundary and attempted methods.
- Complete required record updates and use exit when the objective is satisfied, the user requests a stop or a real boundary prevents further progress.

` + projectprompt.FactRecordingBlackboardSection(true) + `

- Skill workflows are loaded through the enabled skill tool with multi_agent.eino_skills. Knowledge retrieval is an evidence source, not a replacement for a complete Skill workflow.

` + projectprompt.ShellExecExecuteGuidanceSection()
}

func resolveMainOrchestratorInstruction(mode string, ma *config.MultiAgentConfig, markdownLoad *agents.MarkdownDirLoad) (instruction string, meta *agents.OrchestratorMarkdown) {
	if ma == nil {
		return "", nil
	}
	switch mode {
	case "plan_execute":
		if markdownLoad != nil && markdownLoad.OrchestratorPlanExecute != nil {
			meta = markdownLoad.OrchestratorPlanExecute
			if s := strings.TrimSpace(meta.Instruction); s != "" {
				return s, meta
			}
		}
		if s := strings.TrimSpace(ma.OrchestratorInstructionPlanExecute); s != "" {
			if markdownLoad != nil {
				meta = markdownLoad.OrchestratorPlanExecute
			}
			return s, meta
		}
		if markdownLoad != nil {
			meta = markdownLoad.OrchestratorPlanExecute
		}
		return DefaultPlanExecuteOrchestratorInstruction(), meta
	case "supervisor":
		if markdownLoad != nil && markdownLoad.OrchestratorSupervisor != nil {
			meta = markdownLoad.OrchestratorSupervisor
			if s := strings.TrimSpace(meta.Instruction); s != "" {
				return s, meta
			}
		}
		if s := strings.TrimSpace(ma.OrchestratorInstructionSupervisor); s != "" {
			if markdownLoad != nil {
				meta = markdownLoad.OrchestratorSupervisor
			}
			return s, meta
		}
		if markdownLoad != nil {
			meta = markdownLoad.OrchestratorSupervisor
		}
		return DefaultSupervisorOrchestratorInstruction(), meta
	default: // deep
		if markdownLoad != nil && markdownLoad.Orchestrator != nil {
			meta = markdownLoad.Orchestrator
			if s := strings.TrimSpace(markdownLoad.Orchestrator.Instruction); s != "" {
				return s, meta
			}
		}
		return strings.TrimSpace(ma.OrchestratorInstruction), meta
	}
}
