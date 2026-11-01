package multiagent

import (
	"context"
	"strings"

	"github.com/cloudwego/eino/components/tool"
)

// injectToolNamesOnlyInstruction prepends a compact tool-name-only section into
// the system instruction so the model can reference current callable names.
// toolSearchMiddlewareActive must be true when prependEinoMiddlewares mounted toolsearch (dynamic tools); do not infer this
// by scanning tool names — tool_search is injected by middleware and is usually absent from the pre-split tools list.
func injectToolNamesOnlyInstruction(ctx context.Context, instruction string, tools []tool.BaseTool, toolSearchMiddlewareActive bool) string {
	names := collectToolNames(ctx, tools)
	if len(names) == 0 {
		return strings.TrimSpace(instruction)
	}
	hasToolSearch := toolSearchMiddlewareActive
	if !hasToolSearch {
		for _, n := range names {
			if strings.EqualFold(strings.TrimSpace(n), "tool_search") {
				hasToolSearch = true
				break
			}
		}
	}

	var sb strings.Builder
	sb.WriteString("The following is an index of the names of the tools used for the current session binding (name only, no parameters JSON Schema).\n")
	sb.WriteString("Annotations: If it's enabled tool_search, list may contain\"Not at all.\"Tools——They don't necessarily appear in the definition of tools for distribution to models under the current rotation.; The complete tool is not seen schema Front, Ban name-based surmising parameters.\n")
	for _, name := range names {
		sb.WriteString("- ")
		sb.WriteString(name)
		sb.WriteByte('\n')
	}
	sb.WriteString("\nUse rules:\n")
	sb.WriteString("1) The above table is only an index of names and does not contain a definition of parameters. It is prohibited to guess parameter names, types, enumeration values or whether they must be filled in.\n")
	if hasToolSearch {
		sb.WriteString("[Force / Highest Priority]This session is enabled tool_search (Dynamic Tool Pool) .Where the name index appears, But you are.\"Annex to the current request tools Definitions\"Can not see full parameters schema Tools, You have to call first. tool_search; To Province token Or skip the schedule. tool_search, Direct call to business tools, An explicitly banned error process.\n")
		sb.WriteString("2) Default Policy: As long as there is any uncertainty about the definition of the parameters of the target tool, Just first. tool_search; I'd rather do it again. tool_search, Not without seeing. schema Time-blind Business Tool.\n")
		sb.WriteString("3) Call Order: First tool_search (Only Required Parameters regex_pattern: Regular by Tool Name, Like a substring nuclei or ^exact_tool_name$) → Target confirmation tool in subsequent rounds tools Listed and read schema → Then launch a real call to the tool..\n")
		sb.WriteString("4) tool_search Returns are only a list of matching filenames; schema The next round after unlocking..Prohibited schema Make-up when not present JSON Parameters.\n")
		sb.WriteString("5) Do not imagine a tool name that does not exist.\n\n")
	} else {
		sb.WriteString("2) Before calling on specific tools, please confirm the parameters requirements for the tool (based on the definition of the tool in the current request); clarify and then call if there is uncertainty.\n")
		sb.WriteString("3) Do not imagine a tool name that does not exist.\n\n")
	}
	if s := strings.TrimSpace(injectShellToolGuidance("", names)); s != "" {
		sb.WriteString(s)
		sb.WriteString("\n\n")
	}
	if s := strings.TrimSpace(instruction); s != "" {
		sb.WriteString(s)
	}
	return sb.String()
}

func collectToolNames(ctx context.Context, tools []tool.BaseTool) []string {
	if len(tools) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(tools))
	out := make([]string, 0, len(tools))
	for _, t := range tools {
		if t == nil {
			continue
		}
		info, err := t.Info(ctx)
		if err != nil || info == nil {
			continue
		}
		name := strings.TrimSpace(info.Name)
		if name == "" {
			continue
		}
		key := strings.ToLower(name)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, name)
	}
	return out
}
