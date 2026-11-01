package app

import (
	"context"
	"fmt"
	"strings"

	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/database"
	"cyberstrike-ai/internal/mcp"
	"cyberstrike-ai/internal/mcp/builtin"
	"cyberstrike-ai/internal/project"

	"go.uber.org/zap"
)

func projectIDFromConversation(db *database.DB, ctx context.Context) (string, error) {
	convID := mcpAuthorizationConversationID(ctx)
	if convID == "" {
		return "", fmt.Errorf("Could not determine the current dialogue, please use the project fact-finding tool in the context of the dialogue")
	}
	pid, err := db.GetConversationProjectID(convID)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(pid) == "" {
		return "", fmt.Errorf("No item bound for the current dialogue, please select the item or create the dialogue with the item during the dialogue")
	}
	return pid, nil
}

func textResult(msg string, isErr bool) *mcp.ToolResult {
	return &mcp.ToolResult{
		Content: []mcp.Content{{Type: "text", Text: msg}},
		IsError: isErr,
	}
}

// registerProjectFactTools 注册项目黑板 MCP 工具。
func registerProjectFactTools(mcpServer *mcp.Server, db *database.DB, cfg *config.Config, logger *zap.Logger) {
	if db == nil || cfg == nil || !cfg.Project.Enabled {
		if logger != nil {
			logger.Info("Project blackboard tool not registered (not enabled)")
		}
		return
	}

	upsertTool := mcp.Tool{
		Name:             builtin.ToolUpsertProjectFact,
		Description:      "Write or update project facts with reproducible context; record deliverable vulnerabilities separately with record_vulnerability. Save verified observations promptly under stable fact_key values. summary states what, where and how verified; body includes ordered steps, original requests/responses or commands and evidence. Use finding|chain|exploit|poc/<slug> for findings, target|auth|infra|business/<slug> for environment facts. For scripts, use category=note and artifact/<slug> with path, dependencies, invocation and success evidence; use test/<slug> for methods, conditions, evidence and retest triggers. Confirmed negative tests are not deprecated. Updating the same key preserves omitted body and links.",
		ShortDescription: "Write/update project facts (including attack chain body)",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"fact_key": map[string]interface{}{
					"type":        "string",
					"description": "Unique in the project key: target/primary_domain, finding/sqli-login, exploit/upload-rce etc.",
				},
				"category": map[string]interface{}{
					"type":        "string",
					"description": "target | auth | infra | business | finding | chain | exploit | poc | note",
					"enum":        []string{"target", "auth", "infra", "business", "finding", "chain", "exploit", "poc", "note"},
				},
				"summary": map[string]interface{}{
					"type":        "string",
					"description": "Index with one line: Conclusion + Location + Trigger/ Verifier Point (do not write only empty words such as \"Existing XSS\")",
				},
				"body": map[string]interface{}{
					"type": "string",
					"description": "Full reproducible context (retrieved by get_project_fact): ordered steps, original HTTP/command, observed results, evidence and related IDs. " +
						"Required for initial finding/exploitation records; include source evidence for environment facts. Suggested sections: conclusion, targets/entry points, attack chain, exploit/POC, key evidence, relationships and notes. " +
						"When updating an existing fact_key, omitting or leaving body empty preserves its stored body while allowing summary updates.",
				},
				"confidence": map[string]interface{}{
					"type":        "string",
					"description": "confirmed | tentative | deprecated",
					"enum":        []string{"confirmed", "tentative", "deprecated"},
				},
				"pinned": map[string]interface{}{
					"type":        "boolean",
					"description": "Whether the blackboard index is preferred",
				},
				"related_vulnerability_id": map[string]interface{}{
					"type":        "string",
					"description": "Optional: Linked bug record ID",
				},
				"links": map[string]interface{}{
					"type":        "array",
					"description": "optional: Relations (from → Current fact) .finding At least. 1 Article {from:target/*, type:discovered_on}; finding Record exploit Use {from:exploit/*, type:exploits}.Ignore Retention Already Edge; Pass [] Clear all relationships.",
					"items": map[string]interface{}{
						"type": "object",
						"properties": map[string]interface{}{
							"from": map[string]interface{}{
								"type":        "string",
								"description": "Source fact_key: Store as from current fact",
							},
							"type": map[string]interface{}{
								"type":        "string",
								"description": "depends_on | leads_to | enables | exploits | discovered_on | contains | part_of | supports",
							},
							"confidence": map[string]interface{}{
								"type":        "string",
								"description": "confirmed | tentative | deprecated",
							},
						},
						"required": []string{"from", "type"},
					},
				},
			},
			"required": []string{"fact_key", "summary"},
		},
	}

	mcpServer.RegisterTool(upsertTool, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		projectID, err := projectIDFromConversation(db, ctx)
		if err != nil {
			return textResult("Error: "+err.Error(), true), nil
		}
		factKey, _ := args["fact_key"].(string)
		summary, _ := args["summary"].(string)
		if database.IsContextCheckpointKey(factKey) {
			return textResult("Error: note/context-* contains system resume records and cannot be overwritten by fact tools; use a separate fact_key for shared project facts", true), nil
		}
		if strings.TrimSpace(factKey) == "" || strings.TrimSpace(summary) == "" {
			return textResult("Error: fact_key and summary will be filled", true), nil
		}
		if len([]rune(summary)) > cfg.Project.FactSummaryMaxRunesEffective() {
			return textResult(fmt.Sprintf("Error: summary Too long. (at most %d Word) ", cfg.Project.FactSummaryMaxRunesEffective()), true), nil
		}
		f := &database.ProjectFact{
			ProjectID:              projectID,
			FactKey:                factKey,
			Category:               strArg(args, "category"),
			Summary:                summary,
			Body:                   strArg(args, "body"),
			Confidence:             strArg(args, "confidence"),
			Pinned:                 boolArg(args, "pinned"),
			RelatedVulnerabilityID: strArg(args, "related_vulnerability_id"),
		}
		if convID := mcpAuthorizationConversationID(ctx); convID != "" {
			f.SourceConversationID = convID
		}
		created, err := db.UpsertProjectFact(f)
		if err != nil {
			return textResult("Error: "+err.Error(), true), nil
		}
		if _, hasLinks := args["links"]; hasLinks {
			linkInputs, err := project.ParseFactLinkInputs(args["links"])
			if err != nil {
				return textResult("Error: "+err.Error(), true), nil
			}
			convID := mcpAuthorizationConversationID(ctx)
			if err := project.PersistFactLinksFromParsed(db, projectID, created.FactKey, convID, linkInputs, true); err != nil {
				return textResult("Error: Saving relationship edge failed: "+err.Error(), true), nil
			}
			created, _ = db.GetProjectFactByKey(projectID, created.FactKey)
		} else if parsed := project.ParseLinksFromBody(created.Body); len(parsed) > 0 {
			if err := project.PersistFactIncomingLinks(db, projectID, created.FactKey, parsed, true); err != nil {
				return textResult("Error: Failed to parse side from body: "+err.Error(), true), nil
			}
			created, _ = db.GetProjectFactByKey(projectID, created.FactKey)
		}
		msg := fmt.Sprintf("The facts have been preserved.\nfact_key: %s\nid: %s\nconfidence: %s", created.FactKey, created.ID, created.Confidence)
		if in, _ := db.ListIncomingProjectFactEdges(projectID, created.FactKey); len(in) > 0 {
			in = scopedProjectMemoryEdges(db, projectID, mcpAuthorizationConversationID(ctx), false, in)
			if len(in) > 0 {
				msg += "\nRelationship side: " + project.FormatFactLinksText(in)
			}
		}
		if warn := project.SparseBodyWarningIfNeeded(f.Category, f.FactKey, f.Body); warn != "" {
			msg += warn
		}
		return textResult(msg, false), nil
	})

	getTool := mcp.Tool{
		Name:             builtin.ToolGetProjectFact,
		Description:      "Gets the full body and metadata of the project by fact_key. Default reading of shared facts and current session extensions; other sessions must be visible include_history=true, for historical reference only. Summary calls when not available and details are forbidden.",
		ShortDescription: "Press key to get fact details",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"include_history": map[string]interface{}{"type": "boolean", "description": "A visible query for auto-relay records of other sessions of this item; default false, history is not a current task command"},
				"fact_key":        map[string]interface{}{"type": "string", "description": "Facts key"},
			},
			"required": []string{"fact_key"},
		},
	}
	mcpServer.RegisterTool(getTool, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		projectID, err := projectIDFromConversation(db, ctx)
		if err != nil {
			return textResult("Error: "+err.Error(), true), nil
		}
		key := strings.TrimSpace(strArg(args, "fact_key"))
		if key == "" {
			return textResult("Error: fact_key must be filled", true), nil
		}
		f, err := db.GetProjectFactByKey(projectID, key)
		if err != nil {
			return textResult("Error: "+err.Error(), true), nil
		}
		conversationID := mcpAuthorizationConversationID(ctx)
		includeHistory := boolArg(args, "include_history")
		if !database.ContextCheckpointVisible(f, conversationID, includeHistory) {
			return textResult("This key is a history continuation of other sessions or unknown sources; if you need any reference, send the message visibly include_history=true. No historical tasks are performed automatically.", true), nil
		}
		msg := fmt.Sprintf("fact_key: %s\ncategory: %s\nconfidence: %s\nsummary: %s\nupdated_at: %s",
			f.FactKey, f.Category, f.Confidence, f.Summary, f.UpdatedAt.Format("2006-01-02 15:04:05"))
		if f.RelatedVulnerabilityID != "" {
			msg += fmt.Sprintf("\nrelated_vulnerability_id: %s", f.RelatedVulnerabilityID)
		}
		if f.SourceConversationID != "" {
			msg += fmt.Sprintf("\nsource_conversation_id: %s", f.SourceConversationID)
		}
		if in, _ := db.ListIncomingProjectFactEdges(projectID, f.FactKey); len(in) > 0 {
			in = scopedProjectMemoryEdges(db, projectID, conversationID, includeHistory, in)
			msg += "\nRelations (from → Ben. fact) :\n"
			for _, e := range in {
				msg += fmt.Sprintf("- %s ← %s (%s)\n", e.EdgeType, e.SourceFactKey, e.Confidence)
			}
		}
		if out, _ := db.ListOutgoingProjectFactEdges(projectID, f.FactKey); len(out) > 0 {
			out = scopedProjectMemoryEdges(db, projectID, conversationID, includeHistory, out)
			msg += "It points to other facts:\n"
			for _, e := range out {
				msg += fmt.Sprintf("- %s → %s (%s)\n", e.EdgeType, e.TargetFactKey, e.Confidence)
			}
		}
		msg += checkpointReadLabel(f, conversationID)
		msg += "\n\n--- body ---\n" + f.Body
		if warn := project.SparseBodyWarningIfNeeded(f.Category, f.FactKey, f.Body); warn != "" {
			msg += warn
		}
		return textResult(msg, false), nil
	})

	listTool := mcp.Tool{
		Name:             builtin.ToolListProjectFacts,
		Description:      "Lists the current project shared facts and current session extensions (leaf break); include_history=true is visible about the history of the project.",
		ShortDescription: "Presentation of project facts",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"source_conversation_id": map[string]interface{}{"type": "string", "description": "optional: Filter by Source Session; We still need the rest of the session. include_history=true"},
				"include_history":        map[string]interface{}{"type": "boolean", "description": "A visible query for auto-relay records of other sessions of this item; default false, history is not a current task command"},
				"category":               map[string]interface{}{"type": "string"},
				"confidence":             map[string]interface{}{"type": "string"},
				"limit":                  map[string]interface{}{"type": "integer"},
				"offset":                 map[string]interface{}{"type": "integer"},
			},
		},
	}
	mcpServer.RegisterTool(listTool, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		projectID, err := projectIDFromConversation(db, ctx)
		if err != nil {
			return textResult("Error: "+err.Error(), true), nil
		}
		limit := intArg(args, "limit", 50)
		offset := intArg(args, "offset", 0)
		filter := database.ProjectFactListFilter{
			Category:                   strArg(args, "category"),
			Confidence:                 strArg(args, "confidence"),
			RestrictContextCheckpoints: !boolArg(args, "include_history"),
			ContextConversationID:      mcpAuthorizationConversationID(ctx),
			SourceConversationID:       strArg(args, "source_conversation_id"),
		}
		list, err := db.ListProjectFacts(projectID, filter, limit, offset)
		if err != nil {
			return textResult("Error: "+err.Error(), true), nil
		}
		var b strings.Builder
		b.WriteString(fmt.Sprintf("Total %d (limit=%d offset=%d):\n", len(list), limit, offset))
		for _, f := range list {
			b.WriteString(fmt.Sprintf("- [%s] %s — %s (%s)\n", f.FactKey, f.Category, f.Summary, f.Confidence))
			b.WriteString(checkpointReadLabel(f, mcpAuthorizationConversationID(ctx)))
		}
		return textResult(b.String(), false), nil
	})

	searchTool := mcp.Tool{
		Name:             builtin.ToolSearchProjectFacts,
		Description:      "Search the item for shared facts and current session extensions by keyword (summary/body/fact_key); other session extensions require include_history=true.",
		ShortDescription: "Search for project facts",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"source_conversation_id": map[string]interface{}{"type": "string", "description": "optional: Filter by Source Session; We still need the rest of the session. include_history=true"},
				"include_history":        map[string]interface{}{"type": "boolean", "description": "A visible query for auto-relay records of other sessions of this item; default false, history is not a current task command"},
				"query":                  map[string]interface{}{"type": "string"},
				"limit":                  map[string]interface{}{"type": "integer"},
				"offset":                 map[string]interface{}{"type": "integer"},
			},
			"required": []string{"query"},
		},
	}
	mcpServer.RegisterTool(searchTool, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		projectID, err := projectIDFromConversation(db, ctx)
		if err != nil {
			return textResult("Error: "+err.Error(), true), nil
		}
		q := strings.TrimSpace(strArg(args, "query"))
		if q == "" {
			return textResult("Error: query must fill", true), nil
		}
		list, err := db.ListProjectFacts(projectID, database.ProjectFactListFilter{Search: q, RestrictContextCheckpoints: !boolArg(args, "include_history"), ContextConversationID: mcpAuthorizationConversationID(ctx), SourceConversationID: strArg(args, "source_conversation_id")}, intArg(args, "limit", 30), intArg(args, "offset", 0))
		if err != nil {
			return textResult("Error: "+err.Error(), true), nil
		}
		var b strings.Builder
		b.WriteString(fmt.Sprintf("Search \"%s\" Hit. %d Article:\n", q, len(list)))
		for _, f := range list {
			b.WriteString(fmt.Sprintf("- [%s] %s — %s\n", f.FactKey, f.Category, f.Summary))
			b.WriteString(checkpointReadLabel(f, mcpAuthorizationConversationID(ctx)))
		}
		return textResult(b.String(), false), nil
	})

	deprecateTool := mcp.Tool{
		Name:             builtin.ToolDeprecateProjectFact,
		Description:      "Marks the fact as deprecated, excluding it from the blackboard index.",
		ShortDescription: "Facts about the abandoned project",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"fact_key": map[string]interface{}{"type": "string"},
			},
			"required": []string{"fact_key"},
		},
	}
	mcpServer.RegisterTool(deprecateTool, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		projectID, err := projectIDFromConversation(db, ctx)
		if err != nil {
			return textResult("Error: "+err.Error(), true), nil
		}
		key := strings.TrimSpace(strArg(args, "fact_key"))
		if database.IsContextCheckpointKey(key) {
			f, err := db.GetProjectFactByKey(projectID, key)
			if err != nil || !database.ContextCheckpointVisible(f, mcpAuthorizationConversationID(ctx), false) {
				return textResult("Error: Unable to modify autorelay records for other sessions", true), nil
			}
		}
		if err := db.DeprecateProjectFact(projectID, key); err != nil {
			return textResult("Error: "+err.Error(), true), nil
		}
		return textResult("Fact marked as deprecated: "+key, false), nil
	})

	restoreTool := mcp.Tool{
		Name:             builtin.ToolRestoreProjectFact,
		Description:      "Discarded (deprecated) The truth is back to tentative or confirmed, Reinvolved in Blackboard Index.",
		ShortDescription: "Recover the facts of the abandoned project",
		InputSchema: map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"fact_key": map[string]interface{}{"type": "string"},
				"confidence": map[string]interface{}{
					"type":        "string",
					"description": "Confidence after restoration: tentative (Default) or confirmed",
					"enum":        []string{"tentative", "confirmed"},
				},
			},
			"required": []string{"fact_key"},
		},
	}
	mcpServer.RegisterTool(restoreTool, func(ctx context.Context, args map[string]interface{}) (*mcp.ToolResult, error) {
		projectID, err := projectIDFromConversation(db, ctx)
		if err != nil {
			return textResult("Error: "+err.Error(), true), nil
		}
		key := strings.TrimSpace(strArg(args, "fact_key"))
		if database.IsContextCheckpointKey(key) {
			f, err := db.GetProjectFactByKey(projectID, key)
			if err != nil || !database.ContextCheckpointVisible(f, mcpAuthorizationConversationID(ctx), false) {
				return textResult("Error: Unable to modify autorelay records for other sessions", true), nil
			}
		}
		if key == "" {
			return textResult("Error: fact_key must be filled", true), nil
		}
		conf := strArg(args, "confidence")
		if err := db.RestoreProjectFact(projectID, key, conf); err != nil {
			return textResult("Error: "+err.Error(), true), nil
		}
		if conf == "" {
			conf = "tentative"
		}
		return textResult(fmt.Sprintf("The truth is back to %s: %s", conf, key), false), nil
	})

	if logger != nil {
		logger.Debug("Project blackboard MCP tool registered successfully")
	}
}

func strArg(args map[string]interface{}, key string) string {
	if v, ok := args[key].(string); ok {
		return v
	}
	return ""
}

func boolArg(args map[string]interface{}, key string) bool {
	if v, ok := args[key].(bool); ok {
		return v
	}
	return false
}

func intArg(args map[string]interface{}, key string, def int) int {
	switch v := args[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case int64:
		return int(v)
	default:
		return def
	}
}

// History is a read opt-in, not promotion to a confirmed fact or new authorization.
func checkpointReadLabel(f *database.ProjectFact, conversationID string) string {
	if !database.IsContextCheckpointKey(f.FactKey) {
		return ""
	}
	label := "Record of current session"
	if strings.TrimSpace(conversationID) == "" || f.SourceConversationID != conversationID {
		label = "Historical references, not current tasks; checking current mandates, objectives and validity of evidence"
	}
	source := f.SourceConversationID
	if source == "" {
		source = "Unknown source"
	}
	return fmt.Sprintf("\n[Resumed records: %s; source session = %s; update time = %s]\n", label, source, f.UpdatedAt.Format("2006-01-02T15:04:05Z07:00"))
}

func scopedProjectMemoryEdges(db *database.DB, projectID, conversationID string, includeHistory bool, edges []*database.ProjectFactEdge) []*database.ProjectFactEdge {
	if includeHistory {
		return edges
	}
	var visible []*database.ProjectFactEdge
	allowed := make(map[string]bool)
	for _, e := range edges {
		keep := true
		for _, key := range []string{e.SourceFactKey, e.TargetFactKey} {
			if !database.IsContextCheckpointKey(key) {
				continue
			}
			ok, seen := allowed[key]
			if !seen {
				f, err := db.GetProjectFactByKey(projectID, key)
				ok = err == nil && database.ContextCheckpointVisible(f, conversationID, false)
				allowed[key] = ok
			}
			if !ok {
				keep = false
				break
			}
		}
		if keep {
			visible = append(visible, e)
		}
	}
	return visible
}
