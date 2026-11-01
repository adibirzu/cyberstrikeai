package handler

// apiDocI18n 为 OpenAPI 文档提供 x-i18n-* 扩展键，供前端 apiDocs 国际化使用。
// 前端通过 apiDocs.tags.* / apiDocs.summary.* / apiDocs.response.* 翻译。

var apiDocI18nTagToKey = map[string]string{
	"Auth": "auth", "Conversation Management": "conversationManagement", "Conversation Interaction": "conversationInteraction",
	"Batch Task": "batchTasks", "Vulnerability Management": "vulnerabilityManagement",
	"Role Management": "roleManagement", "Skills Management": "skillsManagement", "Monitoring": "monitoring",
	"Configuration Management": "configManagement", "External MCP Management": "externalMCPManagement", "Attack Chains": "attackChain",
	"Knowledge Base": "knowledgeBase", "MCP": "mcp",
	"FOFA Recon": "fofaRecon", "Terminal": "terminal", "WebShell Management": "webshellManagement",
	"Chat uploads": "chatUploads", "Robot Integration": "robotIntegration", "Markdown Agents": "markdownAgents",
	"Project Management": "projectManagement", "Asset Management": "assetManagement",
}

var apiDocI18nSummaryToKey = map[string]string{
	"User login": "login", "User logout": "logout", "Change password": "changePassword", "Validate Token": "validateToken",
	"Conversation created": "createConversation", "List conversations": "listConversations", "Get conversation detail": "getConversationDetail",
	"Update conversation": "updateConversation", "Conversation deleted": "deleteConversation", "Get conversation result": "getConversationResult",
	"Send message and get AI reply (non-stream)": "sendMessageNonStream", "Send message and get AI reply (stream)": "sendMessageStream",
	"Cancel Task": "cancelTask", "List running tasks": "listRunningTasks", "List completed tasks": "listCompletedTasks",
	"Batch task queue created": "createBatchQueue", "List batch task queues": "listBatchQueues", "Get batch task queue": "getBatchQueue",
	"Batch task queue deleted": "deleteBatchQueue", "Batch task queue started": "startBatchQueue", "Batch task queue paused": "pauseBatchQueue",
	"Add task to queue": "addTaskToQueue", "SQL injection scan": "sqlInjectionScan", "Port scan": "portScan",
	"Update batch task": "updateBatchTask", "Delete batch task": "deleteBatchTask",
	"List vulnerabilities": "listVulnerabilities", "Create vulnerability": "createVulnerability", "Get vulnerability statistics": "getVulnerabilityStats",
	"Get vulnerability": "getVulnerability", "Update vulnerability": "updateVulnerability", "Delete vulnerabilities": "deleteVulnerability",
	"List roles": "listRoles", "Role created": "createRole", "Get role": "getRole", "Role updated": "updateRole", "Role deleted": "deleteRole",
	"Get available Skills list": "getAvailableSkills", "List Skills": "listSkills", "Create Skill": "createSkill",
	"Get Skill statistics": "getSkillStats", "Clear Skill statistics": "clearSkillStats", "Get Skill": "getSkill",
	"Update Skill": "updateSkill", "Delete Skill": "deleteSkill", "Get bound roles": "getBoundRoles",
	"Get monitoring info": "getMonitorInfo", "Get execution records": "getExecutionRecords", "Delete execution": "deleteExecutionRecord",
	"Batch delete execution records": "batchDeleteExecutionRecords", "Get statistics": "getStats",
	"Get configuration": "getConfig", "Update configuration": "updateConfig", "Get tool configuration": "getToolConfig", "Apply config": "applyConfig",
	"List external MCP": "listExternalMCP", "Get external MCP statistics": "getExternalMCPStats", "Get external MCP": "getExternalMCP",
	"Add or update external MCP": "addOrUpdateExternalMCP", "stdio mode config": "stdioModeConfig", "SSE mode config": "sseModeConfig",
	"Delete external MCP": "deleteExternalMCP", "Start external MCP": "startExternalMCP", "Stop external MCP": "stopExternalMCP",
	"Get attack chain": "getAttackChain", "Regenerate attack chains": "regenerateAttackChain",
	"Pin conversation": "pinConversation",
	"Get categories":   "getCategories", "List knowledge items": "listKnowledgeItems", "Create knowledge item": "createKnowledgeItem",
	"Get knowledge item": "getKnowledgeItem", "Update knowledge item": "updateKnowledgeItem", "Knowledge item deleted": "deleteKnowledgeItem",
	"Get index status": "getIndexStatus", "Build index": "startKnowledgeIndex", "Scan knowledge base": "scanKnowledgeBase",
	"Search knowledge base": "searchKnowledgeBase", "Basic search": "basicSearch", "Search by risk type": "searchByRiskType",
	"Get retrieval logs": "getRetrievalLogs", "Delete retrieval log": "deleteRetrievalLog",
	"MCP endpoint": "mcpEndpoint", "List all tools": "listAllTools", "Invoke tool": "invokeTool", "Initialize connection": "initConnection",
	"Success response": "successResponse", "Error response": "errorResponse",
	// 新增缺失端点
	"Conversation turn deleted": "deleteConversationTurn", "Get message process details": "getMessageProcessDetails",
	"Batch task queue rerun": "rerunBatchQueue", "Update queue metadata": "updateBatchQueueMetadata",
	"Update queue schedule": "updateBatchQueueSchedule", "Toggle cron auto-schedule": "setBatchQueueScheduleEnabled",
	"FOFA search": "fofaSearch", "Parse natural language to FOFA syntax": "fofaParse",
	"Test OpenAI API connection": "testOpenAI",
	"Execute terminal commands":  "terminalRun", "Run terminal command (stream)": "terminalRunStream", "WebSocket terminal": "terminalWS",
	"List WebShell connections": "listWebshellConnections", "Create WebShell connection": "createWebshellConnection",
	"Update WebShell connection": "updateWebshellConnection", "Delete WebShell connection": "deleteWebshellConnection",
	"Get connection state": "getWebshellConnectionState", "Save connection state": "saveWebshellConnectionState",
	"Get AI chat history": "getWebshellAIHistory", "List AI conversations": "listWebshellAIConversations",
	"Execute WebShell command": "webshellExec", "WebShell file operation": "webshellFileOp",
	"List uploads": "listChatUploads", "Export uploads": "exportChatUploads", "Upload file": "uploadChatFile", "Delete upload": "deleteChatUpload",
	"Download upload": "downloadChatUpload", "Get file text content": "getChatUploadContent",
	"Write file text content": "putChatUploadContent", "Create upload directory": "mkdirChatUpload", "Rename upload": "renameChatUpload",
	"WeCom callback verification": "wecomCallbackVerify", "WeCom message callback": "wecomCallbackMessage",
	"DingTalk message callback": "dingtalkCallback", "Lark message callback": "larkCallback", "Test robot message processing": "testRobot",
	"List Markdown agents": "listMarkdownAgents", "Create Markdown agent": "createMarkdownAgent",
	"Get Markdown agent detail": "getMarkdownAgent", "Update Markdown agent": "updateMarkdownAgent", "Delete Markdown agent": "deleteMarkdownAgent",
	"List skill package files": "listSkillPackageFiles", "Get skill package file content": "getSkillPackageFile", "Write skill package file": "putSkillPackageFile",
	"Batch get tool names":     "batchGetToolNames",
	"Get knowledge base stats": "getKnowledgeStats",
	"List projects":            "listProjects", "Create project": "createProject", "Get project": "getProject",
	"Update project": "updateProject", "Delete project": "deleteProject",
	"Import assets in bulk":   "importAssets",
	"List or get fact by key": "listProjectFacts", "Create/update fact": "upsertProjectFact",
	"Get project fact attack path graph": "getProjectFactGraph", "List all project fact edges": "listProjectFactEdges",
	"Add fact edge": "createProjectFactEdge", "Delete fact edge": "deleteProjectFactEdge",
	"Promote conversation attack chain to project fact graph": "promoteAttackChainToProject",
}

var apiDocI18nResponseDescToKey = map[string]string{
	"Success": "getSuccess", "Unauthorized": "unauthorized", "Unauthorized, valid Token required": "unauthorizedToken",
	"Created successfully": "createSuccess", "Bad request": "badRequest", "Conversation not found": "conversationNotFound",
	"Conversation or result not found": "conversationOrResultNotFound", "Bad request (e.g. task is empty)": "badRequestTaskEmpty",
	"Bad request (e.g. invalid config or missing required fields)": "badRequestConfig",
	"Bad request (e.g. query is empty)":                            "badRequestQueryEmpty", "Method not allowed (POST only)": "methodNotAllowed",
	"Login successful": "loginSuccess", "Invalid password": "invalidPassword", "Logout successful": "logoutSuccess",
	"Password changed successfully": "passwordChanged", "Token valid": "tokenValid", "Token invalid or expired": "tokenInvalid",
	"Conversation created": "conversationCreated", "Internal server error": "internalError", "Updated successfully": "updateSuccess",
	"Deleted successfully": "deleteSuccess", "Queue not found": "queueNotFound", "Started successfully": "startSuccess",
	"Paused successfully": "pauseSuccess", "Added successfully": "addSuccess",
	"Task not found":           "taskNotFound",
	"Cancel request submitted": "cancelSubmitted", "No running task found": "noRunningTask",
	"Message sent, AI reply returned": "messageSent", "Stream response (Server-Sent Events)": "streamResponse",
	// 新增缺失端点响应
	"Bad request or delete failed": "badRequestOrDeleteFailed",
	"Invalid parameters":           "paramError", "Only completed or cancelled queues can be rerun": "onlyCompletedOrCancelledCanRerun",
	"Bad request or queue is running": "badRequestOrQueueRunning", "Set successfully": "setSuccess",
	"Search successful": "searchSuccess", "Parse successful": "parseSuccess", "Test result": "testResult",
	"Execution completed": "executionDone", "SSE event stream": "sseEventStream", "WebSocket connection established": "wsEstablished",
	"File download": "fileDownload", "File not found": "fileNotFound", "Written successfully": "writeSuccess",
	"Renamed successfully": "renameSuccess", "Verification successful, decrypted echostr returned": "wecomVerifySuccess",
	"Processed successfully": "processSuccess", "Agent not found": "agentNotFound", "Saved successfully": "saveSuccess",
	"Operation result": "operationResult", "Execution result": "executionResult", "Connection not found": "connectionNotFound",
	"Project list": "projectList", "Project detail": "projectDetail",
	"Fact list or single fact (may include link_counts / outgoing_links)": "projectFactList",
	"nodes + edges": "factGraphNodesEdges",
	"Edge list":     "edgeList", "Edge created": "edgeCreated",
	"Promotion result (facts/edges/graph)": "promoteAttackChainResult",
	"Import completed":                     "assetImportCompleted", "Asset count or field validation failed": "assetImportValidationFailed",
	"Missing asset:write permission or access to the specified project": "assetImportForbidden",
	"Import transaction failed":                                         "assetImportTransactionFailed",
}

// enrichSpecWithI18nKeys 在 spec 的每个 operation 上写入 x-i18n-tags、x-i18n-summary，
// 在每个 response 上写入 x-i18n-description，供前端按 key 做国际化。
func enrichSpecWithI18nKeys(spec map[string]interface{}) {
	paths, _ := spec["paths"].(map[string]interface{})
	if paths == nil {
		return
	}
	for _, pathItem := range paths {
		pm, _ := pathItem.(map[string]interface{})
		if pm == nil {
			continue
		}
		for _, method := range []string{"get", "post", "put", "delete", "patch"} {
			opVal, ok := pm[method]
			if !ok {
				continue
			}
			op, _ := opVal.(map[string]interface{})
			if op == nil {
				continue
			}
			// x-i18n-tags: 与 tags 一一对应的 i18n 键数组（spec 中 tags 为 []string）
			switch tags := op["tags"].(type) {
			case []string:
				if len(tags) > 0 {
					keys := make([]string, 0, len(tags))
					for _, s := range tags {
						if k := apiDocI18nTagToKey[s]; k != "" {
							keys = append(keys, k)
						} else {
							keys = append(keys, s)
						}
					}
					op["x-i18n-tags"] = keys
				}
			case []interface{}:
				if len(tags) > 0 {
					keys := make([]interface{}, 0, len(tags))
					for _, t := range tags {
						if s, ok := t.(string); ok {
							if k := apiDocI18nTagToKey[s]; k != "" {
								keys = append(keys, k)
							} else {
								keys = append(keys, s)
							}
						}
					}
					if len(keys) > 0 {
						op["x-i18n-tags"] = keys
					}
				}
			}
			// x-i18n-summary
			if summary, _ := op["summary"].(string); summary != "" {
				if k := apiDocI18nSummaryToKey[summary]; k != "" {
					op["x-i18n-summary"] = k
				}
			}
			// responses -> 每个 status -> x-i18n-description
			if respMap, _ := op["responses"].(map[string]interface{}); respMap != nil {
				for _, rv := range respMap {
					if r, _ := rv.(map[string]interface{}); r != nil {
						if desc, _ := r["description"].(string); desc != "" {
							if k := apiDocI18nResponseDescToKey[desc]; k != "" {
								r["x-i18n-description"] = k
							}
						}
					}
				}
			}
		}
	}
}
