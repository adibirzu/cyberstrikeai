package handler

// addAgentRunSpec reuses each synchronous request schema without changing it.
func addAgentRunSpec(spec map[string]interface{}) {
	paths := spec["paths"].(map[string]interface{})
	for _, base := range []string{"/api/eino-agent", "/api/multi-agent"} {
		original := paths[base].(map[string]interface{})["post"].(map[string]interface{})
		paths[base+"/runs"] = map[string]interface{}{"post": map[string]interface{}{
			"tags": []string{"Conversation Interaction"}, "summary": "Step forward to dialogue mandate", "description": "Returns 202 after receiving, and the client breakline does not cancel the task. Idempotency-Key must be provided by user-separated; the same key and request return the original letter, with different requests returning 409. The final result of the query via statusUrl; the use of /api/agent-loop/cancel must be cancelled.",
			"requestBody": original["requestBody"],
			"parameters":  []map[string]interface{}{{"in": "header", "name": "Idempotency-Key", "required": true, "schema": map[string]interface{}{"type": "string", "minLength": 1, "maxLength": 200}}},
			"responses":   map[string]interface{}{"202": map[string]interface{}{"description": "Received: runId, conversationId, assistantMessageId, status, statusUrl; Location contains the status URL"}, "400": map[string]interface{}{"description": "Invalid parameter or mode"}, "403": map[string]interface{}{"description": "No permission"}, "409": map[string]interface{}{"description": "Keyload conflict or session is ongoing"}, "500": map[string]interface{}{"description": "Failed to receive record"}},
		}}
		paths[base+"/runs/{runId}"] = map[string]interface{}{"get": map[string]interface{}{
			"tags": []string{"Conversation Interaction"}, "summary": "Querying the hiking dialogue task", "description": "Return to Protracted Status, result, Organisation.Unfinished service after restart interrupted, Do not automatically replay.",
			"parameters": []map[string]interface{}{{"in": "path", "name": "runId", "required": true, "schema": map[string]interface{}{"type": "string"}}},
			"responses":  map[string]interface{}{"200": map[string]interface{}{"description": "Status and results of the mission"}, "403": map[string]interface{}{"description": "Lack of access to dialogue"}, "404": map[string]interface{}{"description": "Task not found"}},
		}}
	}
}
