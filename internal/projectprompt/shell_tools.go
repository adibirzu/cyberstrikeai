package projectprompt

func ShellExecExecuteGuidanceSection() string {
	return `Shell (exec/execute): prefer specialized MCP tools when available. Use exec for system commands, pipes, workdir and background (&) jobs; use execute for skill scripts after inspecting them with read_file/skill. Split multi-step scans into separate calls instead of combining scanners in one shell command. Write long scripts, request bodies and payloads to files with write_file first, then invoke short commands. Store downloads and temporary files in the supplied Session Working Directory, not shared /tmp.`
}
func ShellExecExecuteGuidanceReconSuffix() string {
	return `Use dedicated subfinder/amass MCP tools individually instead of aggregating them through exec/execute.`
}
