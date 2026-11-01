package project

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func sanitizeWorkspacePathSegment(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "default"
	}
	s = strings.ReplaceAll(s, string(filepath.Separator), "-")
	s = strings.ReplaceAll(s, "/", "-")
	s = strings.ReplaceAll(s, "\\", "-")
	s = strings.ReplaceAll(s, "..", "__")
	if len(s) > 180 {
		s = s[:180]
	}
	return s
}

// WorkspaceRootDir returns the relative workspace root for downloads and local analysis.
// Project-bound sessions share projects/<id>/; otherwise conversations/<id>/.
func WorkspaceRootDir(configuredBase, projectID, conversationID string) string {
	base := strings.TrimSpace(configuredBase)
	if base == "" {
		base = filepath.Join("tmp", "workspace")
	}
	if pid := strings.TrimSpace(projectID); pid != "" {
		return filepath.Join(base, "projects", sanitizeWorkspacePathSegment(pid))
	}
	conv := strings.TrimSpace(conversationID)
	if conv == "" {
		conv = "default"
	}
	return filepath.Join(base, "conversations", sanitizeWorkspacePathSegment(conv))
}

// EnsureWorkspace creates the workspace directory and returns its absolute path.
func EnsureWorkspace(root string) (string, error) {
	abs, err := filepath.Abs(strings.TrimSpace(root))
	if err != nil {
		return "", fmt.Errorf("workspace abs: %w", err)
	}
	if err := os.MkdirAll(abs, 0o755); err != nil {
		return "", fmt.Errorf("workspace mkdir: %w", err)
	}
	return abs, nil
}

// BuildWorkspaceBlock instructs the agent to use the session workspace instead of /tmp.
func BuildWorkspaceBlock(absPath string) string {
	absPath = strings.TrimSpace(absPath)
	if absPath == "" {
		return ""
	}
	return fmt.Sprintf(`## Session Working Directory (downloads and local analysis)
Save downloaded files and analysis artifacts under:
`+"`%s`"+`
- This project/session workspace survives conversation restarts. Save verified reusable scripts in artifacts/ and register their relative paths, usage and evidence with upsert_project_fact(category=note, fact_key=artifact/<name>).
- Do not use shared /tmp or other global temporary directories; concurrent projects/sessions may collide.
- Example: curl -o '%s/page.html' 'https://target/'; set exec workdir to this directory.
- Limit glob/grep/read_file searches for downloaded artifacts to this workspace.
- When the user refers to their current directory or existing local files, check the service process working directory. An empty session workspace is not the project root.`, absPath, absPath)
}
