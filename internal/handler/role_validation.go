package handler

import (
	"fmt"
	"strings"
	"unicode"
	"unicode/utf8"

	"cyberstrike-ai/internal/config"
)

func validateRoleName(name string) error {
	if strings.TrimSpace(name) == "" {
		return fmt.Errorf("Role name is required")
	}
	if name != strings.TrimSpace(name) || utf8.RuneCountInString(name) > 64 {
		return fmt.Errorf("Role name cannot contain a first-end space and cannot exceed 64 characters")
	}
	if strings.Contains(name, "..") || strings.ContainsAny(name, `/\:*?"<>|`) {
		return fmt.Errorf("Role name cannot contain path or file name special characters")
	}
	for _, r := range name {
		if unicode.IsControl(r) {
			return fmt.Errorf("Role name cannot contain control characters")
		}
	}
	return nil
}

func (h *RoleHandler) validateRole(role config.RoleConfig) error {
	if err := validateRoleName(role.Name); err != nil {
		return err
	}
	// Spaces are kept in display names but mapped to underscores on disk.
	for key, existing := range h.config.Roles {
		name := existing.Name
		if name == "" {
			name = key
		}
		if name != role.Name && strings.EqualFold(sanitizeFileName(name), sanitizeFileName(role.Name)) {
			return fmt.Errorf("Role name conflicts with existing role file name")
		}
	}
	if strings.TrimSpace(role.WorkflowID) != "" {
		if h.db == nil {
			return fmt.Errorf("Workstream storage is not available, binding cannot be verified")
		}
		wf, err := h.db.GetWorkflowDefinition(role.WorkflowID)
		if err != nil {
			return fmt.Errorf("Could not verify current binding: %w", err)
		}
		if wf == nil {
			return fmt.Errorf("Role-bound workflows don't exist.")
		}
	}
	return nil
}
