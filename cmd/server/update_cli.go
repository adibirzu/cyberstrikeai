package main

import (
	"context"
	"cyberstrike-ai/internal/config"
	"cyberstrike-ai/internal/update"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// The same one-click update the console page drives, for the two cases a page cannot
// serve: the process is not running at all, and somebody is ssh'd in with a keyboard.
// Keeping it in the binary rather than only in a shell script means one implementation of
// "fetch, fast-forward, rebuild, swap" instead of two that can disagree. The update
// source is read from the same config.yaml field the page saves to, so the keyboard and
// the button can never update from different repositories.
func updateCommandIfNeeded(configPath string, check, apply, rollback bool) (bool, int) {
	if !check && !apply && !rollback {
		return false, 0
	}
	root := filepath.Dir(configPath)
	repo, err := config.LoadUpdateRepo(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read update source: %v\n", err)
		return true, 1
	}
	opts := update.Options{Root: root, Repo: repo}
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Minute)
	defer cancel()

	source := strings.TrimSpace(repo)
	if source == "" {
		source = update.DefaultRepoURL + "(official warehouse default)"
	}
	fmt.Printf("Install Directory: %s\n", root)
	fmt.Printf("Update Source: %s\n", source)
	switch {
	case check:
		snap, err := update.Check(ctx, opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Check update failed: %v\n", err)
			return true, 1
		}
		printSnapshot(snap)
		if !snap.Installed || snap.CheckError != "" {
			return true, 1
		}
		return true, 0
	case apply:
		res, err := update.Apply(ctx, opts, func(s update.Step) {
			fmt.Printf("[%s] %s\n", s.Phase, s.Message)
		})
		if res != nil {
			printResult(res)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "Update not completed: %v\n", err)
			return true, 1
		}
		fmt.Println("Source code and binary are in position; new code is effective after restarting service.")
		return true, 0
	case rollback:
		res, err := update.Rollback(ctx, opts)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Rollback incomplete: %v\n", err)
			return true, 1
		}
		printResult(res)
		return true, 0
	}
	return true, 0
}

func printSnapshot(s *update.Snapshot) {
	if !s.Installed {
		fmt.Printf("Not this directory. git Work Tree (%s) , Cannot update automatically\n", s.Root)
		return
	}
	target := s.TargetBranch
	if target == "" {
		target = "?"
	}
	fmt.Printf("%s / Submit %s (%s), update source default branch %s\n", s.Branch, s.Commit, s.Subject, target)
	if s.CheckError != "" {
		fmt.Printf("Check failed: %s\n", s.CheckError)
		return
	}
	fmt.Printf("Update source %s (%s), late %d, local %d lead\n", s.RemoteCommit, s.RemoteSubject, s.Behind, s.Ahead)
	for _, c := range s.Incoming {
		fmt.Printf("  ○ %s %s\n", c.Commit, c.Subject)
	}
	if s.Behind > len(s.Incoming) {
		fmt.Printf("  ... (%d in total, only %d in list)\n", s.Behind, len(s.Incoming))
	}
	if len(s.BlockingChanges) > 0 {
		fmt.Printf("This machine has modified %d source files and updates will refuse to execute:\n", len(s.BlockingChanges))
		for _, c := range s.BlockingChanges {
			fmt.Printf("  ! %s (%s)\n", c.Path, c.Status)
		}
	}
	if !s.CanBuild {
		fmt.Println("No Go Tool Chain: Update only source code, not recompiled")
	}
	if s.BuildPending {
		fmt.Println("The last update left uncompleted translations (source code in place, binary or old): reruning the update once the tool chain is installed")
	}
	if s.HasRollback {
		fmt.Printf("But roll back to %s\n", s.RollbackTo)
	}
}

func printResult(r *update.Result) {
	moved := r.Commits > 0 || r.ToCommit != r.FromCommit
	if !moved && !r.BinaryBuilt {
		fmt.Println("It's the latest. It hasn't changed.")
		return
	}
	if moved {
		fmt.Printf("%s → %s (%d Submitted, Involving %d File, Time used %s) \n", r.FromCommit, r.ToCommit, r.Commits, r.FilesTouched, r.Duration)
	} else {
		// commits == 0 but a binary was built: a retry that finished a build the previous
		// attempt could not. Saying "已经是最新，没有改动" here would bury the one thing
		// that did happen.
		fmt.Printf("Source code is the latest (%s) and this time binary is added\n", r.ToCommit)
	}
	if len(r.KeptContent) > 0 {
		fmt.Printf("Keep it. %d Local content files (roles/skills/tools etc., Not covered upstream) : \n", len(r.KeptContent))
		for _, p := range r.KeptContent {
			fmt.Printf("  = %s\n", p)
		}
	}
	if r.BinaryBuilt {
		fmt.Printf("Binary has been replaced: %s (old version left in %s to roll back)\n", r.BinaryPath, r.PrevBinary)
	}
}
