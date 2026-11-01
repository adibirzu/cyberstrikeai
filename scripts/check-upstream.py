#!/usr/bin/env python3
"""Dry-run an upstream merge in an isolated temporary clone. Never promote it."""
import argparse
import json
import pathlib
import subprocess
import tempfile

UPSTREAM = 'https://github.com/AIPentest/CyberStrikeAI.git'

def git(root, *args, check=True):
    return subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', '-C', str(root), *args],
                          text=True, capture_output=True, check=check)

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upstream', default=UPSTREAM, help='Official vendor URL; local fixture repositories are supported for offline testing')
    parser.add_argument('--ref', default='refs/heads/main')
    parser.add_argument('--report', type=pathlib.Path)
    args = parser.parse_args()
    if args.ref.startswith('-') or any(c.isspace() for c in args.ref):
        parser.error('ref must be a single Git ref or commit')
    root = pathlib.Path(__file__).resolve().parents[1]
    head = git(root, 'rev-parse', 'HEAD').stdout.strip()
    with tempfile.TemporaryDirectory(prefix='cyberstrike-upstream-check-') as temporary:
        clone = pathlib.Path(temporary) / 'candidate'
        subprocess.run(['git', '-c', 'core.hooksPath=/dev/null', 'clone', '--no-hardlinks', '--no-checkout', str(root), str(clone)], check=True, capture_output=True)
        git(clone, 'checkout', '--detach', head)
        git(clone, 'config', 'user.name', 'Upstream dry run')
        git(clone, 'config', 'user.email', 'dry-run@invalid.example')
        git(clone, 'fetch', '--no-tags', '--', args.upstream, args.ref)
        candidate = git(clone, 'rev-parse', 'FETCH_HEAD').stdout.strip()
        base = git(clone, 'merge-base', head, candidate).stdout.strip()
        merge = git(clone, 'merge', '--no-commit', '--no-ff', candidate, check=False)
        conflicts = git(clone, 'diff', '--name-only', '--diff-filter=U').stdout.splitlines()
        commits = git(clone, 'log', '--format=%H %s', head+'..'+candidate).stdout.splitlines()
        report = {'fork_head': head, 'upstream': args.upstream, 'candidate': candidate,
                  'merge_base': base, 'merge_clean': merge.returncode == 0,
                  'conflicts': conflicts, 'incoming_commits': commits,
                  'promoted': False, 'tests_run': False}
        rendered = json.dumps(report, indent=2)+'\n'
        if args.report:
            args.report.write_text(rendered)
        print(rendered, end='')
        if merge.returncode != 0:
            if not conflicts:
                raise RuntimeError('Merge failed without content conflicts: '+merge.stderr.strip())
            return 1
    return 0

if __name__ == '__main__':
    raise SystemExit(main())
