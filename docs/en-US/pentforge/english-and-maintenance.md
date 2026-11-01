# Pentforge English fork and maintenance

This maintained fork supplies English UI text, tool/parameter metadata, agent/skill/role instructions, prompts, help and diagnostics. Preserve tool IDs, schema enums/keys, RBAC keys, command syntax, format arguments and exact evidence. Target/user content and historical records are data; never translate them in bulk to satisfy a character check. The security status and unresolved boundaries live in the single [known-risk ledger](security-review.md).

[maintenance/upstream.json](../../../maintenance/upstream.json) pins the fork/vendor/SSO bases. The upstream Apache 2.0 license/attribution remains. The SSO baseline is merged fork PR #1, including release `764ea9dfaf09f74dbb083f9bced94fb32b915014`. Corporate portal customers receive no native operator role from this work.

## English policy and exact exceptions

English is selected even with a Chinese browser, old csai_lang preference or later unsupported-locale request. The selector offers English and the old zh-CN resource is archived outside served web assets. Browser tests execute the initializer and role/account presentation paths.

The finite reviewed input/data exceptions are listed in [maintenance/english-exceptions.json](../../../maintenance/english-exceptions.json):

- internal/config/role_aliases.go accepts exact historical bundled role selectors; exact operator custom roles take precedence. Stored records are preserved and bundled display names resolve to English.
- internal/legacytext/aliases.go accepts old guard/transcript/placeholder envelopes, command/decision/branch tokens and fact-link patterns. These are parsers, not trust sources. Model/target/imported/persisted text cannot mint identities, scope, approvals or permissions. Native authorization and user-scoped pending actions still apply.
- web/static/js/i18n.js contains the matching legacy role-input table and exact factory admin-label presentation alias. It does not modify accounts/roles or grants. web/static/js/assets.js retains bounded prior-export header/enum/format input tables; native import permissions remain required.
- The MySQL knowledge article retains the original U+9023 glyph for the GBK 0xDF5C byte-semantic SQL example. Translating that glyph to an English word corrupts the payload. This is data, not Chinese operational prose.
- Source comments, synthetic/historical fixtures, original attribution, README_CN.md/vendor documentation under docs/zh-CN and maintenance/vendor-locales are non-product material. Custom packages, account names, historical conversations/findings, filenames, target evidence and third-party tool output retain their original content and require separate operator review where relevant.

The runtime audit invokes actual tool/role/skill/agent loaders, generated prompts and HTML/English-JSON consumers. The separate Go source lint checks string literals, excluding comments/tests and exactly the two Go compatibility files above. scripts/check-tool-contracts.py consumes normalized tool definitions, checks reviewed executable/schema hashes, compiles embedded Python and inspects executable string literals without running tools. It also checks standalone MCP Python literals without importing/starting them. Syntax checks alone do not prove English or model behavior. Optional Java/browser extension strings were reviewed; no live extension/MCP/model acceptance is implied.

## Translation provenance and semantic checks

Translation assistance processed public source **offline in developer-only tooling**. No customer data/source was sent to an external translation API and no translation model ships/runs in the product. The isolated tools were Argos Translate 1.10.0 and official package translate-zh_en-1_9.argosmodel (1.9), SHA-256 `62e7af5a3a48b530e47b7b3e5c78c2de79073ecd815750d2bf3ab35b4a67da2d`, identified through the [official package index](https://github.com/argosopentech/argospm-index).

Machine candidates produced ambiguous permissions, damaged placeholders and unrelated diagnostics; they were rejected/corrected. All bundled tool/parameter descriptions, roles, agents and operational skill bodies were manually authored/reviewed. Shared scope/evidence/shell/WebShell/attack-chain guidance received an additional read-only source-semantics review. No production/live-LLM acceptance was run.

Original/current Go format-bearing literals and typed YAML command/schema fields were compared. Embedded recipe structure/ASCII contracts were inspected separately from translated diagnostics. Deliberate changes include English fscan output, disabled-by-default OAST/private sessions, exact role aliases, constrained child environments, fork updater/registry defaults and the optional reverse-shell loopback default. Public input parsers remain compatible. Review negation, root/administrator requirements, scheduling, cancellation, secret handling and destructive effects against original meaning at every upstream integration.

## Existing-install upgrade

A source update deliberately preserves operator-owned tools/, roles/, skills/, agents/ and knowledge data. Updating the binary alone therefore does **not** replace old operational packages. Never bulk-translate SQLite rows or overwrite customized prompts/catalogs.

1. Coordinate an idle maintenance window. Stop promotion/production changes until the reviewed source/binary and rollback set are ready. Back up exact Git SHA, binary/digest, config, SQLite DB and operator catalogs; protect backups containing secrets.
2. Use an isolated developer Python environment with official PyYAML==6.0.3. Run the replacement script from the reviewed candidate checkout, with an explicit existing installation path. The default is a dry-run:

```sh
python scripts/migrate-bundled-english.py --install-root /path/to/installation
```

3. Review every state. Only exact recognized baseline factory hashes can be replaced. Unknown/custom files or renamed-destination conflicts block **before planned writes**; absent operator-deleted packages remain absent. Exact custom English config scalars are preserved; customized Chinese operational config needs a manual operator-approved translation. No DB is opened.
4. The manifest recognizes bundled files plus four factory config scalars: tool-guard rule name/message and the two HITL audit prompts. Only those exact scalar values can change; credentials, other YAML bytes, custom settings and historical data stay intact.
5. Apply only the reviewed plan with a **new**, private backup directory on the installation filesystem:

```sh
python scripts/migrate-bundled-english.py --install-root /path/to/installation --apply --backup-dir /path/to/private-new-backup
```

The script rechecks source/config/destination after planning. A renamed destination is never overwritten: reuse an exact English copy or exclusively create an absent path. Simulated concurrent edits are tested. Replacement is atomic **per file**, not a transaction across all files; an interrupted/failed apply can leave a partial migration with its plan/backups. Keep the installation idle, inspect the report and restore only the reviewed affected paths from backup if necessary. Do not roll back over subsequent operator edits. Repeat dry-run to confirm state before release.

Legacy queue/conversation/bookmark role IDs continue resolving through compatibility aliases, and browser/robot display names are English for recognized bundled roles. Exact custom roles win. The old factory admin label is presentation-normalized without changing stored identity/permissions. Customized operational catalogs still require review; data in conversations/findings is never automatically rewritten.

For an internal OAST recipe using configured environment values, explicitly permit DNSLOG_BASE_URL/DNSLOG_SESSION_DIR through CYBERSTRIKE_CHILD_ENV_ALLOWLIST if needed; do not inherit server secrets wholesale. Prefer authorized HTTPS/self-hosted OAST. The optional classic reverse-shell MCP defaults to 127.0.0.1; use an explicit IPv4 bind_host or REVERSE_SHELL_BIND_HOST only for an authorized isolated interface. 0.0.0.0 is a deliberate wildcard opt-in and provides no authentication/encryption.

## Upstream integration

The application/upgrader defaults to https://github.com/adibirzu/cyberstrikeai.git. Keep update.repo on the maintained fork. An explicit override is a trust decision. Dirty/diverged-source refusal and recovery/rollback gates remain enabled.

1. Start in a clean isolated fork-main checkout. Never reset main to vendor history or discard fork merge/gate commits.
2. Run `python3 scripts/check-upstream.py --report upstream-report.json`. It fetches vendor history and attempts a merge **only in a disposable clone**, recording exact fork/candidate/base SHAs, incoming commits and conflicts. It never promotes/pushes/restarts/deploys; clean merge does not mean tests ran.
3. Create a candidate branch and merge the reported exact vendor SHA with a merge commit. Resolve conflicts explicitly, especially SSO/RBAC, tool execution, child env, prompts/language, migrations and update source.
4. Review incoming code, dependencies, endpoints, schedulers/downloads and executable contracts. Translate new operational content semantically and inspect scripts/credential paths. Update maintenance/tool-contracts.json with `python scripts/check-tool-contracts.py --write-reviewed` **only after** reviewing each deliberate machine-contract change. Regenerate the catalog manifest with `python scripts/build-english-manifest.py --baseline <reviewed-fork-baseline>` and test a clean install plus that upgrade baseline.
5. Require full regression/build/advisory/English/contract checks and a fresh independent review in a fork PR. Update the reviewed vendor base only after that integration is accepted. Deployment needs separate coordination.

The Maintained fork workflow has read-only repository permissions and commit-pinned official Actions. PR/fork-main validation checks runtime/process/authorization behavior, builds, browser behavior, maintenance fixtures and English/contracts. Weekly/manual maintenance retains a disposable upstream report and native Linux amd64/arm64 advisory evidence. No job can merge or deploy. Review weekly and promptly after relevant vendor/security releases; conflicts/new untranslated catalogs block promotion rather than relaxing gates.

## Validation, release and rollback

Use the patched Go version declared by go.mod. Keep GOCACHE/GOMODCACHE/GOTMPDIR/TMPDIR and developer environments on task-owned storage; never clean shared caches or unrelated worktrees. In an isolated Linux container, use a proper init/reaper (--init) for orphan-process cleanup tests, a sanitized environment and --network none for runtime tests. Do not mount production config/DB, inherit real provider/OAuth/cloud credentials or invoke live models/security targets.

```sh
go mod verify
go test -race ./internal/... ./cmd/...
go build ./...
go run ./cmd/english-audit
node --test web/static/js/*.test.cjs
python -m unittest discover -s scripts -p 'test_*.py'
python scripts/check-tool-contracts.py
bash -n run.sh upgrade.sh
govulncheck -json ./... > govulncheck.json
govulncheck -mode convert < govulncheck.json > govulncheck.txt
```

Use pinned official govulncheck v1.9.0 and retain source SHA, Go/platform/scanner versions, module verification and JSON/text. JSON mode always exits 0 for findings; the official text converter enforces reachable-symbol failure on the same report. Unfixed module advisories remain visible in the ledger/artifacts. Reassess platform/import/configuration changes and do not equate a clean call graph with zero vulnerabilities.

Stage the release on non-production Linux arm64. Verify exact owner SSO, unmapped/corporate identity denial, RS256/issuer/audience/expiry, accessVersion revocation, SSO-only password 410, initialization/identity replacement and event/C2 stream expiry. Inspect MCP descriptions/parameter help, all configured catalogs, validation errors/background handles and harmless local queue fixtures. No customer scan/live model call is a default release test.

Record approved commit/binary digest, catalog backup, test/advisory artifacts and independent reviewer. On failure, stop promotion and restore the previous reviewed source/binary/config/DB/catalog release set through guarded rollback. Do not reset Git history or restore mismatched binary/data versions. Preserve new customer evidence/operator edits and recheck owner/revoked-session behavior. This branch authorizes no production deployment, restart, native-role grant or policy change.
