# Changelog

## v0.1.0 — 2026-11-04

First release. Audits one Claude Code settings file — or
a whole chain of them — as static text, and reports:

- the full rule inventory (allow / ask / deny, with tool
  and specifier), grouped by file in documented
  precedence order (managed > project local > shared
  project > user), with the chain's effective
  `defaultMode` and the file it came from;
- `BROAD_GRANT` — wildcard-everything allows (`Bash(*)`,
  bare tool names, `WebFetch(domain:*)`): ERROR for
  code-running and writing tools, WARN otherwise;
- `DANGEROUS_MODE` — `bypassPermissions` or the
  dangerous-mode prompt switched off: ERROR in shared /
  managed files, WARN in user / local files, with the
  documented ≥ v2.1.257 version nuance stated;
- `SHADOWED_RULE` — rules that can never take effect
  under the documented deny → ask → allow evaluation
  order (allows under a wider deny or ask; asks under a
  wider deny), using the stated prefix-coverage model;
- `DUPLICATE_RULE` — identical rules accreting across
  the merged chain;
- `UNBOUNDED_FILE_ACCESS` — Read / Edit / Write grants
  rooted at the filesystem itself;
- `RULE_NEVER_MATCHES` — tool names that are
  case-variants of the documented names and so match
  nothing;
- `PERMISSIONS_SHAPE` / `INVALID_JSON` — entries and
  files the loader skips or cannot parse, JSON errors
  with exact line and column;
- `REDUNDANT_RULE` and `BYPASS_DISABLED` at INFO.

Read-only by construction and by test (fixture bytes
verified unchanged after CLI runs); never evaluates or
executes a command. `--json` everywhere, `{"error": ...}`
input errors including argument errors, exits 1 / 0 / 2.
Python 3.10+ standard library only; no network code.
