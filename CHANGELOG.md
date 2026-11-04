# Changelog

## v1.0.0 — 2026-11-04

The checks are unchanged from v0.1.0 — this release is
about being installable and readable as a product:

- **Packaged install.** `pyproject.toml` (setuptools,
  single-module layout) — `pip install permission-audit` /
  `pipx install permission-audit` now put a
  `permission-audit` console command on PATH.
  `python3 src/permission_audit.py` from a checkout
  keeps working, unchanged.
- **README rebuilt as a landing page:** one-line hook,
  badge row, an animated demo (a dangerous shared
  settings file fails with six errors; a clean file
  passes), a 20-second quickstart, a what-it-catches
  table with the fixture examples, and a comparison
  table against reading the JSON yourself and against
  syntax-only linters. The full reference — rule table
  and verbatim fixture reports — moved below the fold.
- **Demo + social assets** in `docs/`: `demo.gif`
  (rendered from real v1.0.0 output) and
  `social-preview.png` (1280×640).
- **Community files:** SECURITY.md and issue templates
  added; CONTRIBUTING and FUNDING unchanged.
- Version string is now 1.0.0 everywhere (tool header,
  `--json` output, package metadata). All 68 tests pass
  unmodified.

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
