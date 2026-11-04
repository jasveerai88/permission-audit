# permission-audit — agent skill

Audit Claude Code `settings.json` permission chains
with one command. Use it whenever a task touches a
settings file's permissions — reviewing a repo's
committed `.claude/settings.json`, checking your own
user allowlist, or auditing what a fleet of machines
inherits — before trusting what the allowlist permits.

## The one command

```
permission-audit audit <settings file OR folder> [more files...] [--home DIR] [--json]
```

(Installed via `pipx install permission-audit` or
`pip install permission-audit`. From a source checkout,
the same command is
`python3 src/permission_audit.py audit <settings file
OR folder> …`.)

- Accepts one settings file, several files (a chain —
  argument order does not matter), or a folder (a
  `.claude/` folder's settings files, then loose
  `settings.json` / `settings.local.json` /
  `managed-settings.json` files in it). Passing the same
  file twice audits it once.
- `--home DIR` sets the home directory the user-scope
  inference compares against (default: the real home).
  Pass it when auditing a fixture or another machine's
  files.
- Exit codes: **0** no ERROR findings, **1** at least
  one ERROR finding, **2** input error (missing file,
  unreadable input, folder with no settings files, bad
  arguments). In `--json` mode every error — including
  argument errors — is one JSON object with an `error`
  key. Never a traceback.
- **Read-only.** It edits nothing, writes nothing, and
  never runs a command. Permission rules are analysed as
  static text — nothing in the files is evaluated or
  executed. Safe to point at any settings file.

## Documented semantics (the ground the rules stand on)

From the official Claude Code permissions and settings
documentation (code.claude.com/docs/en/permissions and
/en/settings, checked 2026-11-04):

- **Evaluation order: deny, then ask, then allow.**
  The first matching rule in that order decides;
  specificity does not change the order. A broad deny
  blocks a narrower allow; a more specific allow cannot
  carve an exception out of a deny; a matching ask
  prompts even when a more specific allow also matches.
- **Permission lists merge** across settings files
  rather than overriding one another.
- **File precedence, highest first:** managed settings >
  command line > project local
  (`.claude/settings.local.json`) > shared project
  (`.claude/settings.json`) > user
  (`~/.claude/settings.json`). (Command line args are
  not files; the chain this tool audits is managed >
  local > project > user.)
- `Bash(*)` is equivalent to a bare `Bash` rule: both
  match every call of the tool. `Bash(ls *)` also
  matches a bare `ls` call (the documented
  trailing-space nuance) — the coverage model below
  encodes this.
- Malformed permission rules are skipped by the loader
  (surfacing as a Settings Warning); a file that does
  not parse contributes nothing at all.
- `permissions.defaultMode` values `auto` and
  `bypassPermissions` do not take effect from project
  or local settings in current versions (the threshold
  documented for bypass is v2.1.257; **before
  v2.1.257, `bypassPermissions` took effect from any
  file**). `permissions.disableBypassPermissionsMode:
  "disable"` prevents bypass mode for the whole
  machine.
- Rules for MCP tools (`mcp__…`) written with
  parentheses are skipped on load (documented).

**The shadowing direction follows from the evaluation
order, and it is the opposite of the common intuition:**
a deny rule can never be shadowed by an allow or an
ask, because deny is evaluated first. The dead rules
are **allows covered by a wider deny or ask**, and
**asks covered by a wider deny**. Any auditor (or
reviewer) claiming a "shadowed deny" under these
semantics is modelling a different system.

## Scope inference

Each file's scope is read off its name and location:

| Scope | When |
|---|---|
| `managed` | file named `managed-settings.json` |
| `local` | file named `settings.local.json` |
| `user` | `<home>/.claude/settings.json` |
| `project` | any other `.claude/settings.json` |
| `unknown` | anything else (findings fall back to the cautious severity) |

The effective `defaultMode` of a chain is the value in
the highest-precedence file that sets one; the report
names the file it came from. Both spellings are read:
`permissions.defaultMode` and the top-level `defaultMode`
key (the docs use the top-level key in one example and
the nested key in another — the tool does not guess
between them, it honours both).

## The coverage model (heuristic — stated, not hidden)

Coverage decides SHADOWED_RULE and REDUNDANT_RULE. A
rule is `Tool` or `Tool(specifier)`. Specifiers classify
as:

- **all** — no specifier, or the specifier is exactly
  `*`. Matches every call of the tool.
- **exact** — no `*` anywhere. Matches that one string.
- **prefix** — a single trailing `*` (e.g. `aws *`,
  `git log *`). Matches any string starting with the
  text before the `*`, **plus** — for the documented
  trailing-space form — the text without its trailing
  space (`Bash(ls *)` matches bare `ls`).
- **complex** — everything else: parameter specifiers
  (`domain:…`, `model:…`), wildcards anywhere but the
  end, multiple wildcards. Judged to cover **only an
  identical rule string**.

Rule A covers rule B when they name the same tool and:
A is **all**; or both are identical; or A is **prefix**
and B is exact/prefix whose string starts with A's
prefix (or equals the prefix minus its trailing space);
or A is **exact** and B is the same exact string.
Coverage never crosses tools.

This is a model of the documented wildcard behaviour,
not the runtime: real matching involves shell parsing
and tool-specific semantics the model cannot see.
SHADOWED_RULE and UNBOUNDED_FILE_ACCESS findings say
"Heuristic" in their own text. A rule reported dead is
dead under this model; a rule not reported may still
never fire in practice.

## The rule table

| Rule | Severity | Basis |
|---|---|---|
| `INVALID_JSON` | ERROR | File does not parse (line/column from the JSON parser), or the JSON root is not an object. |
| `PERMISSIONS_SHAPE` | ERROR | `permissions` is not an object, or an allow/ask/deny value is not a list — nothing in it can take effect. |
| `PERMISSIONS_SHAPE` | WARN | One entry the loader skips: non-string, empty string, unparseable rule text (unbalanced parens, no tool, nested parens), empty specifier, or an `mcp__` rule with parentheses (documented skip). |
| `BROAD_GRANT` | ERROR | Allow rule is wildcard-everything (all-class specifier, or `WebFetch(domain:*)`, or a bare `*` rule) for Bash, PowerShell, Edit, Write, MultiEdit, NotebookEdit, or WebFetch. |
| `BROAD_GRANT` | WARN | Same shape for any other tool (read-only tools included). Ask/deny lists are never flagged — they are not grants. |
| `DANGEROUS_MODE` | ERROR | `defaultMode: bypassPermissions` (either key spelling) or `skipDangerousModePermissionPrompt: true` in a managed or shared-project file. |
| `DANGEROUS_MODE` | WARN | Same, in a user, local, or unknown-scope file — one person's own machine, stated as such in the finding. Carries the ≥ v2.1.257 version nuance either way. |
| `SHADOWED_RULE` | WARN (heuristic) | Allow covered by any deny or ask in the merged chain; ask covered by any deny. |
| `DUPLICATE_RULE` | WARN | Identical rule string twice in the same list across the chain. (The same string in *different* lists is a shadow question, not a duplicate.) |
| `UNBOUNDED_FILE_ACCESS` | WARN (heuristic) | Read/Edit/Write allow whose specifier — after stripping one leading `./` — is one of `*`, `**`, `/*`, `/**`, `//*`, `//**`, `/`, `//`, or starts with `**/`. Project-rooted globs (`./src/**`, `src/**`) and home-rooted (`~/…`) are not flagged. A rule already BROAD_GRANT-flagged is not double-flagged. |
| `RULE_NEVER_MATCHES` | ERROR | Tool name differs from a documented tool name only by case (`bash`, `read`, …). The documented tool list is a snapshot (2026-11-04): Bash, AskUserQuestion, Edit, Read, Write, Glob, Grep, NotebookEdit, WebFetch, WebSearch, Task, Agent, PowerShell, Monitor, Workflow, SendMessage, TeamCreate, TeamDelete, EnterWorktree, ExitWorktree, ToolSearch, Skill, StructuredOutput, Artifact, PushNotification, RemoteTrigger, CronCreate, CronDelete, CronList, ScheduleWakeup, EnterPlanMode, ExitPlanMode, LSP, ShareOnboardingGuide. Unknown names are deliberately left alone — the tool list grows, and an unlisted tool is not evidence. |
| `REDUNDANT_RULE` | INFO | Rule covered by a broader rule in the same list. Coverage by an all-class rule is excluded (that rule is the BROAD_GRANT finding); identical strings are DUPLICATE_RULE, not this. |
| `BYPASS_DISABLED` | INFO | `permissions.disableBypassPermissionsMode` is `"disable"` — the fence exists; worth knowing it is there. |

## JSON schema (`--json`)

One object:

- `tool`, `version`, `command`
- `files[]`: `file`, `scope`, `rules` (count),
  `default_modes` (every spelling found),
  `skip_dangerous_mode_prompt` (bool),
  `bypass_disabled` (bool), `parse_error` (bool|null),
  `error` (string|null)
- `rules[]`: `file`, `scope`, `list`
  (`allow`|`ask`|`deny`), `rule` (verbatim text),
  `tool`, `specifier` (string|null)
- `effective_default_mode` (string|null),
  `effective_mode_from` (file|null)
- `findings[]`: `rule`, `severity`
  (`ERROR`|`WARN`|`INFO`), `file`, `list` (or null),
  `rule_text` (or null), `message`, `fix`
- `summary`: `findings`, `errors`, `warnings`, `info`
  — counts that recount exactly against `findings`
- `clean`: true when there are no ERROR findings

Findings are sorted deterministically: severity, then
chain position, then rule name — the same input always
produces the same report.

## Deliberate non-goals (honesty)

- **It never evaluates or executes anything.** No
  command in a rule is run, simulated, or shell-parsed;
  specifiers are compared as text under the model
  above.
- **Settings keys beyond permissions are out of scope**
  — hooks, env, model choice. (`additionalDirectories`
  widens file access in practice and is not modelled in
  v1.0.0; it is named here so the gap is explicit, not
  silent.)
- **No telemetry, no network, no writes.** Stdlib only;
  the source contains no network calls at all.
- **Heuristics are labelled in the finding text**,
  never presented as documented behaviour; documented
  claims name the documentation and its check date.
