# permission-audit — Permission Allowlist Auditor

Audits Claude Code `settings.json` permission chains —
the allow / ask / deny lists that decide what runs
without asking you — and reports the grants that are
broader than their text, the rules that can never take
effect, and the dangerous modes hiding in shared files.

A permission allowlist only grows. You approve a command
once and the grant lives forever: `Bash(*)` approved for
one workflow and never revisited, allow rules dead under
a wider deny nobody remembers writing, and — worst of
all — `bypassPermissions` committed to a shared repo's
`.claude/settings.json`, where every teammate inherits
it. Nobody reads the chain until something runs that
shouldn't have. permission-audit reads it for you:
every rule inventoried, the documented evaluation order
applied, each finding labelled with the rule, the file,
and what is actually true about it.

**Read-only, and static.** It edits nothing, writes
nothing, and never runs a command. Permission rules are
analysed as text — nothing in the files is evaluated or
executed. The test suite proves the read-only claim:
every fixture audited through the CLI comes out
byte-identical.

**The semantics are documented, not guessed.** The
shipped checks rest on the official Claude Code
permissions and settings documentation (checked
2026-11-04): rules are evaluated **deny first, then
ask, then allow** — specificity does not change the
order, a matching ask prompts even when a more specific
allow exists, and an allow cannot carve an exception
out of a deny. Permission lists **merge** across files
rather than overriding. File precedence, highest first:
**managed > project local (`.claude/settings.local.json`)
> shared project (`.claude/settings.json`) > user
(`~/.claude/settings.json`)**. Where a check goes beyond
the documented semantics — pattern coverage — the model
is stated in SKILL.md and the finding says "Heuristic"
in its own text.

One consequence of the documented order is worth
stating plainly, because intuition gets it backwards:
**a deny rule can never be shadowed by an allow.** Deny
is evaluated first, so the rules that die are allows
covered by a wider deny or ask, and asks covered by a
wider deny. That is what SHADOWED_RULE reports.

## Quick start

```bash
python3 src/permission_audit.py audit ~/.claude/settings.json
python3 src/permission_audit.py audit .claude/settings.json .claude/settings.local.json ~/.claude/settings.json --home ~
python3 src/permission_audit.py audit .claude/ --json
```

No dependencies — Python 3.10+ standard library only.
Pass one settings file, several (a chain — order does
not matter, precedence sorts them), or a folder (a
`.claude/` folder's settings files, or loose
`settings.json` / `settings.local.json` /
`managed-settings.json` files inside it).

## What it checks

| Rule | Severity | What it catches |
|---|---|---|
| `INVALID_JSON` | ERROR | The file does not parse (exact line / column reported), or the JSON root is not an object. An unparseable file loads nothing — including its deny rules. |
| `PERMISSIONS_SHAPE` | ERROR / WARN | `permissions` is not an object, or a list is not a list (ERROR — nothing in it can take effect); a single entry the loader skips — non-string, empty, unparseable, empty specifier, or an `mcp__` rule with parentheses (WARN). |
| `BROAD_GRANT` | ERROR / WARN | An allow rule that auto-approves a whole tool: `Bash(*)`, a bare tool name, `WebFetch(domain:*)`, or a bare `*`. ERROR for tools that run code or write (Bash, PowerShell, Edit, Write, MultiEdit, NotebookEdit, WebFetch); WARN for read-only tools. Broad deny/ask rules are never flagged — they are not grants. |
| `DANGEROUS_MODE` | ERROR / WARN | `defaultMode: bypassPermissions` (either spelling of the key), or `skipDangerousModePermissionPrompt: true`. ERROR in shared or managed files — committed for everyone who clones; WARN in user / local / unknown files, where it is one person's own machine. The finding carries the version nuance: current Claude Code (≥ v2.1.257) ignores `bypassPermissions` from project and local files, but older versions honored it from any file. |
| `SHADOWED_RULE` | WARN | A rule that can never take effect because a higher tier covers it: an allow covered by a deny or an ask, an ask covered by a deny. Heuristic — coverage uses the SKILL.md prefix model. |
| `DUPLICATE_RULE` | WARN | The identical rule string twice in the same list across the merged chain. Lists merge, so the copy changes nothing — pure accretion. |
| `UNBOUNDED_FILE_ACCESS` | WARN | A Read / Edit / Write allow rooted at the filesystem itself: `**`, `/*`, `//**`, or a `**/`-leading pattern with no project boundary. Heuristic — the exact forms judged are listed in SKILL.md. |
| `RULE_NEVER_MATCHES` | ERROR | The tool name is a case-variant of a documented tool name (`bash(npm test)`) — rules match canonical names exactly, so the rule matches nothing, ever. Unknown tool names are left alone: the tool list grows. |
| `REDUNDANT_RULE` | INFO | A rule fully covered by a broader rule in the *same* list (`Bash(git log *)` under `Bash(git *)`). Coverage by a wildcard-everything rule is excluded — that rule is already the BROAD_GRANT finding. |
| `BYPASS_DISABLED` | INFO | `permissions.disableBypassPermissionsMode: "disable"` is set — bypass mode is fenced off machine-wide. The good kind of finding. |

Every finding names the file, and rule findings name the
list and the rule text. Exit codes: **1** when any ERROR
finding exists, **0** otherwise, **2** for input errors
(missing file, unreadable input, folder with no settings
files) — always as a clean `{"error": ...}` object in
`--json` mode, never a traceback.

## A real run — a bloated shared settings file

`examples/dangerous/.claude/settings.json` is a
constructed project file with every fault planted: a
wildcard-everything grant, a bare `Write`,
`WebFetch(domain:*)`, `bypassPermissions` and the
dangerous-mode prompt switched off in a *shared* file,
a dead allow, a dead ask, an exact duplicate, three
entries the loader skips, a case-variant tool name, and
two filesystem-rooted file grants (run from the pack
root; the output below is verbatim):

```
$ python3 src/permission_audit.py audit examples/dangerous/.claude/settings.json
permission-audit v0.1.0 — audit · 1 settings file · scope project
17 permission rules in the chain · effective defaultMode: bypassPermissions (from examples/dangerous/.claude/settings.json)
Read-only: it edits nothing and never runs a command. Permission rules are analysed as static text — nothing in the files is evaluated or executed.
Documented semantics: rules are evaluated deny first, then ask, then allow — specificity does not change the order; permission lists merge across scopes; file precedence is managed > project local > shared project > user.

INVENTORY (17 rules):
  examples/dangerous/.claude/settings.json (project scope) — 17 rules · defaultMode: bypassPermissions
    allow Bash(*)
    allow Bash(npm run *)
    allow Bash(npm run *)
    allow Bash(aws s3 ls)
    allow Bash(git *)
    allow Bash(git log *)
    allow bash(npm test)
    allow Read(**)
    allow Edit(//**)
    allow WebFetch(domain:*)
    allow Write
    ask   Bash(deploy *)
    ask   Bash(git push *)
    deny  Bash(aws *)
    deny  Bash(deploy *)
    deny  Bash(rm -rf *)
    deny  Read(./.env)

ERRORS — grants broader than their text, or rules that can never work as configured (6):
[BROAD_GRANT] examples/dangerous/.claude/settings.json · allow · Bash(*)
  allow rule "Bash(*)" auto-approves every Bash call — a wildcard-everything grant. Grants like this are the ones an accreted allowlist hides: it was presumably added for one workflow and now covers all of them
  fix: narrow it to the pattern the workflow actually needs (e.g. Bash(npm run *)), or remove it and let the calls prompt
[BROAD_GRANT] examples/dangerous/.claude/settings.json · allow · WebFetch(domain:*)
  allow rule "WebFetch(domain:*)" auto-approves every WebFetch call, to any domain — a wildcard-everything grant. Grants like this are the ones an accreted allowlist hides: it was presumably added for one workflow and now covers all of them
  fix: narrow it to the pattern the workflow actually needs (e.g. Bash(npm run *)), or remove it and let the calls prompt
[BROAD_GRANT] examples/dangerous/.claude/settings.json · allow · Write
  allow rule "Write" auto-approves every Write call — a wildcard-everything grant. Grants like this are the ones an accreted allowlist hides: it was presumably added for one workflow and now covers all of them
  fix: narrow it to the pattern the workflow actually needs (e.g. Bash(npm run *)), or remove it and let the calls prompt
[DANGEROUS_MODE] examples/dangerous/.claude/settings.json
  permissions.defaultMode is "bypassPermissions" in a SHARED settings file — it is committed to the repo and ships to every teammate who clones it: sessions start with permission prompts skipped. Version nuance: current Claude Code (>= v2.1.257) ignores bypassPermissions set in project and local files — but older versions honored it from any file, and a committed bypass is the loaded gun of a settings file either way
  fix: remove bypassPermissions from the shared file; anyone who wants it can set it in their own user settings, per machine, on purpose
[DANGEROUS_MODE] examples/dangerous/.claude/settings.json
  skipDangerousModePermissionPrompt is true in a SHARED settings file, committed for every teammate to inherit: the one warning that stands between a user and bypassPermissions mode is switched off
  fix: remove the key from the shared file; leave the dangerous-mode prompt on
[RULE_NEVER_MATCHES] examples/dangerous/.claude/settings.json · allow · bash(npm test)
  "bash(npm test)" names the tool "bash" — permission rules match canonical tool names exactly, so this rule can never match the Bash tool and does nothing (for deny and ask rules Claude Code shows a startup warning; the rule still does not match)
  fix: change the tool name to "Bash"

WARNINGS — rules that can never take effect, or probably do not do what you intend (8):
[DUPLICATE_RULE] examples/dangerous/.claude/settings.json · allow · Bash(npm run *)
  the allow rule "Bash(npm run *)" appears more than once in the chain (first in examples/dangerous/.claude/settings.json) — permission lists merge across scopes, so the extra copy changes nothing; it is the allowlist accreting
  fix: keep the rule in one file (the scope it belongs to) and remove the copies
[PERMISSIONS_SHAPE] examples/dangerous/.claude/settings.json · allow
  "" cannot be parsed as a permission rule (Tool or Tool(specifier)) — it matches nothing and the loader skips it
  fix: write it as a tool name, or as Tool(specifier) with balanced parentheses
[PERMISSIONS_SHAPE] examples/dangerous/.claude/settings.json · allow · Bash(npm run
  "Bash(npm run" cannot be parsed as a permission rule (Tool or Tool(specifier)) — it matches nothing and the loader skips it
  fix: write it as a tool name, or as Tool(specifier) with balanced parentheses
[PERMISSIONS_SHAPE] examples/dangerous/.claude/settings.json · deny · 42
  an entry in the deny list is an int, not a string — Claude Code skips malformed permission rules (a documented Settings Warning), so this entry does nothing
  fix: make every entry a rule string: a tool name, or Tool(specifier)
[SHADOWED_RULE] examples/dangerous/.claude/settings.json · allow · Bash(aws s3 ls)
  the allow rule "Bash(aws s3 ls)" can never take effect: the deny rule "Bash(aws *)" in examples/dangerous/.claude/settings.json matches everything it matches, and rules are evaluated deny first, then ask, then allow (documented) — the call is denied instead. Heuristic: coverage uses the prefix model in SKILL.md
  fix: remove the dead rule, or narrow the covering rule if the exception was the intent (an allow cannot carve an exception out of a deny — documented)
[SHADOWED_RULE] examples/dangerous/.claude/settings.json · ask · Bash(deploy *)
  the ask rule "Bash(deploy *)" can never take effect: the deny rule "Bash(deploy *)" in examples/dangerous/.claude/settings.json matches everything it matches, and rules are evaluated deny first, then ask, then allow (documented) — the call is denied instead. Heuristic: coverage uses the prefix model in SKILL.md
  fix: remove the dead rule, or narrow the covering rule if the exception was the intent (an allow cannot carve an exception out of a deny — documented)
[UNBOUNDED_FILE_ACCESS] examples/dangerous/.claude/settings.json · allow · Edit(//**)
  allow rule "Edit(//**)" grants Edit access rooted at the filesystem itself — the path pattern has no project boundary, so it reaches every file the user account can. Heuristic: read off the specifier's shape; the exact forms judged are listed in SKILL.md
  fix: root the pattern inside the project (e.g. Read(./src/**)), or drop the rule and let reads outside the project prompt
[UNBOUNDED_FILE_ACCESS] examples/dangerous/.claude/settings.json · allow · Read(**)
  allow rule "Read(**)" grants Read access rooted at the filesystem itself — the path pattern has no project boundary, so it reaches every file the user account can. Heuristic: read off the specifier's shape; the exact forms judged are listed in SKILL.md
  fix: root the pattern inside the project (e.g. Read(./src/**)), or drop the rule and let reads outside the project prompt

INFO — worth knowing (1):
[REDUNDANT_RULE] examples/dangerous/.claude/settings.json · allow · Bash(git log *)
  the allow rule "Bash(git log *)" is fully covered by the allow rule "Bash(git *)" in examples/dangerous/.claude/settings.json — the outcome is the same with or without it. Pure accretion: the list grows, nothing changes
  fix: remove the narrower rule, or keep both knowingly — the broad rule is the one doing the work

Summary: 15 findings · 6 errors · 8 warnings · 1 info
Verdict: FAIL — 6 error(s): at least one grant is wildcard-broad, a dangerous mode is set where others inherit it, or a rule can never match. Fix the errors before trusting this allowlist.
(exit code 1)
```

Note what is *not* flagged: `ask Bash(git push *)` sits
under `allow Bash(git *)`, but ask is evaluated before
allow, so the prompt still fires — no finding. And
`deny Bash(rm -rf *)` is exactly as live as it looks:
nothing outranks deny.

## A chain — three files, one merged verdict

The chain example ships a user file, a shared project
file, and a project-local file under `examples/chain/`.
The arguments below are deliberately scrambled —
precedence, not argument order, sorts the chain:

```
$ python3 src/permission_audit.py audit examples/chain/project/.claude/settings.json examples/chain/home/.claude/settings.json examples/chain/project/.claude/settings.local.json --home examples/chain/home
permission-audit v0.1.0 — audit · 3 settings files · chain order (highest precedence first): local > project > user
6 permission rules in the chain · effective defaultMode: acceptEdits (from examples/chain/project/.claude/settings.json)
Read-only: it edits nothing and never runs a command. Permission rules are analysed as static text — nothing in the files is evaluated or executed.
Documented semantics: rules are evaluated deny first, then ask, then allow — specificity does not change the order; permission lists merge across scopes; file precedence is managed > project local > shared project > user.

INVENTORY (6 rules):
  examples/chain/project/.claude/settings.local.json (local scope) — 1 rule
    allow Bash(npm run build)
  examples/chain/project/.claude/settings.json (project scope) — 2 rules · defaultMode: acceptEdits
    allow Bash(make *)
    deny  Bash(npm *)
  examples/chain/home/.claude/settings.json (user scope) — 3 rules
    allow Bash(make *)
    allow Bash(npm run build)
    allow Read(./docs/*)

WARNINGS — rules that can never take effect, or probably do not do what you intend (4):
[SHADOWED_RULE] examples/chain/project/.claude/settings.local.json · allow · Bash(npm run build)
  the allow rule "Bash(npm run build)" can never take effect: the deny rule "Bash(npm *)" in examples/chain/project/.claude/settings.json matches everything it matches, and rules are evaluated deny first, then ask, then allow (documented) — the call is denied instead. Heuristic: coverage uses the prefix model in SKILL.md
  fix: remove the dead rule, or narrow the covering rule if the exception was the intent (an allow cannot carve an exception out of a deny — documented)
[DUPLICATE_RULE] examples/chain/home/.claude/settings.json · allow · Bash(make *)
  the allow rule "Bash(make *)" appears more than once in the chain (first in examples/chain/project/.claude/settings.json) — permission lists merge across scopes, so the extra copy changes nothing; it is the allowlist accreting
  fix: keep the rule in one file (the scope it belongs to) and remove the copies
[DUPLICATE_RULE] examples/chain/home/.claude/settings.json · allow · Bash(npm run build)
  the allow rule "Bash(npm run build)" appears more than once in the chain (first in examples/chain/project/.claude/settings.local.json) — permission lists merge across scopes, so the extra copy changes nothing; it is the allowlist accreting
  fix: keep the rule in one file (the scope it belongs to) and remove the copies
[SHADOWED_RULE] examples/chain/home/.claude/settings.json · allow · Bash(npm run build)
  the allow rule "Bash(npm run build)" can never take effect: the deny rule "Bash(npm *)" in examples/chain/project/.claude/settings.json matches everything it matches, and rules are evaluated deny first, then ask, then allow (documented) — the call is denied instead. Heuristic: coverage uses the prefix model in SKILL.md
  fix: remove the dead rule, or narrow the covering rule if the exception was the intent (an allow cannot carve an exception out of a deny — documented)

Summary: 4 findings · 0 errors · 4 warnings · 0 info
Verdict: NO ERROR-CLASS GRANTS — but 4 warning(s) describe rules that can never take effect or grants broader than they look.
(exit code 0)
```

The project deny `Bash(npm *)` kills the
`Bash(npm run build)` allow in *both* other files —
cross-file shadowing is the whole point of auditing the
chain instead of one file at a time. (`--home` points
the user-scope inference at the fixture home; on a real
machine it defaults to your actual home directory.)

## A clean file, and a broken one

```
$ python3 src/permission_audit.py audit examples/clean/.claude/settings.json
permission-audit v0.1.0 — audit · 1 settings file · scope project
6 permission rules in the chain · effective defaultMode: default (from examples/clean/.claude/settings.json)
Read-only: it edits nothing and never runs a command. Permission rules are analysed as static text — nothing in the files is evaluated or executed.
Documented semantics: rules are evaluated deny first, then ask, then allow — specificity does not change the order; permission lists merge across scopes; file precedence is managed > project local > shared project > user.

INVENTORY (6 rules):
  examples/clean/.claude/settings.json (project scope) — 6 rules · defaultMode: default
    allow Bash(npm run *)
    allow Bash(git status)
    allow Read(./src/**)
    ask   Bash(git push *)
    deny  Bash(rm -rf *)
    deny  Read(./.env)

No findings — every rule passes the static rules.
Summary: 0 findings · 0 errors · 0 warnings · 0 info
Verdict: CLEAN — no broad grants, dead rules or dangerous modes found by the static rules.
(exit code 0)
```

```
$ python3 src/permission_audit.py audit examples/invalid-settings.json
permission-audit v0.1.0 — audit · 1 settings file · scope unknown
0 permission rules in the chain · no defaultMode set in the chain
Read-only: it edits nothing and never runs a command. Permission rules are analysed as static text — nothing in the files is evaluated or executed.
Documented semantics: rules are evaluated deny first, then ask, then allow — specificity does not change the order; permission lists merge across scopes; file precedence is managed > project local > shared project > user.

INVENTORY (0 rules):
  examples/invalid-settings.json (unknown scope) — 0 rules
    (file does not parse — no rules load from it)

ERRORS — grants broader than their text, or rules that can never work as configured (1):
[INVALID_JSON] examples/invalid-settings.json
  the file is not valid JSON — line 5, column 5: Expecting value. Claude Code loads nothing from a file it cannot parse: every permission rule in it is inert, including its deny rules
  fix: fix the JSON at the reported position (a trailing comma and unquoted keys are the usual causes)

Summary: 1 findings · 1 errors · 0 warnings · 0 info
Verdict: FAIL — 1 error(s): at least one grant is wildcard-broad, a dangerous mode is set where others inherit it, or a rule can never match. Fix the errors before trusting this allowlist.
(exit code 1)
```

## For agents

`--json` emits one object: per-file records (scope,
rule count, default modes, parse status), the full rule
inventory with parsed tool and specifier, the effective
default mode and which file set it, findings (`rule`,
`severity`, `file`, `list`, `rule_text`, `message`,
`fix`), and summary counts that recount exactly against
the findings. Input errors — including argument errors —
are a single JSON object with an `error` key and exit 2.
SKILL.md states the full rule model, the coverage
arithmetic, the documented-semantics citations, and
what the tool deliberately does not claim.

## Tests

```
python3 -m unittest discover -s tests
```

68 tests: every rule in both directions, the coverage
model pinned pair by pair (including the documented
trailing-space nuance: `Bash(ls *)` also matches bare
`ls`), chain precedence and effective-mode resolution,
per-fixture hand-counted tables, JSON recount, exit
codes 0/1/2 with no-traceback assertions, and the
read-only proof — fixture bytes hashed before and after
CLI runs.

## Honest limits

- **Coverage is a model, not the runtime.** Real
  matching involves argument semantics, shell parsing,
  and tool-specific behaviour the prefix model cannot
  see. A rule reported dead is provably dead only under
  the stated model; a rule *not* reported may still
  never fire in practice. Findings say "Heuristic"
  where this applies.
- **Tool inventory is a snapshot.** The never-matches
  check compares case-variants against the documented
  tool names as of 2026-11-04; new tools simply are not
  case-checked until the list is refreshed.
- **Scope is inferred from file name and location.**
  A file passed by an unusual path is `unknown` scope,
  and mode findings fall back to the cautious severity.
- **Settings keys beyond permissions are out of scope**
  (hooks have their own auditor — see hook-doctor).
  `additionalDirectories` widens file access in practice
  and is deliberately not modelled in v0.1.0.

## License

MIT — see LICENSE.

## Support

If permission-audit saves you a 2 a.m. incident,
consider [sponsoring](https://github.com/sponsors/jasveerai88).
