#!/usr/bin/env python3
"""permission-audit — a static audit of your OWN Claude Code
permission rules: the grants broader than you remember
making, the rules that can never take effect, and the
dangerous modes committed where teammates will inherit
them, found before something runs that shouldn't have.

Pure Python standard library. READ-ONLY and local only: it
reads the settings file (or settings chain) you point it
at, edits nothing, and NEVER evaluates or executes a
command — permission rules are analysed as static text.

Allowlists only grow. Each entry was added the day some
workflow got annoying; nobody re-reads the list afterwards.
Anthropic's own study (1,053 paid testers) found humans
caught only 13.6% of dangerous commands while
reflex-approving — so the written rules are the real
security boundary, and they accrete unaudited across the
settings chain: user settings, the shared project file
committed to the repo, and the local file approvals are
saved into. This tool applies an explicit rule table (see
RULES below and SKILL.md) to every permission rule in one
file or a whole chain.

THE SEMANTICS THE RULES ARE JUDGED AGAINST (documented —
"Configure permissions" and "Settings files and
precedence", code.claude.com/docs, checked 2026-11-04):

  * Rule evaluation: "Rules are evaluated in order: deny,
    then ask, then allow. The first match in that order
    determines the outcome, and rule specificity doesn't
    change the order. A broad deny rule like Bash(aws *)
    blocks every matching call, including calls that also
    match a narrower allow rule like Bash(aws s3 ls). An
    allow rule can't carve an exception out of a deny
    rule. The same precedence applies between ask and
    allow."
  * Lists merge: "When you set the same list key, such as
    permissions.allow, in more than one file, Claude Code
    combines the lists instead of picking one."
  * File precedence (highest first): managed settings >
    command line > project local
    (.claude/settings.local.json) > shared project
    (.claude/settings.json) > user
    (~/.claude/settings.json).
  * `Bash(*)` is equivalent to `Bash` — both match all
    uses of the tool.
  * Malformed permission rules are skipped by the loader
    (a Settings Warning), and a settings file that does
    not parse contributes nothing at all.

THE RULES (v0.1.0 — where a check is a heuristic, the
finding says so):

  INVALID_JSON (ERROR) — a settings file in the chain is
    not valid JSON, or its top level is not an object.
    Claude Code loads nothing from a file it cannot
    parse — every permission rule in it is inert. The
    parse position is reported.
  PERMISSIONS_SHAPE (ERROR / WARN) — the permissions
    structure cannot be used as written: `permissions`
    not an object, an allow/ask/deny key not a list
    (ERROR: the loader drops the whole list); or a single
    entry the loader skips or that can match nothing —
    a non-string entry, an empty string, an unparseable
    rule, an empty specifier, an mcp__ rule with
    parentheses (documented: skipped on load) (WARN).
  BROAD_GRANT (ERROR / WARN) — an allow rule that matches
    EVERY use of a tool: a bare tool name, Tool(*), the
    bare rule "*", or WebFetch(domain:*). ERROR for the
    tools that execute, write or fetch (Bash, Edit,
    Write, MultiEdit, NotebookEdit, WebFetch) and for
    "*"; WARN for the rest.
  DANGEROUS_MODE (ERROR / WARN) —
    permissions.defaultMode (or a top-level defaultMode)
    set to bypassPermissions, or
    skipDangerousModePermissionPrompt: true. ERROR in a
    shared project or managed file — it ships to every
    clone and every teammate; WARN in a user, project
    local or unknown-scope file — your own machine, your
    own choice, still worth seeing in the report. The
    finding carries the version nuance: current Claude
    Code (>= v2.1.257) ignores bypassPermissions from
    project and local files; older versions honored it
    from any file.
  SHADOWED_RULE (WARN, heuristic coverage) — a rule that
    can never take effect because a higher-tier rule
    covers everything it matches: an allow covered by a
    deny (the call is denied instead) or by an ask (the
    call prompts instead); an ask covered by a deny.
    Coverage uses the prefix model in SKILL.md and is
    labelled a heuristic. Note the direction: under the
    documented evaluation order a DENY rule can never be
    shadowed by an allow or an ask — the dangerous
    direction does not exist; what exists is dead allows
    and dead asks.
  DUPLICATE_RULE (WARN) — the identical rule string
    twice in the same list, in one file or across the
    chain. Lists merge, so the copy adds nothing.
  UNBOUNDED_FILE_ACCESS (WARN, heuristic) — a Read /
    Edit / Write allow rule whose path specifier is
    rooted at the filesystem itself (`**`, `/**`, `//**`,
    `/*`, `/`, `//` or a leading `**/`): reads or writes
    with no project boundary. The exact forms judged are
    in SKILL.md.
  RULE_NEVER_MATCHES (ERROR) — a rule whose tool part is
    a case-variant of a documented tool name ("bash" for
    "Bash"). Permission rules match canonical tool names;
    the variant can never match the tool it names.
  REDUNDANT_RULE (INFO) — a rule fully covered by a
    broader rule in the SAME list: same outcome with or
    without it. Pure accretion — the allowlist growing
    without changing anything.
  BYPASS_DISABLED (INFO) —
    permissions.disableBypassPermissionsMode is "disable"
    in a file: bypass mode cannot be used from that
    scope — worth knowing when reading mode findings
    elsewhere in the chain.

WHAT IT DOES NOT JUDGE (stated plainly): whether a grant
is wise — only its breadth, its shape and whether it can
take effect. Coverage is undecidable for patterns with
wildcards in the middle or at the start; those are judged
only when identical to another rule. Unknown tool names
that are not case-variants may be newer tools and are
left alone; mcp__ rules are left alone except for the
documented parentheses skip. Scalar keys other than the
mode keys (model, theme, env…) are out of scope — this
audits permissions, not settings generally.

THE LIMIT: a finding means "the rules, as written, have
this property by the documented semantics" — a statement
about the files, not a run. A clean audit means no grant
is broader than its text, no rule is dead and no
dangerous mode is set BY THESE RULES — not that the
resulting setup is safe for your threat model.

Exit codes: 0 = no ERROR findings (WARN/INFO may exist) ·
1 = at least one ERROR finding · 2 = input error — clean
message, never a traceback; with --json the error is
{"error": ...}.
"""
import argparse
import json
import sys
from pathlib import Path

__version__ = "0.1.0"
TOOL = "permission-audit"

# Rule text excerpts in findings are truncated to this many
# characters, in text and JSON output alike.
EXCERPT_LIMIT = 120

ERROR = "ERROR"
WARN = "WARN"
INFO = "INFO"
_SEVERITY_RANK = {ERROR: 0, WARN: 1, INFO: 2}

# The lists, in the documented evaluation order.
LISTS = ("deny", "ask", "allow")

# File precedence for scalar keys (documented, highest
# first): managed > project local > shared project >
# user. Unknown-scope files sort last, in argument order.
# (Permission LISTS merge across all scopes — precedence
# matters here for the effective defaultMode and for
# reporting order, not for which rules exist.)
_SCOPE_RANK = {"managed": 0, "local": 1, "project": 2,
               "user": 3, "unknown": 4}

# The commonly documented tool names — labelled as such
# because the list grows between versions. Only
# case-variants of these are ever flagged: wrong under
# every reading. Unknown plain names may be newer tools.
KNOWN_TOOLS = {
    "Agent", "AskUserQuestion", "Bash", "BashOutput",
    "Edit", "EnterPlanMode", "ExitPlanMode", "Glob",
    "Grep", "KillShell", "LS", "MultiEdit",
    "NotebookEdit", "PowerShell", "Read", "Skill", "Task",
    "TaskOutput", "TaskStop", "TodoWrite", "WebFetch",
    "WebSearch", "Write",
}
_TOOLS_BY_LOWER = {t.lower(): t for t in KNOWN_TOOLS}

# Tools where allowing EVERY use is an ERROR-class grant:
# they execute commands, modify files, or fetch from the
# network. A whole-tool allow of any other tool is still
# flagged, as a WARN.
_DANGEROUS_TOOLS = {
    "Bash", "PowerShell", "Edit", "Write", "MultiEdit",
    "NotebookEdit", "WebFetch",
}

# The tools the unbounded-path rule judges (per the
# rule's definition: file access tools).
_FILE_TOOLS = {"Read", "Edit", "Write"}

# Path specifiers (after stripping one leading "./") that
# are rooted at the filesystem itself: no project
# boundary.
_UNBOUNDED_FORMS = {"*", "**", "/*", "/**", "//*",
                    "//**", "/", "//"}


class ToolError(Exception):
    """A clean, user-facing failure (printed as ERROR,
    exit 2)."""


def _truncate(text):
    if text is None or len(text) <= EXCERPT_LIMIT:
        return text
    return text[:EXCERPT_LIMIT - 1].rstrip() + "…"


# --------------------------------------------------------------------------
# rule parsing + the coverage model.
#
# A rule is `Tool` or `Tool(specifier)`; parentheses inside
# the specifier are literal (documented), so the FIRST "("
# splits and the string must end with ")".
#
# A parsed specifier is one of:
#   all    — no specifier, or "*": matches every call
#   exact  — no "*": matches one string
#   prefix — exactly one "*", at the very end: matches
#            strings starting with the literal prefix —
#            and, per the docs' trailing-" *" nuance, the
#            prefix minus its trailing space (Bash(ls *)
#            also matches the bare command `ls`)
#   complex — any other wildcard placement, and
#            Tool(param:value) specifiers: coverage is
#            undecidable in this model and is judged ONLY
#            when the two rule strings are identical.
# --------------------------------------------------------------------------

def parse_rule(raw):
    """Parse one rule string -> (tool, specifier|None), or
    None when the string cannot be a rule at all."""
    text = raw.strip()
    if not text:
        return None
    if "(" not in text:
        if ")" in text:
            return None
        return text, None
    idx = text.index("(")
    tool = text[:idx]
    if not tool or not text.endswith(")"):
        return None
    return tool, text[idx + 1:-1]


def _spec_kind(spec):
    if spec is None or spec == "*":
        return "all"
    if "*" not in spec:
        # Tool(param:value) specifiers match a parameter,
        # not the tool's content — coverage between them
        # and content patterns is not decidable here.
        if ":" in spec and not spec.startswith(
                ("./", "../", "/", "~")):
            return "complex"
        return "exact"
    if spec.count("*") == 1 and spec.endswith("*"):
        return "prefix"
    return "complex"


def _covers(a, b):
    """True when parsed rule a matches every call parsed
    rule b matches — under the model above. a and b are
    (tool, specifier) pairs; tools must be identical
    (rule matching is on canonical names, case-sensitively).

    The arithmetic, for tests to pin:
      all    covers everything of the same tool.
      exact  covers only an identical specifier.
      prefix p covers exact s iff s == p, s starts with
             p, or (p ends with a space and s == p without
             the space) — the trailing-" *" nuance.
      prefix p covers prefix q iff q == p, q starts with
             p, or (p ends with a space and q == p without
             the space).
      complex covers only an identical specifier.
    Identical raw specifiers are handled by the exact /
    all paths and by an equality shortcut in the caller
    for complex pairs.
    """
    if a[0] != b[0]:
        return False
    kind_a, kind_b = _spec_kind(a[1]), _spec_kind(b[1])
    if kind_a == "all":
        return True
    if kind_b == "all":
        return False
    if a[1] == b[1]:
        return True
    if kind_a == "exact" or kind_a == "complex":
        return False
    # a is a prefix pattern
    p = a[1][:-1]
    if kind_b == "exact":
        s = b[1]
        return s == p or s.startswith(p) or (
            p.endswith(" ") and s == p[:-1])
    if kind_b == "prefix":
        q = b[1][:-1]
        return q == p or q.startswith(p) or (
            p.endswith(" ") and q == p[:-1])
    return False


# --------------------------------------------------------------------------
# scopes and chain assembly
# --------------------------------------------------------------------------

def infer_scope(path, home):
    """The scope of a settings file, from its name and
    location — the documented file layout:
      managed-settings.json            -> managed
      settings.local.json              -> local
      <home>/.claude/settings.json     -> user
      <project>/.claude/settings.json  -> project (shared)
      anything else                    -> unknown
    """
    name = path.name
    if name == "managed-settings.json":
        return "managed"
    if name == "settings.local.json":
        return "local"
    if name == "settings.json":
        if path.parent.name == ".claude":
            if path.parent.parent == home:
                return "user"
            return "project"
    return "unknown"


def _expand_inputs(paths):
    """Turn CLI paths into the chain's files. A folder
    contributes the standard settings files inside it
    (its .claude/ files first, then loose ones); a file
    contributes itself. Duplicates (same resolved path)
    are dropped."""
    files = []
    seen = set()
    for raw in paths:
        p = Path(raw)
        if p.is_dir():
            candidates = [
                p / ".claude" / "managed-settings.json",
                p / ".claude" / "settings.local.json",
                p / ".claude" / "settings.json",
                p / "managed-settings.json",
                p / "settings.local.json",
                p / "settings.json",
            ]
            found = [c for c in candidates if c.is_file()]
            if not found:
                raise ToolError(
                    f"no settings files found in folder "
                    f"{p} (looked for .claude/settings.json, "
                    f".claude/settings.local.json, "
                    f"settings.json, settings.local.json, "
                    f"managed-settings.json)")
            batch = found
        elif p.is_file():
            batch = [p]
        else:
            raise ToolError(f"settings file not found: {p}")
        for f in batch:
            key = str(f.resolve())
            if key not in seen:
                seen.add(key)
                files.append(f)
    return files


# --------------------------------------------------------------------------
# the audit
# --------------------------------------------------------------------------

class _FileAudit:
    def __init__(self, path, scope, index):
        self.path = path
        self.scope = scope
        self.index = index          # position in the chain
        self.display = _display(path)
        self.parse_error = False
        self.data = None
        self.mode = None            # defaultMode value set
        self.mode_key = None        # where it was set
        self.bypass_disabled = False


def _display(path):
    """The path as shown in output: relative to the
    working directory when that is shorter/clearer."""
    try:
        rel = path.resolve().relative_to(Path.cwd())
        return str(rel)
    except ValueError:
        return str(path)


class _Chain:
    def __init__(self):
        self.files = []             # _FileAudit, chain order
        self.rules = []             # rule instances (dicts)
        self.findings = []

    def add(self, rule, severity, message, fix, file_audit,
            lst=None, rule_text=None):
        self.findings.append({
            "rule": rule,
            "severity": severity,
            "list": lst,
            "rule_text": _truncate(rule_text),
            "file": file_audit.display,
            "scope": file_audit.scope,
            "message": message,
            "fix": fix,
            "_file_index": file_audit.index,
        })


def _check_entry(chain, fa, lst, entry):
    """One allow/ask/deny entry: shape, case, breadth,
    unboundedness. Returns the rule instance (or None for
    an entry that is not a usable rule)."""
    if not isinstance(entry, str):
        tname = type(entry).__name__
        article = "an" if tname[0] in "aeiou" else "a"
        chain.add(
            "PERMISSIONS_SHAPE", WARN,
            f"an entry in the {lst} list is {article} "
            f"{tname}, not a string — "
            f"Claude Code skips malformed permission rules "
            f"(a documented Settings Warning), so this "
            f"entry does nothing",
            "make every entry a rule string: a tool name, "
            "or Tool(specifier)",
            fa, lst=lst, rule_text=repr(entry))
        return None
    parsed = parse_rule(entry)
    if parsed is None:
        chain.add(
            "PERMISSIONS_SHAPE", WARN,
            f"\"{entry}\" cannot be parsed as a permission "
            f"rule (Tool or Tool(specifier)) — it matches "
            f"nothing and the loader skips it",
            "write it as a tool name, or as "
            "Tool(specifier) with balanced parentheses",
            fa, lst=lst, rule_text=entry)
        return None
    tool, spec = parsed
    inst = {
        "file": fa.display, "scope": fa.scope,
        "_file_index": fa.index, "list": lst,
        "raw": entry, "tool": tool, "specifier": spec,
    }
    chain.rules.append(inst)
    if spec == "":
        chain.add(
            "PERMISSIONS_SHAPE", WARN,
            f"\"{entry}\" has an empty specifier — as "
            f"written it matches nothing",
            "drop the parentheses to match every use of "
            "the tool, or put the pattern inside them",
            fa, lst=lst, rule_text=entry)
        return inst
    if tool.startswith("mcp__") and spec is not None:
        chain.add(
            "PERMISSIONS_SHAPE", WARN,
            f"\"{entry}\" is an mcp__ rule with "
            f"parentheses — when Claude Code loads a "
            f"settings file it skips any mcp__ rule that "
            f"has parentheses (documented), so this rule "
            f"does nothing",
            "write the mcp__ rule without a specifier",
            fa, lst=lst, rule_text=entry)
        return inst
    if tool not in KNOWN_TOOLS \
            and not tool.startswith("mcp__"):
        proper = _TOOLS_BY_LOWER.get(tool.lower())
        if proper is not None:
            chain.add(
                "RULE_NEVER_MATCHES", ERROR,
                f"\"{entry}\" names the tool \"{tool}\" — "
                f"permission rules match canonical tool "
                f"names exactly, so this rule can never "
                f"match the {proper} tool and does nothing "
                f"(for deny and ask rules Claude Code shows "
                f"a startup warning; the rule still does "
                f"not match)",
                f"change the tool name to \"{proper}\"",
                fa, lst=lst, rule_text=entry)
            return inst
    if lst == "allow":
        _check_breadth(chain, fa, inst)
    return inst


def _check_breadth(chain, fa, inst):
    """Broad-grant and unbounded-path checks for one
    allow rule."""
    tool, spec, entry = inst["tool"], inst["specifier"], \
        inst["raw"]
    kind = _spec_kind(spec)
    broad = kind == "all" or entry.strip() == "*" or (
        tool == "WebFetch" and spec == "domain:*")
    if broad:
        if tool in _DANGEROUS_TOOLS or entry.strip() == "*":
            severity = ERROR
        else:
            severity = WARN
        if entry.strip() == "*":
            what = "a bare \"*\" rule, which matches " \
                   "every tool call of every kind"
        elif tool == "WebFetch" and spec == "domain:*":
            what = "every WebFetch call, to any domain"
        else:
            what = f"every {tool} call"
        chain.add(
            "BROAD_GRANT", severity,
            f"allow rule \"{entry}\" auto-approves {what}"
            f" — a wildcard-everything grant. Grants "
            f"like this are the ones an accreted allowlist "
            f"hides: it was presumably added for one "
            f"workflow and now covers all of them",
            "narrow it to the pattern the workflow "
            "actually needs (e.g. Bash(npm run *)), or "
            "remove it and let the calls prompt",
            fa, lst="allow", rule_text=entry)
        return
    if tool in _FILE_TOOLS and spec is not None:
        stripped = spec[2:] if spec.startswith("./") \
            else spec
        if stripped in _UNBOUNDED_FORMS \
                or stripped.startswith("**/"):
            chain.add(
                "UNBOUNDED_FILE_ACCESS", WARN,
                f"allow rule \"{entry}\" grants {tool} "
                f"access rooted at the filesystem itself "
                f"— the path pattern has no project "
                f"boundary, so it reaches every file the "
                f"user account can. Heuristic: read off "
                f"the specifier's shape; the exact forms "
                f"judged are listed in SKILL.md",
                "root the pattern inside the project "
                "(e.g. Read(./src/**)), or drop the rule "
                "and let reads outside the project prompt",
                fa, lst="allow", rule_text=entry)


def _check_mode(chain, fa, data):
    """The mode keys of one file: defaultMode in either
    documented location, skipDangerousModePermissionPrompt,
    and the disableBypassPermissionsMode mitigation."""
    perms = data.get("permissions")
    mode = None
    mode_key = None
    if isinstance(perms, dict):
        if "defaultMode" in perms:
            mode = perms.get("defaultMode")
            mode_key = "permissions.defaultMode"
        if perms.get("disableBypassPermissionsMode") \
                == "disable":
            fa.bypass_disabled = True
    if mode is None and "defaultMode" in data:
        mode = data.get("defaultMode")
        mode_key = "defaultMode"
    fa.mode = mode
    fa.mode_key = mode_key
    shared = fa.scope in ("project", "managed")
    if mode == "bypassPermissions":
        if shared:
            severity = ERROR
            where = ("a SHARED settings file — it is "
                     "committed to the repo and ships to "
                     "every teammate who clones it")
        else:
            severity = WARN
            where = ("a personal settings file — your "
                     "own machine and your own choice, "
                     "flagged so it is a decision and not "
                     "an accretion")
        chain.add(
            "DANGEROUS_MODE", severity,
            f"{mode_key} is \"bypassPermissions\" in "
            f"{where}: sessions start with permission "
            f"prompts skipped. Version nuance: current "
            f"Claude Code (>= v2.1.257) ignores "
            f"bypassPermissions set in project and local "
            f"files — but older versions honored it from "
            f"any file, and a committed bypass is the "
            f"loaded gun of a settings file either way",
            "remove bypassPermissions from the shared "
            "file; anyone who wants it can set it in "
            "their own user settings, per machine, on "
            "purpose",
            fa)
    if data.get("skipDangerousModePermissionPrompt") is True:
        if shared:
            severity = ERROR
            where = "a SHARED settings file, committed " \
                    "for every teammate to inherit"
        else:
            severity = WARN
            where = "a personal settings file"
        chain.add(
            "DANGEROUS_MODE", severity,
            f"skipDangerousModePermissionPrompt is true "
            f"in {where}: the one warning that stands "
            f"between a user and bypassPermissions mode "
            f"is switched off",
            "remove the key from the shared file; leave "
            "the dangerous-mode prompt on",
            fa)
    if fa.bypass_disabled:
        chain.add(
            "BYPASS_DISABLED", INFO,
            "permissions.disableBypassPermissionsMode is "
            "\"disable\" in this file: bypassPermissions "
            "mode cannot be used from this scope — worth "
            "knowing when reading mode findings elsewhere "
            "in the chain",
            "nothing to fix — this is the mitigation, "
            "recorded so the chain's mode picture is "
            "complete",
            fa)


def _audit_file(chain, fa):
    """Read + per-file checks for one settings file. A
    file that exists but is broken JSON is a FINDING
    (INVALID_JSON) and contributes no rules — that is
    exactly the defect the tool exists to report. Only a
    missing/unreadable file is an input error, and the
    chain assembly already established the files exist."""
    try:
        raw = fa.path.read_text(encoding="utf-8-sig")
    except (OSError, UnicodeDecodeError) as exc:
        raise ToolError(
            f"could not read settings file {fa.path.name} "
            f"({exc.__class__.__name__})")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        fa.parse_error = True
        chain.add(
            "INVALID_JSON", ERROR,
            f"the file is not valid JSON — line "
            f"{exc.lineno}, column {exc.colno}: {exc.msg}. "
            f"Claude Code loads nothing from a file it "
            f"cannot parse: every permission rule in it "
            f"is inert, including its deny rules",
            "fix the JSON at the reported position (a "
            "trailing comma and unquoted keys are the "
            "usual causes)",
            fa)
        return
    if not isinstance(data, dict):
        fa.parse_error = True
        chain.add(
            "INVALID_JSON", ERROR,
            f"the top level of the file is a JSON "
            f"{type(data).__name__}, not an object — "
            f"settings are read as an object, so nothing "
            f"in this file loads",
            "make the file a single JSON object with a "
            "\"permissions\" key",
            fa)
        return
    fa.data = data
    _check_mode(chain, fa, data)
    perms = data.get("permissions")
    if perms is None:
        return  # no permissions configured in this file
    if not isinstance(perms, dict):
        chain.add(
            "PERMISSIONS_SHAPE", ERROR,
            f"\"permissions\" is a "
            f"{type(perms).__name__}, not an object — "
            f"Claude Code cannot read allow / ask / deny "
            f"from it, so no permission rule in this "
            f"file applies",
            "shape \"permissions\" as an object with "
            "\"allow\", \"ask\" and \"deny\" lists",
            fa)
        return
    for lst in LISTS:
        entries = perms.get(lst)
        if entries is None:
            continue
        if not isinstance(entries, list):
            chain.add(
                "PERMISSIONS_SHAPE", ERROR,
                f"\"permissions.{lst}\" is a "
                f"{type(entries).__name__}, not a list — "
                f"the loader drops it, so every {lst} "
                f"rule in this file is inert",
                f"make \"{lst}\" a list of rule strings",
                fa, lst=lst)
            continue
        for entry in entries:
            _check_entry(chain, fa, lst, entry)


# --------------------------------------------------------------------------
# cross-rule checks over the merged chain. Permission
# lists merge across scopes (documented) and evaluation
# is deny -> ask -> allow regardless of which file a rule
# came from (documented), so these checks run over the
# whole chain, not file by file.
# --------------------------------------------------------------------------

def _covers_inst(a, b):
    if a["raw"] == b["raw"]:
        return True
    return _covers((a["tool"], a["specifier"]),
                   (b["tool"], b["specifier"]))


def _check_cross(chain):
    instances = chain.rules
    # DUPLICATE_RULE — identical string, same list,
    # anywhere in the chain (lists merge: copies are
    # pure accretion).
    first_seen = {}
    for inst in instances:
        key = (inst["list"], inst["raw"])
        if key in first_seen:
            first = first_seen[key]
            chain.add(
                "DUPLICATE_RULE", WARN,
                f"the {inst['list']} rule \"{inst['raw']}\""
                f" appears more than once in the chain "
                f"(first in {first['file']}) — permission "
                f"lists merge across scopes, so the extra "
                f"copy changes nothing; it is the "
                f"allowlist accreting",
                "keep the rule in one file (the scope it "
                "belongs to) and remove the copies",
                _file_of(chain, inst), lst=inst["list"],
                rule_text=inst["raw"])
        else:
            first_seen[key] = inst
    # SHADOWED_RULE — a rule that can never take effect
    # because a higher tier covers it.
    tiers = {lst: [i for i in instances if i["list"] == lst]
             for lst in LISTS}
    shadow_sources = {"allow": ("deny", "ask"),
                      "ask": ("deny",)}
    for lst, sources in shadow_sources.items():
        for inst in tiers[lst]:
            for src in sources:
                cover = next(
                    (c for c in tiers[src]
                     if _covers_inst(c, inst)), None)
                if cover is not None:
                    chain.add(
                        "SHADOWED_RULE", WARN,
                        f"the {lst} rule \"{inst['raw']}\" "
                        f"can never take effect: the {src} "
                        f"rule \"{cover['raw']}\" in "
                        f"{cover['file']} matches everything "
                        f"it matches, and rules are "
                        f"evaluated deny first, then ask, "
                        f"then allow (documented) — the "
                        f"call is "
                        f"{'denied' if src == 'deny' else 'prompted for'}"
                        f" instead. Heuristic: coverage "
                        f"uses the prefix model in SKILL.md",
                        "remove the dead rule, or narrow "
                        "the covering rule if the exception "
                        "was the intent (an allow cannot "
                        "carve an exception out of a deny "
                        "— documented)",
                        _file_of(chain, inst), lst=lst,
                        rule_text=inst["raw"])
                    break
    # REDUNDANT_RULE — covered by a broader rule in the
    # SAME list (identical strings are duplicates, above,
    # and are excluded here). Coverage by a
    # wildcard-everything rule is also excluded: that
    # rule is already a BROAD_GRANT finding, and the
    # narrower rules under it are the intended rules
    # trapped under a bad one, not accretion.
    for lst in LISTS:
        for inst in tiers[lst]:
            cover = next(
                (c for c in tiers[lst]
                 if c is not inst and c["raw"] != inst["raw"]
                 and _spec_kind(c["specifier"]) != "all"
                 and _covers_inst(c, inst)), None)
            if cover is not None:
                chain.add(
                    "REDUNDANT_RULE", INFO,
                    f"the {lst} rule \"{inst['raw']}\" is "
                    f"fully covered by the {lst} rule "
                    f"\"{cover['raw']}\" in "
                    f"{cover['file']} — the outcome is "
                    f"the same with or without it. Pure "
                    f"accretion: the list grows, nothing "
                    f"changes",
                    "remove the narrower rule, or keep "
                    "both knowingly — the broad rule is "
                    "the one doing the work",
                    _file_of(chain, inst), lst=lst,
                    rule_text=inst["raw"])


def _file_of(chain, inst):
    for fa in chain.files:
        if fa.index == inst["_file_index"]:
            return fa
    raise AssertionError("rule instance without a file")


def audit_chain(paths, home):
    """Audit one settings file or a chain of them.
    Returns the full audit dict (the JSON shape; the text
    view renders from it). Raises ToolError only for input
    failures (a path that does not exist, a folder with no
    settings files, an unreadable file)."""
    home = Path(home).resolve()
    files = _expand_inputs(paths)
    chain = _Chain()
    audits = []
    for order, path in enumerate(files):
        fa = _FileAudit(path, infer_scope(path.resolve(),
                                          home), order)
        audits.append(fa)
    # Chain order = documented precedence (stable: files
    # of equal rank keep argument order).
    audits.sort(key=lambda f: _SCOPE_RANK[f.scope])
    for index, fa in enumerate(audits):
        fa.index = index
        chain.files.append(fa)
    for fa in chain.files:
        _audit_file(chain, fa)
    _check_cross(chain)
    return _finish(chain)


def _finish(chain):
    chain.findings.sort(key=lambda f: (
        _SEVERITY_RANK[f["severity"]],
        f["_file_index"],
        f["rule"],
        f["list"] or "",
        f["rule_text"] or "",
        f["message"],
    ))
    for f in chain.findings:
        del f["_file_index"]
    summary = {
        "findings": len(chain.findings),
        "errors": sum(1 for f in chain.findings
                      if f["severity"] == ERROR),
        "warnings": sum(1 for f in chain.findings
                        if f["severity"] == WARN),
        "info": sum(1 for f in chain.findings
                    if f["severity"] == INFO),
    }
    effective_mode = None
    effective_from = None
    for fa in chain.files:  # chain order = precedence
        if fa.mode is not None:
            effective_mode = fa.mode
            effective_from = fa.display
            break
    return {
        "tool": TOOL, "version": __version__,
        "command": "audit",
        "files": [{
            "file": fa.display, "scope": fa.scope,
            "rules": sum(1 for r in chain.rules
                         if r["_file_index"] == fa.index),
            "parse_error": fa.parse_error,
            "default_mode": fa.mode,
        } for fa in chain.files],
        "rules": [{
            "file": r["file"], "scope": r["scope"],
            "list": r["list"], "rule": r["raw"],
            "tool": r["tool"], "specifier": r["specifier"],
        } for r in chain.rules],
        "effective_default_mode": effective_mode,
        "effective_mode_from": effective_from,
        "findings": chain.findings,
        "summary": summary,
        "clean": summary["errors"] == 0,
    }


# --------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------

SCOPE_LINE = ("Read-only: it edits nothing and never "
              "runs a command. Permission rules are "
              "analysed as static text — nothing in the "
              "files is evaluated or executed.")
SEMANTICS_LINE = ("Documented semantics: rules are "
                  "evaluated deny first, then ask, then "
                  "allow — specificity does not change "
                  "the order; permission lists merge "
                  "across scopes; file precedence is "
                  "managed > project local > shared "
                  "project > user.")


def _where(finding):
    parts = [finding["file"]]
    if finding["list"]:
        parts.append(finding["list"])
    if finding["rule_text"]:
        parts.append(finding["rule_text"])
    return " · ".join(parts)


def render_text(audit):
    files = audit["files"]
    if len(files) == 1:
        head = (f"1 settings file · scope "
                f"{files[0]['scope']}")
    else:
        head = (f"{len(files)} settings files · chain "
                f"order (highest precedence first): "
                + " > ".join(
                    f"{f['scope']}" for f in files))
    lines = [
        f"permission-audit v{__version__} — audit · {head}",
        f"{len(audit['rules'])} permission rules in the "
        f"chain"
        + (f" · effective defaultMode: "
           f"{audit['effective_default_mode']} (from "
           f"{audit['effective_mode_from']})"
           if audit["effective_default_mode"] else
           " · no defaultMode set in the chain"),
    ]
    lines.append(SCOPE_LINE)
    lines.append(SEMANTICS_LINE)
    lines.append("")
    lines.append(f"INVENTORY ({len(audit['rules'])} rules):")
    for fa in files:
        own = [r for r in audit["rules"]
               if r["file"] == fa["file"]]
        mode = (f" · defaultMode: {fa['default_mode']}"
                if fa["default_mode"] else "")
        lines.append(
            f"  {fa['file']} ({fa['scope']} scope) — "
            f"{fa['rules']} rule"
            f"{'s' if fa['rules'] != 1 else ''}{mode}")
        if fa["parse_error"]:
            lines.append("    (file does not parse — no "
                         "rules load from it)")
        for lst in ("allow", "ask", "deny"):
            for r in own:
                if r["list"] == lst:
                    lines.append(
                        f"    {lst:<5} {r['rule']}")
    lines.append("")
    findings = audit["findings"]
    if not findings:
        if not audit["rules"]:
            lines.append("No permission rules configured "
                         "in the chain — nothing to audit.")
        else:
            lines.append("No findings — every rule passes "
                         "the static rules.")
    else:
        sections = [
            (ERROR, "ERRORS — grants broader than their "
                    "text, or rules that can never work "
                    "as configured"),
            (WARN, "WARNINGS — rules that can never take "
                   "effect, or probably do not do what "
                   "you intend"),
            (INFO, "INFO — worth knowing"),
        ]
        for severity, title in sections:
            group = [f for f in findings
                     if f["severity"] == severity]
            if not group:
                continue
            lines.append(f"{title} ({len(group)}):")
            for f in group:
                lines.append(
                    f"[{f['rule']}] {_where(f)}")
                lines.append(f"  {f['message']}")
                lines.append(f"  fix: {f['fix']}")
            lines.append("")
    s = audit["summary"]
    lines.append(
        f"Summary: {s['findings']} findings · "
        f"{s['errors']} errors · {s['warnings']} warnings "
        f"· {s['info']} info")
    if s["errors"]:
        lines.append(
            f"Verdict: FAIL — {s['errors']} error(s): at "
            f"least one grant is wildcard-broad, a "
            f"dangerous mode is set where others inherit "
            f"it, or a rule can never match. Fix the "
            f"errors before trusting this allowlist.")
    elif s["warnings"]:
        lines.append(
            f"Verdict: NO ERROR-CLASS GRANTS — but "
            f"{s['warnings']} warning(s) describe rules "
            f"that can never take effect or grants "
            f"broader than they look.")
    elif not audit["rules"]:
        lines.append("Verdict: CLEAN — nothing was "
                     "configured, so nothing is granted.")
    else:
        lines.append("Verdict: CLEAN — no broad grants, "
                     "dead rules or dangerous modes found "
                     "by the static rules.")
    return "\n".join(lines)


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

class _JsonAwareParser(argparse.ArgumentParser):
    """ArgumentParser that reports usage errors as JSON in
    --json mode ({"error": ...} on stdout, same exit code
    2) — an agent driving this tool with --json never gets
    plain text or a traceback. The flag lives on the class
    so subparsers share it."""

    json_mode = False

    def error(self, message):
        if self.json_mode:
            print(json.dumps({"error": message}))
            self.exit(2)
        super().error(message)


def cmd_audit(a):
    home = Path(a.home) if a.home else Path.home()
    audit = audit_chain(a.paths, home)
    if a.json:
        print(json.dumps(audit, indent=2))
    else:
        print(render_text(audit))
    return 0 if audit["clean"] else 1


def main(argv=None):
    argv = sys.argv[1:] if argv is None else list(argv)
    _JsonAwareParser.json_mode = "--json" in argv
    ap = _JsonAwareParser(
        prog=TOOL,
        description="Statically audit Claude Code "
                    "permission rules in one settings "
                    "file or a whole settings chain: "
                    "wildcard-everything grants, rules "
                    "that can never take effect, dangerous "
                    "modes committed to shared files, "
                    "invalid JSON. Read-only, executes "
                    "nothing (stdlib only, local only).")
    sub = ap.add_subparsers(dest="command", required=True,
                            parser_class=_JsonAwareParser)

    p_audit = sub.add_parser(
        "audit", help="audit settings file(s): check "
                      "every permission rule against the "
                      "static rule table; exit 1 on any "
                      "ERROR finding")
    p_audit.add_argument(
        "paths", nargs="+",
        help="one or more settings files (a chain — "
             "merged and checked across scopes), or "
             "folders containing settings files")
    p_audit.add_argument(
        "--home", default=None,
        help="the home folder used to recognise the "
             "user settings file "
             "(<home>/.claude/settings.json) when "
             "inferring scopes (default: your real home "
             "folder)")
    p_audit.add_argument("--json", action="store_true",
                         help="print one JSON object "
                              "instead of text")
    p_audit.set_defaults(func=cmd_audit)

    a = ap.parse_args(argv)

    def fail(msg):
        if getattr(a, "json", False):
            print(json.dumps({"error": msg}))
        else:
            print(f"ERROR: {msg}")
        return 2

    try:
        return a.func(a)
    except ToolError as exc:
        return fail(str(exc))


if __name__ == "__main__":
    sys.exit(main())
