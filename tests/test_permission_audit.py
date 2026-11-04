#!/usr/bin/env python3
"""Tests for permission-audit. Stdlib unittest only.

Run from the pack root:
    python3 -m unittest discover -s tests -v

The bundled fixtures are CONSTRUCTED settings files
(fictional, labelled as such) whose expected findings were
worked out by hand from the rule table in SKILL.md and
the documented semantics — never copied from the tool's
own output:

dangerous/.claude/settings.json (project scope), 20 list
entries, 17 parseable rules:
    ERROR  BROAD_GRANT        Bash(*) · WebFetch(domain:*)
                              · Write (bare)
    ERROR  DANGEROUS_MODE     permissions.defaultMode
                              bypassPermissions (shared
                              file) · skipDangerousMode-
                              PermissionPrompt: true
    ERROR  RULE_NEVER_MATCHES bash(npm test)
    WARN   PERMISSIONS_SHAPE  "Bash(npm run" (unbalanced)
                              · "" (empty) · 42 (not a
                              string, in deny)
    WARN   DUPLICATE_RULE     Bash(npm run *) twice
    WARN   SHADOWED_RULE      allow Bash(aws s3 ls) dead
                              by deny Bash(aws *) · ask
                              Bash(deploy *) dead by deny
                              Bash(deploy *)
    WARN   UNBOUNDED          Read(**) · Edit(//**)
    INFO   REDUNDANT_RULE     Bash(git log *) under
                              Bash(git *)
    => 15 findings · 6 errors · 8 warnings · 1 info
       · exit 1
    Negative pins inside the same fixture: ask
    Bash(git push *) is covered by allow Bash(git *) but
    ask outranks allow, so it earns NO finding; the
    narrower Bash rules under Bash(*) earn no
    REDUNDANT_RULE (the broad grant is the finding).

clean/.claude/settings.json: narrow rules, default mode
    => 0 findings · 6 rules · exit 0

invalid-settings.json: a trailing comma — the stdlib
parser reports line 5, column 5 ("Expecting value")
    => 1 INVALID_JSON ERROR · exit 1

chain/ (user + shared project + project local, audited
with --home chain/home, arguments deliberately out of
order):
    WARN   DUPLICATE_RULE     Bash(make *) in project +
                              user · Bash(npm run build)
                              in local + user
    WARN   SHADOWED_RULE      both copies of
                              Bash(npm run build) dead by
                              project deny Bash(npm *)
    => 4 findings · 0 errors · 4 warnings · exit 0
       · effective defaultMode acceptEdits (project —
       local sets none) · chain order local > project
       > user

Both directions are covered per rule: the fault present
earns the finding with the right rule and severity; the
fault absent earns none. The coverage model is pinned
with the arithmetic stated in SKILL.md. And the auditor
is proven read-only: every fixture file's bytes are
unchanged after runs through the CLI.
"""
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

PACK_ROOT = Path(__file__).resolve().parents[1]
SRC = PACK_ROOT / "src" / "permission_audit.py"
EXAMPLES = PACK_ROOT / "examples"
sys.path.insert(0, str(PACK_ROOT / "src"))

import permission_audit as pa  # noqa: E402

DANGEROUS = EXAMPLES / "dangerous" / ".claude" / \
    "settings.json"
CLEAN = EXAMPLES / "clean" / ".claude" / "settings.json"
INVALID = EXAMPLES / "invalid-settings.json"
CHAIN_HOME = EXAMPLES / "chain" / "home"
CHAIN_USER = CHAIN_HOME / ".claude" / "settings.json"
CHAIN_PROJECT = EXAMPLES / "chain" / "project" / \
    ".claude" / "settings.json"
CHAIN_LOCAL = EXAMPLES / "chain" / "project" / \
    ".claude" / "settings.local.json"


def run_cli(*args):
    proc = subprocess.run(
        [sys.executable, str(SRC), *args],
        capture_output=True, text=True)
    return proc.returncode, proc.stdout, proc.stderr


def audit_dict(paths, home=None):
    if not isinstance(paths, (list, tuple)):
        paths = [paths]
    return pa.audit_chain(list(paths),
                          Path(home) if home
                          else Path.home())


def rules(audit, rule=None, severity=None):
    out = audit["findings"]
    if rule is not None:
        out = [f for f in out if f["rule"] == rule]
    if severity is not None:
        out = [f for f in out if f["severity"] == severity]
    return out


def write_settings(tmp, data, name="settings.json",
                   subdir=None):
    folder = Path(tmp)
    if subdir:
        folder = folder / subdir
        folder.mkdir(parents=True, exist_ok=True)
    path = folder / name
    if isinstance(data, str):
        path.write_text(data, encoding="utf-8")
    else:
        path.write_text(json.dumps(data), encoding="utf-8")
    return path


def perms(allow=None, ask=None, deny=None, **extra):
    p = {}
    if allow is not None:
        p["allow"] = allow
    if ask is not None:
        p["ask"] = ask
    if deny is not None:
        p["deny"] = deny
    p.update(extra)
    return {"permissions": p}


class TestFixtures(unittest.TestCase):
    def test_dangerous_fixture_matches_hand_counted_table(
            self):
        audit = audit_dict(DANGEROUS)
        self.assertEqual(len(audit["rules"]), 17)
        self.assertEqual(audit["files"][0]["scope"],
                         "project")
        self.assertEqual(
            audit["effective_default_mode"],
            "bypassPermissions")
        expected = [
            ("BROAD_GRANT", "ERROR", 3),
            ("DANGEROUS_MODE", "ERROR", 2),
            ("RULE_NEVER_MATCHES", "ERROR", 1),
            ("PERMISSIONS_SHAPE", "WARN", 3),
            ("DUPLICATE_RULE", "WARN", 1),
            ("SHADOWED_RULE", "WARN", 2),
            ("UNBOUNDED_FILE_ACCESS", "WARN", 2),
            ("REDUNDANT_RULE", "INFO", 1),
        ]
        for rule, severity, count in expected:
            self.assertEqual(
                len(rules(audit, rule, severity)), count,
                f"{rule}/{severity}")
        s = audit["summary"]
        self.assertEqual(
            (s["findings"], s["errors"], s["warnings"],
             s["info"]), (15, 6, 8, 1))
        self.assertFalse(audit["clean"])

    def test_dangerous_shadowed_rules_are_the_two_planted(
            self):
        audit = audit_dict(DANGEROUS)
        texts = sorted(f["rule_text"] for f in
                       rules(audit, "SHADOWED_RULE"))
        self.assertEqual(texts, ["Bash(aws s3 ls)",
                                 "Bash(deploy *)"])
        # the planted negative: ask Bash(git push *) sits
        # under allow Bash(git *) but ask outranks allow —
        # no finding of any rule names it as the subject
        for f in audit["findings"]:
            self.assertNotEqual(f["rule_text"],
                                "Bash(git push *)")

    def test_clean_fixture_has_no_findings(self):
        audit = audit_dict(CLEAN)
        self.assertEqual(audit["findings"], [])
        self.assertEqual(len(audit["rules"]), 6)
        self.assertTrue(audit["clean"])
        self.assertEqual(audit["effective_default_mode"],
                         "default")

    def test_invalid_fixture_reports_position(self):
        audit = audit_dict(INVALID)
        found = rules(audit, "INVALID_JSON", "ERROR")
        self.assertEqual(len(found), 1)
        self.assertIn("line 5, column 5",
                      found[0]["message"])
        self.assertTrue(audit["files"][0]["parse_error"])
        self.assertEqual(len(audit["rules"]), 0)

    def test_chain_fixture_matches_hand_counted_table(
            self):
        # arguments deliberately scrambled: chain order
        # must come from documented precedence
        audit = audit_dict([CHAIN_USER, CHAIN_LOCAL,
                            CHAIN_PROJECT],
                           home=CHAIN_HOME)
        self.assertEqual(
            [f["scope"] for f in audit["files"]],
            ["local", "project", "user"])
        self.assertEqual(len(audit["rules"]), 6)
        self.assertEqual(
            audit["effective_default_mode"],
            "acceptEdits")
        self.assertEqual(
            audit["effective_mode_from"],
            audit["files"][1]["file"])
        self.assertEqual(
            len(rules(audit, "DUPLICATE_RULE", "WARN")),
            2)
        self.assertEqual(
            len(rules(audit, "SHADOWED_RULE", "WARN")), 2)
        s = audit["summary"]
        self.assertEqual(
            (s["findings"], s["errors"], s["warnings"],
             s["info"]), (4, 0, 4, 0))
        self.assertTrue(audit["clean"])

    def test_chain_folder_expansion(self):
        audit = audit_dict(EXAMPLES / "chain" / "project",
                           home=CHAIN_HOME)
        self.assertEqual(len(audit["files"]), 2)
        self.assertEqual(
            len(rules(audit, "SHADOWED_RULE")), 1)
        self.assertEqual(audit["summary"]["findings"], 1)

    def test_fixture_exit_codes(self):
        code, _, _ = run_cli("audit", str(DANGEROUS))
        self.assertEqual(code, 1)
        code, _, _ = run_cli("audit", str(CLEAN))
        self.assertEqual(code, 0)
        code, _, _ = run_cli(
            "audit", str(CHAIN_USER), str(CHAIN_LOCAL),
            str(CHAIN_PROJECT), "--home", str(CHAIN_HOME))
        self.assertEqual(code, 0)


class TestCoverageModel(unittest.TestCase):
    """The prefix arithmetic from SKILL.md, pinned pair
    by pair."""

    def cov(self, a, b):
        return pa._covers(pa.parse_rule(a),
                          pa.parse_rule(b))

    def test_prefix_covers_exact_under_it(self):
        self.assertTrue(
            self.cov("Bash(aws *)", "Bash(aws s3 ls)"))

    def test_trailing_space_star_matches_bare_command(self):
        # Bash(ls *) also matches `ls` itself (documented)
        self.assertTrue(self.cov("Bash(ls *)", "Bash(ls)"))

    def test_prefix_does_not_cover_sibling_string(self):
        # "aws " is not a prefix of "awsx ls", and "awsx
        # ls" is neither "aws " nor "aws"
        self.assertFalse(
            self.cov("Bash(aws *)", "Bash(awsx ls)"))

    def test_prefix_covers_narrower_prefix(self):
        self.assertTrue(
            self.cov("Bash(git *)", "Bash(git log *)"))
        self.assertFalse(
            self.cov("Bash(git log *)", "Bash(git *)"))

    def test_all_covers_everything_of_the_tool(self):
        self.assertTrue(self.cov("Bash", "Bash(rm -rf *)"))
        self.assertTrue(self.cov("Bash(*)", "Bash(x)"))

    def test_nothing_covers_all_but_all(self):
        self.assertFalse(
            self.cov("Bash(rm *)", "Bash"))
        self.assertFalse(
            self.cov("Bash(rm *)", "Bash(*)"))

    def test_coverage_needs_the_same_tool(self):
        self.assertFalse(self.cov("Bash(*)", "Read(x)"))
        self.assertFalse(
            self.cov("Bash(aws *)", "Read(aws s3 ls)"))

    def test_exact_covers_only_identical(self):
        self.assertTrue(
            self.cov("Bash(npm test)", "Bash(npm test)"))
        self.assertFalse(
            self.cov("Bash(npm test)",
                     "Bash(npm test --watch)"))

    def test_complex_patterns_cover_only_identical(self):
        self.assertTrue(
            self.cov("Bash(* run *)", "Bash(* run *)"))
        self.assertFalse(
            self.cov("Bash(* run *)",
                     "Bash(npm run build)"))
        # a parameter specifier is complex in this model
        self.assertFalse(
            self.cov("Agent(model:*)",
                     "Agent(model:opus)"))
        self.assertTrue(
            self.cov("Agent(model:opus)",
                     "Agent(model:opus)"))


class TestBroadGrant(unittest.TestCase):
    def audit(self, allow):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_settings(tmp, perms(allow=allow))
            return audit_dict(path)

    def test_bash_wildcard_is_error(self):
        a = self.audit(["Bash(*)"])
        found = rules(a, "BROAD_GRANT", "ERROR")
        self.assertEqual(len(found), 1)

    def test_bare_dangerous_tools_are_errors(self):
        for tool in ("Write", "Edit", "WebFetch",
                     "MultiEdit"):
            a = self.audit([tool])
            self.assertEqual(
                len(rules(a, "BROAD_GRANT", "ERROR")), 1,
                tool)

    def test_bare_read_only_tools_are_warnings(self):
        for tool in ("Read", "Grep", "Glob"):
            a = self.audit([tool])
            self.assertEqual(
                len(rules(a, "BROAD_GRANT", "WARN")), 1,
                tool)
            self.assertEqual(
                len(rules(a, "BROAD_GRANT", "ERROR")), 0,
                tool)

    def test_webfetch_any_domain_is_error(self):
        a = self.audit(["WebFetch(domain:*)"])
        self.assertEqual(
            len(rules(a, "BROAD_GRANT", "ERROR")), 1)
        a = self.audit(["WebFetch(domain:example.com)"])
        self.assertEqual(rules(a, "BROAD_GRANT"), [])

    def test_bare_star_rule_is_error(self):
        a = self.audit(["*"])
        self.assertEqual(
            len(rules(a, "BROAD_GRANT", "ERROR")), 1)

    def test_narrow_allow_is_not_broad(self):
        a = self.audit(["Bash(npm run *)",
                        "Read(./src/**)",
                        "Grep(pattern)"])
        self.assertEqual(rules(a, "BROAD_GRANT"), [])

    def test_broad_deny_and_ask_are_not_flagged(self):
        # a broad deny is a lockdown; a broad ask is a
        # prompt for everything — neither is a grant
        with tempfile.TemporaryDirectory() as tmp:
            path = write_settings(
                tmp, perms(ask=["Bash"], deny=["Bash"]))
            a = audit_dict(path)
        self.assertEqual(rules(a, "BROAD_GRANT"), [])


class TestDangerousMode(unittest.TestCase):
    def test_bypass_in_shared_project_file_is_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_settings(
                tmp, perms(defaultMode="bypassPermissions"),
                subdir="proj/.claude")
            a = audit_dict(path)
        self.assertEqual(a["files"][0]["scope"],
                         "project")
        self.assertEqual(
            len(rules(a, "DANGEROUS_MODE", "ERROR")), 1)

    def test_bypass_in_user_file_is_warning(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            path = write_settings(
                tmp, perms(defaultMode="bypassPermissions"),
                subdir="home/.claude")
            a = audit_dict(path, home=home)
        self.assertEqual(a["files"][0]["scope"], "user")
        self.assertEqual(
            len(rules(a, "DANGEROUS_MODE", "WARN")), 1)
        self.assertEqual(
            len(rules(a, "DANGEROUS_MODE", "ERROR")), 0)

    def test_top_level_default_mode_spelling_is_caught(
            self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_settings(
                tmp, {"defaultMode": "bypassPermissions",
                      "permissions": {}},
                subdir="proj/.claude")
            a = audit_dict(path)
        self.assertEqual(len(rules(a, "DANGEROUS_MODE")),
                         1)

    def test_skip_prompt_in_shared_file_is_error(self):
        with tempfile.TemporaryDirectory() as tmp:
            data = perms()
            data["skipDangerousModePermissionPrompt"] = \
                True
            path = write_settings(tmp, data,
                                  subdir="proj/.claude")
            a = audit_dict(path)
        self.assertEqual(
            len(rules(a, "DANGEROUS_MODE", "ERROR")), 1)

    def test_other_modes_are_not_flagged(self):
        for mode in ("default", "acceptEdits", "plan",
                     "auto"):
            with tempfile.TemporaryDirectory() as tmp:
                path = write_settings(
                    tmp, perms(defaultMode=mode),
                    subdir="proj/.claude")
                a = audit_dict(path)
            self.assertEqual(rules(a, "DANGEROUS_MODE"),
                             [], mode)

    def test_bypass_disabled_is_info(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_settings(
                tmp, perms(
                    disableBypassPermissionsMode="disable"))
            a = audit_dict(path)
        self.assertEqual(
            len(rules(a, "BYPASS_DISABLED", "INFO")), 1)
        a = audit_dict(CLEAN)
        self.assertEqual(rules(a, "BYPASS_DISABLED"), [])


class TestShadowedAndDuplicate(unittest.TestCase):
    def audit(self, **kw):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_settings(tmp, perms(**kw))
            return audit_dict(path)

    def test_allow_shadowed_by_deny(self):
        a = self.audit(allow=["Bash(aws s3 ls)"],
                       deny=["Bash(aws *)"])
        found = rules(a, "SHADOWED_RULE", "WARN")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["list"], "allow")

    def test_allow_shadowed_by_ask(self):
        a = self.audit(allow=["Bash(git push)"],
                       ask=["Bash(git *)"])
        self.assertEqual(len(rules(a, "SHADOWED_RULE")),
                         1)

    def test_ask_shadowed_by_deny(self):
        a = self.audit(ask=["Bash(deploy *)"],
                       deny=["Bash(deploy *)"])
        found = rules(a, "SHADOWED_RULE")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["list"], "ask")

    def test_ask_is_not_shadowed_by_allow(self):
        # ask is evaluated BEFORE allow (documented): a
        # broader allow cannot make an ask dead
        a = self.audit(allow=["Bash(git *)"],
                       ask=["Bash(git push *)"])
        self.assertEqual(rules(a, "SHADOWED_RULE"), [])

    def test_deny_is_never_shadowed(self):
        # the dangerous direction does not exist under
        # the documented evaluation order
        a = self.audit(allow=["Bash(git *)"],
                       deny=["Bash(git push *)"])
        self.assertEqual(rules(a, "SHADOWED_RULE"), [])

    def test_uncovered_allow_is_not_shadowed(self):
        a = self.audit(allow=["Bash(npm run *)"],
                       deny=["Bash(aws *)"])
        self.assertEqual(rules(a, "SHADOWED_RULE"), [])

    def test_duplicate_in_one_file(self):
        a = self.audit(allow=["Bash(npm run *)",
                              "Bash(npm run *)"])
        self.assertEqual(
            len(rules(a, "DUPLICATE_RULE", "WARN")), 1)

    def test_same_string_in_different_lists_is_not_a_dup(
            self):
        # identical text in allow and deny is a shadow,
        # not a duplicate
        a = self.audit(allow=["Bash(x)"], deny=["Bash(x)"])
        self.assertEqual(rules(a, "DUPLICATE_RULE"), [])
        self.assertEqual(len(rules(a, "SHADOWED_RULE")),
                         1)

    def test_distinct_rules_are_not_duplicates(self):
        a = self.audit(allow=["Bash(a)", "Bash(b)"])
        self.assertEqual(rules(a, "DUPLICATE_RULE"), [])


class TestUnboundedAndCase(unittest.TestCase):
    def audit(self, allow):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_settings(tmp, perms(allow=allow))
            return audit_dict(path)

    def test_rooted_globs_are_flagged(self):
        for rule in ("Read(**)", "Edit(//**)",
                     "Write(/*)", "Read(/**)",
                     "Read(**/secrets)"):
            a = self.audit([rule])
            self.assertEqual(
                len(rules(a, "UNBOUNDED_FILE_ACCESS",
                          "WARN")), 1, rule)

    def test_project_rooted_globs_are_not_flagged(self):
        for rule in ("Read(./src/**)", "Read(src/**)",
                     "Edit(./docs/*)", "Read(~/notes/**)"):
            a = self.audit([rule])
            self.assertEqual(
                rules(a, "UNBOUNDED_FILE_ACCESS"), [],
                rule)

    def test_unbounded_does_not_double_fire_with_broad(
            self):
        # Edit(*) is a broad grant (ERROR); it must not
        # also earn the unbounded warning
        a = self.audit(["Edit(*)"])
        self.assertEqual(
            len(rules(a, "BROAD_GRANT", "ERROR")), 1)
        self.assertEqual(
            rules(a, "UNBOUNDED_FILE_ACCESS"), [])

    def test_case_variant_tool_is_error(self):
        a = self.audit(["bash(npm test)"])
        self.assertEqual(
            len(rules(a, "RULE_NEVER_MATCHES", "ERROR")),
            1)
        a = self.audit(["read(./x)"])
        self.assertEqual(
            len(rules(a, "RULE_NEVER_MATCHES")), 1)

    def test_canonical_and_unknown_tools_left_alone(self):
        a = self.audit(["Bash(npm test)",
                        "Frobnicate(x)",
                        "mcp__server__tool"])
        self.assertEqual(rules(a, "RULE_NEVER_MATCHES"),
                         [])


class TestShape(unittest.TestCase):
    def audit_data(self, data):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_settings(tmp, data)
            return audit_dict(path)

    def test_permissions_not_an_object_is_error(self):
        a = self.audit_data({"permissions": ["Bash"]})
        self.assertEqual(
            len(rules(a, "PERMISSIONS_SHAPE", "ERROR")),
            1)

    def test_list_not_a_list_is_error(self):
        a = self.audit_data(
            {"permissions": {"allow": "Bash(*)"}})
        self.assertEqual(
            len(rules(a, "PERMISSIONS_SHAPE", "ERROR")),
            1)

    def test_non_string_entry_is_warning(self):
        a = self.audit_data(perms(deny=[42]))
        self.assertEqual(
            len(rules(a, "PERMISSIONS_SHAPE", "WARN")),
            1)

    def test_unparseable_entries_are_warnings(self):
        for entry in ("", "Bash(npm run", "Bash()"):
            a = self.audit_data(perms(allow=[entry]))
            self.assertEqual(
                len(rules(a, "PERMISSIONS_SHAPE", "WARN")),
                1, repr(entry))

    def test_mcp_rule_with_parentheses_is_warning(self):
        a = self.audit_data(
            perms(deny=["mcp__server__tool(arg)"]))
        self.assertEqual(
            len(rules(a, "PERMISSIONS_SHAPE", "WARN")),
            1)

    def test_valid_shape_has_no_findings(self):
        a = self.audit_data(perms(allow=["Bash(x)"]))
        self.assertEqual(rules(a, "PERMISSIONS_SHAPE"),
                         [])
        self.assertEqual(a["findings"], [])

    def test_top_level_not_an_object_is_invalid(self):
        a = self.audit_data('["not", "an", "object"]')
        self.assertEqual(
            len(rules(a, "INVALID_JSON", "ERROR")), 1)

    def test_no_permissions_key_is_clean(self):
        a = self.audit_data({"model": "opus"})
        self.assertEqual(a["findings"], [])
        self.assertTrue(a["clean"])


class TestRedundant(unittest.TestCase):
    def audit(self, **kw):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_settings(tmp, perms(**kw))
            return audit_dict(path)

    def test_narrower_under_broader_same_list_is_info(
            self):
        a = self.audit(allow=["Bash(git *)",
                              "Bash(git log *)"])
        found = rules(a, "REDUNDANT_RULE", "INFO")
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["rule_text"],
                         "Bash(git log *)")

    def test_redundant_in_deny_list_too(self):
        a = self.audit(deny=["Bash(aws *)",
                             "Bash(aws s3 ls)"])
        self.assertEqual(len(rules(a, "REDUNDANT_RULE")),
                         1)

    def test_no_redundant_without_coverage(self):
        a = self.audit(allow=["Bash(git *)",
                              "Bash(npm *)"])
        self.assertEqual(rules(a, "REDUNDANT_RULE"), [])

    def test_identical_is_duplicate_not_redundant(self):
        a = self.audit(allow=["Bash(x)", "Bash(x)"])
        self.assertEqual(rules(a, "REDUNDANT_RULE"), [])
        self.assertEqual(len(rules(a, "DUPLICATE_RULE")),
                         1)

    def test_coverage_by_wildcard_everything_not_counted(
            self):
        # Bash(*) is the BROAD_GRANT finding; the rules
        # under it are not also labelled accretion
        a = self.audit(allow=["Bash(*)", "Bash(git log *)"])
        self.assertEqual(rules(a, "REDUNDANT_RULE"), [])
        self.assertEqual(len(rules(a, "BROAD_GRANT")), 1)


class TestChainSemantics(unittest.TestCase):
    def test_effective_mode_comes_from_highest_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            project = write_settings(
                tmp, perms(defaultMode="acceptEdits"),
                subdir="proj/.claude")
            local = write_settings(
                tmp, perms(defaultMode="plan"),
                name="settings.local.json",
                subdir="proj/.claude")
            a = audit_dict([project, local])
        self.assertEqual([f["scope"] for f in a["files"]],
                         ["local", "project"])
        self.assertEqual(a["effective_default_mode"],
                         "plan")

    def test_broken_file_in_chain_is_a_finding_not_a_crash(
            self):
        with tempfile.TemporaryDirectory() as tmp:
            broken = write_settings(
                tmp, '{"permissions": {', name="broken.json")
            good = write_settings(
                tmp, perms(allow=["Bash(*)"]),
                name="good.json")
            a = audit_dict([broken, good])
        self.assertEqual(
            len(rules(a, "INVALID_JSON", "ERROR")), 1)
        self.assertEqual(
            len(rules(a, "BROAD_GRANT", "ERROR")), 1)
        self.assertEqual(len(a["rules"]), 1)

    def test_scope_inference(self):
        home = Path("/home/someone")
        cases = {
            "/x/managed-settings.json": "managed",
            "/x/settings.local.json": "local",
            "/home/someone/.claude/settings.json": "user",
            "/repo/.claude/settings.json": "project",
            "/tmp/whatever.json": "unknown",
        }
        for raw, scope in cases.items():
            self.assertEqual(
                pa.infer_scope(Path(raw), home), scope,
                raw)

    def test_same_file_twice_is_audited_once(self):
        a = audit_dict([CLEAN, CLEAN])
        self.assertEqual(len(a["files"]), 1)
        self.assertEqual(rules(a, "DUPLICATE_RULE"), [])


class TestJsonAndCli(unittest.TestCase):
    def test_json_summary_recounts_against_findings(self):
        code, out, _ = run_cli("audit", str(DANGEROUS),
                               "--json")
        self.assertEqual(code, 1)
        audit = json.loads(out)
        s = audit["summary"]
        self.assertEqual(s["findings"],
                         len(audit["findings"]))
        self.assertEqual(
            s["errors"],
            sum(1 for f in audit["findings"]
                if f["severity"] == "ERROR"))
        self.assertEqual(
            s["warnings"],
            sum(1 for f in audit["findings"]
                if f["severity"] == "WARN"))
        self.assertEqual(
            s["info"],
            sum(1 for f in audit["findings"]
                if f["severity"] == "INFO"))
        self.assertEqual(
            len(audit["rules"]),
            sum(f["rules"] for f in audit["files"]))

    def test_missing_file_is_exit_2_with_clean_error(self):
        code, out, err = run_cli(
            "audit", "/nonexistent/settings.json")
        self.assertEqual(code, 2)
        self.assertIn("ERROR:", out)
        self.assertNotIn("Traceback", out + err)

    def test_missing_file_json_error_object(self):
        code, out, _ = run_cli(
            "audit", "/nonexistent/settings.json",
            "--json")
        self.assertEqual(code, 2)
        self.assertIn("error", json.loads(out))

    def test_folder_without_settings_is_exit_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            code, out, err = run_cli("audit", tmp)
        self.assertEqual(code, 2)
        self.assertNotIn("Traceback", out + err)

    def test_argparse_error_is_json_in_json_mode(self):
        code, out, _ = run_cli("audit", "--json")
        self.assertEqual(code, 2)
        self.assertIn("error", json.loads(out))

    def test_no_traceback_on_any_fixture(self):
        for target in (DANGEROUS, CLEAN, INVALID):
            code, out, err = run_cli("audit", str(target))
            self.assertNotIn("Traceback", out + err)


class TestReadOnly(unittest.TestCase):
    def test_fixture_bytes_unchanged_after_cli_runs(self):
        targets = [DANGEROUS, CLEAN, INVALID, CHAIN_USER,
                   CHAIN_PROJECT, CHAIN_LOCAL]

        def digest():
            return {str(p): hashlib.sha256(
                p.read_bytes()).hexdigest()
                for p in targets}

        before = digest()
        run_cli("audit", str(DANGEROUS))
        run_cli("audit", str(CLEAN), "--json")
        run_cli("audit", str(CHAIN_USER),
                str(CHAIN_PROJECT), str(CHAIN_LOCAL),
                "--home", str(CHAIN_HOME))
        run_cli("audit", str(EXAMPLES / "chain"))
        self.assertEqual(digest(), before)

    def test_audit_creates_no_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = write_settings(
                tmp, perms(allow=["Bash(*)"],
                           defaultMode="bypassPermissions"))
            before = sorted(
                str(p) for p in Path(tmp).rglob("*"))
            code, _, _ = run_cli("audit", str(path))
            after = sorted(
                str(p) for p in Path(tmp).rglob("*"))
        self.assertEqual(code, 1)
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
