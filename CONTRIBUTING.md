# Contributing

Thanks for looking. permission-audit has a small scope
on purpose: it reads Claude Code settings files as
static text and reports what their permission rules
actually grant. Contributions that keep that scope
sharp are welcome.

## Ground rules

- **Standard library only.** No third-party
  dependencies, no network calls, ever. If a change
  seems to need one, it is probably out of scope.
- **Read-only, always.** The auditor must never write
  to, move, or "fix" a settings file, and must never
  evaluate or execute a command found in one. A test
  proves fixture bytes are unchanged after CLI runs;
  keep it passing.
- **The rule table is the product.** Every check lives
  in SKILL.md's table with its basis. A new check needs:
  the rule name, the severity, whether it rests on
  documented semantics (cite the doc and the date you
  checked it) or is a heuristic (say so — heuristics
  are labelled in the finding text itself).
- **Documented semantics outrank intuition.** The
  evaluation order (deny → ask → allow) and the merge /
  precedence behaviour come from the official docs.
  If the docs change, update the citations and the
  check dates with the code.
- **Both directions tested.** Every rule needs a case
  where the fault is present (finding fires, right rule
  and severity) and a case where it is absent (no
  finding). Coverage-model changes need the pair
  arithmetic pinned in a test comment.
- **Fixtures stay fictional.** Example settings files
  are constructed for the pack. Never commit a real
  allowlist — yours or anyone's; a real one is a map
  of what a machine will run without asking.
- **No tracebacks, ever.** Bad input is a finding or a
  clean `{"error": ...}` with exit 2 — including
  argument errors in `--json` mode.

## Running the tests

```bash
python3 -m unittest discover -s tests
```

All tests must pass on a clean checkout with nothing
but Python 3.10+.

## Changing the output

The text report and the `--json` schema are both public
surface: scripts and agents consume them. Keep summary
counts recounting exactly against the findings list,
keep finding order deterministic, and note any schema
change in CHANGELOG.md.
