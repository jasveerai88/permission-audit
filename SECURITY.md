# Security

## permission-audit's own posture

permission-audit is a security tool, and its own attack
surface is deliberately minimal:

- **No network code, no subprocess code.** The source
  imports only `argparse`, `json`, `sys` and `pathlib`.
  It cannot phone home because it has no way to.
- **It never evaluates or executes what it reads.** No
  command named in a permission rule is run, simulated,
  or shell-parsed; rules are analysed as static text.
  Pointing permission-audit at a hostile settings file
  is safe by construction, and the test suite proves
  the read-only claim (fixture bytes are hashed before
  and after CLI runs and must come out identical).
- **No dependencies.** Python 3.10+ standard library
  only — there is no supply chain beyond Python itself.

## Reporting a problem

If you find a way to make permission-audit execute a
command from a settings file, write outside its
read-only behaviour, or crash with a traceback on
malformed input, please report it privately through
GitHub's "Report a vulnerability" flow on this
repository (Security → Advisories), rather than a
public issue. A minimal fixture settings file that
reproduces the problem is the most helpful thing you
can include — keep fixtures constructed, as the shipped
examples are; never send a real allowlist, which is a
map of what a machine will run without asking.

If permission-audit *misjudges* a settings file — a
dead rule it misses or a finding it should not fire —
that is a correctness bug, not a vulnerability: open a
regular issue with a constructed fixture.

## Supported versions

Only the latest release is supported. Fixes land in a
new release, never as silent edits to an existing one.
