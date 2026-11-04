---
name: Bug report
about: A crash, a wrong verdict, or a finding that should not have fired
title: ""
labels: bug
assignees: ""
---

**What happened**
A clear description of the bug — the command you ran and what
permission-audit reported.

**What you expected**
The verdict or finding you expected instead, and why.

**The settings file**
If the file is shareable, attach it or link it. If not, a minimal
*constructed* fixture that reproduces the problem is just as good.
Never attach a real allowlist — yours or anyone's; a real one is a
map of what a machine will run without asking.

**Environment**
- permission-audit version (the report header prints it):
- Python version:
- OS:

**Output**
Paste the full text report, or the `--json` output if the bug is
in the schema.
