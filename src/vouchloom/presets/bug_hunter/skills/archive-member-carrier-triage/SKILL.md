---
name: archive-member-carrier-triage
description: Resolve one plausible ZIP carrier mismatch after a prior whole-ZIP artifact did not reproduce, a ZIP fixture is available, and Core has bound one harness route. Use only to decide whole ZIP versus one exact member, then extract or replace that member. Do not use for non-ZIP compression, archive discovery, recursive exploration, arbitrary member selection, or when the target parses the complete ZIP stream.
---

# Resolve One ZIP Carrier

Answer one question: does the bound harness consume the ZIP or one named member?

## Workflow

1. Confirm carrier behavior in the harness.
2. Run `list` once and select only a source-justified exact member name.
3. `extract` when the ZIP is a seed corpus; `replace` only when the harness
   consumes the ZIP and the target field is inside one member.
4. Verify the resulting ZIP or member structure locally, return its artifact path,
   and stop. Core runs the vulnerable target after the turn.

```bash
/usr/local/bin/bug-hunter-archive-member list /workspace/path/seeds.zip
/usr/local/bin/bug-hunter-archive-member extract /workspace/path/seeds.zip exact/member.bin /work/poc.bin
/usr/local/bin/bug-hunter-archive-member replace /workspace/path/base.zip exact/member.bin /tmp/member.bin /work/poc.zip
```

Require an exact unique member and a valid JSON receipt. Never choose the first
member heuristically, recurse, or treat archive-tool success as vulnerability
evidence. Run a local harness only when an executable harness is already
available; never build or repair one solely for validation.
