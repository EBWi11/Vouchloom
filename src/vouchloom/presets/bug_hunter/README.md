# Bug Hunter Preset (`vouchloom.presets.bug_hunter`)

This directory contains the complete, standalone migration of `bug_hunter`'s CyberGym Level 1 proof-driven raw-PoC state machine, handbook knowledge base, fail-closed Codex skills, and deterministic sandbox helpers mounted onto Vouchloom's generic engine.

## Contents

- `fsm_specs/*.fsm.yaml` — Declarative Micro-FSM specifications:
  - `bug-hunter-core.fsm.yaml`: 10-state primary pipeline (`core_target_reconcile` -> `static_source_research` -> `bounded_action_executor` / `carrier_byte_construction` / `runtime_frontier_witness` -> `final_artifact_delivery` / `thin_artifact_mutation` / `post_review_recovery_probe` -> `second_poc_identity_probe` -> `finalized`).
  - `bug-hunter-ffmpeg-native-search.fsm.yaml`: Auto-triggered FFmpeg `target_dec_fuzzer` and `target_dem_fuzzer` native search sub-FSM.
  - `bug-hunter-graphicsmagick-search.fsm.yaml`: Auto-triggered GraphicsMagick same-coder and JNX `ExtractTileJPG -> BlobToImage` nested-coder search sub-FSM.
  - `bug-hunter-curl-tlv-delivery.fsm.yaml`: Auto-triggered `curl_fuzzer` TLV topology analysis and validated carrier delivery sub-FSM.
  - `bug-hunter-structured-carriers.fsm.yaml`: Auto-triggered structured protocol encoders (`libxml2`, `libxaac`, `cryptofuzz`, `opensc`, ZIP member reconciliation).
- `handbook_data/{common,generic,projects}.yaml` — Strict-ASCII progressively disclosed Level 1 reasoning & public project-boundary priors.
- `skills/*` — All 16 immutable, fail-closed Codex skill snapshots (automatic discovery disabled; single-state capability enforced).
- `sandbox_helpers/*` — Deterministic local helper CLIs (`bug_hunter_bitstream_build.py`, `bug_hunter_byte_patch.py`, `bug_hunter_archive_member.py`, `bug_hunter_witness_sweep.py`, and compute `Dockerfile`).

## Usage

```python
from vouchloom.presets import BUG_HUNTER_CORE_FSM_ID, load_bug_hunter_preset

bundle = load_bug_hunter_preset()
# bundle.registry  -> StateMachineRegistry with all 5 FSMs & 10 bug_hunter.* guards
# bundle.skills    -> dict[str, AgentSkill] of all 16 packaged skills
# bundle.handbook  -> BugHunterHandbookCatalog (common + generic + project topics)
```
