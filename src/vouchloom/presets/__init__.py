"""Domain presets packaged on top of Vouchloom's generic state-machine core."""

from vouchloom.presets.bug_hunter import (
    BUG_HUNTER_CORE_FSM_ID,
    BUG_HUNTER_PRESET_ROOT,
    BUG_HUNTER_SKILL_STAGE,
    BugHunterHandbookCatalog,
    BugHunterPresetBundle,
    BugHunterRequestComposer,
    HandbookTopic,
    load_bug_hunter_handbook,
    load_bug_hunter_preset,
    load_bug_hunter_skills,
    register_bug_hunter_guards,
    select_bug_hunter_handbook_topics,
)
from vouchloom.presets.pentest import (
    PENTEST_PRESET_ROOT,
    PENTEST_ROOT_FSM_ID,
    PentestPresetBundle,
    load_pentest_preset,
)

__all__ = [
    "BUG_HUNTER_CORE_FSM_ID",
    "BUG_HUNTER_PRESET_ROOT",
    "BUG_HUNTER_SKILL_STAGE",
    "BugHunterHandbookCatalog",
    "BugHunterPresetBundle",
    "BugHunterRequestComposer",
    "HandbookTopic",
    "load_bug_hunter_handbook",
    "load_bug_hunter_preset",
    "load_bug_hunter_skills",
    "register_bug_hunter_guards",
    "select_bug_hunter_handbook_topics",
    "PENTEST_PRESET_ROOT",
    "PENTEST_ROOT_FSM_ID",
    "PentestPresetBundle",
    "load_pentest_preset",
]
