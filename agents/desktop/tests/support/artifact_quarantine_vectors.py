from __future__ import annotations

CANONICAL_ARTIFACT_PRUNE_QUARANTINE = "outbox/.artifact-prune-quarantine-" + "a" * 64

ARTIFACT_PRUNE_QUARANTINE_VECTORS = (
    ("canonical", CANONICAL_ARTIFACT_PRUNE_QUARANTINE, True),
    (
        "uppercase_prefix",
        "outbox/.ARTIFACT-PRUNE-QUARANTINE-" + "a" * 64,
        False,
    ),
    (
        "uppercase_token",
        "outbox/.artifact-prune-quarantine-" + "A" * 64,
        False,
    ),
    ("short_token", "outbox/.artifact-prune-quarantine-" + "a" * 63, False),
    ("long_token", "outbox/.artifact-prune-quarantine-" + "a" * 65, False),
    (
        "non_hex_token",
        "outbox/.artifact-prune-quarantine-" + "a" * 63 + "g",
        False,
    ),
    ("trailing_slash", CANONICAL_ARTIFACT_PRUNE_QUARANTINE + "/", False),
    (
        "duplicate_separator",
        CANONICAL_ARTIFACT_PRUNE_QUARANTINE.replace("outbox/", "outbox//"),
        False,
    ),
    ("dot_alias", "./" + CANONICAL_ARTIFACT_PRUNE_QUARANTINE, False),
    ("parent_alias", "../" + CANONICAL_ARTIFACT_PRUNE_QUARANTINE, False),
    (
        "embedded_parent_alias",
        "outbox/../" + CANONICAL_ARTIFACT_PRUNE_QUARANTINE,
        False,
    ),
    (
        "backslash",
        CANONICAL_ARTIFACT_PRUNE_QUARANTINE.replace("outbox/", "outbox\\"),
        False,
    ),
    ("absolute", "/" + CANONICAL_ARTIFACT_PRUNE_QUARANTINE, False),
    (
        "extra_subdirectory",
        "outbox/extra/.artifact-prune-quarantine-" + "a" * 64,
        False,
    ),
    ("suffix", CANONICAL_ARTIFACT_PRUNE_QUARANTINE + ".json", False),
    ("contains_quarantine", "outbox/artifact-containing-quarantine.pcapng", False),
    ("nul_initial", "\x00" + CANONICAL_ARTIFACT_PRUNE_QUARANTINE, False),
    (
        "nul_in_prefix",
        CANONICAL_ARTIFACT_PRUNE_QUARANTINE.replace("quarantine", "quaran\x00tine"),
        False,
    ),
    (
        "nul_in_token",
        "outbox/.artifact-prune-quarantine-" + "a" * 31 + "\x00" + "a" * 32,
        False,
    ),
    ("nul_final", CANONICAL_ARTIFACT_PRUNE_QUARANTINE + "\x00", False),
    (
        "nul_suffix",
        CANONICAL_ARTIFACT_PRUNE_QUARANTINE + "\x00ignored-suffix",
        False,
    ),
    (
        "multiple_nul",
        "outbox/.artifact-prune-quarantine-" + "a" * 30 + "\x00\x00" + "a" * 32,
        False,
    ),
)
