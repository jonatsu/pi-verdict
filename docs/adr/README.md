# Architecture decision records

Each file records one decision: the context that forced it, the decision, the alternatives rejected, and the
consequences. A record is never rewritten when the code moves on. A later change appears as a dated amendment at
the end of the record, or as a new record that supersedes the old one. Read the amendments with the decision,
because they correct passages above them.

Name a new record `NNNN-title.md` with the next unused number, and give it a header block with `status:` and
`date:`. The status is `accepted` or `superseded by ADR-NNNN`. A date is the day the record was written.

## Index

The status column repeats each record's own status and adds what its amendments changed.

| ADR | Decision | Status | Date |
| --- | --- | --- | --- |
| [0001](0001-self-protection-layer.md) | Self-protection layer: the gate protects its own files over any configuration exemption | Superseded by ADR-0005 (removed 2026-09-25, restored 2026-10-04); kept as the history of the removal | 2026-08-27 |
| [0002](0002-deny-paths-deterministic-ask.md) | `denyPaths`: a deterministic ask on a declared protected path, with an existence hint for the classifier | Accepted; amended 2026-09-09 (subtree scope for scope tools), 2026-09-25 (layer removed, restored by ADR-0005), 2026-10-05 (kernel-true spellings, transcript redaction) and 2026-10-24 (tool dispatch replaced by ADR-0009) | 2026-08-31 |
| [0003](0003-jev-decisions-adapter.md) | Jev decisions adapter: a non-generative model as a classifier backend | Accepted; amended for the second transport (2026-09-19), the removal of tamper detection and write-deny (2026-09-24, 2026-09-25), the approve dialog (2026-10-01) and the write protection of the adapter copy (2026-10-24) | 2026-09-19 |
| [0004](0004-classifier-fallback-cascade.md) | Classifier fallback cascade: a second layer that adjudicates uncertain first-layer verdicts | Accepted; decisions 4 and 6 superseded and decision 5 refined by the 2026-09-21 amendment (autonomy floor); amended 2026-10-04 (default mode `enforce`) | 2026-09-21 |
| [0005](0005-self-protection-layer-restored.md) | Self-protection layer restored: a hard, config-exempt deny over the gate's own files, without snapshots | Accepted; amended 2026-10-04 (every tool input is tested, the trust store is read-denied, the plugin manifests are protected) | 2026-10-04 |
| [0006](0006-fork-posture-and-override-hardening.md) | Fork operating posture: fail-closed defaults, project overrides that only narrow, hash-bound trust | Accepted; amended 2026-10-04 (overrides narrow only) and 2026-10-05 (per-key direction table) | 2026-10-04 |
| [0007](0007-monotone-floor.md) | Monotone floor: a raw-text tripwire decides, and a sound word view may only clear | Accepted | 2026-10-04 |
| [0008](0008-simple-command-allow.md) | The user `allow` layer admits one simple command | Accepted | 2026-10-04 |
| [0009](0009-tool-access-adapter.md) | The tool-access adapter: one model of what a tool call reads and writes | Accepted; amended 2026-10-05 (`eval` grading, session-start coverage report) and 2026-10-06 (glob targets, host path spellings) | 2026-10-05 |
| [0010](0010-policy-degraded.md) | `policyDegraded`: configuration errors change the fail direction | Accepted; the list of degrading triggers was extended on 2026-10-06 (type-invalid `deny` and `denyPaths`) | 2026-10-05 |
