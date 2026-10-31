# Variant generator seeds

CLAUDE.md C11 (weight methodology): robustness is measured only on generated variants that were
never used to choose weights or structural rules. The generator seed is recorded **before** any such
change, and a later change retires that seed.

| Seed | Recorded | Status | Note |
|---|---|---|---|
| 171139148 | 2026-10-31, before any v2.0 code | **active** | For the structural changes of v2.0 (below). Drawn with `secrets.randbelow(900_000_000) + 100_000_000`, not chosen by looking at any output. v1.7 and v2.0 are evaluated on the variants of this seed and on no other. |
| 616687759 | 2026-10-31, before any v1.7 code | **retired** (evaluated once: v1.6 and v1.7 side by side in [v1.5-evaluation.md](v1.5-evaluation.md)) | For the structural change of v1.7 (below). Drawn with `secrets.randbelow(900_000_000) + 100_000_000`, not chosen by looking at any output. v1.6 and v1.7 are evaluated on the variants of this seed and on no other. |
| 545728926 | 2026-10-31, before any v1.6 code | **retired** (evaluated once: v1.5 and v1.6 side by side in [v1.5-evaluation.md](v1.5-evaluation.md)) | For the structural change of v1.6 (below). Drawn with `secrets.randbelow(900_000_000) + 100_000_000`, not chosen by looking at any output. v1.5 and v1.6 are evaluated on the variants of this seed and on no other. |
| 833754500 | 2026-10-31, before any v1.5 code | **retired** (evaluated once: v1.4 and v1.5 side by side in [v1.5-evaluation.md](v1.5-evaluation.md)) | For the structural changes of v1.5 (below). Drawn with `secrets.randbelow(900_000_000) + 100_000_000`, not chosen by looking at any output. v1.4 and v1.5 are evaluated on the variants of this seed and on no other. |
| 711829743 | 2026-10-29, before any v1.4 code | **retired** (its allowed variants are recorded as G1, G4 in `tests/variants/known_gaps.yaml`) | For the structural change of v1.4 (below). Drawn with `secrets.randbelow(900_000_000) + 100_000_000`, not chosen by looking at any output. v1.0 to v1.4 are evaluated on the variants of this seed and on no other. |
| 654514256 | 2026-10-29, before any v1.3 code and before any benign variant was generated | **retired** (evaluated once: v1.0 to v1.3 side by side in [v1.3-evaluation.md](v1.3-evaluation.md)) | For the structural change of v1.3 (below) and the first benign variants. Drawn with `secrets.randbelow(900_000_000) + 100_000_000`, not chosen by looking at any output. v1.0, v1.1, v1.2 and v1.3 are evaluated on the variants of this seed and on no other. |
| 892499628 | 2026-10-29, before any v1.2 code was written | **retired** (evaluated once: v1.0, v1.1 and v1.2 side by side in [v1.2-evaluation.md](v1.2-evaluation.md)) | For the structural changes of v1.2 (below). Drawn with `secrets.randbelow(900_000_000) + 100_000_000`, not chosen by looking at any output. v1.0, v1.1 and v1.2 are evaluated on the variants of this seed and on no other. |
| 268805905 | 2026-10-29, before the first v1.1 run and before any v1.1 code was written | **retired** (evaluated once: v1.0 and v1.1 side by side in [v1.1-evaluation.md](v1.1-evaluation.md)) | For the structural changes of v1.1 (below). Drawn with `secrets.randbelow(900_000_000) + 100_000_000`, not chosen by looking at any output. v1.0 and v1.1 are both evaluated on the variants of this seed and on no other. |

If a weight or a structural rule is changed after this date, add a row below with the reason (one that
does not mention a scenario), mark the seed above `retired`, and record a new seed before generating.

## What a seed changes (v1.2: all variants now depend on it)

Until v1.1, only the seeded *combinations* (12 per malicious scenario, two to four factors each) depend on the
seed. The no-label variants and the one-factor mutations (one level of one dimension at a time) are
the same events for every seed, so the one-factor variants of the new seed are not new to the
design findings that motivated v1.1 (they were seen in the Phase 7 matrix). The v1.1 evaluation
therefore reported the two groups apart.

From the seed above on, the seed also draws the numeric parameters of every variant that has one
(the gap between events for `timing`, the entropy and the whitespace run for `obfuscation`), per
scenario and level, so the one-factor variants are new for every seed too. The baselines and the
no-label variants have no parameter and stay the same events. Variants are generated once per seed
to a file (`scripts/generate_variants.py`) and every version replays that same file.

## Retired seeds

| Seed | Recorded | Retired | Reason |
|---|---|---|---|
| 20261029 | 2026-10-29, before the first generation run (Phase 7) | 2026-10-29, when v1.1 was started | Phase 7 evaluated v1.0 on it and recorded design findings F1 to F4. v1.1 changes four structural rules in response (a universal contract for external content, hold containment for stories without a labeled process, role-scoped trust of destination classes, evidence-carrying labels and an hour-scale rate window). Variants generated under this seed cannot measure those changes, because the findings were derived from them. v1.0 stays tagged `v1.0` and is the frozen reference; the weights are unchanged. |
| 268805905 | 2026-10-29, before the first v1.1 run | 2026-10-29, when v1.2 was started | v1.2 changes two structural rules in response to design findings of the v1.1 evaluation (what a fallback hold pauses, and what a block does when no process of the story is labeled). Variants of this seed cannot measure those changes, because the findings were derived from them. v1.1 stays tagged; the weights are unchanged. |
| 892499628 | 2026-10-29, before any v1.2 code | 2026-10-29, when v1.3 was started | v1.3 changes the way the evidence calculus weighs a signal (F8) and nothing else. Variants of this seed cannot measure it, because the finding was derived from them. v1.2 stays tagged; the weights are unchanged. |
| 654514256 | 2026-10-29, before any v1.3 code | 2026-10-29, when v1.4 was started | A randomised property test of the label calculus found a second route by which a weaker label produces stronger evidence (how a label becomes persistent), after v1.3 had closed the first. Variants of this seed cannot measure that change. v1.3 stays tagged; the weights are unchanged. |
| 711829743 | 2026-10-29, before any v1.4 code | 2026-10-31, when v1.5 was started | v1.5 changes four structural rules in answer to the design findings that stayed open (F2, F3, F10) and to two operational faults (an incident never closed, so every baseline could stay frozen; the state of a long-running pipeline only grew). Variants of this seed cannot measure those changes, because the allowed variants it produced were read before they were made. The weights are unchanged. |
| 833754500 | 2026-10-31, before any v1.5 code | 2026-10-31, when v1.6 was started | The v1.5 evaluation on this seed found that a block in a story with an external origin label but no labeled process acts on nothing (a hold that times out becomes such a block), and that the matrix did not count a kill as containment. v1.6 changes the first and corrects the second; variants of this seed cannot measure either. The weights are unchanged. |
| 545728926 | 2026-10-31, before any v1.6 code | 2026-10-31, when v1.7 was started | A randomised property test (tests/test_v13.py) found that the label a reused fingerprint hands to a process was the strongest live one, so the decay speed changed which stories events linked into. v1.7 hands over every live label instead; variants of this seed were evaluated before it. The weights are unchanged. |
| 616687759 | 2026-10-31, before any v1.7 code | 2026-10-31, when v2.0 was started | The v1.7 evaluation on this seed found false blocks of signed software from a trusted root source whose steps are further apart than the story quiet window (design finding F10). v2.0 changes how a story continues across the quiet window and the rules that follow from it; variants of this seed cannot measure that, because the finding was derived from them. The weights are unchanged. |

## Benign variants (from the seed above on)

The 19 benign golden files are mutated along the same six dimensions as the malicious ones, with the
same seeded numbers and the same combinations, and are generated into the same file. Their expected
decision is the decision of the unmodified file (allow, except S49 and S50, which are holds by
design): a neutral mutation must not make a benign story worse. A variant is **labelled in the
generator**, from its dimension levels, its events and the policy's contracts, before any version is
replayed, when the mutation itself adds behaviour that the specification forbids. Its expected
decision is then none (it is reported apart, not counted as a false alarm). The rules, fixed here:

| Mutation | Labelled `contract` (adds a Contract violation) | Labelled `effect` (adds an Effect) |
|---|---|---|
| `entry=web_worker` | always: a web worker may not start programs | |
| `entry=terminal` | when the story has external, untrusted content: an interactive shell may not run it (`external_content_exec: deny`) | |
| `entry=run_dialog`, `file_manager`, `script_host`, `scheduled_task` | when the story has external, untrusted content that an `exec` runs as command text (the universal `external_content_exec`, C4), or a launcher starts an unsigned external file | |
| `destination=<class>` | when the acting role's contract lists `may_connect` and the class is not in it (and is not `any`) | when it does not, and the class is `unknown` or not a trusted class |
| `obfuscation=high_entropy`, `padded` | | always: a hidden or obfuscated command is the `hide` Effect |
| `delivery=*`, `obfuscation=stripped`, `lineage=*`, `timing=*` | never (they change how the story arrives, not what it does) | never |

A combination takes the union of the labels of its levels. The headline false-alarm figures are
for the **neutral** variants (no label); the labelled ones are reported in two further groups, so
that a false block on a labelled variant can be told from one on a neutral variant.
