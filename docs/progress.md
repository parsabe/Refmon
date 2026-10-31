# Progress

One entry per phase: what was built, test count, deviations, open questions. Design findings are numbered F-n and autonomous decisions A-n; both are collected in [design-decisions.md](design-decisions.md).

The structural rules and weights are frozen (CLAUDE.md C11). A phase that cannot pass without changing them records a design finding here and marks the affected test as an expected failure.

## Phase 0 and the design phase (done)

Schemas, replay, simulated enforcer, empty core, 7 golden scenarios, the design decisions D1-D23 and four catalog checks. 169 tests. Tags: none (before the tagging rule).

## Phase 1: Understand (done)

Built: Observe (HMAC fingerprints, the Observe-time checks of C2, ring buffer of observed events only), Tag (rules 1 to 7 with decay and persistence), Link (story graph with quiet window), Judge (Origin, Contract, Effect, overrides, the plain fail rule) and the Pipeline that connects them; the policy model with the reference default policy; counted rate detectors; 46 golden scenarios (every C8 scenario except the adaptive S16, S28, S29) with expected verdicts; the C13 coverage check, read straight from CLAUDE.md.

Tests: 731 (unit per propagation rule, contract rule, effect type and override; three property tests; every golden file against its `rule_decision`).

Done when: every golden file reaches its `rule_decision` (46 of 46); every malicious file yields 3 fails or its override, except the known gaps S05 and S22; benign files at most 1 fail except the documented ones; the coverage map has no family without a passing scenario. All pass.

Deviations: see A1 to A10 in design-decisions.md. Open questions: none blocking.

## Phase 2: Policy and contracts (done)

Built: the signed YAML policy loader (Ed25519 detached signature in the `signature` field, duplicate keys rejected, trust anchors passed in), `PolicyStore` (last valid policy kept on a failed reload, rejection log), rule pack loading (pinned by name, version and signature, additive merge), validated rule ids with per-rule modes, exceptions with reason, scope and expiry, every remaining hard-coded threshold moved into the policy model (strict exec roles, credential classes, label alive floor, channel roles of Link), contract learning mode (counts only, per-change proposal, human approval, apply, sign) and a small CLI (`keygen`, `init-policy`, `sign`, `verify`, `learn`, `approve`, `apply`).

Tests: 813 (82 new: loader and tampering, packs, outcomes that change with the policy alone, learning, CLI flow, a guard that stage code has no numeric literals beyond 0 to 3).

Done when: changing only the policy changes outcomes (decision for three and two fails, origin threshold, a contract, a trust flag, an exception); a tampered, unsigned or invalid policy or pack is rejected and the last valid policy is kept; learning on all benign golden files proposes a contract that, once approved, leaves 0 Contract fails in each of them; learning on S46-S48 with the allowances removed proposes `may_mass_change` (backup_job), `may_fan_out` (vuln_scanner) and `may_tamper` (patch_tool), and once approved the three files are allowed. All pass.

Deviations: A11 to A16 in design-decisions.md. Open questions: none blocking.

## Phase 3: Act (done)

Built: Gate (mode downgrade, endpoint and server hold flows, answers, timeouts, idempotent and latched containment), Contain (kill process tree, cut network per process, quarantine new files, revert persistence, restore from the known-good baseline, isolate host; labeled-only; nothing is ever deleted), the user and admin notice schemas, a stateful `SimulatedEnforcer` over a `SimWorld`, and the Pipeline option `gate=True`.

Tests: 945 (132 new: Contain unit and property tests, Gate flows, replay of every golden file with the simulated enforcer, undo).

Done when: in replay every block touches exactly the labeled objects the scenario declares (checked against `derive_actions`, which never reads pipeline output); S14 and S26c quarantine the written file and kill the worker; undo restores files, persistence, network and host isolation (a killed process stays killed). All pass.

Design finding F1 (recorded, not fixed): a hold on a story without a labeled process, which is S05 once the calculus holds it, pauses nothing, because Contain is labeled-only and the typed command carries no label. The user is asked, but a stop has nothing to stop. This is the known gap S05 seen from the containment side. No rule was changed.

Deviations: A17 to A22 in design-decisions.md. Open question for the reviewer: should warn mode still ask the user (A17)?

Design finding **F1** (continues in Phase 7: a hold that cannot pause anything).

## Phase 4: Report and Tune (done)

Built: the Reporter (what happened, action taken, next step, in fixed plain phrases; MITRE ATT&CK tactic names), pseudonymization with a sealed vault and four-eyes re-identification (two different approvers, signed requests, one use, hash-chained audit log), Tune (false alarm proposes a scoped expiring exception and a contract extension; confirmed proposes fingerprint block-list entries; nothing applies without a named approver, and the result must be signed), and the privacy audit (`python -m refmon.audit`, also `refmon audit`, a CI step).

Tests: 1001 (56 new: reports, tactics, pseudonyms and four-eyes, tune, the audit and its sensitivity checks).

Done when: the audit finds zero raw content (257 outputs scanned: verdicts, actions, notices, reports, stories, labels, buffered events, suggestions, proposals and the committed golden files) and zero reversals (2119 dictionary attempts against 349 fingerprints; a control with the real key reverses 6 words, so the attack code works), and none of 10 re-identification attempts without four-eyes succeeds while the legitimate two-approver request does. All pass.

Deviations: A23 to A27 in design-decisions.md. Open question: block-list entries are per-device fingerprints; a fleet-wide indicator needs a raw value and a list-keyed digest (A26).

## Phase 4b: Mathematical core (done)

Built: C11 as pure functions in `calculus/` (label decay, attenuation, noisy-OR; Laplace-smoothed rarity, surprisal, Good-Turing maturity; evidence combination with max per question and sum across questions; cost-based thresholds; the contract gate; Poisson tail, CUSUM, EMA; Laplace noise, k-anonymity, Bloom filters; weight re-estimation with Laplace smoothing), wired into the pipeline (Judge, `StatRates`, Observe features and Bloom lists, baseline gating, verdict contributions), plus the fleet dashboard (`aggregate.py`).

Tests: 1404 (403 new: pure-function unit and property tests, the whole catalog on `decision`, rates, rarity, features, Bloom, attenuation).

Done when: all 46 scenarios reach their expected `decision` with the example default weights and the frozen rules, with no weight or rule changed (S11 is allowed with L = -5.11, S05 is held with L = -4.41, S22, S49 and S50 are held by the contract gate); every verdict's contributions sum to its log-odds (checked per verdict of every scenario, tolerance 1e-12); S08 and S34 (block) and S09, S24, S37 (allow) are overrides. Property tests: decay monotone, noisy-OR in [0, 1] and never below its largest input, adding a signal never lowers the log-odds, thresholds move the right way with the costs, no raw content survives Observe. From here on golden tests assert `decision`.

Design findings: none new. The catalog check 4 table and the real pipeline agree on every decision.

Deviations: A28 to A33 in design-decisions.md. Open question: the Poisson baselines (A29) are expert estimates and should be re-estimated in a pilot.

## Phase 5: Exposure and adaptive protection (done)

Built: the Exposure stage (inventory and local advisory files, version constraints, the five states, assessment, the per-role overlay, `ExposureManager` with escalation and reversion), network restriction for escalated roles, `Pipeline.set_policy`, `Verdict.virtual_patch` and the report sentence that names the reason, optional signatures on advisory files, and the adaptive part of the coverage map.

Tests: 1436 (32 new).

Done when: S16 shows mode escalation on an exposed component (the web_worker role goes to block mode, the same attack that was only recorded before is now killed, the verdict names `webshop:ADV-2026-001`) and reversion after the fixture reports the patched version (the next attack is observed only again); another role is not touched by the flaw. S28 escalates a role for an end-of-life runtime until the inventory shows its replacement. S29 stays `mitigated` with the workaround flag and escalates when the flag disappears. All input is from local fixture files. The coverage map now has S16, S28 and S29 passing.

Deviations: A34 to A37 in design-decisions.md. Open question: should an escalation also need an administrator's approval before it blocks (it currently does not, as C5 says "automatically")?

## Phase 6: Continuous self-test and rule packs (done)

Built: the self-test scheduler (38 harmless synthetic stories on an isolated copy of the live pipeline, checked against what the signed policy intends), alerts, the heartbeat (alive, policy version, self-test status, switched-off protections, degraded protection per missing sensor capability) and its monitor (stale or missing heartbeat is an alert), `RuleSetting.enabled`, and rule packs with weakening analysis, signed approvals, publisher keys and downgrade protection. The privacy audit now covers self-test alerts and heartbeats.

Tests: 1520 (84 new).

Done when: disabling any one of the 31 switchable protections in the live pipeline makes its own self-test alert "protection X is not working" while the others still pass (parametrized over every signal rule and override), and broken decision, gate and judge stages are found by the structural cases; a heartbeat older than the policy's `stale_after` raises an alert, once, and a device that never reports does too; an unsigned pack is rejected (and so is a pack from an untrusted publisher, a tampered pack, a pack that would weaken the policy without a signed approval, and an older pack than the one in force). Self-test stories never reach the live state: checked on stories, labels, processes, holds, notifier and the rate baselines.

Deviations: A38 to A41 in design-decisions.md. Open questions: (a) A41 replaces A12 (packs may now tighten existing roles). (b) The self-test copy is a deep copy of the whole pipeline, which is cheap for the replay tests and will cost memory on a device with a long history; Phase 8 should measure it.

## Phase 7: Variant and robustness testing (done)

Built: the variant generator (`refmon.variants`, seed 20261029 recorded in docs/variant-seeds.md before the first run), six mutation dimensions and seeded combinations, the no-label variants of S17-S20, the robustness matrix as CSV with the list of allowed variants and the questions that passed, hold outcomes for each answer a user or administrator can give, the share of role `other` for every variant, a known-gaps file and a CI step that fails on an undocumented allowed variant.

Tests: 1541 collected, 1538 passed and 3 expected failures (the three xfail tests below), in `tests/test_phase7_robustness.py` and the rest of the suite.

Result of the run on the 27 malicious golden files: **636 variants** (the 27 baselines, the four no-label variants of S17-S20, 368 one-factor mutations and 237 seeded combinations of two to four factors). Baselines: 25 block, 2 hold (S05 and S22, the known gaps). No-label variants of S17, S18, S19 and S20: all four block (D22 holds). Over all variants: **453 block, 174 hold, 9 allow**. Single-factor mutations (count of block / hold / allow per level):

| Level | block | hold | allow | Level | block | hold | allow |
|---|---|---|---|---|---|---|---|
| delivery=dragged | 7 | 1 | 0 | entry=file_manager | 7 | 10 | 0 |
| delivery=opened | 7 | 1 | 0 | entry=run_dialog | 7 | 10 | 0 |
| delivery=inbound_request | 16 | 0 | 0 | entry=scheduled_task | 4 | 13 | 0 |
| delivery=typed | 1 | 7 | 0 | entry=script_host | 4 | 13 | 0 |
| destination=internal_network | 17 | 1 | 0 | entry=terminal | 16 | 1 | 0 |
| destination=popular_trusted | 16 | 1 | 2 | entry=web_worker | 17 | 0 | 0 |
| destination=unknown | 3 | 1 | 0 | obfuscation (3 levels) | 16 | 1 | 0 |
| lineage depth 1 to 4 | 19 | 1 | 0 | timing=minutes | 22 | 4 | 1 |
| | | | | timing=beyond_window | 11 | 14 | 2 |

Share of processes in role `other`: 0.043 in the unmodified malicious files, 0.198 on average over all variants (the lineage mutation adds `other` processes; maximum 0.83), 0.061 on average over the benign golden workload. The workload the contracts cover is therefore mostly covered; the stories that fall under no contract are the ones with an unlisted process in the middle (S49 type).

Done when: the matrix is generated in CI (`python -m refmon.variants`, artifact `build/robustness-matrix.csv`, and `build/allowed-variants.csv`) and every one of the 9 allowed variants is documented as a known gap in `tests/variants/known_gaps.yaml` (G1 to G3, linked to F2 and F3 below). No weight or structural rule was changed to fix any of them (frozen), and the seed stays active. The three xfail tests state what a robust pipeline would do and become failures the day one is fixed.

Design findings (recorded, not fixed; each affects the paper's limits section):

- **F1 (Phase 3, extended).** A hold on a story with no labeled process pauses nothing. In the matrix 49 of the 174 held variants (typed delivery and similar, all in the S05 family) cannot pause or contain anything whatever the user answers; the user is only asked. The hold is a notification, not a containment.
- **F2.** `fetch` does not fire for a destination class the policy trusts, and `lateral` needs an internal class, so a payload, command-and-control channel or fan-out over a trusted class leaves the Effect question passed. Allowed: S07 and S18 with the destination set to a trusted class, and S13 in a combination. The exposure is as wide as the policy's trusted classes. Mitigation without a rule change: keep trusted classes narrow and list each role's destinations in its contract (the Contract question still fires).
- **F3.** Slow-and-low evades the windowed tests. Events minutes apart never form a burst (60 s window) or a repeat per client, and the request label decays (half-life 30 min) before the effect. Allowed: S19 with 90 s or 11 min between file changes, and S27 with 11 min between oversized responses. CUSUM covers volume only.
- **F4.** The Contract signal for pasted commands depends on the role that runs them. `external_content_exec: deny` is set for `interactive_shell` and `agent`; when the same content is run through a launcher, script host or scheduler (no such clause), the story has no Contract signal and the gate caps it at hold. Not allowed, but 10 to 13 of 17 variants per entry level fall from block to hold. A policy proposal (add the clause to `launcher`, `script_host` and `scheduler`) would have to be evaluated on newly generated variants under a new seed (C11 freeze rule); it was not made.

Deviations: A42 and A43 in design-decisions.md. Open question: whether F4 should become a policy change under a new seed.


## After Phase 7: review answers (no decision changes)

The reviewer answered the open questions on 2026-10-29. Recorded in design-decisions.md (A44, A45) and in tests/test_review_answers.py:

1. Warn mode stays notice-only (A17).
2. An exposure escalation needs no administrator approval by default: it only tightens and reverts by itself, and the administrator is told immediately. An optional per-role `exposure.require_approval` policy flag makes a role wait for `ExposureManager.approve` (A44).
3. F4 becomes a policy change under a new variant seed: see "v1.1" below.
4. **Limitation.** The Poisson baselines, `baseline_bytes` and the 0.01 response rate (A29) are expert estimates. They were not measured on real traffic; the long-window baselines of v1.1 (A49) are expert estimates too. They must be re-estimated in a pilot before any of the false-alarm or detection figures is read as a rate.
5. Block-list entries are per-device fingerprints (A26); a fleet-wide indicator needs a raw value and a list-keyed digest made by an analyst. Accepted as designed.
6. The memory cost of the self-test deep copy (A38) is measured in Phase 8.
7. **Limitation.** In the matrix, a hold of a `beyond_window` variant times out between two events during the replay, so its "continue" outcome reads as contained. The hold-outcome column is indicative for those rows. (The effective-hold count of v1.1 does not depend on it: it counts the pause actions the hold issued, whatever happened later.)

A28's fall back to the 3/2/1 rule is logged and reported in the heartbeat (A45).

## v1.1 (post-Phase 7 changes, tagged `v1.1`; `v1.0` stays frozen)

Four structural changes made after Phase 7, each motivated by a design finding of the Phase 7 matrix (F1 to F4), decided before the first run on the new variant seed 268805905 (recorded in [variant-seeds.md](variant-seeds.md) first; the old seed is retired). The weights are unchanged. Every change is in design-decisions.md (A46 to A50) and in the freeze table of CLAUDE.md C11.

| Finding | Change in v1.1 |
|---|---|
| F4 | `external_content_exec` is part of the universal contract: any role, unless its contract allows it (A46; scoped to labeled command text for roles with no setting). |
| F1 | A hold on a story with no labeled process pauses the processes that produced the story's signals (A47). |
| F2 | A trusted destination class excuses only roles whose contract lists it; a labeled process connecting to it elsewhere is a fetch (A48). |
| F3 | A label that carries Contract evidence does not decay; the Poisson and repeat tests also run over an hour-scale window (A49). |

Tests: 1580 passed, 2 expected failures (the two F3 tests). New: tests/test_v11.py (27), tests/test_review_answers.py (11). The golden catalog is unchanged: all 46 files reach the same `decision` and `rule_decision`; S05 now declares the pause it gets (F1) and `tests/golden/S05.expected.json` records it.

Evaluation on the new seed, 634 variants, v1.0 and v1.1 side by side (full report and the 114 variants whose outcome changed: [v1.1-evaluation.md](v1.1-evaluation.md)):

| | v1.0 | v1.1 |
|---|---:|---:|
| block | 446 | 487 |
| effective hold | 105 | 140 |
| uncontained (allow + hold that pauses nothing) | 83 (14 + 69) | 7 (7 + 0) |

On the 235 seeded combinations only (the independent test): block 138 to 156, effective hold 55 to 75, uncontained 42 to 4. No variant got worse. 114 changed: 69 holds that paused nothing now pause something, 38 holds became blocks (F4: a pasted command through a launcher, script host or scheduler now has a Contract signal), 4 allows became effective holds and 3 allows became blocks (F2).

Not closed: 7 variants stay allowed (G1 to G3 in tests/variants/known_gaps.yaml). The hour-scale window works, but the S19 stand-in changes 55 files (the test needs 60 in an hour) and the S27 stand-in sends 3 oversized responses (it needs 5); a lower long-window baseline would catch them and would be fitted to those two stand-ins.

New design findings, recorded and not fixed (each would be a v1.2 under another seed):

- **F5.** The hold fallback can pause a process that is not part of the attack, typically the launcher that started the command; when the story becomes a block the launcher stays paused. v1.0 left a process paused after 1 of 446 blocks, v1.1 after 64 of 487 (56 launchers that never carried a label). Fixes: release the fallback pauses a block does not kill, or leave the channel roles out of the fallback.
- **F6.** A block on a story with no labeled process acts on nothing (F1 for blocks): 11 of 446 blocks in v1.0, 9 of 487 in v1.1.
- **F7 (a limit of the method).** Only the seeded combinations depend on the seed. The 399 baseline, no-label and one-factor variants are the same events for every seed and were seen in the Phase 7 matrix, so they show that v1.1 does not regress and are not independent evidence. The benign side was checked on the golden catalog only; benign variants (a labeled helper that now reaches a trusted host, a pasted benign command run through a launcher) are not generated, and v1.1 can only be said not to have raised a benign alarm on the 19 benign golden files.

Deviations: A46 is narrower than the literal instruction (reason in A46). Open questions: whether to fix F5 and F6 in a v1.2; whether `stop` on a fallback hold should kill the paused processes (v1.1 leaves them paused).

## v1.2 (tagged `v1.2`; `v1.1` and `v1.0` stay frozen)

The open questions of v1.1 answered and two of its findings fixed, decided before the first run on the third variant seed 892499628 (recorded in [variant-seeds.md](variant-seeds.md) first; the previous seed is retired). The weights and the decisions are unchanged: no variant has a different block, hold or allow in v1.2 than in v1.1.

| Change | |
|---|---|
| F5 | The hold fallback never reaches a channel role (A51). |
| F6 | A block with no labeled process and no origin label acts on the producers of its signals (A52). |
| Open question 2 | `stop` on a fallback hold acts on the paused producers (A53). |
| F7 | The seed draws the numbers of every variant that has one, and variants are generated once to a file that every version replays (A54). |

Tests: 1595 passed, 2 expected failures (the two F3 tests). New: tests/test_v12.py (16). The Contain property test now also draws channel-role processes and asserts that nothing unlabeled is touched except a non-channel producer. The privacy audit, the golden builder check, ruff and the matrix CLI pass.

Evaluation on seed 892499628, 635 variants, v1.0, v1.1 and v1.2 on the same file ([v1.2-evaluation.md](v1.2-evaluation.md)):

| | v1.0 | v1.1 | v1.2 |
|---|---:|---:|---:|
| block | 423 | 478 | 478 |
| effective hold | 133 | 147 | 145 |
| uncontained (allow + hold that pauses nothing) | 79 (14 + 65) | 10 (10 + 0) | 12 (10 + 2) |
| blocks that act on nothing | 14 | 10 | 0 |
| blocks after which a process is still paused | 0 | 69 | 6 |

On the 324 variants the seed decides (the independent test): block 180, 218, 218; effective hold 99, 96, 94; uncontained 45, 10, 12. v1.1 reproduces its gain from the previous seed on fresh numbers (uncontained 79 to 10), and v1.2 keeps it while the Gate now acts where v1.1 acted on nothing or paused a launcher.

Not closed: 10 variants stay allowed (G1 to G3). New finding, recorded and not fixed: **F8**, the strength of a signal is the label's strength while the label is above the origin threshold and 1.0 below it, so the calculus is not monotone in label strength; one variant (S02 timing=minutes) is a block in v1.0 and a hold in v1.1 because of it (details in v1.2-evaluation.md). **F9**: benign variants are not generated; benign behaviour is checked on the 19 benign golden files.

Deviations: none from the instructions of this round. Open questions: whether to fix F8 (a change to C11.4, so a v1.3 on another seed); whether to generate benign variants before Phase 8; the long-window baseline (A49) from a pilot.

## v1.3 (tagged `v1.3`; `v1.0`, `v1.1` and `v1.2` stay frozen)

The two decisions of the reviewer's last answer: F8 fixed and benign variants generated (F9), decided before the first run on the fourth seed 654514256 (recorded in [variant-seeds.md](variant-seeds.md) first, with the rules that label a benign variant; the previous seed is retired).

| Change | |
|---|---|
| F8 | The calculus is monotone in label strength: a Contract or Effect signal counts at full strength, only Origin carries the label's strength; C11.4 is updated (A55). |
| F9 | Benign variants from the 19 benign golden files, same dimensions, same seed, same file; labelled by the generator before any replay when the mutation itself adds a Contract violation or an Effect (A56). |

Tests: 1608 passed, 1 expected failure (a slow burst, pinned to a fixed gap in tests/test_v13.py). New: tests/test_v13.py (14), including the monotonicity property (it fails on the v1.2 source and passes here, under 12 seeds of the whole suite and 100 more of the property tests).

Evaluation on seed 654514256, 879 variants (633 malicious, 246 benign), the same file replayed in v1.0, v1.1, v1.2 and v1.3 ([v1.3-evaluation.md](v1.3-evaluation.md)):

| malicious variants | v1.0 | v1.1 | v1.2 | v1.3 |
|---|---:|---:|---:|---:|
| block | 425 | 467 | 467 | 486 |
| effective hold | 121 | 157 | 157 | 139 |
| uncontained (allow + hold that pauses nothing) | 87 | 9 | 9 | 8 |
| weaker than in v1.0 | 0 | 2 | 2 | 0 |

| benign variants | v1.0 | v1.1 | v1.2 | v1.3 |
|---|---:|---:|---:|---:|
| neutral (151): allow / hold / block | 126 / 22 / 3 | 126 / 22 / 3 | 126 / 22 / 3 | 125 / 23 / 3 |
| neutral false block rate | 2.0% | 2.0% | 2.0% | 2.0% |
| labelled Contract violation (55): block | 30 | 32 | 32 | 34 |
| labelled Effect (40): block | 5 | 5 | 5 | 5 |

F8 is repaired (no malicious variant is weaker in v1.3 than in v1.0; v1.2 left two), a slow leak (S27) is no longer allowed, and none of v1.1 to v1.3 adds a false alarm to a neutral benign variant. 8 malicious variants stay allowed (G1 to G3).

New finding, recorded and not fixed: **F10**, the trusted-source override covers one story. A signed installer (S37) or a deployment (S24) whose steps are further apart than the story quiet window (10 minutes) loses the trusted flag at its persistence step and is blocked (S37, 3 of 151 neutral variants, the same in every version) or held (S24). Also recorded: the 17 benign variants labelled as adding a Contract violation that stay allowed are by design (a lone external-command signal is 1.8 nats; the trusted-root override allows a story whatever it then connects to).

Deviations: none. Open questions: none blocking; before publishing see docs/results.md, "Decisions before publishing".

## Paper-ready (after v1.3)

- `README.md` rewritten: what Refmon is, install, tests, one command to reproduce.
- `make reproduce` (`scripts/reproduce.py`) regenerates every result table from scratch and checks it against the committed per-variant data; `docs/results.md` holds the final tables for v1.0 to v1.3 (malicious and benign variants, Wilson intervals and McNemar's test, the golden catalog, the coverage map, the privacy audit, the test count), the known gaps G1 to G3, the findings F1 to F10, the limitations, and the decisions the owner must take before publishing.
- `scripts/check_publishable.py` (`make publishable`) scans the tracked files and the history of every ref for secrets, personal data and raw content, and checks that every replay file is a post-Observe event stream. The content is clean; the only personal data is the git author and committer identity of the commits, which is reported for the owner to decide.
- Phase 8 was not run: `docs/phase-8-plan.md` says why and what it needs (A58).
- Nothing was pushed.

## v1.4 in progress (seed 711829743): state of the suite

The v1.4 change (A59: a derived label that becomes persistent is frozen at the strength it has then, `pipeline/tag.py`) is in the code and seed 711829743 is active, but the v1.4 evaluation has not been run or written up. On this seed the matrix allows 14 malicious variants. Eleven fall under G1 to G3 as before. Three are new instances of documented findings and are now listed in `tests/variants/known_gaps.yaml`; no rule or weight was changed:

- S18 combo-3 and combo-11 (G1, F2): fan-out to a trusted class 15 to 22 minutes after the request. The actor has lost its label, so the trusted class excuses the connection, and `lateral` counts internal classes only.
- S27 timing=beyond_window (new G4, F3): oversized responses 30 minutes apart. Each is its own story, the label is below the origin threshold, and at most two share the hour window, so the repeat test never fires (L = -5.41 per story).

Not repairable in this clone: the history was squashed and the tags `v1.0` to `v1.3` exist neither here nor on the remote, so `make reproduce`, the CI reproduction step and `tests/test_reproduce.py::test_the_tags_the_reproduction_needs_exist` fail until the tags are restored from the original repository. The LICENSE (GPL-3.0) URLs are now allowlisted in `scripts/check_publishable.py`.

Security fixes to the live daemon (`src/refmon/live.py`, tests in `tests/test_live.py`): the HTTP API of `refmon serve` was unauthenticated, so any user of a shared node could run commands through `/api/guard` (with `execute`) or switch the barrier off through `/api/mode`; every `/api/` call now needs a random per-daemon token (`<workdir>/api.token`), a non-local `Host` header is refused, and a client whose request is refused no longer falls back to running the command in-process. The work directory (default `/tmp/refmon-live-<uid>`) is created `0700` and refused when it is a symlink or belongs to another user. The Observe key of the daemon was derived from the work-directory path, and `refmon scan-rootkit` used the constant default key, which made their fingerprints reversible; both now use random keys (`<workdir>/device.key`, `0600`; a fresh key per scan).

## v1.5 to v1.7 (seeds 833754500, 545728926, 616687759)

Two rounds, each on a seed recorded before its code (docs/variant-seeds.md); results in
docs/v1.5-evaluation.md. v1.5: lineage-aware trust (A60, F2), incidents that end (A61), bounded
state for the live daemon (A62). v1.6: a labeled block with no labeled process acts on its producers
(A63, F11). v1.7: every live label of reused content is handed over, which restores the
monotonicity property a randomised test had broken (A64). Contained malicious variants: 99.1 % (v1.5, seed 833754500) 98.1 % (v1.6, seed
545728926) and 98.3 % (v1.7, seed 616687759), neutral false block rate 0.6 to 1.9 %; no benign variant changed. New findings: **F11**
(fixed in v1.6) and **F12** (the matrix did not count a kill as containment; corrected for every
version alike). Still open: F2 for processes with no external lineage (G1, a policy decision) and F3
(G2, G3, needs a pilot baseline).

The live command barrier now predicts behaviour from the command text (`src/refmon/intent.py`):
23 attacker behaviours are refused when typed and blocked when pasted, 23 benign look-alikes stay
allowed (`tests/test_intent.py`).

## v2.0 (seed 171139148)

Results are in docs/v2.0-evaluation.md, and the seed was recorded before any v2.0 code.

Changes:
- **A65 (F10):** trust from a trusted root source is lineage. It is carried by the ingesting
  process and its children and fades like a label. It is narrower than a label: a channel role that
  ingests trusted content does not acquire it, it never passes to files, and any live external
  label in the lineage cancels it.
- **A66:** a fallback that reaches a channel role which started a program acts on that program.
- **A67:** the live barrier undoes the shell's word-hiding and recognises six more behaviours.

Results on the new seed:
- neutral false block rate 1.3 % → **0.0 %** (0 of 158, Wilson [0.0, 2.4]);
- false holds 3 → 0, and no benign variant ends worse than its unmodified file;
- 98.4 % of malicious variants contained in both versions, with none changed.

New allowed variants were documented, not fixed: S05 is now listed under G1, and S27 with minutes
between responses is G5, 0.02 nats under the hold threshold. F10 is closed. Still open: G1 (a
policy decision) and F3 (needs a pilot baseline).
