# Review list: autonomous decisions and design findings

Everything decided without asking while Phases 2 to 7 were built (2026-10-29), in one place. Details and reasons are in [design-decisions.md](design-decisions.md) (A1 to A43) and [progress.md](progress.md) (F1 to F4, open questions). Through Phase 7 the structural rules and weights were not touched (tag `v1.0`, same as `phase-7-done` plus these docs). After the reviewer's answers, v1.1 changed four structural rules (A46 to A49, tag `v1.1`); the weights are still identical to `phase-1-done` and the Phase 7 test still compares them with the text of CLAUDE.md C11. The golden event files are unchanged; `S05.expected.json` now declares the pause of F1, and CLAUDE.md has the v1.1 row in its freeze table and short v1.1 notes in C4, C6 and C7.

## Design findings

| # | Finding | Where it shows | Handling |
|---|---|---|---|
| F1 | A hold on a story with no labeled process pauses nothing (Contain is labeled-only). 69 of 174 held variants on the new seed. | S05 under the calculus; typed-delivery variants | **v1.1 (A47)**: the hold pauses the processes that produced the signals; 0 of 140 holds pause nothing |
| F2 | `fetch` does not fire for a trusted destination class and `lateral` needs an internal class, so a payload, C2 or fan-out over a trusted class passes the Effect question. | S07, S13, S18 variants | **v1.1 (A48)**: trust is role-scoped for labeled processes; the 3 allowed variants of Phase 7 are now caught; one typed (unlabeled) variant stays allowed (G1) |
| F3 | Slow-and-low evades the windowed burst and repeat tests, and the request label decays before the effect. | S19, S27 | **v1.1 (A49)**: evidence-carrying labels do not decay, hour-scale window; partly closed: 6 slow variants stay allowed because the stand-ins are shorter than the hour-scale thresholds (G2, G3) |
| F4 | The Contract signal for pasted commands existed only for roles whose contract says `external_content_exec: deny`. | entry=run_dialog, file_manager, script_host, scheduled_task | **v1.1 (A46)**: universal for labeled command text; 38 holds became blocks; narrower than the literal instruction (reason in A46) |
| F5 | The hold fallback paused an unlabeled launcher that stayed paused after the story became a block (v1.1: 69 of 478 blocks on the third seed). | S32 to S35 in the golden catalog | **v1.2 (A51)**: a channel role is never in the fallback; 0 launchers left paused, 6 blocks leave an attack process paused |
| F6 | A block on a story with no labeled process acted on nothing (14 of 423 blocks in v1.0). | no-label S17, S19, S20; typed S08 | **v1.2 (A52)**: acts on the producers when the story has no origin label either; 0 of 478 act on nothing |
| F7 | Only the seeded combinations depended on the seed. | the method | **v1.2 (A54)**: the seed draws every variant's numbers, variants are generated once to a file |
| F8 | The calculus was not monotone in label strength: a signal counted at the label's strength above the origin threshold and at 1.0 below it. Two variants were worse in v1.1 and v1.2 than in v1.0 because of it. | S02 timing=minutes, combo-4 | **v1.3 (A55)**: a behavioural signal counts at full strength; C11.4 updated; a property test fails on v1.2 and passes on v1.3 |
| F9 | Benign variants were not generated. | the method | **v1.3 (A56)**: 246 benign variants, labelled by the generator before any replay; neutral false block rate 2.0% (3 of 151), the same in every version |
| F10 | The trusted-source override covers one story: an installer or deployment whose steps are further apart than the story quiet window loses the trusted flag. | S37 (3 variants block), S24 (2 hold) | recorded, not fixed |

## Autonomous decisions

**Phase 1 (made in the earlier session, listed so the whole list is here)**
- A1 `Policy` is a typed model with a reference default policy. A2 `fetch` fires for any process whose destination is outside its contract and not trusted (labeled or not); a role with no contract counts as `may_connect: []`. A3 `escalate`, `credential`, `asset_access` count only when the contract does not allow them. A4 Raw attribute names consumed by Observe, two new event attribute keys, three new policy sections, `may_connect: [any]`. A5 `browser`, `mail`, `launcher` do not carry labels. A6 Story linking rules. A7 A scenario's result is the highest-decision story. A8 A verdict is emitted when the decision changes (refined by A23). A9 Concrete readings of S21, S22, S25, S26a, S27 and the new benign scenarios; S41 to S43 dropped. A10 Counted rate thresholds in Phases 1 to 4.

**Phase 2: policy and contracts**
- A11 Ed25519 signature over canonical JSON in the `signature` field; trust anchors passed in; duplicate YAML keys rejected. A12 Packs pinned by name, version and signature, additive merge (replaced by A41). A13 `PolicyStore` keeps the last valid policy; no fallback on a failed first load. A14 Exceptions need reason, scope, known rule ids, a date; overrides cannot be excepted. A15 Learning counts only; per-change proposals; relaxing changes need to be asked for; `other` skipped; `learned_roles` recorded. A16 Guard test: no numeric literals beyond 0 to 3 in stage code.

**Phase 3: Act**
- A17 observe never acts; warn sends a notice and touches nothing; block acts. A18 Hold flows: endpoint (pause, ask, timeout is stop, continue withdrawn at three fails), server (pause, quarantine, notify, stays quarantined after `server_hold_wait`, new field). A19 A process counts as labeled for Contain if it carried a live label at any time in the story. A20 Contain is labeled-only for holds too (see F1). A21 One action per object per Gate; blocked stays blocked; device kind from policy `devices`. A22 `SimWorld` for the simulated enforcer; undo restores prior state except kills.

**Phase 4: Report and Tune**
- A23 A verdict is emitted again when effects or Contract reasons change. A24 Summaries from fixed phrases, audited against a template vocabulary; `Verdict.users`; ATT&CK tactic names only. A25 Pseudonyms, sealed vault, four-eyes with signed requests, one use per request, hash-chained log. A26 False alarm proposes an expiring scoped exception and a contract extension; confirmed proposes fingerprint block-list entries; nothing applies without a named approver. A27 Random per-device keys (`new_device_key`); the audit attacks guessable keys.

**Phase 4b: mathematical core**
- A28 `engine: auto`: calculus when weights exist, else the 3/2/1 rule; both always computed. A29 Poisson baselines, EMA beta, the 0.01 response-anomaly rate and the backup byte baseline are policy data (expert estimates). A30 Surprisal needs a mature baseline and is not raised for what the contract lists; learned contracts wait for maturity. A31 Edge attenuation is a policy table, default 1.0. A32 Obfuscation features measured in Observe on the raw text; Bloom threat lists with exact confirmation. A33 Contributions listed for every signal, only the strongest per question counted.

**Phase 5: exposure**
- A34 Fifth state `not_reachable`; EOL from inventory or advisory; versions are dotted integers and bare YAML numbers are refused. A35 Virtual patching is a derived overlay that only tightens and reverts by itself. A36 `Pipeline.set_policy`, `ExposureManager.rebase`, optional signed advisories. A37 S16, S28, S29 are policy-over-time tests, not golden event files.

**Phase 6: self-test and packs**
- A38 Self-test runs on an isolated deep copy of the live pipeline, never in the live one. A39 Intent comes from the signed policy, behaviour from the live pipeline; cases declare when they do not apply. A40 Heartbeat contents, degraded protection per missing capability, monitor alerts once per silence. A41 Packs overlay, may tighten, loosening needs a signed approval, downgrade refused, publisher keys.

**Phase 7: robustness**
- A42 One-factor plus seeded combination variants; inapplicable mutations skipped; meaning of each mutation. A43 "Allowed" means allow; holds reported with the outcome of each answer; known gaps matched by dimension levels; strict xfails.

**Post-Phase 7 (v1.1)**
- A44 Review answers: warn mode stays notice-only; an exposure escalation applies at once and tells the administrator, with an optional per-role `exposure.require_approval`. A45 The fall back to the 3/2/1 rule is logged and reported in the heartbeat. A46 to A49 the four v1.1 structural changes. A50 How v1.0 and v1.1 are compared. A51 to A54 the v1.2 changes (channel roles out of the fallback, blocks without a label act, stop acts, the seed draws every variant). A55 and A56 the v1.3 changes (monotone calculus, benign variants). A57 the evaluation statistics and `make reproduce`. A58 Phase 8 not run.

## Open questions

Answered by the reviewer after Phase 7 (kept for the record): 1 warn mode stays notice-only; 2 no approval by default, admin notified at once, optional `require_approval` per role; 3 F4 became a policy change under a new seed (v1.1); 4 and 7 are recorded as limitations in progress.md; 5 agreed; 6 is measured in Phase 8.

Answered by the instruction to finish (2026-10-29): F5 and F6 are fixed in v1.2 (A51, A52), `stop` on a fallback hold acts on the paused processes (A53).

Answered by the instruction to finish (2026-10-29): F8 is fixed in v1.3 (A55) and benign variants are generated (A56).

Open after v1.3: none that blocks. A lower long-window baseline (A49) from a pilot; F10; the decisions before publishing in docs/results.md.
