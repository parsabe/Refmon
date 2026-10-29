# Default weights

**Status: approved on 2026-10-28, with the structural rules D13-D18 in [design-decisions.md](design-decisions.md).** The table is in CLAUDE.md C11 (`math.weights`). The seven weights that CLAUDE.md already had are unchanged. Phase 4b reads the table from policy.

## How the numbers were chosen

A weight is `w = ln( P(signal | attack story) / P(signal | benign story) )` in nats (C11.4). For each new signal I wrote down two assumed rates and rounded `ln(a/b)` to the nearest 0.5:

- `a`: the share of attack stories, across all families, that show the signal at all.
- `b`: the share of benign stories in which the signal fires, after the role's approved contract or the signal's own statistical test has already filtered routine behaviour.
- Rate-tested signals (Poisson, CUSUM) all use `b = 0.01`: the test's nominal level of 1e-6 inflated 10,000 times for stale or incomplete baselines.

The rates are expert estimates about attacks and benign activity in general. No scenario was consulted to pick them. They should be re-estimated from observe-mode counts (C11.4) once a pilot exists.

`e^w` reads as "how many times more common in attack stories than in benign ones".

## The table

| Signal | Question | w | e^w | a | b | Why (one line) |
|---|---|---|---|---|---|---|
| origin_external | origin | 0.8 | 2.2 | spec | spec | External input starts most attacks but also most benign activity (browsing, mail, downloads), so it is weak evidence alone. |
| contract_external_exec | contract | 1.0 | 2.7 | spec | spec | People and agents do run commands copied from outside, and benign copying (docs, forums) is common. |
| contract_web_worker_exec | contract | 3.0 | 20.1 | spec | spec | A hardened worker has no reason to start processes; approved exceptions sit on its allowlist. Applies to `web_worker` and `node_app_server`. |
| contract_exec_violation | contract | 2.5 | 12.2 | 0.25 | 0.02 | A role limited to its allowlisted helpers (office, reader, scheduler) starting something else is a usual first step of attachment and macro chains. |
| contract_write_executable | contract | 3.5 | 33.1 | 0.20 | 0.005 | A role that handles data writing a new executable or script is how web shells and droppers land; legitimate deployments use a deployment tool. |
| contract_write_other | contract | 1.0 | 2.7 | 0.10 | 0.03 | Writes outside approved path groups are common after updates and config changes, so this is mild evidence. |
| contract_connect_violation | contract | 2.5 | 12.2 | 0.50 | 0.04 | Nearly every intrusion needs a callback or staging connection; benign violations are mostly new dependencies missing from the contract. |
| contract_persist_violation | contract | 3.5 | 33.1 | 0.30 | 0.01 | A role with `may_persist: false` creating startup items is almost never legitimate (vendor installers are the exception). |
| contract_asset_violation | contract | 2.5 | 12.2 | 0.30 | 0.02 | A role reading assets its contract excludes is how services get abused for data access; benign cases are contract gaps. |
| contract_privilege_violation | contract | 3.5 | 33.1 | 0.35 | 0.01 | A service gaining privileges beyond its role is rare at runtime, because legitimate privilege is configured, not acquired. |
| contract_surprisal | contract | 2.0 | 7.4 | 0.40 | 0.05 | Rare for the role under its learned baseline, but baselines are incomplete, so a rare event is often just new. |
| effect_fetch | effect | 2.5 | 12.2 | spec | spec | A labeled process reaching a destination outside its contract is what staging looks like; benign cases mostly go to listed sources. |
| effect_hide | effect | 2.0 | 7.4 | spec | spec | Hidden windows and encoded payloads are rare in routine administration but exist (installers, packers), so below fetch. |
| effect_persist | effect | 2.5 | 12.2 | spec | spec | Startup entries, scheduled tasks and new executables in web roots are the standard way to survive a restart; installs do it too. |
| effect_exfil | effect | 2.5 | 12.2 | spec | spec | Sustained outbound volume above the role's baseline; backup and sync are the benign look-alikes. |
| effect_escalate | effect | 2.5 | 12.2 | 0.40 | 0.03 | Attackers often need more privilege, but admins elevate routinely (sudo, UAC), so the unconditional signal is moderate. |
| effect_lateral | effect | 3.5 | 33.1 | 0.30 | 0.01 | Statistically extreme fan-out to distinct internal hosts marks scanning and spread; monitoring and backup roles have their own baselines. |
| effect_tamper | effect | 3.0 | 20.1 | 0.50 | 0.02 | Stopping security tools or clearing logs is a defence-evasion step; legitimate cases are rare and happen inside change windows. |
| effect_credential | effect | 3.5 | 33.1 | 0.40 | 0.015 | Reading credential stores or key material outside normal app use; benign readers (the browser, a password manager) are the exception. |
| effect_asset_access | effect | 1.5 | 4.5 | 0.35 | 0.08 | Touching a protected asset is routine for the owning service, so alone it is weak. (A labeled process doing so is an override, not this weight.) |
| effect_mass_change | effect | 2.5 | 12.2 | 0.15 | 0.01 | A burst of file changes beyond the role baseline; updates, builds and backups cause benign bursts and only some attacks encrypt or wipe. |
| effect_response_anomaly | effect | 1.5 | 4.5 | 0.05 | 0.01 | Responses far above baseline to one client; large exports are common look-alikes and only a small share of attacks leak memory this way. |
| contract_universal_violation | contract | 2.0 | 7.4 | 0.90 | 0.10 | Given tampering, mass change, fan-out or repeated oversized responses happened, 90 % of attack instances come from a role that is not allowed to do it against about 10 % of benign ones (contract gaps). Added after check 2 (D19). |
| contract_unsigned_launch | contract | 1.5 | 4.5 | 0.70 | 0.15 | Given an externally labeled file is launched and the sensor reports it unsigned (`unknown` raises nothing), most attack instances lack a valid signature (stolen certificates exist) against about 15 % of benign ones (internal scripts, open-source tools). Added after check 2 (D20). |
| effect_response_anomaly_repeated | effect | 3.5 | 33.1 | 0.05 | 0.0015 | The same client exceeding its baseline again at Poisson level is far rarer in benign traffic than a single large response. Weight set by the reviewer; the rates are the ones it implies. Added after check 1 (D14). |
| effect_threat_list_hit | effect | 4.5 | 90.0 | 0.10 | 0.001 | A hit confirmed against the exact list is strong; stale or shared-infrastructure entries cause the residual false hits. Belongs to the Effect question (approved, D12). |

Block needs 2.99 nats above the prior (-6.91), hold needs 1.97. At the block threshold the posterior attack probability is 1.96 %, at the hold threshold 0.71 %.

## Process rules (now in CLAUDE.md: C11 weight methodology and Phase 7)

1. Weights and structural rules are fixed before any catalog run. A change needs approval and a reason that does not mention a scenario.
2. If a scenario cannot reach its expected decision with justified weights and rules, that is reported as a design finding. It is not fixed by moving a weight or a rule.
3. From Phase 7, robustness is measured only on generated variants that were never used to choose weights or structural rules. The generator seed is recorded before any such change; any later change retires that seed and the next matrix needs a new one.

## Catalog check 1 (before the structural rules)

Run once, after the table above (without the repeated-anomaly row) was fixed. Signals per scenario are read from C8 and C13; every strength is 1.0. Where the wording leaves a choice, every variant is shown. Overrides (S08 canary, S34 protected asset, S09, S24, S37 trusted root) bypass the calculus.

| Scenario | Variant | Sum (nats) | L | Decision | Expected | |
|---|---|---|---|---|---|---|
| S01-S04, S07, S12 | | 4.3 | -2.61 | block | block | ok |
| S05 | | 2.5 | -4.41 | hold | hold | ok |
| S06 | delayed run, persistent label | 3.3 | -3.61 | block | block | ok |
| S13 | | 6.3 | -0.61 | block | block | ok |
| S14 | | 6.8 | -0.11 | block | block | ok |
| S15 | | 5.8 | -1.11 | block | block | ok |
| S17 | with or without origin label | 6.8 / 6.0 | -0.11 / -0.91 | block | block | ok |
| S18 | with / without origin label | 4.3 / 3.5 | -2.61 / -3.41 | block | block | ok |
| S19 | with origin label | 3.3 | -3.61 | block | block | ok |
| S19 | **no origin label** | 2.5 | -4.41 | **hold** | block | **differs** |
| S20 | with origin label | 3.8 | -3.11 | block | block | ok |
| S20 | no origin label | 3.0 | -3.91 | block | block | ok, **by 0.005 nats** |
| S21 | | 7.8 | 0.89 | block | block | ok |
| S22 | exfil volume only | 2.5 | -4.41 | hold | known gap | consistent |
| S25 | child process only | 3.8 | -3.11 | block | block | ok |
| S26 | outbound connection / executable written | 5.8 / 6.8 | -1.11 / -0.11 | block | block | ok |
| S26 | **non-executable file written** | 1.8 | -5.11 | **allow** | block | **differs** |
| S27 | first anomalous response | 2.3 | -4.61 | hold | hold | ok |
| S27 | **repeated** | 2.3 | -4.61 | **hold** | block on repeat | **differs** |
| S31 | with or without an effect | 5.8 / 3.3 | -1.11 / -3.61 | block | block | ok |
| S32, S33, S35 | | 3.3 | -3.61 | block | block | ok |
| S10, S11, S23, S30 | | 0.0 to 1.8 | -6.91 to -5.11 | allow | allow | ok |
| S36 | contract allows the print helper | 0.8 | -6.11 | allow | allow | ok |
| S36 | **print helper missing from contract** | 3.3 | -3.61 | **block** | allow | **differs** |

### Findings from check 1

These are properties of the calculus with justified weights, not weight problems. They led to the structural rules D13-D18, which means check 2 below is not an independent test of them.

1. **S27 "block on repeat" cannot be reached.** Within a question only the maximum counts (C11.4), so repeating the same anomaly adds nothing, and even at strength 1.0 with an origin label the story reaches only -4.61. Something has to turn repetition into evidence, for example letting the CUSUM or Poisson statistic set the signal's strength, or counting a repeat as its own signal. C11 specifies neither.
2. **S26 depends on the variant.** "Unexpected file write or outbound connection" blocks for a connection or an executable write, but a plain non-executable write reaches only -5.11 and is allowed. The scenario definition needs to say which.
3. **Single-signal stories are fragile.** S19 without an origin label is only a hold, and S20 without one blocks by 0.005 nats, so a different rounding of the prior would flip it. Block needs about 3 nats above the prior, which a single effect barely supplies. This is why the S17-S20 stories should carry an initial-access label (design decision D2).
4. **Origin plus any one effect of 2.2 nats or more blocks, whatever the contract says.** Prior -6.91 + 0.8 + 2.5 = -3.61 is above the block threshold. That matches the cost model (block at 2 % posterior because a missed attack costs 50 times a false block), but it means about 49 of 50 such blocks are false. It conflicts with the C10 target of zero benign blocks per simulated week unless trusted sources and exceptions are complete. A benign download from an unlisted vendor that then persists blocks.
5. **Benign outcomes rest on approved contracts.** S36 is allowed only if the reader's contract lists the print helper; without it the same story blocks. Contract learning mode (Phase 2) has to capture such helpers before enforcement.
6. **Rare-family signals are weak by construction.** Weights are calibrated over all attacks, so a signal that only some families show (response anomaly 1.5, asset access 1.5) can never block by itself. Per-family or per-exposure conditioning would be a different model and is not proposed here.

## Catalog check 2 (after the structural rules D13-D18)

Weights as above plus `effect_response_anomaly_repeated` 3.5. Rules: contract gate (block needs a Contract signal or an override, else hold), S26 split, print helper in the S36 reader contract, S17-S20 with and without an initial-access label. Signals are read from C8 and C13; every strength is 1.0. Prior -6.91, block threshold -3.91, hold threshold -4.94. No weight or rule was changed after this run.

| Scenario | Variant | L | Decision | Expected | Result | Reason |
|---|---|---|---|---|---|---|
| S01-S04 |  | -2.61 | block | block | ok | origin 0.8 + contract 1 + effect 2.5 = 4.3; L -2.61 >= block -3.91 |
| S05 | typed, no label | -4.41 | hold | hold | ok | effect 2.5 = 2.5; L -4.41 in [-4.94, -3.91) |
| S06 | delayed run, persistent label | -3.61 | **hold** | block | **differs** | origin 0.8 + effect 2.5 = 3.3; L -3.61 crosses block but no Contract signal, capped at hold |
| S07 |  | -2.61 | block | block | ok | origin 0.8 + contract 1 + effect 2.5 = 4.3; L -2.61 >= block -3.91 |
| S08 | canary override | - | block | block | ok | override: canary -> block |
| S09 | trusted root override | - | allow | allow | ok | override: trusted_root -> allow |
| S10 |  | -6.91 | allow | allow | ok | no signals = 0.0; L -6.91 < hold -4.94 |
| S11 |  | -5.11 | allow | allow | ok | origin 0.8 + contract 1 = 1.8; L -5.11 < hold -4.94 |
| S12 |  | -2.61 | block | block | ok | origin 0.8 + contract 1 + effect 2.5 = 4.3; L -2.61 >= block -3.91 |
| S13 |  | -0.61 | block | block | ok | origin 0.8 + contract 3 + effect 2.5 = 6.3; L -0.61 >= block -3.91 |
| S14 |  | -0.11 | block | block | ok | origin 0.8 + contract 3.5 + effect 2.5 = 6.8; L -0.11 >= block -3.91 |
| S15 |  | -1.11 | block | block | ok | origin 0.8 + contract 2.5 + effect 2.5 = 5.8; L -1.11 >= block -3.91 |
| S17 | with initial-access label | -0.11 | block | block | ok | origin 0.8 + contract 3.5 + effect 2.5 = 6.8; L -0.11 >= block -3.91 |
| S17 | no label (Phase 7 variant) | -0.91 | **block** | hold | **differs** | contract 3.5 + effect 2.5 = 6.0; L -0.91 >= block -3.91 |
| S18 | with initial-access label | -2.61 | **hold** | block | **differs** | origin 0.8 + effect 3.5 = 4.3; L -2.61 crosses block but no Contract signal, capped at hold |
| S18 | no label (Phase 7 variant) | -3.41 | hold | hold | ok | effect 3.5 = 3.5; L -3.41 crosses block but no Contract signal, capped at hold |
| S19 | with initial-access label | -3.61 | **hold** | block | **differs** | origin 0.8 + effect 2.5 = 3.3; L -3.61 crosses block but no Contract signal, capped at hold |
| S19 | no label (Phase 7 variant) | -4.41 | hold | hold | ok | effect 2.5 = 2.5; L -4.41 in [-4.94, -3.91) |
| S20 | with initial-access label | -3.11 | **hold** | block | **differs** | origin 0.8 + effect 3 = 3.8; L -3.11 crosses block but no Contract signal, capped at hold |
| S20 | no label (Phase 7 variant) | -3.91 | hold | hold | ok | effect 3 = 3.0; L -3.91 crosses block but no Contract signal, capped at hold |
| S21 |  | 0.89 | block | block | ok | origin 0.8 + contract 3.5 + effect 3.5 = 7.8; L 0.89 >= block -3.91 |
| S22 | exfil volume only | -4.41 | hold | known gap | known gap | effect 2.5 = 2.5; L -4.41 in [-4.94, -3.91) |
| S23 |  | -6.11 | allow | allow | ok | origin 0.8 = 0.8; L -6.11 < hold -4.94 |
| S24 | trusted root override | - | allow | allow | ok | override: trusted_root -> allow |
| S25 | child process only | -3.11 | block | block | ok | origin 0.8 + contract 3 = 3.8; L -3.11 >= block -3.91 |
| S26a | non-executable write | -5.11 | allow | allow | ok | origin 0.8 + contract 1 = 1.8; L -5.11 < hold -4.94 |
| S26b | outbound connection | -1.11 | block | block | ok | origin 0.8 + contract 2.5 + effect 2.5 = 5.8; L -1.11 >= block -3.91 |
| S26c | executable write | -0.11 | block | block | ok | origin 0.8 + contract 3.5 + effect 2.5 = 6.8; L -0.11 >= block -3.91 |
| S27 | first anomalous response | -4.61 | hold | hold | ok | origin 0.8 + effect 1.5 = 2.3; L -4.61 in [-4.94, -3.91) |
| S27 | repeated, Poisson-significant | -2.61 | **hold** | block | **differs** | origin 0.8 + effect 3.5 = 4.3; L -2.61 crosses block but no Contract signal, capped at hold |
| S30 | allowlisted child | -6.11 | allow | allow | ok | origin 0.8 = 0.8; L -6.11 < hold -4.94 |
| S31 |  | -1.11 | block | block | ok | origin 0.8 + contract 2.5 + effect 2.5 = 5.8; L -1.11 >= block -3.91 |
| S32 |  | -3.61 | **hold** | block | **differs** | origin 0.8 + effect 2.5 = 3.3; L -3.61 crosses block but no Contract signal, capped at hold |
| S33 |  | -3.61 | **hold** | block | **differs** | origin 0.8 + effect 2.5 = 3.3; L -3.61 crosses block but no Contract signal, capped at hold |
| S34 | protected asset override | - | block | block | ok | override: protected_asset -> block |
| S35 |  | -3.61 | **hold** | block | **differs** | origin 0.8 + effect 2.5 = 3.3; L -3.61 crosses block but no Contract signal, capped at hold |
| S36 | print helper in reader contract | -6.11 | allow | allow | ok | origin 0.8 = 0.8; L -6.11 < hold -4.94 |
| S37 | trusted root override | - | allow | allow | ok | override: trusted_root -> allow |

Rows marked **differs** are discussed below. S08, S34 (block) and S09, S24, S37 (allow) are overrides and bypass the calculus. S22 is a documented known gap.

### Findings from check 2

1. **The contract gate and the catalog contradict each other for 8 scenarios.** S18, S19, S20, S27 (repeat), S32, S33 and S35 are capped at hold although C8 expects block. They are exactly the expected-block scenarios without an override whose C13 Contract column is "—": no contract rule is meant to catch them, so with the gate they can never block. S06 is the eighth (finding 3). D14's new signal cannot lift S27 because the gate caps it, and the initial-access label added to S18-S20 changes their log-odds but not their decision, so with-label and no-label variants both hold.
2. **S17 without a label blocks (L -0.91), not hold.** `contract_privilege_violation` plus `effect_escalate` is 6.0 nats of evidence and satisfies the gate. The Phase 7 expectation of hold for this variant does not match; either that expectation is block, or the variant tells us nothing.
3. **S06 depends on how Link works.** The delayed-run story contains no Contract signal (the shell executing pasted content happened a day earlier, in another story), so it is capped at hold. If a persistent label carried the Contract signal of its origin story into the new one, S06 would block. That is a Link design question.
4. **The gate removes the false-block exposure of check 1.** An unlisted vendor installer that persists (origin plus effect) is now a hold, which asks the user, and not a block, unless it also breaks a contract. That fits the C10 target of at most one hold per user per week better than it fits a target of zero holds.
5. **Options for finding 1, not chosen here:** (a) give a labeled process of a role with no contract a default-deny contract (`may_persist: false`, `may_connect: []`), so persisting or connecting out counts as a Contract signal for S32, S33 and S35; (b) change the expected decision of S18, S19, S20, S27-repeat, S32, S33, S35 to hold in C8; (c) exempt named effects (tamper, mass_change, lateral) from the gate; (d) carry Contract signals along persistent labels (S06 only).

## Catalog check 3 (after the structural rules D19-D22)

Weights as above, including the two Contract weights fixed from the rates in the table before this run. Rules: the contract gate, the universal contract and the launcher contract (an allowed behaviour raises neither a Contract signal nor its Effect), persistent contract evidence (S06 carries the Contract signal of its origin story), S17-S20 with and without an initial-access label, and the new scenarios S46-S49. Prior -6.91, block threshold -3.91, hold threshold -4.94. Every strength is 1.0. No weight or rule was changed after this run. **This is the last check the structural rules may be changed on.**

| Scenario | Variant | L | Decision | Expected | Result | Reason |
|---|---|---|---|---|---|---|
| S01-S04 |  | -2.61 | block | block | ok | origin 0.8 + contract 1 + effect 2.5 = 4.3; L -2.61 >= block -3.91 |
| S05 | typed, no label | -4.41 | hold | hold | ok | effect 2.5 = 2.5; L -4.41 in [-4.94, -3.91) |
| S06 | delayed run, Contract evidence carried (D21) | -2.61 | block | block | ok | origin 0.8 + contract 1 + effect 2.5 = 4.3; L -2.61 >= block -3.91 |
| S07 |  | -2.61 | block | block | ok | origin 0.8 + contract 1 + effect 2.5 = 4.3; L -2.61 >= block -3.91 |
| S08 | canary override | - | block | block | ok | override: canary -> block |
| S09 | trusted root override | - | allow | allow | ok | override: trusted_root -> allow |
| S10 |  | -6.91 | allow | allow | ok | no signals = 0.0; L -6.91 < hold -4.94 |
| S11 |  | -5.11 | allow | allow | ok | origin 0.8 + contract 1 = 1.8; L -5.11 < hold -4.94 |
| S12 |  | -2.61 | block | block | ok | origin 0.8 + contract 1 + effect 2.5 = 4.3; L -2.61 >= block -3.91 |
| S13 |  | -0.61 | block | block | ok | origin 0.8 + contract 3 + effect 2.5 = 6.3; L -0.61 >= block -3.91 |
| S14 |  | -0.11 | block | block | ok | origin 0.8 + contract 3.5 + effect 2.5 = 6.8; L -0.11 >= block -3.91 |
| S15 |  | -1.11 | block | block | ok | origin 0.8 + contract 2.5 + effect 2.5 = 5.8; L -1.11 >= block -3.91 |
| S17 | with initial-access label | -0.11 | block | block | ok | origin 0.8 + contract 3.5 + effect 2.5 = 6.8; L -0.11 >= block -3.91 |
| S17 | no label (Phase 7 variant) | -0.91 | block | block | ok | contract 3.5 + effect 2.5 = 6.0; L -0.91 >= block -3.91 |
| S18 | with initial-access label | -0.61 | block | block | ok | origin 0.8 + contract 2 + effect 3.5 = 6.3; L -0.61 >= block -3.91 |
| S18 | no label (Phase 7 variant) | -1.41 | **block** | hold | **differs** | contract 2 + effect 3.5 = 5.5; L -1.41 >= block -3.91 |
| S19 | with initial-access label | -1.61 | block | block | ok | origin 0.8 + contract 2 + effect 2.5 = 5.3; L -1.61 >= block -3.91 |
| S19 | no label (Phase 7 variant) | -2.41 | **block** | hold | **differs** | contract 2 + effect 2.5 = 4.5; L -2.41 >= block -3.91 |
| S20 | with initial-access label | -1.11 | block | block | ok | origin 0.8 + contract 2 + effect 3 = 5.8; L -1.11 >= block -3.91 |
| S20 | no label (Phase 7 variant) | -1.91 | **block** | hold | **differs** | contract 2 + effect 3 = 5.0; L -1.91 >= block -3.91 |
| S21 |  | 0.89 | block | block | ok | origin 0.8 + contract 3.5 + effect 3.5 = 7.8; L 0.89 >= block -3.91 |
| S22 | exfil volume only | -4.41 | hold | known gap | known gap | effect 2.5 = 2.5; L -4.41 in [-4.94, -3.91) |
| S23 |  | -6.11 | allow | allow | ok | origin 0.8 = 0.8; L -6.11 < hold -4.94 |
| S24 | trusted root override | - | allow | allow | ok | override: trusted_root -> allow |
| S25 | child process only | -3.11 | block | block | ok | origin 0.8 + contract 3 = 3.8; L -3.11 >= block -3.91 |
| S26a | non-executable write | -5.11 | allow | allow | ok | origin 0.8 + contract 1 = 1.8; L -5.11 < hold -4.94 |
| S26b | outbound connection | -1.11 | block | block | ok | origin 0.8 + contract 2.5 + effect 2.5 = 5.8; L -1.11 >= block -3.91 |
| S26c | executable write | -0.11 | block | block | ok | origin 0.8 + contract 3.5 + effect 2.5 = 6.8; L -0.11 >= block -3.91 |
| S27 | first anomalous response | -4.61 | hold | hold | ok | origin 0.8 + effect 1.5 = 2.3; L -4.61 in [-4.94, -3.91) |
| S27 | repeated, Poisson-significant | -0.61 | block | block | ok | origin 0.8 + contract 2 + effect 3.5 = 6.3; L -0.61 >= block -3.91 |
| S30 | allowlisted child | -6.11 | allow | allow | ok | origin 0.8 = 0.8; L -6.11 < hold -4.94 |
| S31 |  | -1.11 | block | block | ok | origin 0.8 + contract 2.5 + effect 2.5 = 5.8; L -1.11 >= block -3.91 |
| S32 | unsigned program from removable media | -2.11 | block | block | ok | origin 0.8 + contract 1.5 + effect 2.5 = 4.8; L -2.11 >= block -3.91 |
| S33 | unsigned fake installer | -2.11 | block | block | ok | origin 0.8 + contract 1.5 + effect 2.5 = 4.8; L -2.11 >= block -3.91 |
| S34 | protected asset override | - | block | block | ok | override: protected_asset -> block |
| S35 | unsigned file from a link | -2.11 | block | block | ok | origin 0.8 + contract 1.5 + effect 2.5 = 4.8; L -2.11 >= block -3.91 |
| S36 | print helper in reader contract | -6.11 | allow | allow | ok | origin 0.8 = 0.8; L -6.11 < hold -4.94 |
| S37 | trusted root override | - | allow | allow | ok | override: trusted_root -> allow |
| S46 | backup job, role allows mass change | -6.91 | allow | allow | ok | no signals = 0.0; L -6.91 < hold -4.94 |
| S47 | vulnerability scanner, role allows fan-out | -6.91 | allow | allow | ok | no signals = 0.0; L -6.91 < hold -4.94 |
| S48 | patch tool, role allows tampering | -6.91 | allow | allow | ok | no signals = 0.0; L -6.91 < hold -4.94 |
| S49 | signed vendor installer persists | -3.61 | hold | hold | ok | origin 0.8 + effect 2.5 = 3.3; L -3.61 crosses block but no Contract signal, capped at hold |

S08, S34 (block) and S09, S24, S37 (allow) are overrides and bypass the calculus. S22 is a documented known gap.

### What the interpretation of D19 hangs on

Not catalog rows. The same stories if an allowed behaviour still raised its Effect, and the S49 installer without a signature:

| Scenario | Variant | L | Decision | Expected |
|---|---|---|---|---|
| S46 | Effect still fires for an allowed role | -4.41 | hold | allow |
| S47 | Effect still fires for an allowed role | -3.41 | hold | allow |
| S48 | Effect still fires for an allowed role | -3.91 | hold | allow |
| S49 | same installer, unsigned | -2.11 | block | hold |

### Findings from check 3

1. **Every catalog scenario reaches its expected decision except three Phase 7 variants.** The no-label variants of S18, S19 and S20 block (L -1.41, -2.41, -1.91) where D18 expects hold. The decision comes from the gate rule, not from the 2.0 weight: with no Contract signal they would be capped at hold, with one they are above the block threshold, and any Contract weight of 0.5 or more gives the same result. Under D19 a missing initial-access label no longer lowers the decision, because the universal contract supplies the Contract signal by itself. Either those three expectations become block (as D22 did for S17), or the variants stop being informative. Not changed here.
2. **S46-S48 are allowed only because an allowed behaviour raises neither a Contract signal nor its Effect.** If the Effect still fired they would hold (-4.41) or be capped at hold (-3.41, -3.91). That reading is written into CLAUDE.md C4 and C7 and needs your confirmation.
3. **Benign outcomes now rest on the roles being right.** A backup job, scanner or patch tool without the explicit allowance is the same story as the no-label S19, S18 and S20 variants: a block. Contract learning mode (Phase 2) has to propose these allowances.
4. **S49 holds because the installer's role has no contract.** The same story under a role with `may_persist: false` (for example `package_installer`) would add a persist violation and block (0.8 + 3.5 + 2.5 = 6.8). The role is part of the scenario definition. The unsigned counterpart blocks (-2.11), so the signature is what separates hold from block.
5. **A missing `signed` counts as unsigned (my reading, in C4).** A sensor that cannot check signatures turns every launch of an externally labeled file into a Contract signal.
6. **The gate now needs a Contract signal that exists for every family.** With D19-D21 the "—" entries in C13 are gone for ransomware, lateral movement, log tampering, memory leaks, USB, and installers. S05 and S22 are the known gaps that remain without one, as intended.

### After check 3: how its findings were settled

1. Finding 1: the S18, S19 and S20 no-label variants now expect block, consistent with D22.
2. Finding 2: confirmed with a refinement, D23 (an allowance removes the Effect only in a story with no external origin label), with the new scenario S50.
3. Finding 5: replaced. A missing `signed` is `unknown` and raises no signal, instead of counting as unsigned.

## Catalog check 4 (confirms the clarifications changed nothing else)

Same weights and rules as check 3; no weight or rule was changed. The only differences from check 3 are the expectations listed above and the new row S50. The run asserts, row by row, that every row from check 3 gives the same L and the same decision: 42 rows identical, 1 new, none differing from its expectation. Prior -6.91, block threshold -3.91, hold threshold -4.94, every strength 1.0.

| Scenario | Variant | L | Decision | Expected | Result | Reason |
|---|---|---|---|---|---|---|
| S01-S04 |  | -2.61 | block | block | ok | origin 0.8 + contract 1 + effect 2.5 = 4.3; L -2.61 >= block -3.91 |
| S05 | typed, no label | -4.41 | hold | hold | ok | effect 2.5 = 2.5; L -4.41 in [-4.94, -3.91) |
| S06 | delayed run, Contract evidence carried (D21) | -2.61 | block | block | ok | origin 0.8 + contract 1 + effect 2.5 = 4.3; L -2.61 >= block -3.91 |
| S07 |  | -2.61 | block | block | ok | origin 0.8 + contract 1 + effect 2.5 = 4.3; L -2.61 >= block -3.91 |
| S08 | canary override | - | block | block | ok | override: canary -> block |
| S09 | trusted root override | - | allow | allow | ok | override: trusted_root -> allow |
| S10 |  | -6.91 | allow | allow | ok | no signals = 0.0; L -6.91 < hold -4.94 |
| S11 |  | -5.11 | allow | allow | ok | origin 0.8 + contract 1 = 1.8; L -5.11 < hold -4.94 |
| S12 |  | -2.61 | block | block | ok | origin 0.8 + contract 1 + effect 2.5 = 4.3; L -2.61 >= block -3.91 |
| S13 |  | -0.61 | block | block | ok | origin 0.8 + contract 3 + effect 2.5 = 6.3; L -0.61 >= block -3.91 |
| S14 |  | -0.11 | block | block | ok | origin 0.8 + contract 3.5 + effect 2.5 = 6.8; L -0.11 >= block -3.91 |
| S15 |  | -1.11 | block | block | ok | origin 0.8 + contract 2.5 + effect 2.5 = 5.8; L -1.11 >= block -3.91 |
| S17 | with initial-access label | -0.11 | block | block | ok | origin 0.8 + contract 3.5 + effect 2.5 = 6.8; L -0.11 >= block -3.91 |
| S17 | no label (Phase 7 variant) | -0.91 | block | block | ok | contract 3.5 + effect 2.5 = 6.0; L -0.91 >= block -3.91 |
| S18 | with initial-access label | -0.61 | block | block | ok | origin 0.8 + contract 2 + effect 3.5 = 6.3; L -0.61 >= block -3.91 |
| S18 | no label (Phase 7 variant) | -1.41 | block | block | ok | contract 2 + effect 3.5 = 5.5; L -1.41 >= block -3.91 |
| S19 | with initial-access label | -1.61 | block | block | ok | origin 0.8 + contract 2 + effect 2.5 = 5.3; L -1.61 >= block -3.91 |
| S19 | no label (Phase 7 variant) | -2.41 | block | block | ok | contract 2 + effect 2.5 = 4.5; L -2.41 >= block -3.91 |
| S20 | with initial-access label | -1.11 | block | block | ok | origin 0.8 + contract 2 + effect 3 = 5.8; L -1.11 >= block -3.91 |
| S20 | no label (Phase 7 variant) | -1.91 | block | block | ok | contract 2 + effect 3 = 5.0; L -1.91 >= block -3.91 |
| S21 |  | 0.89 | block | block | ok | origin 0.8 + contract 3.5 + effect 3.5 = 7.8; L 0.89 >= block -3.91 |
| S22 | exfil volume only | -4.41 | hold | known gap | known gap | effect 2.5 = 2.5; L -4.41 in [-4.94, -3.91) |
| S23 |  | -6.11 | allow | allow | ok | origin 0.8 = 0.8; L -6.11 < hold -4.94 |
| S24 | trusted root override | - | allow | allow | ok | override: trusted_root -> allow |
| S25 | child process only | -3.11 | block | block | ok | origin 0.8 + contract 3 = 3.8; L -3.11 >= block -3.91 |
| S26a | non-executable write | -5.11 | allow | allow | ok | origin 0.8 + contract 1 = 1.8; L -5.11 < hold -4.94 |
| S26b | outbound connection | -1.11 | block | block | ok | origin 0.8 + contract 2.5 + effect 2.5 = 5.8; L -1.11 >= block -3.91 |
| S26c | executable write | -0.11 | block | block | ok | origin 0.8 + contract 3.5 + effect 2.5 = 6.8; L -0.11 >= block -3.91 |
| S27 | first anomalous response | -4.61 | hold | hold | ok | origin 0.8 + effect 1.5 = 2.3; L -4.61 in [-4.94, -3.91) |
| S27 | repeated, Poisson-significant | -0.61 | block | block | ok | origin 0.8 + contract 2 + effect 3.5 = 6.3; L -0.61 >= block -3.91 |
| S30 | allowlisted child | -6.11 | allow | allow | ok | origin 0.8 = 0.8; L -6.11 < hold -4.94 |
| S31 |  | -1.11 | block | block | ok | origin 0.8 + contract 2.5 + effect 2.5 = 5.8; L -1.11 >= block -3.91 |
| S32 | unsigned program from removable media | -2.11 | block | block | ok | origin 0.8 + contract 1.5 + effect 2.5 = 4.8; L -2.11 >= block -3.91 |
| S33 | unsigned fake installer | -2.11 | block | block | ok | origin 0.8 + contract 1.5 + effect 2.5 = 4.8; L -2.11 >= block -3.91 |
| S34 | protected asset override | - | block | block | ok | override: protected_asset -> block |
| S35 | unsigned file from a link | -2.11 | block | block | ok | origin 0.8 + contract 1.5 + effect 2.5 = 4.8; L -2.11 >= block -3.91 |
| S36 | print helper in reader contract | -6.11 | allow | allow | ok | origin 0.8 = 0.8; L -6.11 < hold -4.94 |
| S37 | trusted root override | - | allow | allow | ok | override: trusted_root -> allow |
| S46 | backup job, role allows mass change | -6.91 | allow | allow | ok | no signals = 0.0; L -6.91 < hold -4.94 |
| S47 | vulnerability scanner, role allows fan-out | -6.91 | allow | allow | ok | no signals = 0.0; L -6.91 < hold -4.94 |
| S48 | patch tool, role allows tampering | -6.91 | allow | allow | ok | no signals = 0.0; L -6.91 < hold -4.94 |
| S49 | signed vendor installer persists | -3.61 | hold | hold | ok | origin 0.8 + effect 2.5 = 3.3; L -3.61 crosses block but no Contract signal, capped at hold |
| S50 | allowed backup role, story has an external origin label | -3.61 | hold | hold | ok | origin 0.8 + effect 2.5 = 3.3; L -3.61 crosses block but no Contract signal, capped at hold |

S08, S34 (block) and S09, S24, S37 (allow) are overrides and bypass the calculus. S22 is a documented known gap. **The structural rules and weights are frozen from here.**

### What the clarifications hang on (not catalog rows)

| Scenario | Variant | L | Decision | Reading |
|---|---|---|---|---|
| S46 | no label: Effect still fires for an allowed role | -4.41 | hold | effect 2.5 = 2.5; L -4.41 in [-4.94, -3.91) |
| S47 | no label: Effect still fires for an allowed role | -3.41 | hold | effect 3.5 = 3.5; L -3.41 crosses block but no Contract signal, capped at hold |
| S48 | no label: Effect still fires for an allowed role | -3.91 | hold | effect 3 = 3.0; L -3.91 crosses block but no Contract signal, capped at hold |
| S50 | allowance void in a labeled story (Contract signal too) | -1.61 | block | origin 0.8 + contract 2 + effect 2.5 = 5.3; L -1.61 >= block -3.91 |
| S49 | same installer, unsigned | -2.11 | block | origin 0.8 + contract 1.5 + effect 2.5 = 4.8; L -2.11 >= block -3.91 |
| S32 | signed = unknown (no D20 signal) | -3.61 | hold | origin 0.8 + effect 2.5 = 3.3; L -3.61 crosses block but no Contract signal, capped at hold |
| S33 | signed = unknown (no D20 signal) | -3.61 | hold | origin 0.8 + effect 2.5 = 3.3; L -3.61 crosses block but no Contract signal, capped at hold |
| S35 | signed = unknown (no D20 signal) | -3.61 | hold | origin 0.8 + effect 2.5 = 3.3; L -3.61 crosses block but no Contract signal, capped at hold |

Reading the table:

- **S46-S48 without a label** would hold if the Effect still fired for an allowed role; D23 is why they are allowed.
- **S50** blocks if an allowance were void in a labeled story (Contract signal raised too). The expected hold fixes D23 as "allowance removes the Contract signal always, the Effect only without a label".
- **S49** blocks if the installer were unsigned: the signature is what separates hold from block.
- **S32, S33, S35 with `signed` unknown** are capped at hold, not blocked, because no Contract signal exists. That is the missing-information principle working as designed: a sensor that cannot check signatures downgrades these three, and says so in its heartbeat as degraded protection.
