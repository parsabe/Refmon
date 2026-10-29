# Results

Everything below is a **replay** result: event streams written by hand as harmless stand-ins for 46
scenarios (27 malicious, 19 benign) and mutations of them, run through the pipeline. Nothing was
measured on a real sensor, a real platform or real users (Phase 8 was not run; see
[phase-8-plan.md](phase-8-plan.md)). Read the numbers as *robustness of the rules to mutation*, not
as detection rates on real attacks.

The blocks marked GENERATED are rewritten by `make reproduce` ([scripts/reproduce.py](../scripts/reproduce.py));
the text around them is written by hand and refers to them rather than repeating their numbers.
Earlier evaluations on retired seeds are listed at the end.

## 1. Versions

<!-- BEGIN GENERATED: versions -->
| tag | commit | |
|---|---|---|
| v1.0 | d9ac319 | the frozen state after Phase 7 |
| v1.1 | 1147d62 | F1 to F4: external command, hold fallback, role-scoped trust, hour window |
| v1.2 | c141ffb | F5 to F7: channel roles out of the fallback, no-label blocks act, seeded numbers |
| v1.3 | 0f71182 | F8 and F9: monotone calculus, benign variants |
<!-- END GENERATED: versions -->

`v1.0` is frozen. Each later tag changes structural rules in response to the findings of the
evaluation before it, and is measured on a seed recorded before the change
([variant-seeds.md](variant-seeds.md)). The weights of CLAUDE.md C11 never changed.

## 2. Generated variants, v1.0 to v1.3

Each of the 27 malicious golden files and each of the 19 benign ones is mutated along six
dimensions (delivery, entry, obfuscation, destination, lineage, timing), one level at a time and in
twelve seeded combinations, with the numbers of a variant (gaps between events, entropy, whitespace
run) drawn from the seed. The same file of variants is replayed in every version, and the event
streams are hashed to prove it.

Malicious variants are **block**, **effective hold** (the Gate paused or quarantined something) or
**uncontained** (allow, or a hold that pauses nothing). Benign variants are **allow**, **hold** or
**block**. A benign variant expects the decision of its unmodified file unless the generator
labelled, before any replay, its mutation as adding a Contract violation or an Effect (the rules are
in [variant-seeds.md](variant-seeds.md)); the **neutral** variants are the false-alarm test.

<!-- BEGIN GENERATED: matrix -->
Seed 654514256; sha256 of the generated variants file `5c3fcbebea616806a8a9de877679d0587441d7cff11d9939b3b1b8cb49927134`.

879 variants, identical event streams in every run (hash checked).

## Malicious variants

**All**

| | v1.0 | v1.1 | v1.2 | v1.3 |
|---|---:|---:|---:|---:|
| variants | 633 | 633 | 633 | 633 |
| block | 425 | 467 | 467 | 486 |
| effective hold | 121 | 157 | 157 | 139 |
| uncontained (allow + hold pauses nothing) | 87 | 9 | 9 | 8 |
| - allow | 18 | 9 | 9 | 8 |
| - hold pauses nothing | 69 | 0 | 0 | 0 |
| blocks that act on nothing | 11 | 9 | 0 | 0 |

**Variants the seed decides (322): the independent test**

| | v1.0 | v1.1 | v1.2 | v1.3 |
|---|---:|---:|---:|---:|
| variants | 322 | 322 | 322 | 322 |
| block | 182 | 207 | 207 | 226 |
| effective hold | 87 | 106 | 106 | 88 |
| uncontained (allow + hold pauses nothing) | 53 | 9 | 9 | 8 |
| - allow | 16 | 9 | 9 | 8 |
| - hold pauses nothing | 37 | 0 | 0 | 0 |
| blocks that act on nothing | 6 | 4 | 0 | 0 |

**Variants that are the same for every seed (311): a regression check, not fresh evidence**

| | v1.0 | v1.1 | v1.2 | v1.3 |
|---|---:|---:|---:|---:|
| variants | 311 | 311 | 311 | 311 |
| block | 243 | 260 | 260 | 260 |
| effective hold | 34 | 51 | 51 | 51 |
| uncontained (allow + hold pauses nothing) | 34 | 0 | 0 | 0 |
| - allow | 2 | 0 | 0 | 0 |
| - hold pauses nothing | 32 | 0 | 0 | 0 |
| blocks that act on nothing | 5 | 5 | 0 | 0 |

## Benign variants

**Benign, neutral (151)**

| | v1.0 | v1.1 | v1.2 | v1.3 |
|---|---:|---:|---:|---:|
| variants | 151 | 151 | 151 | 151 |
| allow | 126 | 126 | 126 | 125 |
| hold | 22 | 22 | 22 | 23 |
| block | 3 | 3 | 3 | 3 |
| block rate (the false block rate for neutral variants) | 2.0% | 2.0% | 2.0% | 2.0% |
| worse than the unmodified file | 5 | 5 | 5 | 5 |

**Benign, adds a contract violation (55)**

| | v1.0 | v1.1 | v1.2 | v1.3 |
|---|---:|---:|---:|---:|
| variants | 55 | 55 | 55 | 55 |
| allow | 17 | 17 | 17 | 17 |
| hold | 8 | 6 | 6 | 4 |
| block | 30 | 32 | 32 | 34 |
| block rate (the false block rate for neutral variants) | 54.5% | 58.2% | 58.2% | 61.8% |
| worse than the unmodified file | 0 | 0 | 0 | 0 |

**Benign, adds an effect (40)**

| | v1.0 | v1.1 | v1.2 | v1.3 |
|---|---:|---:|---:|---:|
| variants | 40 | 40 | 40 | 40 |
| allow | 1 | 1 | 1 | 0 |
| hold | 34 | 34 | 34 | 35 |
| block | 5 | 5 | 5 | 5 |
| block rate (the false block rate for neutral variants) | 12.5% | 12.5% | 12.5% | 12.5% |
| worse than the unmodified file | 0 | 0 | 0 | 0 |

**All benign variants**

| | v1.0 | v1.1 | v1.2 | v1.3 |
|---|---:|---:|---:|---:|
| variants | 246 | 246 | 246 | 246 |
| allow | 144 | 144 | 144 | 142 |
| hold | 64 | 62 | 62 | 62 |
| block | 38 | 40 | 40 | 42 |
| block rate (the false block rate for neutral variants) | 15.4% | 16.3% | 16.3% | 17.1% |
| worse than the unmodified file | 5 | 5 | 5 | 5 |
<!-- END GENERATED: matrix -->

### Rates with intervals, and version comparisons

<!-- BEGIN GENERATED: stats -->
| rate (Wilson 95 % interval) | v1.0 | v1.1 | v1.2 | v1.3 |
|---|---:|---:|---:|---:|
| malicious variants caught (block or hold) | 615/633 = 97.2% [95.6%, 98.2%] | 624/633 = 98.6% [97.3%, 99.3%] | 624/633 = 98.6% [97.3%, 99.3%] | 625/633 = 98.7% [97.5%, 99.4%] |
| malicious variants blocked | 425/633 = 67.1% [63.4%, 70.7%] | 467/633 = 73.8% [70.2%, 77.1%] | 467/633 = 73.8% [70.2%, 77.1%] | 486/633 = 76.8% [73.3%, 79.9%] |
| malicious variants contained (block or effective hold) | 546/633 = 86.3% [83.4%, 88.7%] | 624/633 = 98.6% [97.3%, 99.3%] | 624/633 = 98.6% [97.3%, 99.3%] | 625/633 = 98.7% [97.5%, 99.4%] |
| neutral benign variants blocked (false block rate) | 3/151 = 2.0% [0.7%, 5.7%] | 3/151 = 2.0% [0.7%, 5.7%] | 3/151 = 2.0% [0.7%, 5.7%] | 3/151 = 2.0% [0.7%, 5.7%] |

McNemar's exact test on the same malicious variants (only first / only second = variants that only the first / only the second version gets right):

| comparison | metric | only first | only second | p |
|---|---|---:|---:|---:|
| v1.0 vs v1.3 | caught | 0 | 10 | 0.002 |
| v1.0 vs v1.3 | contained | 0 | 79 | 3.3e-24 |
| v1.0 vs v1.3 | blocked | 0 | 61 | 8.7e-19 |
| v1.0 vs v1.1 | caught | 0 | 9 | 0.0039 |
| v1.0 vs v1.1 | contained | 0 | 78 | 6.6e-24 |
| v1.0 vs v1.1 | blocked | 2 | 44 | 3.1e-11 |
| v1.2 vs v1.3 | caught | 0 | 1 | 1 |
| v1.2 vs v1.3 | contained | 0 | 1 | 1 |
| v1.2 vs v1.3 | blocked | 0 | 19 | 3.8e-06 |
<!-- END GENERATED: stats -->

The Wilson intervals treat variants as independent. They are not: the variants of one scenario are
correlated, so the intervals understate the uncertainty. McNemar's test is paired on the same
variants.

## 3. The golden catalog

A scenario reaches its expected `decision` in every version where its cell is not bold. S05 (a
command typed by hand) and S22 (abuse of the application's own database connection) are the two
catalog scenarios that are known gaps by design, and their expected decision is the hold or the
partial detection the specification names.

<!-- BEGIN GENERATED: golden -->
| scenario | kind | expected | v1.0 | v1.1 | v1.2 | v1.3 |
|---|---|---|---|---|---|---|
| S01 | malicious | block | block | block | block | block |
| S02 | malicious | block | block | block | block | block |
| S03 | malicious | block | block | block | block | block |
| S04 | malicious | block | block | block | block | block |
| S05 | malicious | hold | hold | hold | hold | hold |
| S06 | malicious | block | block | block | block | block |
| S07 | malicious | block | block | block | block | block |
| S08 | malicious | block | block | block | block | block |
| S09 | benign | allow | allow | allow | allow | allow |
| S10 | benign | allow | allow | allow | allow | allow |
| S11 | benign | allow | allow | allow | allow | allow |
| S12 | malicious | block | block | block | block | block |
| S13 | malicious | block | block | block | block | block |
| S14 | malicious | block | block | block | block | block |
| S15 | malicious | block | block | block | block | block |
| S17 | malicious | block | block | block | block | block |
| S18 | malicious | block | block | block | block | block |
| S19 | malicious | block | block | block | block | block |
| S20 | malicious | block | block | block | block | block |
| S21 | malicious | block | block | block | block | block |
| S22 | malicious | hold | hold | hold | hold | hold |
| S23 | benign | allow | allow | allow | allow | allow |
| S24 | benign | allow | allow | allow | allow | allow |
| S25 | malicious | block | block | block | block | block |
| S26a | benign | allow | allow | allow | allow | allow |
| S26b | malicious | block | block | block | block | block |
| S26c | malicious | block | block | block | block | block |
| S27 | malicious | block | block | block | block | block |
| S30 | benign | allow | allow | allow | allow | allow |
| S31 | malicious | block | block | block | block | block |
| S32 | malicious | block | block | block | block | block |
| S33 | malicious | block | block | block | block | block |
| S34 | malicious | block | block | block | block | block |
| S35 | malicious | block | block | block | block | block |
| S36 | benign | allow | allow | allow | allow | allow |
| S37 | benign | allow | allow | allow | allow | allow |
| S38 | benign | allow | allow | allow | allow | allow |
| S39 | benign | allow | allow | allow | allow | allow |
| S40 | benign | allow | allow | allow | allow | allow |
| S44 | benign | allow | allow | allow | allow | allow |
| S45 | benign | allow | allow | allow | allow | allow |
| S46 | benign | allow | allow | allow | allow | allow |
| S47 | benign | allow | allow | allow | allow | allow |
| S48 | benign | allow | allow | allow | allow | allow |
| S49 | benign | hold | hold | hold | hold | hold |
| S50 | benign | hold | hold | hold | hold | hold |

| | v1.0 | v1.1 | v1.2 | v1.3 |
|---|---:|---:|---:|---:|
| scenarios reaching the expected `decision` (of 46) | 46 | 46 | 46 | 46 |
| same `decision` as v1.0 | 46 | 46 | 46 | 46 |
<!-- END GENERATED: golden -->

## 4. Coverage map

Every attack family keeps at least one malicious and one benign scenario (CLAUDE.md C13).

<!-- BEGIN GENERATED: coverage -->
| attack family | malicious | benign |
|---|---|---|
| ClickFix, TerminalFix, FileFix (pasted commands) | S01✓, S02✓, S03✓, S04✓, S06✓, S07✓ | S11✓ |
| Commands typed from videos or phone calls | S05✓ | S10✓ |
| Malicious attachments and macro documents | S31✓ | S36✓ |
| USB and removable media | S32✓ | S38✓ |
| Fake installers, trojanized software, drive-by downloads | S33✓, S35✓ | S37✓, S49✓ |
| Infostealers and credential theft | S08✓, S34✓ | S39✓ |
| Poisoned packages and supply chain | S21✓ | S09✓ |
| Server RCE: PHP2Shell, Node2Shell, future zero-days | S13✓, S25✓, S26b✓, S26c✓ | S23✓, S26a✓, S30✓ |
| Web shells | S14✓ | S24✓ |
| Memory-leak stages | S27✓ | S23✓ |
| Privilege escalation | S17✓ | S40✓ |
| Lateral movement | S18✓ | S47✓ |
| Ransomware | S19✓ | S46✓, S50✓ |
| Defense evasion, log tampering | S20✓ | S48✓ |
| Data theft | S22✓ | S44✓ |
| AI agents running injected instructions | S12✓ | S45✓ |
| Unpatched, workaround-only and end-of-life software | S16✓, S28✓, S29✓ | - |

✓ the scenario reaches its expected `decision` in v1.3 (S16, S28 and S29 are policy-over-time tests in tests/test_phase5_exposure.py).
<!-- END GENERATED: coverage -->

## 5. Privacy audit

The audit scans every output (verdicts, actions, notices, reports, stories, labels, buffered events,
suggestions, proposals and the committed golden files) for raw content, attacks the fingerprints
with a dictionary of common commands and URL paths (and, as a control, with the real key, to show
that the attack code works), and tries to re-identify pseudonyms without and with four-eyes
approval.

<!-- BEGIN GENERATED: audit -->
```
Privacy audit
  strings scanned          264
  raw content findings     0
  fingerprints attacked    349
  reversal attempts        2119
  reversals                0
  control (key known)      6 reversed (attack code works)
  re-identification tries  10
  without four-eyes: ok    0
  two approvers: ok        True
  audit chain intact       True
  result                   PASS
```
<!-- END GENERATED: audit -->

## 6. Tests

<!-- BEGIN GENERATED: tests -->
`1621 passed, 1 xfailed`
<!-- END GENERATED: tests -->

The suite includes property tests (labels never lost along process chains, no raw content in any
output, an event a contract allows never counts as a Contract fail, Contain never touches an
unlabeled object except the documented fallback, and that a label that fades faster never gives a
story a higher log-odds, which fails on the v1.2 source). The remaining expected failure is the
slow-and-low burst of G2.

## 7. Known gaps G1 to G3

The malicious variants still allowed in v1.3 (documented in
[tests/variants/known_gaps.yaml](../tests/variants/known_gaps.yaml); a variant that is allowed and
not documented fails CI).

| id | finding | what is allowed | why |
|---|---|---|---|
| G1 | F2 | a payload to a trusted host when the actor carries no label (a launcher entry, or a label that decayed between the events) | a trusted destination class still excuses a process without a label (A48); the answer is a narrow list of trusted classes |
| G2 | F3 | ransomware stand-in with minutes between file changes | the hour-scale window works (60 distinct files in an hour), but the stand-in changes 55 files in all, so no spacing reaches the threshold |
| G3 | F3 | the same with events further apart than the story quiet window | one change per story, no Contract evidence ever freezes the label |

A lower long-window baseline would catch G2 and G3. It would be fitted to those stand-ins, so it is
left to a pilot (A29, A49). The two catalog gaps S05 and S22 are not G-entries: they are in the
specification (C12).

## 8. Design findings F1 to F10

Found by running the matrix, recorded each time, fixed in the version named or left open.

| # | Finding | Handling |
|---|---|---|
| F1 | A hold on a story with no labeled process paused nothing (Contain is labeled-only) | v1.1 (A47): it pauses the processes that produced the signals |
| F2 | `fetch` did not fire for a trusted destination class, so a payload or C2 channel on a popular host passed the Effect question | v1.1 (A48): trust is role-scoped for labeled processes; residual: G1 |
| F3 | Slow-and-low evades the windowed burst and repeat tests, and the request label decays before the effect | v1.1 (A49): evidence-carrying labels do not decay, hour-scale window; v1.3 also closes the slow leak (S27); residual: G2, G3 |
| F4 | The Contract signal for a pasted command depended on the role that ran it | v1.1 (A46): universal for labeled command text |
| F5 | The hold fallback paused a launcher that stayed paused after the story became a block | v1.2 (A51): channel roles are never in the fallback |
| F6 | A block on a story with no labeled process acted on nothing | v1.2 (A52): it acts on the producers of the signals when the story has no origin label either |
| F7 | Only the seeded combinations depended on the seed, so the one-factor variants were not fresh evidence | v1.2 (A54): the seed draws the numbers of every variant |
| F8 | The calculus was not monotone in label strength: a weaker label could give stronger evidence (two variants were worse in v1.1 and v1.2 than in v1.0) | v1.3 (A55): a behavioural signal counts at full strength; C11.4 updated; a property test fails on v1.2 and passes on v1.3 |
| F9 | Benign variants were not generated | v1.3 (A56): 246 benign variants, labelled by the generator before any replay |
| F10 | The trusted-source override covers one story: an installer or a deployment whose steps are further apart than the story quiet window loses the trusted flag at its persistence step (S37 blocks, S24 holds; the neutral false blocks of the table above) | **open**, recorded |

## 9. Limitations

1. **Replay only.** The evaluation runs event streams through the pipeline. There is no real sensor,
   no real platform and no live traffic; latency, overhead and memory (including the memory cost of
   the self-test copy, A38) are unmeasured. Phase 8 needs an isolated lab with root; the environment
   used here has neither (docs/phase-8-plan.md).
2. **Self-made scenarios.** The 46 scenarios and every variant are written or generated by the same
   people who wrote the rules. The variants test robustness to six kinds of mutation of those
   scenarios, not independent attacks. The headline rates are not detection rates on real malware.
3. **Expert baselines and weights.** The weights are expert defaults (docs/weights-proposal.md), and
   the Poisson baselines (three events per window, 0.01 oversized responses), the long-window
   baselines (ten times those, A49), the exfil baseline and the cost ratios are expert estimates, not
   estimated from traffic (A29). They must be re-estimated in a pilot before any rate is read as a
   rate per user or per server per week (C10).
4. **Small catalogs, correlated variants.** 19 benign scenarios and 246 benign variants say little
   about the false-alarm rate of a real workload; the confidence intervals above assume independence
   that the variants do not have.
5. **Known gaps by design (C12).** S05 (a command typed by hand has no label, so a hold is the best
   it can do), S22 (abuse of an application's own allowed connection leaves only the exfil volume),
   content through unobserved channels (no label), and an attacker with full control of the host.
6. **Signed malware passes the launcher contract (D20).** A signed external file raises no
   `unsigned_external_exec` signal, and a sensor that cannot check signatures reports `unknown`,
   which raises none either (missing information never generates evidence; the heartbeat reports the
   degraded protection).
7. **The trusted-root override.** A story that starts from a trusted source is allowed whatever it
   does next (the labelled S09 variants that connect to an unknown host stay allowed), and the
   override covers one story (F10).
8. **A lone external-command signal is allowed.** Origin and the external-content Contract signal
   alone are 1.8 nats, L = -5.11 (the verdict of S11, a developer copying a documented command), so
   a pasted command that does nothing else is not alerted on, whatever role runs it.
9. **Slow and low.** Behaviour below the rate baselines passes (G2, G3); CUSUM covers volume only.
10. **Fallback containment touches unlabeled processes.** v1.1 to v1.3 pause (and, on stop or a
    block without an origin label, stop) processes that produced a signal but carry no label, never
    a channel role. It is the only exception to "labeled-only", it was measured only in the
    simulated enforcer, and a real `SIGSTOP` of an unlabeled process can break a program that holds
    a lock or a connection.
11. **The privacy audit is a scan of this repository's own outputs.** It cannot prove that a real
    deployment leaks nothing. Fingerprints are keyed per device; the test key
    (`refmon-device-key`) is a constant used by the tests and the golden files, and the audit shows
    that a guessable key is reversible (that is what the control row is for).
12. **Structural changes are evaluated on new seeds, but on the same scenario families.** Each
    version's gain is measured on fresh mutations of the same 46 scenarios.

## 10. Decisions before publishing

The repository was checked for secrets, personal data and raw content (the block below is
regenerated; `make publishable` runs it alone). The content is clean. These are for the owner:

1. **Git identity.** Every commit carries an author and committer name and e-mail address. The
   history records two identities with one e-mail address, one of them the login name of the
   cluster account the work was done on, and the tag `backup-before-author-rewrite` points at the
   history before an earlier rewrite. Publishing the history publishes them. Options: publish
   as is; rewrite with `git filter-repo --mailmap` (and delete the backup tag); or publish a
   squashed export of the final tree. Nothing was rewritten or pushed.
2. **Licence.** None has been chosen; the repository has no LICENSE file.
3. **Which tags to publish.** `phase-1-done` to `phase-7-done`, `v1.0` to `v1.3`. `make reproduce`
   needs `v1.0` to `v1.3`.
4. **CLAUDE.md.** It is the specification, written as a prompt file for the coding agent, and the
   tests read the weights and the coverage map from it. Keep it, or rename it and update the places
   that read it (`tests/test_phase1_golden.py`, `tests/test_phase4b_golden.py`,
   `tests/test_phase5_exposure.py`, `tests/test_phase7_robustness.py` and `scripts/reproduce.py`).
5. **Wording of the claims.** The results are replay-only (limitation 1); say so wherever they are
   quoted.

<!-- BEGIN GENERATED: publishable -->
```
tracked files scanned: 243, history: every ref
findings in the working tree: 0
findings in the history (added lines of every commit of every ref): 0
replay events checked as post-Observe events: 378, rejected: 0
identities recorded by git as author or committer: 2 (masked here so that this output can be published)
  p***e <p***9@g***l.com>
  p***u <p***9@g***l.com>
content: CLEAN
identities: present in the history, the owner decides before publishing
```
<!-- END GENERATED: publishable -->

## 11. Earlier evaluations (retired seeds)

Kept as a record; they are not regenerated, because the generator of those seeds differed (the seed
drew only the combinations before v1.2) and the benign variants did not exist.

| seed | versions | report | data |
|---|---|---|---|
| 20261029 | v1.0 (Phase 7) | [progress.md](progress.md), Phase 7 | `build/` (not kept) |
| 268805905 | v1.0, v1.1 | [v1.1-evaluation.md](v1.1-evaluation.md) | [docs/evaluation/](evaluation/) |
| 892499628 | v1.0, v1.1, v1.2 | [v1.2-evaluation.md](v1.2-evaluation.md) | [docs/evaluation/](evaluation/) |
| 654514256 | v1.0 to v1.3, malicious and benign | [v1.3-evaluation.md](v1.3-evaluation.md) | [docs/evaluation/](evaluation/) |
