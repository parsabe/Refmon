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
| v1.7 | d77b756 | A60 to A64: lineage-aware trust, incidents end, bounded state, producers act, every live label handed over |
| v2.0 | 0bdf46c | A65, A66: trust as lineage (F10), relay containment |
<!-- END GENERATED: versions -->

`v1.0` is frozen. Each later version changes structural rules in response to the findings of the
evaluation before it, and is measured on a seed recorded before the change
([variant-seeds.md](variant-seeds.md)). The weights of CLAUDE.md C11 never changed.

The tables below are those of the active seed, which was recorded to evaluate v1.7 and v2.0. The tags
`v1.7` and `v2.0` hold the code of those versions: `make reproduce` replays the variants in each and
checks the result against the committed per-variant data in [evaluation/](evaluation/), and it was
identical. The code of v1.0 to v1.6 was lost when the history was squashed, so those versions
have no tags (tags `v1.0` to `v1.3` that had been put on unrelated commits were deleted on
2026-11-02, and the reproduction refuses a tag without its version's code); their evaluations on
retired seeds are kept as a record in section 11.

## 2. Generated variants, v1.7 and v2.0 (active seed)

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
Seed 171139148; sha256 of the generated variants file `841cf30ebc7b1fdcf5a0192c7ad96819dc961444bbc1e5e7a1f862e5d24440b5`.

886 variants, identical event streams in every run (hash checked).

## Malicious variants

**All**

| | v1.7 | v2.0 |
|---|---:|---:|
| variants | 635 | 635 |
| block | 483 | 483 |
| effective hold | 142 | 142 |
| uncontained (allow + hold pauses nothing) | 10 | 10 |
| - allow | 10 | 10 |
| - hold pauses nothing | 0 | 0 |
| blocks that act on nothing | 0 | 0 |

**Variants the seed decides (324): the independent test**

| | v1.7 | v2.0 |
|---|---:|---:|
| variants | 324 | 324 |
| block | 223 | 223 |
| effective hold | 91 | 91 |
| uncontained (allow + hold pauses nothing) | 10 | 10 |
| - allow | 10 | 10 |
| - hold pauses nothing | 0 | 0 |
| blocks that act on nothing | 0 | 0 |

**Variants that are the same for every seed (311): a regression check, not fresh evidence**

| | v1.7 | v2.0 |
|---|---:|---:|
| variants | 311 | 311 |
| block | 260 | 260 |
| effective hold | 51 | 51 |
| uncontained (allow + hold pauses nothing) | 0 | 0 |
| - allow | 0 | 0 |
| - hold pauses nothing | 0 | 0 |
| blocks that act on nothing | 0 | 0 |

## Benign variants

**Benign, neutral (158)**

| | v1.7 | v2.0 |
|---|---:|---:|
| variants | 158 | 158 |
| allow | 132 | 137 |
| hold | 24 | 21 |
| block | 2 | 0 |
| block rate (the false block rate for neutral variants) | 1.3% | 0.0% |
| worse than the unmodified file | 5 | 0 |

**Benign, adds a contract violation (50)**

| | v1.7 | v2.0 |
|---|---:|---:|
| variants | 50 | 50 |
| allow | 17 | 17 |
| hold | 3 | 3 |
| block | 30 | 30 |
| block rate (the false block rate for neutral variants) | 60.0% | 60.0% |
| worse than the unmodified file | 0 | 0 |

**Benign, adds an effect (43)**

| | v1.7 | v2.0 |
|---|---:|---:|
| variants | 43 | 43 |
| allow | 0 | 0 |
| hold | 38 | 38 |
| block | 5 | 5 |
| block rate (the false block rate for neutral variants) | 11.6% | 11.6% |
| worse than the unmodified file | 0 | 0 |

**All benign variants**

| | v1.7 | v2.0 |
|---|---:|---:|
| variants | 251 | 251 |
| allow | 149 | 154 |
| hold | 65 | 62 |
| block | 37 | 35 |
| block rate (the false block rate for neutral variants) | 14.7% | 13.9% |
| worse than the unmodified file | 5 | 0 |
<!-- END GENERATED: matrix -->

### Rates with intervals, and version comparisons

<!-- BEGIN GENERATED: stats -->
| rate (Wilson 95 % interval) | v1.7 | v2.0 |
|---|---:|---:|
| malicious variants caught (block or hold) | 625/635 = 98.4% [97.1%, 99.1%] | 625/635 = 98.4% [97.1%, 99.1%] |
| malicious variants blocked | 483/635 = 76.1% [72.6%, 79.2%] | 483/635 = 76.1% [72.6%, 79.2%] |
| malicious variants contained (block or effective hold) | 625/635 = 98.4% [97.1%, 99.1%] | 625/635 = 98.4% [97.1%, 99.1%] |
| neutral benign variants blocked (false block rate) | 2/158 = 1.3% [0.3%, 4.5%] | 0/158 = 0.0% [0.0%, 2.4%] |

McNemar's exact test on the same malicious variants (only first / only second = variants that only the first / only the second version gets right):

| comparison | metric | only first | only second | p |
|---|---|---:|---:|---:|
| v1.7 vs v2.0 | caught | 0 | 0 | 1 |
| v1.7 vs v2.0 | contained | 0 | 0 | 1 |
| v1.7 vs v2.0 | blocked | 0 | 0 | 1 |
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
| scenario | kind | expected | v1.7 | v2.0 |
|---|---|---|---|---|
| S01 | malicious | block | block | block |
| S02 | malicious | block | block | block |
| S03 | malicious | block | block | block |
| S04 | malicious | block | block | block |
| S05 | malicious | hold | hold | hold |
| S06 | malicious | block | block | block |
| S07 | malicious | block | block | block |
| S08 | malicious | block | block | block |
| S09 | benign | allow | allow | allow |
| S10 | benign | allow | allow | allow |
| S11 | benign | allow | allow | allow |
| S12 | malicious | block | block | block |
| S13 | malicious | block | block | block |
| S14 | malicious | block | block | block |
| S15 | malicious | block | block | block |
| S17 | malicious | block | block | block |
| S18 | malicious | block | block | block |
| S19 | malicious | block | block | block |
| S20 | malicious | block | block | block |
| S21 | malicious | block | block | block |
| S22 | malicious | hold | hold | hold |
| S23 | benign | allow | allow | allow |
| S24 | benign | allow | allow | allow |
| S25 | malicious | block | block | block |
| S26a | benign | allow | allow | allow |
| S26b | malicious | block | block | block |
| S26c | malicious | block | block | block |
| S27 | malicious | block | block | block |
| S30 | benign | allow | allow | allow |
| S31 | malicious | block | block | block |
| S32 | malicious | block | block | block |
| S33 | malicious | block | block | block |
| S34 | malicious | block | block | block |
| S35 | malicious | block | block | block |
| S36 | benign | allow | allow | allow |
| S37 | benign | allow | allow | allow |
| S38 | benign | allow | allow | allow |
| S39 | benign | allow | allow | allow |
| S40 | benign | allow | allow | allow |
| S44 | benign | allow | allow | allow |
| S45 | benign | allow | allow | allow |
| S46 | benign | allow | allow | allow |
| S47 | benign | allow | allow | allow |
| S48 | benign | allow | allow | allow |
| S49 | benign | hold | hold | hold |
| S50 | benign | hold | hold | hold |

| | v1.7 | v2.0 |
|---|---:|---:|
| scenarios reaching the expected `decision` (of 46) | 46 | 46 |
| same `decision` as v1.7 | 46 | 46 |
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

✓ the scenario reaches its expected `decision` in v2.0 (S16, S28 and S29 are policy-over-time tests in tests/test_phase5_exposure.py).
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
`1925 passed, 1 xfailed`
<!-- END GENERATED: tests -->

The suite includes property tests (labels never lost along process chains, no raw content in any
output, an event a contract allows never counts as a Contract fail, Contain never touches an
unlabeled object except the documented fallback, and that a label that fades faster never gives a
story a higher log-odds, which fails on the v1.2 source). The remaining expected failure is the
slow-and-low burst of G2.

## 7. Known gaps G1 to G5

The malicious variants still allowed in v2.0 on the active seed (documented in
[tests/variants/known_gaps.yaml](../tests/variants/known_gaps.yaml); a variant that is allowed and
not documented fails CI; details in [v2.0-evaluation.md](v2.0-evaluation.md)).

| id | finding | what is allowed | why |
|---|---|---|---|
| G1 | F2 | a connection to a trusted host by a process with no external lineage (a command typed by hand, a launcher entry, a label gone before the connection) | nothing in the lineage came from outside, so a trusted destination class excuses the connection; closing it means a trusted class excuses only roles whose contract lists it, a policy decision with a false-alarm cost |
| G2 | F3 | ransomware stand-in with minutes between file changes | the hour-scale window works (60 distinct files in an hour), but the stand-in changes 55 files in all, so no spacing reaches the threshold |
| G3 | F3 | the same with events further apart than the story quiet window | one change per story, no Contract evidence ever freezes the label |
| G4 | F3 | oversized responses (S27) further apart than the story quiet window | each lands in its own story with a decayed label, and at most two share the hour window, which the repeat test does not find significant |
| G5 | F3 | oversized responses (S27) minutes apart inside the quiet window | the faded label leaves the story 0.02 nats under the hold threshold |

A lower long-window baseline would catch G2 to G5. It would be fitted to those stand-ins, so it is
left to a pilot (A29, A49). The two catalog gaps S05 and S22 are not G-entries: they are in the
specification (C12).

## 8. Design findings F1 to F12

Found by running the matrix, recorded each time, fixed in the version named or left open.

| # | Finding | Handling |
|---|---|---|
| F1 | A hold on a story with no labeled process paused nothing (Contain is labeled-only) | v1.1 (A47): it pauses the processes that produced the signals |
| F2 | `fetch` did not fire for a trusted destination class, so a payload or C2 channel on a popular host passed the Effect question | v1.1 (A48): trust is role-scoped for labeled processes; v1.5 (A60): a trusted class excuses only a process with no live external lineage; residual: G1 |
| F3 | Slow-and-low evades the windowed burst and repeat tests, and the request label decays before the effect | v1.1 (A49): evidence-carrying labels do not decay, hour-scale window; v1.3 also closes the slow leak (S27); residual: G2 to G5 |
| F4 | The Contract signal for a pasted command depended on the role that ran it | v1.1 (A46): universal for labeled command text |
| F5 | The hold fallback paused a launcher that stayed paused after the story became a block | v1.2 (A51): channel roles are never in the fallback |
| F6 | A block on a story with no labeled process acted on nothing | v1.2 (A52): it acts on the producers of the signals when the story has no origin label either |
| F7 | Only the seeded combinations depended on the seed, so the one-factor variants were not fresh evidence | v1.2 (A54): the seed draws the numbers of every variant |
| F8 | The calculus was not monotone in label strength: a weaker label could give stronger evidence (two variants were worse in v1.1 and v1.2 than in v1.0) | v1.3 (A55): a behavioural signal counts at full strength; C11.4 updated; a property test fails on v1.2 and passes on v1.3 |
| F9 | Benign variants were not generated | v1.3 (A56): 246 benign variants, labelled by the generator before any replay |
| F10 | The trusted-source override covers one story: an installer or a deployment whose steps are further apart than the story quiet window loses the trusted flag at its persistence step (S37 blocks, S24 holds; the neutral false blocks of v1.7 in the table above) | v2.0 (A65): trust from a trusted root source is lineage, carried by the ingesting process and its children |
| F11 | A block with an external origin label but no labeled process acted on nothing (how a hold that timed out could end) | v1.6 (A63): it acts on the producers of its signals, sparing channel roles and the user's shell |
| F12 | The matrix did not count a kill as containment | corrected in the matrix for every version alike |

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
9. **Slow and low.** Behaviour below the rate baselines passes (G2 to G5); CUSUM covers volume only.
10. **Fallback containment touches unlabeled processes.** Since v1.1 the Gate pauses (and, on stop or a
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

1. **Git identity.** Every commit carries an author and committer name and e-mail address, one of
   them the login name of the cluster account the work was done on (the block below lists them
   masked). Publishing the history publishes them. Options: publish as is; rewrite with
   `git filter-repo --mailmap`; or publish a squashed export of the final tree.
2. **Licence.** GPL-3.0 (`LICENSE`).
3. **Which tags to publish.** `v1.7` and `v2.0`: they hold their versions and are what
   `make reproduce` needs. They are the only tags.
4. **CLAUDE.md.** It is the specification, written as a prompt file for the coding agent, and the
   tests read the weights and the coverage map from it. Keep it, or rename it and update the places
   that read it (`tests/test_phase1_golden.py`, `tests/test_phase4b_golden.py`,
   `tests/test_phase5_exposure.py`, `tests/test_phase7_robustness.py` and `scripts/reproduce.py`).
5. **Wording of the claims.** The results are replay-only (limitation 1); say so wherever they are
   quoted.

<!-- BEGIN GENERATED: publishable -->
```
tracked files scanned: 315, history: every ref
findings in the working tree: 0
findings in the history (added lines of every commit of every ref): 0
replay events checked as post-Observe events: 378, rejected: 0
identities recorded by git as author or committer: 3 (masked here so that this output can be published)
  G***b <n***y@g***b.com>
  P***A <1***e@u***b.com>
  P***t <p***u@m***1.cluster>
content: CLEAN
identities: present in the history, the owner decides before publishing
```
<!-- END GENERATED: publishable -->

## 11. Earlier evaluations (retired seeds)

Kept as a record; they are not regenerated: the code of v1.0 to v1.6 was lost when the history was
squashed, and before v1.2 the generator differed (the seed drew only the combinations) and the
benign variants did not exist.

| seed | versions | report | data |
|---|---|---|---|
| 20261029 | v1.0 (Phase 7) | [progress.md](progress.md), Phase 7 | `build/` (not kept) |
| 268805905 | v1.0, v1.1 | [v1.1-evaluation.md](v1.1-evaluation.md) | [docs/evaluation/](evaluation/) |
| 892499628 | v1.0, v1.1, v1.2 | [v1.2-evaluation.md](v1.2-evaluation.md) | [docs/evaluation/](evaluation/) |
| 654514256 | v1.0 to v1.3, malicious and benign | [v1.3-evaluation.md](v1.3-evaluation.md) | [docs/evaluation/](evaluation/) |
| 711829743 | v1.0 to v1.4 (v1.4 not written up) | [progress.md](progress.md), v1.4 | `tests/variants/known_gaps.yaml` |
| 833754500 | v1.4, v1.5 | [v1.5-evaluation.md](v1.5-evaluation.md) | [docs/evaluation/](evaluation/) |
| 545728926 | v1.5, v1.6 | [v1.5-evaluation.md](v1.5-evaluation.md) | [docs/evaluation/](evaluation/) |
| 616687759 | v1.6, v1.7 | [v1.5-evaluation.md](v1.5-evaluation.md) | [docs/evaluation/](evaluation/) |
