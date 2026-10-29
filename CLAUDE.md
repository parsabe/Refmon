# Provenance Gate v2 — Claude Code Prompt File

Save this file as `CLAUDE.md` in the repository root. Claude Code reads it automatically.
Then give Claude Code one phase prompt from Part B at a time, and move on only when that phase's "Done when" condition passes.
If v1 phases are already implemented, start with the "Upgrade from v1" prompt in Part B.

---

## Part A — Context (read every session)

You are building **Provenance Gate v2**, a platform-agnostic pipeline that detects, contains and explains attacks on **endpoints and servers**, including attack types that do not exist yet.

### Core idea

The pipeline never tries to recognise a specific exploit, lure or malware family. It judges **behaviour that any successful attack must show**, using three questions on every story of related events:

| Question                                                                   | Fails when                                                                                                                                                                                    |
| -------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Origin**: did the triggering input come from outside the trust boundary? | Web content, inbound network request, mail, removable media, downloaded package, AI agent input                                                                                               |
| **Contract**: is the acting process doing something outside its role?      | Human instructed to run a command (ClickFix family); web server worker spawning a shell or writing executable files (PHP2Shell-style RCE, web shells); service touching data it never touches; any behaviour forbidden for every role unless its contract allows it (tampering, mass change, lateral fan-out, repeated oversized responses); launching an unsigned externally sourced file (C4) |
| **Effect**: does it try a dangerous action?                                | fetch, hide, persist, escalate, lateral, exfil, tamper, credential access, protected asset access, mass change                                                                                |

3 fails = block. 2 fails = hold (endpoint: ask the user; server: pause or quarantine pending admin). 0–1 = allow.
Block also needs a Contract signal or an override; without either, the decision is capped at hold (the contract gate, C11.5).
Overrides: canary access = block. Labeled process touching a protected asset = block. Tampering with Refmon itself (stopping it, altering its policy or binaries) = block. Trusted root source = allow.

Since v2.1 the fail count is backed by an **evidence calculus** (Part C11): each question yields a strength in [0, 1], signals combine as log-likelihood ratios, and decisions use cost-based thresholds derived from the policy. The 3/2/1 fail rule stays as the human-readable explanation in every verdict and as the fallback when no weights are configured.

Why this generalises: an unknown vulnerability can be exploited in unknown ways, but after exploitation the attacker must still act (run code, write files, connect out, read secrets, persist). Those actions violate the role contract of the exploited process. The pipeline catches the **consequence**, not the vulnerability.

**Missing information never generates evidence.** If a sensor cannot supply something (a signature check, a host name, a baseline that is not yet mature), the signal that depends on it is absent, not raised, and the gap is reported as degraded protection (Phase 6 heartbeat). A destination class `unknown` is not missing information: the host was seen and matched no class, so it still counts for `fetch`.

### Hard constraints

- Core logic is platform-independent. OS and server specifics only behind `Sensor.emit(sink)` and `Enforcer.act(Action)`.
- Privacy: content (commands, request bodies, URLs, file contents) is replaced by HMAC-SHA256 fingerprints with a per-device key in the Observe stage. No raw content after Observe. Raw events live in memory at most 10 minutes, never on disk. The only exceptions are lab fixtures and recordings made in an isolated lab VM with synthetic users, containing harmless synthetic content only (see C2 and Phase 8). Sensors hand raw data to Observe in memory and never hash, log or store it themselves. Only verdicts leave the device, under pseudonyms.
- Deterministic rules and counted baselines only. No machine learning.
- Every behaviour must be testable through replay of JSON Lines event files.
- Never write, download or reproduce real malware or real exploits (including PHP2Shell exploit code). Test stand-ins are harmless and self-made, e.g. a tiny lab-only test web app with a deliberate debug endpoint that spawns `echo`, or a stand-in that writes a harmless `.php` text file into a test webroot.
- Nothing changes the policy without human approval.
- If something is unclear, ask before guessing. Small commits, each with tests.

---

## Part B — Phase prompts

### Upgrade from v1 (only if v1 exists)

```text
Upgrade the existing v1 pipeline to v2 as specified in CLAUDE.md. Rename the Initiator question to Contract and re-implement the human-initiated check as one contract ("interactive_shell" launched from a launcher after external content). Add the new event types, actor roles, effect types and policy sections from Part C without breaking existing golden files. All v1 tests must still pass. Then add golden files S13-S16.
Done when: all v1 tests pass unchanged and S13-S16 reach their expected decisions in replay.
```

### Phase 0 — Foundations

```text
Phase 0: Foundations.
Set up a Python 3.12 project (pyproject.toml, ruff, pytest, CI).
Implement the Event, Label, Story, Contract, Verdict and Action schemas from Part C as typed models with validation.
Implement ReplaySource (JSON Lines -> Events) and SimulatedEnforcer (records Actions with undo records).
Create golden event files for S01, S02, S09, S10, S11, S13, S14 with expected verdicts.
Done when: all golden files validate and stream end to end through an empty core.
```

### Phase 1 — Understand (Observe, Tag, Link, Judge)

```text
Phase 1: Understand.
Implement Observe (HMAC fingerprints, the Observe-time checks of C2, drop raw content, in-memory ring buffer), Tag (propagation rules 1-6 with decay), Link (story graph, quiet window, persistent labels) and Judge (Origin, Contract, Effect, overrides), observe mode only.
Contract checks compare each event against the role contract of the acting process (Part C4).
Unit test per propagation rule, contract rule, effect type and override.
Property tests: labels never lost along process chains; no raw content in any output; an event allowed by a contract never counts as a Contract fail.
Create golden replay files for EVERY scenario in Part C8 except the adaptive ones (S16, S28, S29, which belong to Phase 5), each with its expected decision. Use the coverage map in Part C13 to check that every attack family has at least one malicious and one related benign scenario.
Done when: every golden file reaches its `rule_decision` (the plain 3/2/1 fail rule, or its documented override); every malicious golden file yields 3 fails (or its documented override), except the known gaps S05 and S22; every benign one yields at most 1 fail, except the files whose expected decision is hold (S49, S50: 2 fails) and a file whose `rule_decision` differs from its final `decision` (S11 and S26a: 2 fails, rule decision hold, final decision allow from Phase 4b); and the coverage map shows no attack family without a passing scenario.
```

### Phase 2 — Policy and contracts

```text
Phase 2: Policy and contracts.
Implement the signed YAML policy loader (Part C6): thresholds, decisions, trusted sources, protected assets, canaries, role contracts, rules with per-rule mode, exceptions with reason/scope/expiry, rule packs with version and signature.
Implement contract learning mode: for a configurable period the pipeline only counts what each role actually does and writes a contract PROPOSAL file. It never activates a contract by itself; a human approves it.
Remove every hard-coded threshold.
Done when: changing only the policy changes outcomes as expected; tampered policy or rule pack is rejected and the last valid one kept; a learning run on benign replay files produces a contract proposal that, once approved, makes the benign files pass with 0 Contract fails; a learning run on the benign workloads of S46-S48 proposes the allowances for the backup, scanner and patch roles (`may_mass_change`, `may_fan_out`, `may_tamper`).
```

### Phase 3 — Act (Gate, Contain)

```text
Phase 3: Act.
Implement Gate with mode downgrade (observe never acts, warn never blocks) and two hold flows:
- endpoint hold: pause process, plain-language question to the user, timeout = deny, no continue on 3 fails;
- server hold: pause or quarantine, notify admin, timeout = keep quarantined.
Implement Contain with labeled-only actions and undo records: kill process tree, cut network per process, quarantine new files (move, never delete), revert persistence, restore files from known-good hash baseline, isolate host.
Done when: in replay every block touches exactly the story's labeled objects, server stories quarantine the written web-shell stand-in and kill the worker, and undo restores the prior state in the simulated enforcer.
```

### Phase 4 — Report and Tune

```text
Phase 4: Report and Tune.
Build Verdicts with plain-language summaries for a non-expert service desk (what happened, action taken, next step), mapped to MITRE ATT&CK tactic names.
Add pseudonymization and four-eyes re-identification (two approvers, every use logged).
Feedback: "false alarm" proposes a scoped, expiring exception or a contract extension; "confirmed" proposes block-list entries. Nothing applies without approval.
Privacy audit script: scan all outputs for raw content; try reversing fingerprints with a dictionary of common commands and URL paths; try re-identification without four-eyes.
Done when: audit finds zero raw content and zero reversals.
```

### Phase 4b — Mathematical core (evidence calculus)

```text
Phase 4b: Mathematical core. Implement Part C11 exactly, as pure functions with unit tests and property tests.
1. Label strength: exponential decay with half-life; attenuation per edge; noisy-OR combination of multiple parent labels.
2. Contract rarity: Laplace-smoothed per-role event probabilities, surprisal in bits, Good-Turing unseen probability as a baseline-maturity check (contracts only enforce when mature).
3. Evidence combination: per-signal log-likelihood-ratio weights (expert defaults from policy, optionally re-estimated from labeled replay counts with Laplace smoothing), max within each question, sum across questions, plus prior log-odds.
4. Cost-based thresholds: derive block and hold thresholds from policy costs, prior and hold catch rate; overrides stay absolute. The contract gate caps a block at hold when there is no Contract signal and no override, and the verdict records that it applied.
5. Rate anomalies: Poisson tail test for bursts (mass_change, lateral fan-out) and CUSUM for slow drift (exfil volume), baselines as exponential moving averages frozen during open incidents. A Poisson test on repeated response anomalies per client raises the separate signal `effect_response_anomaly_repeated`.
6. Obfuscation features computed in Observe before raw content is dropped: Shannon entropy, encoded-character ratio, longest whitespace run. Keep only the numbers.
7. Privacy math: Laplace noise (epsilon from policy) on aggregate counts sent to the server, k-anonymity suppression for dashboards, Bloom-filter threat lists checked locally.
8. Every verdict lists each contribution (weight x strength, in nats), the posterior log-odds and the threshold crossed, plus the classic fail count.
Property tests: decay is monotone; noisy-OR is in [0,1] and never below the max input; adding a signal never lowers log-odds; thresholds move in the right direction when costs change; no raw content survives Observe.
Done when: the full scenario catalog reaches its expected decisions with the example default weights, S11 is allowed, S05 is held, and every verdict's contributions sum exactly to its log-odds. From here on, golden tests assert `decision` instead of `rule_decision`.
```

### Phase 5 — Exposure and adaptive protection

```text
Phase 5: Exposure and adaptive protection.
Implement the Exposure stage (Part C5): read a component inventory (name, version, role, exposed: true/false) and a local advisory file (component, affected versions, severity). Match them and produce an exposure list.
When a component that runs under a role is exposed and unpatched, automatically raise protection for that role only: its contract rules switch to block mode, its outbound network is restricted to the contract's allowed destinations, and the verdict summary names the reason. This is "virtual patching". It reverts when the inventory shows a fixed version.
Never fetch advisories from the internet in tests; use local fixture files.
Done when: S16 shows mode escalation on an exposed component and reversion after the fixture reports a patched version.
```

### Phase 6 — Continuous self-test and rule packs

```text
Phase 6: Continuous self-test and rule packs.
Implement a self-test scheduler that periodically injects harmless synthetic stories (tagged as tests, never reported as incidents) for each enabled protection and verifies the expected decision. A failed self-test is itself an alert ("protection X is not working").
Implement a heartbeat: each pipeline instance reports alive + policy version + self-test status + any sensor capability that is missing (for example no signature check), reported as degraded protection; a missing heartbeat is an alert.
Implement rule packs: versioned, signed bundles of rules and contracts that can be shared between organisations; loading a pack never weakens existing block rules without approval.
Done when: disabling a protection in a test makes its self-test alert; a stale heartbeat raises an alert; an unsigned pack is rejected.
```

### Phase 7 — Variant and robustness testing

```text
Phase 7: Robustness.
Write a variant generator that mutates every malicious golden file along: delivery (pasted, typed, dragged, opened, inbound request), launcher or entry (run dialog, terminal, file manager, script host, web worker, scheduled task), obfuscation flags, timing (immediate, minutes, beyond story window), destination (unknown domain, popular trusted host, internal network), process lineage depth, and user/admin behaviour at hold.
Keep a no-label variant of each of S17-S20 (initial-access label removed): expected decision block for all four, because the Contract signals do not depend on the origin label.
Measure robustness only on generated variants that were never used to choose weights or structural rules (see the weight methodology in C11): record the generator seed before any such change; a later change retires that seed.
Run all variants through replay and output a robustness matrix (scenario x variant -> decision) as CSV plus a list of every allowed malicious variant with the questions that passed. Also report, for every run, the share of processes classified as role `other` (a high share means the role contracts do not cover the workload, and stories like S49 fall under no contract).
Done when: the matrix is generated in CI and every allowed variant is either fixed or documented as a known gap.
```

### Phase 8 — First real platforms

```text
Phase 8: Real platforms.
Implement sensor and enforcer adapters for <ENDPOINT PLATFORM> and for <SERVER PLATFORM / WEB SERVER STACK> behind the existing interfaces, without changing core code.
Server sensor must provide: request_in (the raw request handed to Observe in memory; the sensor never hashes, logs or stores body or URL), process ancestry of web workers, file writes under configured web roots, outbound connections per process, privilege changes.
Add a recorder that writes replay files. In an isolated lab VM with synthetic users it may write RawEvents (harmless synthetic content only); everywhere else it records post-Observe Events only.
Build harmless stand-ins for every catalog scenario in an isolated VM lab (snapshots, no internet, local fake attacker server, self-made lab-only test web app). Never use real exploits.
Done when: lab verdicts equal replay verdicts for all scenarios and per-event overhead is measured.
```

### Phase 9 — Pilot report (human-led; agent helps with the report)

```text
Using pilot verdicts and metrics, write an evaluation report: results per scenario, false alarms per user and per server per week, holds per week, time to block, contain completeness, data sent per device per day, self-test pass rate. Compare each metric against the success criteria fixed before the pilot and list every rule or contract that should stay in observe mode, with the reason.
```

---

## Part C — Specification essentials

### C1. Architecture

| Component           | Responsibility                                               | Interface                                   |
| ------------------- | ------------------------------------------------------------ | ------------------------------------------- |
| Sensor adapter      | Platform signals -> `RawEvent`s (in memory only)             | `emit(sink)`                                |
| Replay source       | JSON Lines files -> `Event`s (or `RawEvent` lab fixtures)    | same as sensor                              |
| Exposure stage      | Inventory + advisories -> exposure list, mode escalation     | `assess(Inventory, Advisories) -> Exposure` |
| Core pipeline       | Observe, Tag, Link, Judge, Gate, Contain, Report, Tune       | `process(RawEvent \| Event) -> [Verdict, Action]` |
| Enforcer adapter    | Hold, block, kill, quarantine, network cut, restore, isolate | `act(Action) -> Result`                     |
| Simulated enforcer  | Records actions for tests                                    | same as enforcer                            |
| Self-test scheduler | Injects synthetic stories, checks decisions                  | `run() -> SelfTestReport`                   |
| Reporter            | Verdicts + heartbeats to local log or server                 | `report(Verdict)`                           |
| Policy loader       | Signed policy and rule packs                                 | `load(path) -> Policy`                      |

### C2. Event

```json
{
  "event_id": "e-000184",
  "ts": "2026-10-28T10:02:15.120Z",
  "device": "dev-7f3a",
  "type": "exec",
  "actor": {
    "id": "p-1842",
    "parent": "p-77",
    "role": "web_worker",
    "interactive": false,
    "user": "svc-www"
  },
  "object": { "class": "command_text", "fingerprint": "hmac:9c1e..." },
  "attrs": { "source_class": "inbound_request" }
}
```

Events exist in two forms:

- **`RawEvent`** (sensor -> Observe): what the platform saw. It may carry the content itself (`object.content`, instead of `object.fingerprint`; never both) and free-text attributes such as `domain`. It lives in memory only, and in lab fixtures and isolated-lab recordings made of harmless synthetic content (read by a separate replay source so that Observe itself can be tested).
- **`Event`** (Observe output, everything after Observe): the form shown above. Fingerprints only. `attrs` keys must be on this allowlist and anything else is rejected: `source_class`, `signed` (true, false or `unknown`: whether a launched file has a valid code signature, set by the sensor), `trusted_source`, `destination_class`, `exec_class` (name of the matching `executables` class, or `unknown`), `protected_asset` (name of the matching `protected_assets` entry), `threat_list_hit`, `canary_hit`, `input_method`, `launched_via`, `hidden_window`, `encoded_payload`, `entropy_bits`, `encoded_char_ratio`, `longest_ws_run`, `path_group`, `web_root`, `executable`, `new_file`, `persist_kind`, `bytes`. Adding a key is a change to this list. Values are numbers, flags or short identifiers (`[A-Za-z0-9_.:@-]{1,64}`), never free text. Outside the lab exceptions above, this is the only form that is stored, recorded or sent off the device. Every valid `Event` is also a valid `RawEvent`.

**Observe-time checks.** Everything that needs a raw domain, host name, IP address, URL or path is decided inside Observe, on the `RawEvent`, before the value is fingerprinted or dropped. Only the outcome is emitted: `trusted_source` (name of the matching `trusted_sources` rule; origin only), `destination_class` (name of the matching `destinations` class, or `unknown`; an IP-only connection with no match is `unknown`), `threat_list_hit` (name of a threat list, already confirmed against the exact list), `canary_hit` (a flag; canary URL paths are matched before fingerprinting). The raw attributes Observe consumes and then drops are `domain` (source of content), `host` and `ip` (destination of a connection), `url_path` (path of a request), `program` (name of an executed program) and `signer`. Sensors hand raw data to Observe in memory and never hash, log or store it themselves.

Event types: `content_in`, `request_in`, `exec`, `net_connect`, `file_write`, `persist`, `asset_access`, `priv_change`, `security_tamper`, `user_input`, `admin_input`, `request_end`, `response_out`.

- `request_end`: the request opened by an earlier `request_in` (same object fingerprint) has finished; the handling process stops carrying that request's label (C3 rule 2).
- `response_out`: a server sent a response to a client; carries sizes only (in `attrs`), never content; the input for the `response_anomaly` effect (C7).

Actor roles (extensible in policy): `browser`, `mail`, `office`, `launcher`, `interactive_shell`, `script_host`, `package_installer`, `web_worker`, `app_server`, `node_app_server`, `desktop_app_runtime` (apps that bundle their own runtime), `db_server`, `scheduler`, `agent`, `system_service`, `other`.

Source classes: `web`, `mail`, `removable`, `download`, `inbound_request`, `outbound_response` (data a server fetched itself, e.g. via `fetch()`; Node2Shell can be triggered this way), `package`, `agent_input`, `internal`.

### C3. Labels and propagation

```json
{
  "label_id": "L-91",
  "origin": "external",
  "source_class": "inbound_request",
  "created": "2026-10-28T10:02:15.120Z",
  "strength": 1.0,
  "parents": [],
  "persistent": false,
  "contract_evidence": []
}
```

1. `content_in` or `request_in` from an external source creates a label (strength 1.0).
2. A process that handles a labeled request carries the label for the duration of that request.
3. An `exec` whose command fingerprint matches labeled content inherits that label.
4. Child processes inherit all labels of their parent.
5. Files and persistence items written by a labeled process inherit its labels; persistence items and files in web roots get `persistent: true`.
6. Strength decays unless persistent. Trusted sources create no label.
7. A persistent label also carries the Contract signals that were present in the story that created it (`contract_evidence`). When the labeled item runs later (a startup entry, a scheduled task, a file in a web root), those signals apply to the new story.

### C4. Role contracts

A contract lists what a role is allowed to do. Anything outside it is a Contract fail. Example:

```yaml
contracts:
  web_worker:
    may_exec: [] # never spawns processes
    may_write: [paths: [cache, sessions, uploads_non_executable]]
    may_connect: [db_server, cache_server]
    may_read_assets: []
  interactive_shell:
    external_content_exec: deny # ClickFix family: pasted/typed external commands
  launcher:
    unsigned_external_exec: deny # starting an unsigned file that carries an external label
  backup_job: # roles like these are added in policy
    may_mass_change: true
  vuln_scanner:
    may_fan_out: true
  patch_tool:
    may_tamper: true # stopping services during an update
  office:
    may_exec: [print_helper] # nothing else; never a script host
  package_installer:
    may_connect: [package_index] # destination class from policy `destinations`
    may_persist: false
  agent:
    may_exec: [allowlist_from_policy]
    external_content_exec: deny # prompt-injected commands
```

A `may_connect` entry is a destination class name; the entry `any` allows every destination, and a role without a `may_connect` is treated as `[]` for the `fetch` effect. A `may_exec` entry is an `executables` class name. A `may_read_assets` entry is a `protected_assets` name. `may_change_privilege` is true or false.

**Universal contract.** Four behaviours are forbidden for every role unless the role's own contract explicitly allows them: tampering with security tools or logs (`may_tamper`), many files changed beyond the Poisson threshold (`may_mass_change`), connections to many internal hosts beyond the Poisson threshold (`may_fan_out`), and repeated response anomalies to one client (`may_repeat_large_responses`). Doing one without the allowance is a Contract signal. An allowance removes that Contract signal. It removes the matching Effect only when the story carries no external origin label: without a label the behaviour is simply in role; with one it is not ignored, and the Effect still counts (C7).

**Launcher contract.** Starting an executable or script that carries an external origin label (download, removable, mail) and has no valid code signature is a Contract signal (`unsigned_external_exec: deny`). The sensor sets `signed` to true, false or `unknown`; `unknown` (the sensor cannot check signatures) raises no signal.

**v1.1 (A46).** `external_content_exec` is part of the universal contract: it applies to every role unless the role's contract says `allow`. A role that says `deny` keeps the wider rule (any exec by a labeled process); a role with no setting gets it for labeled command text only.

Contracts can be generated in learning mode as proposals and must be approved by a human.

### C5. Exposure stage

Input: component inventory and advisory fixtures. Output: exposed components per role.
Effect: for an exposed and unpatched component, its role's contract rules run in block mode and its outbound network is restricted to contract destinations (virtual patching). Automatic reversion when patched.

Exposure states per component: `patched`, `mitigated` (a documented workaround is verified active, e.g. a configuration flag, for flaws with no patch yet), `exposed`, `end_of_life` (no fix will ever come; always treated as exposed).
Inventory must include runtimes that are easy to miss: language runtimes inside containers, runtimes bundled inside desktop applications and appliances, and decentrally operated servers.
Escalation is per role and per component, never global: the goal is to replace "take the whole university offline" with "tighten only the exposed roles".

### C6. Policy file (excerpt)

```yaml
version: 2
mode: observe
thresholds:
  {
    origin_strength: 0.5,
    decay_half_life: 30m,
    story_quiet_window: 10m,
    buffer_max_age: 10m,
  }
decisions:
  {
    fails_3: block,
    fails_2: hold,
    fails_0_1: allow,
    endpoint_hold_timeout: 60s,
    server_hold_timeout: keep_quarantined,
  }
trusted_sources: # origin only: sources whose content creates no label
  - {
      name: official-python-index,
      match:
        { source_class: download, domain: [pypi.org, files.pythonhosted.org] },
    }
destinations: # named classes for net_connect; matched in Observe on host name or IP/CIDR
  - { name: package_index, trusted: true, match: { host: [pypi.org, files.pythonhosted.org] } }
  - { name: db_server, trusted: true, match: { host: [db.example.internal] } }
  - { name: internal_network, trusted: false, match: { cidr: [10.0.0.0/8, 192.168.0.0/16] } }
protected_assets:
  - { name: browser-passwords, class: credential_store }
  - { name: app-config-secrets, class: path_group, value: app_secrets }
canaries: # matched in Observe before fingerprinting; Observe emits only canary_hit
  - { name: fake-db-credentials, class: credential }
  - { name: canary-admin-url, class: url_path }
web_roots: [main_site]
contracts: { see C4 }
executables: # named program classes, matched in Observe on the program name
  - { name: print_helper, match: { program: [lpr, cups-print] } }
  - { name: build_tool, match: { program: [npm-build, make] } }
rates: # simple counted thresholds for Phases 1-4; Phase 4b replaces them with the tests of C11.6
  { window: 60s, long_window: 1h, mass_change_files: 50, lateral_hosts: 20, response_anomaly_bytes: 5000000, response_repeat: 2, exfil_bytes: 100000000 }
threat_lists: # confirmed inside Observe; a hit is emitted as threat_list_hit
  - { name: known-bad-hosts, kind: host, entries: [bad.example.invalid] }
exposure:
  {
    inventory: inventory.yaml,
    advisories: advisories.yaml,
    escalate_mode: block,
  }
rule_packs: [{ name: core, version: 2.0.0, signature: <sig> }]
exceptions:
  - {
      id: X-001,
      reason: Research group installs packages,
      scope: { group: research-lab },
      disables: [R-EFF-FETCH],
      expires: 2027-03-31,
    }
reporting: { destination: local, pseudonymize: true, reidentify_requires: 2 }
self_test: { interval: 6h }
signature: <detached signature>
```

### C7. Effect types

`fetch` (a process connects to a destination that is not in its contract's `may_connect` and is not `destination_trusted`; the process need not be labeled, which is how S05 reaches hold; `destination_trusted` means the event's `destination_class` is a `destinations` class with `trusted: true`, and `unknown` never is; v1.1: for a *labeled* process a trusted class excuses the connection only when the role's contract lists it) · `hide` (hidden window, encoded payload, padding) · `persist` (startup entries, scheduled tasks, new executable files in web roots) · `escalate` (privilege change) · `lateral` (new connections to internal hosts) · `exfil` (unusual outbound volume) · `tamper` (security tools, logs, the pipeline itself) · `credential` (credential stores, key material) · `asset_access` (protected assets) · `mass_change` (many files changed quickly) · `response_anomaly` (a server sends one client responses far larger than its baseline, e.g. leaked process memory hidden in a cookie; only sizes are measured, never content; a repeat for the same client that is significant under a Poisson test is the stronger signal `response_anomaly_repeated`) · `threat_list_hit` (a destination or content value confirmed against a threat list inside Observe).

`escalate`, `credential` and `asset_access` count only when the acting role's contract does not allow the privilege change (`may_change_privilege`) or the asset (`may_read_assets`), in the same way as `fetch`. `tamper`, `mass_change`, `lateral` and the repeated `response_anomaly` are Effects unless the acting role's contract allows the behaviour and the story carries no external origin label (universal contract, C4).

### C8. Scenario catalog

| ID  | Scenario                                                                                                                | Kind      | Expected                                                    |
| --- | ----------------------------------------------------------------------------------------------------------------------- | --------- | ----------------------------------------------------------- |
| S01 | Fake CAPTCHA, command pasted into run dialog                                                                            | malicious | block                                                       |
| S02 | Same lure, pasted into terminal                                                                                         | malicious | block                                                       |
| S03 | Command pasted into file manager address bar                                                                            | malicious | block                                                       |
| S04 | Command copied from PDF, pasted                                                                                         | malicious | block                                                       |
| S05 | Command typed by hand from a video                                                                                      | malicious | hold (known gap)                                            |
| S06 | Persistence now, payload runs a day later                                                                               | malicious | block at delayed run                                        |
| S07 | Payload on popular file-sharing host                                                                                    | malicious | block                                                       |
| S08 | Labeled process reads canary credential                                                                                 | malicious | block (override)                                            |
| S09 | Package from official index                                                                                             | benign    | allow                                                       |
| S10 | Admin runs own local script                                                                                             | benign    | allow                                                       |
| S11 | Developer copies doc command, local effect                                                                              | benign    | allow                                                       |
| S12 | AI agent runs command from injected web content                                                                         | malicious | block                                                       |
| S13 | Inbound request -> web worker spawns shell (RCE stand-in, e.g. PHP2Shell-style)                                         | malicious | block                                                       |
| S14 | Web worker writes new executable script file into web root (web shell stand-in)                                         | malicious | block + quarantine                                          |
| S15 | Web worker connects to unknown internet host                                                                            | malicious | block                                                       |
| S16 | Exposed unpatched component -> role escalated to block, reverted after patch                                            | adaptive  | escalation + reversion                                      |
| S17 | Service process gains elevated privileges (story includes an initial-access label)                                      | malicious | block                                                       |
| S18 | Compromised host opens new connections to many internal hosts (story includes an initial-access label)                  | malicious | block                                                       |
| S19 | Process changes many files rapidly (ransomware stand-in; story includes an initial-access label)                        | malicious | block                                                       |
| S20 | Process stops security tool or clears logs (story includes an initial-access label)                                     | malicious | block                                                       |
| S21 | Package install script reads credentials or persists                                                                    | malicious | block                                                       |
| S22 | Attacker abuses app's own allowed DB connection to read data                                                            | malicious | known gap; detect only via exfil volume                     |
| S23 | Web worker writes normal cache and session files                                                                        | benign    | allow                                                       |
| S24 | Admin deploys new site version via deployment tool                                                                      | benign    | allow (trusted source)                                      |
| S25 | Inbound request with malformed compressed body -> Node app server spawns a child process (Node2Shell-style stand-in)    | malicious | block                                                       |
| S26a | Node app server fetches an external URL, response leads to a non-executable file write (cache)                          | benign    | allow                                                       |
| S26b | Node app server fetches an external URL, response triggers an unexpected outbound connection                            | malicious | block (origin `outbound_response`)                          |
| S26c | Node app server fetches an external URL, response triggers an executable file write                                     | malicious | block (origin `outbound_response`)                          |
| S27 | Server returns oversized responses to one client (memory-leak stage stand-in)                                           | malicious | hold, then block on repeat (Poisson/CUSUM on response size) |
| S28 | End-of-life runtime found in inventory                                                                                  | adaptive  | role escalated permanently until replaced                   |
| S29 | Unpatched flaw with verified workaround flag                                                                            | adaptive  | `mitigated`, no escalation; escalation if flag disappears   |
| S30 | Node app server legitimately runs an approved build tool child process                                                  | benign    | allow (contract allowlist)                                  |
| S31 | Document from a mail attachment makes the office app start a script host (macro stand-in)                               | malicious | block                                                       |
| S32 | Program launched from removable media connects out and creates a startup entry                                          | malicious | block                                                       |
| S33 | Downloaded fake installer runs, persists and contacts an unknown host (trojanized software stand-in)                    | malicious | block                                                       |
| S34 | Labeled process reads the real browser credential store (infostealer stand-in)                                          | malicious | block (protected asset override)                            |
| S35 | User opens a file downloaded from a link, it starts a hidden script that fetches more code (drive-by download stand-in) | malicious | block                                                       |
| S36 | User opens a normal PDF from a mail attachment and prints it (the reader's contract lists the print helper)             | benign    | allow                                                       |
| S37 | IT installs signed software from the university software portal                                                         | benign    | allow (trusted source)                                      |
| S38 | User opens and prints a normal document from a removable medium                                                         | benign    | allow                                                       |
| S39 | Browser reads its own password store (its contract allows it)                                                           | benign    | allow                                                       |
| S40 | Admin elevates privileges with an approved elevation tool (its contract allows it)                                      | benign    | allow                                                       |
| S46 | Backup job (role `backup_job`, contract allows mass change) changes many files beyond the Poisson threshold (no external origin label) | benign    | allow                                                       |
| S47 | Admin vulnerability scanner (role `vuln_scanner`, contract allows fan-out) connects to many internal hosts (no external origin label) | benign    | allow                                                       |
| S48 | Patch tool (role `patch_tool`, contract allows tampering) stops services, among them a security service, during an update (no external origin label) | benign    | allow                                                       |
| S44 | Nightly backup sends a large volume to the known backup host (below the backup role's volume threshold)                 | benign    | allow                                                       |
| S45 | AI agent runs a command from its allowlist (no external input)                                                          | benign    | allow                                                       |
| S49 | Signed vendor installer downloaded from the internet persists (role `other`, no contract)                               | benign    | hold                                                        |
| S50 | Backup job (role `backup_job`, contract allows mass change) changes many files beyond the Poisson threshold in a story that carries an external origin label | benign    | hold                                                        |

### C9. Test layers

1. Unit tests per rule, contract, effect type, override, policy field.
2. Property tests: labels never lost; no raw content in output; Contain never touches unlabeled objects; unsigned policy/pack always rejected; allowed-by-contract events never fail Contract.
3. Replay tests: golden file per scenario. Each golden file records `decision` (final) and `rule_decision` (the plain 3/2/1 fail rule, or its override). Phases 1 to 4 assert `rule_decision`; from Phase 4b on tests assert `decision`. They differ only where the evidence calculus overrules the rule (S11).
4. Variant tests: robustness matrix (Phase 7).
5. Self-tests in production (Phase 6).
6. Lab tests: isolated VMs, snapshots, no internet, self-made harmless stand-ins only.

### C10. Proposed targets (confirm after Phase 1)

| Metric                                                 | Proposed target                                |
| ------------------------------------------------------ | ---------------------------------------------- |
| Malicious catalog scenarios reaching expected decision | 100 % (documented gaps excluded)               |
| Benign workload blocks                                 | 0 per simulated week                           |
| Endpoint holds per user                                | at most 1 per week                             |
| Time from first malicious action to block              | under 1 s                                      |
| Contain completeness                                   | 100 % of labeled changes undone or quarantined |
| Raw content leaving a device                           | 0 bytes                                        |
| Self-test pass rate                                    | 100 %                                          |
| Added processing delay per event                       | measured in Phase 8                            |

### C11. Mathematical core (evidence calculus)

All formulas are deterministic and computed from counts; no model training.

**1. Label strength decay**
`s(t) = s0 * 2^(-Δt / T_half)`; persistent labels have `T_half = ∞`.

**2. Propagation and combination**
Along an edge with attenuation `a_e ∈ (0, 1]`: `s_child = s_parent * a_e`.
Several labels on one object combine with noisy-OR: `s = 1 - Π(1 - s_i)`.

**3. Contract rarity (surprisal)**
Per role, event kind `e`: `p(e | role) = (n_e + α) / (N + α * K)` with Laplace smoothing (`α = 1`, `K` = observed kinds + 1 for "unseen").
Surprisal `I = -log2 p(e | role)`. Contract fails when `I ≥ I_max` (policy, e.g. 12 bits ≈ 1 in 4096).
Baseline maturity (Good-Turing): `p_unseen ≈ n1 / N` (`n1` = kinds seen exactly once). A learned contract is only enforced when `p_unseen < maturity_threshold`.

**4. Evidence combination (log-likelihood ratios)**
Per signal `j`: `w_j = ln( P(j | attack) / P(j | benign) )`, from expert defaults or re-estimated from labeled replay and observe-mode counts with Laplace smoothing.
Within a question take the maximum (handles correlated signals); across questions sum:
`L = ln(π / (1 - π)) + Σ_q max_{j ∈ q} ( w_j * s_j )`
where `π` is the prior attack rate and `s_j` the strength of signal `j`: for Origin the strength of the strongest label (C11.1, C11.2), for a Contract or Effect signal 1. **v1.3 (A55):** a weaker label must never produce stronger evidence. Until v1.2 a Contract or Effect signal counted at the strength of the label behind it while that label was at or above the origin threshold and at 1 below it, so a label that had faded to 0.7 made the same behaviour weaker evidence and one that had faded under 0.5 made it full strength again (F8); only Origin carries the label's strength now. `P(attack) = 1 / (1 + e^(-L))`.

**5. Cost-based decision thresholds**
Block when `L ≥ ln(C_false_block / C_missed)`.
Hold when `L ≥ ln(C_hold / (h * C_missed))`, where `h` = probability that a hold stops a real attack.
Otherwise allow. Overrides (canary, protected asset, tampering with Refmon itself, trusted root) bypass this.
**Contract gate:** block also requires a Contract signal or an override. If the block threshold is crossed with neither, the decision is capped at hold and the verdict records that the gate applied.

**6. Rate anomalies**
Bursts (mass*change, lateral fan-out = distinct internal hosts per window): with baseline rate `λ`, alert when `P(X ≥ k) = 1 - Σ*{i<k} e^(-λ) λ^i / i!`<`poisson*alpha`.
Slow drift (exfil volume per role): CUSUM `S_t = max(0, S*{t-1} + x_t - μ - k)`, alert when `S_t > h_cusum` (in standard deviations).
Baselines are exponential moving averages, frozen while an incident is open so attackers cannot teach the baseline.

**7. Obfuscation features (computed in Observe, then raw content is dropped)**
Shannon entropy `H = -Σ p_c log2 p_c` over characters, encoded-character ratio, longest whitespace or comment run. `hide` fires when `H > H_max` or run length `> r_max`.

**8. Privacy mathematics**
Aggregate counts sent to the server: Laplace mechanism, noise `Lap(1 / ε)`, sensitivity 1 per device.
Dashboards suppress any group with fewer than `k` devices (k-anonymity).
Threat lists ship as Bloom filters, false-positive rate `≈ (1 - e^(-k_h n / m))^(k_h)`, sized for ≤ 0.1 %; a local hit is confirmed against the exact list before any action.

**9. Evaluation statistics**
Detection rates are reported with Wilson 95 % intervals (catalogs are small). Versions are compared on the same corpus with McNemar's test.

**Policy additions**

```yaml
math:
  prior_attack: 0.001
  costs: { missed_attack: 1000, false_block: 20, hold: 5 }
  hold_catch_rate: 0.7
  weights: # approved defaults, in nats; assumed rates and one-line reasons in docs/weights-proposal.md
    origin_external: 0.8
    contract_external_exec: 1.0
    contract_web_worker_exec: 3.0 # also node_app_server
    contract_exec_violation: 2.5
    contract_write_executable: 3.5
    contract_write_other: 1.0
    contract_connect_violation: 2.5
    contract_persist_violation: 3.5
    contract_asset_violation: 2.5
    contract_privilege_violation: 3.5
    contract_surprisal: 2.0
    effect_fetch: 2.5
    effect_hide: 2.0
    effect_persist: 2.5
    effect_exfil: 2.5
    effect_escalate: 2.5
    effect_lateral: 3.5
    effect_tamper: 3.0
    effect_credential: 3.5
    effect_asset_access: 1.5
    effect_mass_change: 2.5
    effect_response_anomaly: 1.5
    effect_response_anomaly_repeated: 3.5
    effect_threat_list_hit: 4.5
    contract_universal_violation: 2.0 # D19; rate given the behaviour occurred
    contract_unsigned_launch: 1.5 # D20
  surprisal_max_bits: 12
  baseline_maturity_unseen: 0.01
  poisson_alpha: 1.0e-6
  cusum: { k: 0.5, h: 5 }
  entropy_max_bits: 5.2
  dp_epsilon: 1.0
  k_anonymity: 5
```

**Weight methodology**
Weights and structural rules (such as the contract gate) are fixed before any catalog run. A change needs approval and a reason that does not mention a scenario. If a scenario cannot reach its expected decision with justified weights and rules, that is reported as a design finding; it is not fixed by moving a weight or a rule. From Phase 7, robustness is measured only on generated variants that were never used to choose weights or structural rules; the generator seed is recorded before any such change, and any later change retires that seed.

**Freeze.** The structural rules and weights are frozen as of catalog check 4. There are no further structural rule or weight changes on the basis of the catalog. Any later change must be evaluated only on newly generated Phase 7 variants, and every change made after a catalog check is listed here with the check that motivated it.

| Change introduced after a catalog check | Motivated by |
| --- | --- |
| Contract gate; `effect_response_anomaly_repeated`; self-tamper override; S26 split into S26a-c; print helper in the S36 reader contract; initial-access label on S17-S20 with no-label variants | check 1 |
| Universal contract (four behaviours, `contract_universal_violation`); launcher contract and `signed` (`contract_unsigned_launch`); persistent contract evidence; S17 no-label variant expects block; scenarios S46-S49 | check 2 |
| v1.1, after Phase 7 (tag `v1.1`; `v1.0` stays frozen): `external_content_exec: deny` is universal (any role unless its contract allows it; for a role with no setting it applies to labeled command text); a hold on a story with no labeled process pauses the processes that produced the story's signals; trusted destination classes are role-scoped (a labeled process connecting to a class its role does not list is a `fetch`); a label that carries Contract evidence does not decay, and the Poisson and repeat tests also run over an hour-scale window. Evaluated on seed 268805905 (docs/variant-seeds.md), design-decisions.md A46 to A50 | Phase 7 matrix, design findings F1 to F4 (docs/progress.md) |
| v1.2, after v1.1 (tag `v1.2`): the fallback of a hold never reaches a channel role (browser, mail, launcher); a block with no labeled process and no external origin label acts on the processes that produced its signals; `stop` on a fallback hold acts on the paused processes. Evaluated on seed 892499628, design-decisions.md A51 to A54 | v1.1 evaluation, design findings F5 and F6 (docs/progress.md) |
| v1.3, after v1.2 (tag `v1.3`): the evidence calculus is monotone in label strength: a Contract or Effect signal counts at full strength and only Origin carries the label's strength (C11.4). Evaluated on seed 654514256, design-decisions.md A55 and A56 | v1.2 evaluation, design finding F8 (docs/progress.md) |
| Clarifications made before the freeze, none a new rule or weight: the S17-S20 no-label variants expect block; an allowance removes the Effect only in a story with no external origin label, with scenario S50; `signed` is true, false or `unknown`, and unknown raises no signal; the principle that missing information never generates evidence | check 3 (check 4 found nothing else changed) |

**Worked check with these defaults**
Prior log-odds `ln(0.001 / 0.999) ≈ -6.91`. Block threshold `ln(20 / 1000) ≈ -3.91`. Hold threshold `ln(5 / 700) ≈ -4.94`.

- S01 ClickFix: 0.8 + 1.0 + max(2.5, 2.0) = 4.3 → L ≈ -2.61 → **block**
- S11 doc command, local effect: 0.8 + 1.0 = 1.8 → L ≈ -5.11 → **allow**
- S05 typed from video: no origin label, so no external-exec contract signal either; only effect 2.5 → L ≈ -4.41 → **hold**
- S13 web worker spawns shell: 0.8 + 3.0 + 2.5 = 6.3 → L ≈ -0.61 → **block**

### C12. Known limits (must stay documented)

- Exploits that never leave the exploited process's allowed behaviour (e.g. reading data through the app's own permitted database connection) cannot be caught by contracts; only exfil volume and canaries help.
- Content entering through unobserved channels carries no label.
- An attacker with full control of the host can attack the pipeline; heartbeat, signed policy and self-tests reduce, not remove, this risk.
- The pipeline complements patching and exposure management; it does not replace them.

### C13. Coverage map (attack family -> how it is caught -> scenarios)

Every attack family must keep at least one malicious and one benign scenario in the replay suite.

| Attack family                                            | Origin                             | Contract                                  | Effect / math                                  | Malicious                | Benign      |
| -------------------------------------------------------- | ---------------------------------- | ----------------------------------------- | ---------------------------------------------- | ------------------------ | ----------- |
| ClickFix, TerminalFix, FileFix (pasted commands)         | web, mail                          | interactive_shell external_content_exec   | fetch, hide; entropy features                  | S01–S04, S06, S07        | S11         |
| Commands typed from videos or phone calls                | none (known gap)                   | —                                         | fetch, hide                                    | S05                      | S10         |
| Malicious attachments and macro documents                | mail                               | office must not start script hosts        | fetch, persist                                 | S31                      | S36         |
| USB and removable media                                  | removable                          | launcher: no unsigned external exec       | fetch, persist                                 | S32                      | S38         |
| Fake installers, trojanized software, drive-by downloads | download, web                      | launcher: no unsigned external exec       | persist, fetch, hide                           | S33, S35                 | S37, S49    |
| Infostealers and credential theft                        | any                                | —                                         | credential, protected asset override, canaries | S08, S34                 | S39         |
| Poisoned packages and supply chain                       | package                            | package_installer                         | credential, persist, fetch                     | S21                      | S09         |
| Server RCE: PHP2Shell, Node2Shell, future zero-days      | inbound_request, outbound_response | web_worker, node_app_server must not exec | fetch, persist; surprisal                      | S13, S25, S26b, S26c            | S23, S26a, S30    |
| Web shells                                               | inbound_request                    | web_worker may not write executables      | persist                                        | S14                      | S24         |
| Memory-leak stages                                       | inbound_request                    | universal: no repeated oversized responses | response_anomaly; Poisson, CUSUM               | S27                      | S23         |
| Privilege escalation                                     | any                                | role privilege contract                   | escalate                                       | S17                      | S40         |
| Lateral movement                                         | any                                | universal: no fan-out                     | lateral; Poisson fan-out                       | S18                      | S47         |
| Ransomware                                               | any                                | universal: no mass change                 | mass_change; Poisson burst                     | S19                      | S46, S50    |
| Defense evasion, log tampering                           | any                                | universal: no tampering                   | tamper                                         | S20                      | S48         |
| Data theft                                               | any                                | —                                         | exfil; CUSUM                                   | S22 (partial, known gap) | S44         |
| AI agents running injected instructions                  | agent_input                        | agent external_content_exec               | fetch, hide                                    | S12                      | S45         |
| Unpatched, workaround-only and end-of-life software      | —                                  | Exposure stage escalation                 | —                                              | S16, S28, S29            | —           |

Rows marked "add one" need a benign counterpart before Phase 7; creating them is part of Phase 1.
