# Phase 8 plan: real platforms (not started)

**Status: skipped on purpose.** Phase 8 needs a real sensor in an isolated lab. The environment the
project was built in cannot provide one, and nothing in this repository fakes it. This document says
what was checked, what the adapters need, and how the phase would be run and judged.

## Why it was not started here

Checked on 2026-10-29 on the machine the work was done on:

| Needed | Found |
|---|---|
| Root or `CAP_BPF` / `CAP_SYS_ADMIN` to load eBPF programs | an unprivileged user, no capabilities (`CapEff` 0), `sudo` asks for a password, `kernel.unprivileged_bpf_disabled=1` |
| An eBPF toolchain (`bpftool`, `bpftrace`, BCC, `clang`/`llc`) | none installed; `strace`, `perf` and `auditctl` exist but cannot be used without privilege for system-wide tracing |
| An isolated lab VM with snapshots, no internet, synthetic users | none: a virtualization check reports no VM, no container runtime, no `qemu` or `virsh`; the host is a shared cluster login node used by other people |
| Permission to run harmless stand-ins that spawn processes, write web-root files and open connections | not on a shared login node: the project's own rule is "isolated VM lab (snapshots, no internet, local fake attacker server, self-made lab-only test web app)" |

Using a shared multi-user node, or a user-space `ptrace` sensor, to produce "lab verdicts" would
break the privacy rule (raw events only on synthetic users in an isolated lab) and would not test the
thing Phase 8 tests, so it was not done. Phase 8 is therefore **not claimed** anywhere in the results;
every result in the repository is a replay result.

## What the adapters need

The core stays untouched. Everything platform-specific sits behind the two seams of
`src/refmon/interfaces.py`: `Sensor.emit(sink)` and `Enforcer.act(Action) -> ActionResult`.

### Linux endpoint and server sensor (eBPF, user-space loader in Python or Rust)

| Event type | Source on Linux | Notes |
|---|---|---|
| `exec` | `sched_process_exec` / `sys_enter_execve` tracepoints; parent from `task->real_parent` | `program` and `signer` are raw attributes handed to Observe in memory; `signed` from IMA/fs-verity or the package manager, else `unknown` (never false) |
| process ancestry | `sched_process_fork` / `sched_process_exit` | keeps the tree the Tag stage needs; the sensor must survive PID reuse (use start time as part of `actor.id`) |
| `file_write` | `vfs_write`/`openat2` with write flags, or `fanotify` for configured roots | `path_group`, `web_root`, `new_file`, `executable` are decided in Observe from the raw path; the sensor never hashes |
| `net_connect` | `cgroup/connect4`, `connect6` hooks or `sys_enter_connect` | raw `host`/`ip` to Observe; no DNS content stored |
| `persist` | watches on `systemd` unit dirs, cron spools, `~/.config/autostart`, shell rc files | one event per new or changed item |
| `priv_change` | `setuid`/`setresuid`/`capset` tracepoints, `sudo` exec | |
| `security_tamper` | signals or `ptrace` to the agent and the security tools, writes to their config and logs, `systemctl stop` | includes tampering with Refmon itself |
| `asset_access` | `openat` on configured protected paths, canary files via `fanotify` | canary matching in Observe |
| `request_in`, `request_end`, `response_out` | a module or middleware of the lab web stack (for example an nginx module or a WSGI/ASGI wrapper) that hands the raw request to Observe in memory | the sensor never hashes, logs or stores a body or URL; `response_out` carries sizes only |
| `content_in`, `user_input` (endpoint) | browser and mail download hooks, clipboard and input-method events of the desktop | needs a desktop session in the lab; a headless server lab only exercises the server half |

The sensor reports which capabilities it has (`process_ancestry`, `request_in`, `file_writes`,
`network_connections`, `privilege_changes`, `signature_check`), which feeds the heartbeat's degraded
protection (A40). A missing capability must never become evidence.

### Enforcer

| Action | Linux mechanism | Undo record |
|---|---|---|
| `hold` | `SIGSTOP` of the process, or the cgroup freezer for a tree | `SIGCONT` |
| `kill_process_tree` | kill the cgroup or walk the tree from the root | none (a killed process stays killed) |
| `cut_network` | per-process cgroup with an `nftables` or cgroup-bpf drop rule | remove the rule |
| `quarantine_file` | `rename` into a root-owned quarantine directory, mode 000, never deleted | move back |
| `revert_persistence` | disable the unit or remove the cron entry, keeping a copy | reinstate |
| `restore_file` | from the known-good hash baseline (a snapshot or package manager) | restore prior state |
| `isolate_host` | `nftables` policy dropping everything but the management channel | lift |

Every action is labeled-only (or one of the documented fallbacks, A47, A51, A52) and idempotent.

### Recorder

A recorder that writes replay files. In the isolated lab VM, with synthetic users and harmless
synthetic content only, it may write `RawEvent` fixtures; everywhere else it records post-Observe
`Event`s only. The recordings are what `ReplaySource` already reads, so the replay-versus-lab check
is a diff of two verdict lists.

## Lab design

- Two VMs on an isolated host-only network, snapshots before every run, no route to the internet:
  an endpoint (desktop, synthetic user) and a server (a small lab-only test web app with a deliberate
  debug endpoint that spawns `echo`, and a stand-in that writes a harmless `.php` text file into a
  test web root).
- A local fake attacker server that serves only harmless payload text and records connections.
- Harmless stand-ins, self-made, for every catalog scenario (S01 to S50): the stand-in reproduces the
  *behaviour* the scenario describes (run a command, write a file, connect out, change many files,
  stop a test service) with `echo`, `touch`, `sleep` and files of random text. No real exploit, no
  real malware and no PHP2Shell code is written, downloaded or reproduced.
- The benign scenarios run as benign work on the same VMs.

## Done when (from CLAUDE.md Phase 8)

1. Lab verdicts equal replay verdicts for all 46 scenarios (the same `decision`, the same containment
   actions), measured as a diff and reported per scenario.
2. Per-event overhead is measured: Observe to verdict latency per event (median, 99th percentile) and
   CPU of the sensor, on a quiet VM and under a file-change burst.
3. The open measurements of earlier phases are taken here: the memory cost of the self-test deep copy
   (A38), the Poisson baselines and the long-window baseline (A29, A49) from real benign traffic, and
   the hold-to-containment time (C10: under 1 s from first malicious action to block).
4. The privacy audit runs on the lab recordings: zero raw content outside the isolated lab, zero
   reversals.

## Risks the lab must answer

- Event rate: a busy server may produce more `file_write` and `net_connect` events than Observe can
  fingerprint in line; the sensor needs sampling that never drops a labeled process's events.
- `signed` on Linux is rarely available; the launcher contract (D20) will mostly report `unknown`
  (degraded protection), and signed malware passes it by design.
- A kernel-level sensor is itself attack surface: the agent's own integrity (signed policy,
  heartbeat, self-test) reduces and does not remove the risk of an attacker with full control of the
  host (C12).
- Pausing with `SIGSTOP` can break a program that holds locks or a connection; the fallback pauses
  (A47) touch unlabeled processes and need the most careful lab runs.

## Effort

Roughly: sensor and enforcer for one Linux server stack, two to three weeks; the endpoint half and the
stand-ins for all 46 scenarios, two to three more; measurement and report, one. These are planning
estimates, not measurements.
